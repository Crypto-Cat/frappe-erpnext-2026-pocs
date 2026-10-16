# Frappe and ERPNext security research

Proof-of-concept clients for seven issues reported to Frappe on 29 July 2026,
found by source-first review of Frappe Framework 16.29.0 and ERPNext 16.30.0.

## Contents

| Directory | Issues | Writeup |
|---|---|---|
| [frappe01-email-file-read](frappe01-email-file-read/) | Unauthenticated local file disclosure through email inline expansion | [Writeup](https://cryptocat.me/blog/research/analysis/frappe_email_file_disclosure/) |
| [frappe02-03-04-oauth-jinja-chain](frappe02-03-04-oauth-jinja-chain/) | Guest OAuth stored XSS, Genericode filename traversal, safe-Jinja file write | [Writeup](https://cryptocat.me/blog/research/analysis/frappe_oauth_jinja_rce_chain/) |
| [frappe05-07-web-form-authorization](frappe05-07-web-form-authorization/) | Unpublished Web Form RPC access, Web Form protected-field bypass | [Writeup](https://cryptocat.me/blog/research/analysis/frappe_web_form_authorization/) |
| [frappe06-04-bulk-update-csrf](frappe06-04-bulk-update-csrf/) | State-changing bulk-update GET CSRF | [Writeup](https://cryptocat.me/blog/research/analysis/frappe_bulk_update_csrf_rce/) |

`FRAPPE-01` through `FRAPPE-07` are my own report identifiers from the
disclosure. They are not Frappe advisory numbers.

## Status

No CVE has been assigned to any of the seven. Two have security advisories: [GHSA-8v98-cfpm-9p67](https://github.com/frappe/frappe/security/advisories/GHSA-8v98-cfpm-9p67) for the email file read (FRAPPE-01) and [GHSA-9pp9-wgp9-3p3j](https://github.com/frappe/frappe/security/advisories/GHSA-9pp9-wgp9-3p3j) for the Genericode traversal (FRAPPE-03). The OAuth stored XSS (FRAPPE-02) still has no fix on any stable release. Fix status per issue is in each writeup and in every client's `--help`.

## Running the PoCs

There are eleven clients across the four directories. Each directory has its own
README listing its clients, their preconditions, and the state they leave behind.
Every client takes `-h/--help`, which prints the finding it exploits, the access
it needs, and a worked example. Progress is written to stderr as coloured
`[*]`/`[+]`/`[!]`/`[-]` lines under a banner, while the recovered file, created
document, exploit URL, or command output goes to stdout, so you can pipe a run
and keep only the result. One example:

```console
python3 frappe05-07-web-form-authorization/frappe05_unpublished_web_form_submit.py \
  --url https://frappe.example --web-form unpublished-todo \
  --data '{"description":"x"}' > created.json
```

Colour is auto-disabled when stderr is not a terminal; pass `--no-color` or set
`NO_COLOR=1` to force it off.

## Requirements

Python 3.10 or later. Standard library only, except where a directory README
says otherwise. No `pip install` step.
