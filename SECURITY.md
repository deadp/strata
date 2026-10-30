# Security policy

Strata is an offline forensic tool: it reads evidence images, keeps cases on
disk, and normally talks only to `127.0.0.1`. Its trust story matters, so
reports are taken seriously and handled privately.

## Supported versions

Strata has just had its initial release, so every version currently published
is supported by security fixes.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting for this repository
(**Security → Report a vulnerability**), or contact the maintainer directly.
Include:

- the Strata version and the platform it ran on
- what an attacker could do with the flaw, and how you reached that
- a reproducer — a synthetic image or case file is ideal; please do not send
  real evidence

You can expect an initial response within two weeks. Fixes will be credited to
the reporter on request.

## Scope

In scope:

- the engine's parsing surface: image formats, filesystem parsers, registry,
  archive and artefact parsers, anything that consumes untrusted bytes
- the local HTTP interface and its request gating (origin/host checks,
  session cookies)
- case files: the audit log's tamper-evidence, case SQLite handling
- the password handling for BitLocker and LUKS unlock

Out of scope:

- the trustworthiness of the evidence itself — a malformed exhibit is
  input, not an attack surface; format bugs are exactly what the report
  chain is for
- issues requiring write access to the examiner's own machine first

## Notes for deployers

- `python3 run.py --host 0.0.0.0` serves the interface to the network with
  **no authentication**: anyone who can reach the port can drive the session.
  Use it only on a trusted, isolated network.
- Evidence is opened read-only, but the case folder is not — protect it like
  any case record.

## Optional keyed audit log

The audit chain is unkeyed by default: anyone who can write the case folder
can rebuild a whole forged chain. An optional per-case key stops that.

Set `STRATA_AUDIT_KEY_FILE` (path to a file holding the key; one trailing
newline is dropped) or `STRATA_AUDIT_KEY` before opening the case. Each new
entry then gets a tag, `HMAC-SHA256(key, previous tag | entry hash)`, kept in
the `audit_mac` table. The key is never written to the case or the log.

- Verify without a key behaves as before for unkeyed logs. A keyed log that
  otherwise checks out reports "keyed, key needed", not intact.
- Verify with the key names the first entry whose tag is wrong or missing.
  Tags must run unbroken to the end of the log; entries from before the key
  was turned on may be untagged.
- Tags are compared in constant time; the key is not put in errors or logs.
- Once a case is keyed, logging without the key is refused.

Limits: this stops forging without the key. It does not stop someone who
holds the key, deleting the whole log, or removing every tag and the keyed
marker (the case then looks unkeyed). The recorded head is not keyed, so
cutting entries from the end is caught as before, not by the key.

### Assumptions

1. Off by default; unkeyed cases and old logs behave as today.
2. Key from a file path or environment variable only; no passphrase prompt
   or UI.
3. Unkeyed and keyed verify modes; first bad entry named; keyed without key
   is "key needed".
4. Constant-time comparison; key never logged.
5. Tags live in a separate `audit_mac` table keyed by entry number, chained
   through the previous tag; the existing hash columns are unchanged.
6. A keyed case refuses new entries without the key (an untagged entry would
   break the log for good).
7. The web UI is unchanged; a key-needed result shows there as a broken
   chain with no entry number.

### Questions for maintainers

- Key source: are a file and an environment variable enough, or do you want
  a passphrase-derived key or a UI?
- Tag format and place: separate `audit_mac` table, hex HMAC over previous
  tag and entry hash. Prefer a column on `audit`, or a MAC over the raw
  fields?
- Should keyed ever become the default (e.g. a generated key stored beside,
  not in, the case)?
- Migration: existing logs stay unkeyed until the key is first set, with
  older entries left untagged. Should there be a command to tag them, or to
  refuse mixed logs?
- Should the head record be keyed too, and a keyed marker kept outside the
  case so stripping tags cannot downgrade it?
- Should refusing to log without the key be an error, a warning, or a
  read-only open?
- UI and report wording for "keyed, key needed".