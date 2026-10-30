# State: Strata (fork)

## Goal
Strata is an offline, stdlib-only forensic image examiner that opens evidence read-only and keeps a tamper-evident audit log.
This fork (deadp/strata) is where Joshua's changes are written before they go to upstream switch-nz/strata as PRs.

## Now
- Fork last synced with upstream on 30-10-2026 (merge of switch-nz:main into main); the earlier sync was 17-10-2026. Main has upstream's 0.9.0 release (03-10-2026) plus upstream's #185 (volume keys, 25-10-2026) and #187 (hostile-input bounds, 29-10-2026). Ahead/behind counts were not checked because upstream could not be fetched from the runner.
- 21-10-2026 security audit fixes landed on the fork (#5, #6, #7), each also intended as its own upstream PR:
  - #5: unlocked BitLocker/LUKS volume keys are no longer written to the case file. The `volume_keys` table and save/get/forget_volume_key are gone, unlocked state is session memory only, and opening a case drops any legacy `volume_keys` table.
  - #6: hostile-input allocations are bounded: EWF2 chunk indexes capped by image size, oversized registry log hive sizes/page offsets refused, AFF4 chunk and member inflation capped. PDF `#HH` name escapes are decoded before matching.
  - #7: a truncated AFF4 deflate member or chunk is now an error, not silently short data.
- 26-10-2026 LUKS2 reader fixes landed on the fork (#9): keyslot `key_size` is read as bytes, the keyslot area IV starts at 0, and data IVs count 512-byte units on 4096-sector volumes. `tests/imagebuild_luks.py` was corrected to match and `tests/test_luks.py` has one test per fix. #9 reported the full suite at 1415 passed, 14 skipped; the new tests were not run against the old reader.
- LUKS2 is implemented but still unticked in docs/ROADMAP.md: it has only been checked against synthetic images. `tests/fixtures/luks/make_fixtures.sh` (#4) builds fixtures with real cryptsetup, but no real cryptsetup-written image has been checked yet and none is committed.
- Tests on synced main (before #5-#7; not re-run since): `python -m unittest discover -s tests -p "test_*.py"` ran 1422 tests, OK (14 skipped); `python tests/smoke.py` passed all checks (25 ok lines).
- Joshua has no open PRs on upstream that this repo shows. His 22 PRs there were all merged or closed as of the last check (latest then: browser disk caches, 23-09-2026); since then #187 (hostile-input bounds, PDF escapes; the upstream version of fork #6) landed upstream on 29-10-2026.
- Open fork PR #11 (not merged; branch queue/q659, 30-10-2026): optional keyed HMAC-SHA256 audit log chain, opt-in per case via env var or key file, new `audit_mac` table, keyed and unkeyed verify modes, 14 new tests. It is written to be offered upstream; the design choices are listed as assumptions in the PR. Nothing from it is on main yet.
- Upstream CI is green: Fuzz 13-10-2026, CodeQL 12-10-2026. The fork's last CI run was 16-09-2026 and passed.
- Upstream has 9 open issues, mostly feature requests (fuzz corpus, plugin API, localisation, GPS map, fragment carving, memory forensics, FileVault 2).
- The fork has 11 old feature branches whose PRs are merged or closed upstream; they could be pruned.
- Several roadmap items (Ex01, DMG, AFF4, QCOW2, VHD) are tested on synthetic images only; real-evidence checks are still open.

## Decisions
- Unclear date: A roadmap item is ticked only after it is exercised against real evidence.
- 15-09-2026: First commit upstream. Python standard library only, nothing touches the network.
- 16-09-2026: Add CI, parser tests, fuzzing, request-gate tests and CodeQL.
- 17-09-2026: A case can be previewed without writing to it.
- 18-09-2026: The native crypto sidecar is optional; the core stays dependency-free.
- 02-10-2026: Cross-check Strata against independent readers (libewf and others) on a synthetic corpus.
- 03-10-2026: Upstream cuts 0.9.0 with EWF2 (Ex01) and AFF4 read support.
- 21-10-2026: Volume keys are never persisted in the case file (session memory only), matching the README; old cases lose any stored keys on open.
- 21-10-2026: Parsers treat evidence files as hostile: sizes read from the file are capped before allocating, and truncated compressed data is an error.
- 26-10-2026: The LUKS2 reader follows the on-disk spec (key_size in bytes, keyslot IV from 0, 512-byte data IV units), and the synthetic test builder must not share wrong assumptions with the reader.

## Next action
`Finish the open roadmap item "LUKS2 with Argon2 against real cryptsetup images" (docs/ROADMAP.md): the reader is built and fixed (#9), so run tests/fixtures/luks/make_fixtures.sh with real cryptsetup, check Strata unlocks the resulting images, and tick the item only if it does. Open the PR on the fork first.`

Last updated: 31-10-2026
