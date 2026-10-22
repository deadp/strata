# State: Strata (fork)

## Goal
Strata is an offline, stdlib-only forensic image examiner that opens evidence read-only and keeps a tamper-evident audit log.
This fork (deadp/strata) is where Joshua's changes are written before they go to upstream switch-nz/strata as PRs.

## Now
- Fork synced with upstream on 17-10-2026 (Sync fork): main now has upstream's 0.9.0 release (03-10-2026) plus the fork's STATE.md commit. Ahead/behind counts were not checked because upstream could not be fetched from the runner.
- 21-10-2026 security audit fixes landed on the fork (#5, #6, #7), each also intended as its own upstream PR:
  - #5: unlocked BitLocker/LUKS volume keys are no longer written to the case file. The `volume_keys` table and save/get/forget_volume_key are gone, unlocked state is session memory only, and opening a case drops any legacy `volume_keys` table.
  - #6: hostile-input allocations are bounded: EWF2 chunk indexes capped by image size, oversized registry log hive sizes/page offsets refused, AFF4 chunk and member inflation capped. PDF `#HH` name escapes are decoded before matching.
  - #7: a truncated AFF4 deflate member or chunk is now an error, not silently short data.
- Tests on synced main (before #5-#7; not re-run since): `python -m unittest discover -s tests -p "test_*.py"` ran 1422 tests, OK (14 skipped); `python tests/smoke.py` passed all checks (25 ok lines).
- Joshua has no open PRs on upstream. His 22 PRs there are all merged or closed (latest: browser disk caches, 23-09-2026).
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

## Next action
`Take the open roadmap item "LUKS2 with Argon2 against real cryptsetup images" (docs/ROADMAP.md): build a LUKS2 volume with real cryptsetup, check Strata unlocks it, and tick the item only if it does. Open the PR on the fork first.`

Last updated: 23-10-2026
