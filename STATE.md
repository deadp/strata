# State: Strata (fork)

## Goal
Strata is an offline, stdlib-only forensic image examiner that opens evidence read-only and keeps a tamper-evident audit log.
This fork (deadp/strata) is where Joshua's changes are written before they go to upstream switch-nz/strata as PRs.

## Now
- Upstream main is at release 0.9.0 (03-10-2026). This fork's main is still at 16-09-2026, 179 commits behind upstream.
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

## Next action
`Sync this fork's main with upstream switch-nz/strata (fast-forward, no force push), run the tests, then pick one open roadmap item that needs real-evidence checking and open a PR on the fork first.`

Last updated: 14-10-2026
