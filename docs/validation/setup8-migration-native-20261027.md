# Setup8 migration: native pairs and installed fixtures

Root accepted **cachy-asahi-setup 0.3.0-1** for finite generic native ARM 4K
build-pair and disposable installed-migration evidence only.
[Run 40490674681, attempt 1](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40490674681)
used exact [source 5d0f5ae6331807704a8ebafc7922972629e0b96f](https://github.com/Gabriel-Kahen/cachy-asahi/tree/5d0f5ae6331807704a8ebafc7922972629e0b96f)
on `codex/setup8-explicit-validator-source-v5`, tree
`10a8649ee4e9df0dcf5e7ef3e8bf62d1cc562a78`.
[Job 122143535275](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40490674681/job/122143535275)
retained [artifact 12728587696](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40490674681/artifacts/12728587696).

| Evidence | Accepted result |
| --- | --- |
| Setup8 fresh pair | Two identical 33,900-byte archives; ten-file payload, PKGINFO and BUILDINFO identical |
| Held Setup7 fresh pair | Two identical 30,316-byte archives; six-file payload, PKGINFO and BUILDINFO identical |
| Independence | Distinct recorded build containers on one native ARM machine; independent machines are not attested |
| Setup8 installed lifecycle | Six install/upgrade/repeat/remove/reinstall/final-remove transitions; nine old7-owned components migrated; original 574-package inventory restored |
| Delivered CLI | 12 initial cases and 1 reinstall case; 50 initial, 12 reinstall and 7 separate upgrade-home CLI observations, including actual SIGKILL/recovery and refusal/conflict preservation |
| Held installed baseline | Eight Setup4↔7 plus six Setup5↔7 transitions; six profiles/24 phase observations; 6 recovery and 19 status cases |
| Hosted source controls | Maintained 21, held lane 30, migration lane 14, original migration 29 and package 4; setup suite 93 registered, 91 passed, 2 skipped |

The nonverbose setup-suite log does not identify the two skipped test names.
They remain skips and do not establish installed shell coverage.
Execution used unsigned local candidates, ordinary UID 1000 and inert private
fixtures in disposable native `aarch64` containers with 4096-byte pages.

The Setup8 archives have SHA256
`8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47`;
the Setup7 archives have SHA256
`027c802a90fde820a4773b259203a77e18132cbb7b0fb9454c2d368426f66d09`.
The artifact digest is
`sha256:2f27ac455f2a1bd1961d2b9c4021849eac7ecf1d24c01e35147298f2f35f25ba`.

The [Root qualification receipt](../../artifacts/development/setup8-explicit-validator-source-native-actual-20261027/Root-native-component-qualification.json)
adopts the same sealed collection without reacquisition. The
[frozen 101-file reader](../../artifacts/development/setup8-v5-real-flock-reader-correction-development-20261027/author-freeze.json)
has freeze SHA256 `85e5764e305ad27e474bf53299a506c58f27d859f70682361c4500daafa9a5a0`.
Its [strict result](../../artifacts/development/setup8-v5-real-flock-reader-correction-development-20261027/projection-corrected/strict.stdout)
is 28,418 bytes, SHA256 `05eb1bdf1b880119450d8d2733896384677f049e27f77b61b7edc3c989f7dc87`:
119 source files and their five-source inverse chain, terminal metadata, logs,
pairs and all 463 members/462 retention leaves join. Root acceptance is separate
from the passive reader's data-consistency result.

Preservation and cleanup rely on exact-source runtime assertions and joined
receipts; full raw snapshots, target bytes and ledger bytes were not retained
for independent recomputation. The pinned lifecycle checks the staged delivery
driver against source; runtime receipts emit no independent driver hash.
Signed input pins join the exact-policy producer result; the passive reader
performs no fresh GPG, ALPM, cache or live daemon authentication/recheck.

Canonical adoption is a separate proposal: retain the existing migration engine
and copy the three `scripts/setup8/` files plus twenty recipe inputs exactly from
the accepted source. Frozen package README/provenance statements saying native
or installed **NOT RUN** describe their pre-run state. Preserve those tested
`0.3.0-1` bytes; this external record supplies the later result.

Actual user profiles, real shell-module behavior, native 16K and both physical
M2 Air sizes remain **NOT RUN**. Signed integrated lifecycle and full installation
are not accepted. Performance is **NOT MEASURED**; release is **NOT ADMITTED**.
