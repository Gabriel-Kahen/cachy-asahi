# KSM control foundation: read-only status/report

Development candidate `cachy-asahi-ksmctl` expands beyond configuration templates
with a licensed executable diagnostic. It implements **read-only status/report
only**, not complete KSM management or R4/M6 acceptance. Native builds,
installation, exact-model hardware execution and performance results are
**NOT RUN**. Enable/disable/pause, policy integration, restoration and measured
platform acceptance remain owned work below.

Owned paths: `packages/tools/cachy-asahi-ksmctl/**` and this report. The preceding
[functionality matrix](../port/tools-functionality.md) retains all 74 scoped
recipe paths, all 49 tagged settings payloads and 12 sysctl controls. This work
changes no original four-package recipes/locks, canonical setup helper, shared
manifest, workflow, Git state, platform/default configuration or host sysfs.
Native package coordination and any inventory selection belong to the root
coordinator.

## Source and license review

Upstream source:
[`cachyos-ksm-settings/ksmctl`](https://raw.githubusercontent.com/CachyOS/CachyOS-PKGBUILDS/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-ksm-settings/ksmctl),
CachyOS-PKGBUILDS full revision
`c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`.
Exact original bytes (2,606 bytes) are retained as `upstream-ksmctl`, SHA256
`cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9`.
The source explicitly grants GPL version 2 or later and credits
Vasiliy Stelmachenok/CachyOS, 2024–2025. The complete original notice remains in
the translated runtime, alongside the derivative copyright. NOTICE retains
attribution and describes the modifications. This code is GPL-2.0-or-later,
not relicensed under the project's original MIT grant.

Full [GNU GPL version 2 text](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)
is included as LICENSE, SHA256
`edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6`.
`source-provenance.json` pins origin, derivative, full license and complete
`adaptation.patch`. `check-source.py` verifies all pins, the origin declaration,
retained header and exact recomputed diff without running either executable.
Source acquisition and review occurred before candidate implementation.

The original shell executable is attribution/review input only; it is neither
executed nor installed. Its enable/disable/pause/root-write branches are absent
from the derivative. The larger `cachyos-ksm-settings` package, its services,
user/session/getty overrides and default enablement are not selected. `ksmstats`
was not copied: it lacks an individual grant header and assumes 4 KiB pages.

## Implemented behavior and package contract

The Python 3.11+ CLI exposes default `--status`/`-s`, `--report`/`-r`, `--json`,
`--help`, and `--version`. Status 0/1/2 describes stopped/scanning-enabled/unmerge
requested; it does not infer merge savings, active work or unmerge completion.
Optional unavailable counters are explicit null/unavailable. Present malformed,
truncated, nonfinite, oversized, unreadable, symlink or special input fails.

It reads only fixed KSM interface filenames using read-only, no-follow,
nonblocking descriptors and validates regular-file type. Required interface
absence exits 3, observation errors exit 1, and unsupported management arguments
exit 2 before any kernel read. Successful observation exits 0; it is not a health
or compatibility verdict. `--help`/`--version` read no sysfs. No writes, external
commands, privilege escalation, service start, user configuration or network
request occur in the runtime.

Page counters use actual `os.sysconf('SC_PAGE_SIZE')` for exact decimal MiB
conversion. There is no CLI page-size override. `general_profit` is signed bytes,
converted without multiplying by page size; `full_scans` is a scan count.
Independently sampled counters are not represented as an atomic snapshot or
measured performance. Python-only fixture injection supplies test directories
and 4 KiB/16 KiB page sizes; no test writes host `/sys`.

The separate `packages/tools/` recipe stages a CLI under `/usr/bin`, README and
source-provenance under `/usr/share/doc`, and NOTICE/full LICENSE under
`/usr/share/licenses`. It has no install script, hook, service, timer, default,
protected platform path, conflicts, replaces, provides or system mutation.
Removal deletes those package-owned files only. Runtime dependency: Python
3.11+; no external shell/coreutils tool is called. `arch=any` is a script package
declaration, not proof of ARM execution or M2 compatibility.

The recipe's checks parse Python source, verify provenance and run temporary
fixture tests. Packaging is reserved for the existing isolated ARM builder;
PKGBUILD must not be sourced or built/installed on the host. Complete source,
origin, test/build files and diff must remain retrievable alongside any future
distributed package. The installed Python executable itself is source, while
the origin/diff are retained with the recipe.

## Remaining required management and measured platform work

| Required function | Accountable track / gate before implementation or acceptance |
| --- | --- |
| Supported capability and diagnostics | Platform owner: exact selected Asahi CONFIG_KSM/controls, kernel/page geometry and both Air model records. An absent optional feature is reported unsupported, never a reason to replace the platform kernel automatically. |
| Enable/scanning policy | Platform/performance owner: application eligibility/madvise or supported per-process policy, privilege/security implications, bounded scan/interval/CPU policy, baseline capture and explicit activation. Source architecture declarations do not pass this gate. |
| Pause and disable/unmerge | Platform owner: separate stopping from unmerge semantics, operation progress/error handling, concurrent changes and low-memory/OOM failure tests. Unmerge can increase memory demand; no restoration promise based only on writing an old control value. |
| State restoration and removal | Tools/platform owner: journal prior effective values, unit enablement/active state and owned config; undo only owned changes, preserve administrator edits; test interruption/repetition and removal/reinstall. Previously unmerged pages or killed applications cannot be recreated from a control journal. |
| Measured policy/default selection | Performance owner: predefined usefulness/regression budgets, documented unchanged baseline, repeated correctness/latency/throughput/memory/CPU/energy/thermal trials, retained failures, both exact Air sizes. A counter estimate is not a measured gain. |
| Native package acceptance | Build owner/coordinator: full frozen recipe input map, isolated native build/rebuild, archive hashes and payload/mode/owner/metadata/provenance inspection; then signed package install/upgrade/remove/reinstall. No shared manifest promotion from source checks alone. |
| Integrated release/maintenance | Coordinator/platform/release owners: retained known-good platform and tested recovery, full-port package closure, independent contributor/user workflow, repeated release, named ongoing maintenance. This diagnostic cannot satisfy A13/R4 by itself. |

No management action or policy default is silently discarded: it remains an
explicit required work item. The broader [M6 matrix](../port/tools-functionality.md)
retains GUI/update/kernel/hardware/shell/default functionality beyond this first
bounded package.

## Historical 11-file diagnostic checkpoint

The checks and hashes in this section record the earlier diagnostic-only
checkpoint. Its 18-test result and 11-file/e66 map are historical; use the final
15-file handoff below for subsequent candidate builds.

| Check | Actual result / limit |
| --- | --- |
| Original bytes/explicit GPL grant and full license | PASS: fresh primary GNU license/source retrieval and pinned original/diff/header verification; no upstream executable run. |
| `python -B packages/tools/cachy-asahi-ksmctl/test_ksmctl.py -v` | **18 PASS**: 14 runtime fixture tests and four provenance groups with stale/coherent tampering subcases. |
| 4 KiB / 16 KiB conversion | PASS: 256 pages report exactly 1 / 4 MiB; runtime `os.sysconf` calls also verified through mocks. No physical 16 KiB kernel execution claimed. |
| Signed byte estimate / scan units | PASS: `general_profit=-1048576` remains -1 MiB at either page size; scans have no MiB conversion. |
| Missing/unreadable/nonfinite/truncated/special inputs | PASS: fixture absence, null optional counters, I/O denial, strict LF/numeric/range bounds, symlink/directory/FIFO refusal and distinct exit behavior. |
| No mutation or implicit management | PASS: fixtures' bytes/modes/mtimes unchanged, opens read-only; unsupported write flags refused before reads; help/version require no interface. |
| Provenance/check-source | PASS: hard origin/full-license pins, exact complete diff and retained GPL notice; coherent origin/license changes or omitted notice cannot bypass checks. |
| Python AST and `bash -n PKGBUILD` | PASS; PKGBUILD was parsed as text only, never sourced or executed. |
| Existing static package checker, explicit recipe path | PASS: all 11 recipe input files bound, local source hashes correct, literal PKGBUILD/SRCINFO metadata equal, no install hooks/platform relations. |
| Independent source/fixture/packet review | PASS for licensing/provenance, read-only I/O, conversions, units, failure cases, all nine source checksums and final metadata/package staging; native behavior remains unverified. |
| Original four package trees | PASS: remain byte-identical to their existing reviewed lock after this work. |
| Native ARM build/rebuild / package archive | NOT RUN; coordinator owns execution and actual isolated makepkg metadata/archive comparison. |
| Installation/upgrade/removal / actual Asahi KSM status | NOT RUN. |
| Both Air hardware / management / performance | NOT RUN / not implemented / NOT MEASURED. |

Historical frozen source handoff:

| Input | SHA256 |
| --- | --- |
| Runtime | `f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558` |
| Full adaptation diff | `0bc6b1f4725eb510a0f890bd616ce682b98332b371c93d2144ad643181727212` |
| Tests | `e42602fd16579e30c8cb799f26c897c1e3e89515f20a49a346b1888ce3c94b6f` |
| PKGBUILD | `aa0c3fb8a317edaf7d331b589a93278328951e024220fe27389d3bc613478ec6` |
| SRCINFO | `c2b632627e2b4d0445a6a4c9dce2980c46ecc133cee5904befffe082257d265b` |
| Builder reviewed input map | `e66d2a92dd61c418318a2c4ffc52f6d4682f9d8d4d8661eb91715f6aff198731` |

Temporary read-only static report and builder input map:
`/tmp/cachy-asahi-ksmctl-review-trwyyvyj/{static-report,reviewed-inputs}.json`.
The map is deliberately outside the recipe to avoid recursive self-hashing.
The existing build controller can consume it via `--reviewed-inputs` with the
explicit `packages/tools/cachy-asahi-ksmctl` path. Default checker discovery
currently scans desktop/shells/settings, so broader tools discovery/native CI
integration needs coordinator reconciliation; no shared tool was changed here.
Recompute the complete map if any recipe file changes before dispatch.

An interim test fixture attempted to rewrite its own mode-0444 inputs; the test
helper was corrected to temporarily restore write permission before preparing
each case, then return to read-only mode before snapshots/runtime invocation.
Final tests pass. The runtime never wrote those fixture files. An in-flight
static review also caught the test-source checksum changing; PKGBUILD/SRCINFO
were refreshed before the frozen handoff above.

No native build, host installation, hardware operation or performance
experiment was performed by this workstream.

## Final 15-file handoff — 2026-10-12

This supersedes the historical 11-file/e66 build-input handoff above. The final
candidate adds source-only `policy.py`, its tests, a management source audit and
separate native-stage instructions. The installed CLI remains read-only and
retains the same five payload paths. The policy validator consumes bounded
regular JSON fixtures, validates declared baseline/digest/action/tuning and
restoration proposals, and keeps management unavailable, execution unimplemented
and hardware/acceptance gates NOT RUN. It performs no kernel discovery or writes.
See [management policy](../../packages/tools/cachy-asahi-ksmctl/management-policy.md)
and [native-stage proposal](../../packages/tools/cachy-asahi-ksmctl/native-stage.md).

**Actual software result: 36 tests PASS** — 18 runtime/provenance tests and 18
policy tests, including writerless FIFO, symlink and directory rejection without
fixture mutation. The coordinator independently reran all 36 successfully.
Independent final packet review passed: all 15 inputs matched the frozen map,
all 13 local source hashes matched the recipe, constant PKGBUILD/SRCINFO metadata
matched, and Python AST/package syntax checks passed. No native package build,
installation/removal, Apple hardware execution or performance result follows
from these checks. The original four recipe inputs remained unchanged.

The exact retained full input map is
`/tmp/cachy-asahi-ksm-policy-review-f4y_y4y4/reviewed-inputs.json`, SHA256
`f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44`.
Its sibling `static-report.json` records the explicit-path recipe inspection;
`software-validation.json` records the 36-test result, independent review and
unfinished execution gates. This documentation update rechecked the full map
against the current candidate tree without changing any candidate input.
The packet is temporary local evidence: retain it with the later job artifacts
before relying on it as durable release provenance. Keep the map outside the
recipe and regenerate/review it if any of the 15 inputs changes.

| Final recipe input | SHA256 |
| --- | --- |
| `.SRCINFO` | `60740b4d54a4ad38ba432b98784fdb804ec370154e93614afb40e204c2ebd196` |
| `LICENSE` | `edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6` |
| `NOTICE` | `939ad92c65a6c2f9da2c723a4c6e136add87ccb4a7a6e8ba0dd89692a77f3f10` |
| `PKGBUILD` | `b3714b1ef1136589081c69ed1f4aa48909d874c11f9c2d67ddb4b545309499d4` |
| `README.md` | `e7f806f7c81d5ddb2388faa4f7ddc53e04c004596a4f346bb270b47f8aad023d` |
| `adaptation.patch` | `0bc6b1f4725eb510a0f890bd616ce682b98332b371c93d2144ad643181727212` |
| `cachy-asahi-ksmctl` | `f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558` |
| `check-source.py` | `7cca209ee6ad36726b03c0f54100b07bd6d08d974473d00c2092bbd5be4089a6` |
| `management-policy.md` | `ba5ca032b7e3b4757be38c18b24c295399ab1ec43c0ba3552ae5e2ff75d32437` |
| `native-stage.md` | `a2f0ea5fc896f06843bdf56a6b655cc93421d36fc3b59a864814a5c248bd6259` |
| `policy.py` | `53cea58f017b06ac55f5a39c388abf050e034f67132578e384e20c00bfe68281` |
| `source-provenance.json` | `d46e93a9893225d205a01fdcd3429782ba51d44c86b78e77fce458b53448b849` |
| `test_ksmctl.py` | `e42602fd16579e30c8cb799f26c897c1e3e89515f20a49a346b1888ce3c94b6f` |
| `test_policy.py` | `1ed306235087a760b8199829c35e99ecdb4ab6b6ddb2eb27562a9659d518121f` |
| `upstream-ksmctl` | `cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9` |

Native execution must use the refreshed accepted snapshot bound to input SHA256
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`
(including Perl `5.42.3-1`) and its actual 341-package bootstrap inventory.
The coordinator reports the hosted image from run **38200957061** is now
unavailable after job teardown. Recreate the same accepted snapshot in a later
native job, capture its new immutable image ID and package-lock receipt, then
execute the separate candidate stage while that image is available. The earlier
run **38189520114**, its image ID and old 341-row lock remain historical evidence;
they are not substitutes for the refreshed snapshot.

The native-stage document remains a proposal. Two fresh native builds and
archive/metadata/payload comparison, a separately reviewed disposable-container
installation/removal stage, actual KSM management, both exact Air models and
measured policy/default selection remain unfinished. The coordinator owns
pipeline integration; this handoff changes only this workstream report.
