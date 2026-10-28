# FDK finite native adapter independent review

October 12, 2026. **Source/local fixture review complete; ready for controlled
native integration at the frozen lock below. No material acceptance bypass was
reproduced within this stage's documented scope.** Actual native Docker/build,
native ABI/smoke/cleanup, 16K loading, provider installation, publication,
performance and M2 execution remain **NOT RUN**.

This reviewer owns only this document. Updated roadmap and package inventory
were read. No implementation/template/lock/shared manifest/workflow/Git edit,
Git command, native stage, source fetch or package/host installation was run.
Source readiness does not establish any R1–R5 or release acceptance gate.

## Independent checks

`python3 -B -m unittest discover -s scripts/port/fdk-native-stage -p 'test_*.py' -q`:
**73 PASS, zero skips, 9.639 seconds**. The initial sandbox run could not bind the
18 owned temporary Unix-socket fixtures; the narrowly authorized rerun outside
that socket-restricted sandbox passed the complete suite. Broker tests use a
fake CLI/owned socket, and runtime tests use disposable own processes/descendants.
No real Docker daemon or native codec was executed.

Independent `/tmp/fdk-native-independent-review.py` checked all **39 actual
file hashes/modes**, the unchanged approved **22-file template map** and complete
**23-file materialized map** identities. Its explicit synthetic archive-inspector
control passed. With retained hashes refreshed, unapproved ABI dependency,
too-short classic roundtrip, missing xHE configuration marker and altered native
image still refused. Each of byte/payload/PKGINFO/BUILDINFO comparison failure
independently refused. Unverified second-worker cleanup forced sanitized public
FAIL while retaining hardware/installation/binary-publication NOT RUN. These are
data/semantic regressions, not codec execution or artifact acceptance.

## Input, daemon and execution boundaries

The adapter requires the actual accepted canonical 341 inventory and input lock,
an immutable ARM image and bootstrap binding, accepted original native build
result/recipe/input/helper hashes, explicit source commit, and current job SHA
agreement. The original native result lacks a commit field; this documented
limit is handled by separate source/checkout/job binding rather than inventing
a field. Native-build PASS does not imply original lifecycle acceptance.

The source snapshot checks every locked byte and executable mode against the
supplied Git commit, then rechecks source/copy hashes for race drift. The lock
binds the existing builder/comparator/checker/entry/bootstrap and the approved
FDK template; extra/missing/uncommitted inputs refuse. Template/materialized
maps stay `b569ff9a...`/`4c9a6e04...`. The selector is limited to the fixed
upstream revision/archive pin and produces the selected 900-file packet; the
materializer must reproduce all 23 approved hashes before worker launch.

Every broker operation uses the canonical approved Unix socket and pinned CLI,
with private empty Docker config and no inherited context/endpoint settings.
Socket inode/owner/mode, CLI bytes/inode and daemon identity are checked around
operations. Native daemon identity uses bounded fixed `GET /info`; CLI plugin
metadata enumeration is avoided. All permitted CLI operations are finite builtin
queries/create/start/owned removal. Image/command/resource/mount/environment
identity is checked before attach. Drift refuses rather than switching daemons.

Container names and create-attempt ownership are durably journaled before create,
including unknown outcomes. The journal binds nonce label, image, user, daemon,
socket/CLI pins and expected command/mounts. Cleanup reloads it after worker
cancellation, inspects ownership before removal and verifies name/ID absence.
Unrelated collisions are not removed. Unknown asynchronous create plus empty
listing is treated as uncertain absence/FAIL; cleanup has its own finite budget.

The generic builder is reused read-only through a module-local command proxy;
the checker retains its standard subprocess module. Compilation is confined to
network-disabled, capability-free, nonroot containers with read-only root/input
mounts, private IPC/cgroup namespace and finite CPU/RAM/PID/tmpfs limits.
Host/checker children have bounded output/time/resources, separate tracked groups,
spawn signal masking, subreaper cleanup and direct-child parent-death handling.
The documented limit remains: these controls do not attest arbitrary detached
processes or a failed daemon under host loss.

## Receipt and publication authority

Worker acceptance binds actual recipe snapshots, generated/artifact metadata,
all retained evidence hashes, actual accepted inventory and reinspection of the
package archive. BUILDINFO binds recipe and the complete versioned installed set.
ABI/smoke records require both AArch64 libraries, SONAME/export counts, allowed
glibc dependencies, 16K LOAD geometry, classic AAC-LC roundtrip and explicit
xHE configuration-only scope. Compilation and log claims still require the
actual native trial; xHE encoding/roundtrip and 16K/M2 loader behavior are not
accepted from these checks.

Comparison requires distinct clean containers and all four exact equalities:
archive bytes, installed payloads, PKGINFO and BUILDINFO. Parent/worker finalizers
retain FAIL on cancellation, receipt failure or uncertain cleanup; cancellation
during final publication/handler restoration invalidates prior PASS. The public
status requires every prerequisite, both worker cleanups, comparison and final
owned-container absence. Only fixed sanitized status fields enter `public/`;
source, binaries, raw logs, paths and exception text remain private.

Codec notices/terms and publication restrictions remain mandatory. A native
development PASS cannot select the provider, install it, publish binaries or
establish Apple/PipeWire integration. Performance and physical M2 work remain
separate required tasks in the complete port.

## Frozen source snapshot

| Input | SHA256 |
| --- | --- |
| `stage.lock.json` | `a7048064c0c20abd246a466035313abaf65590f3ed10d0f7927b21a346200ad6` |
| `stage.py` | `700f9bef190f7c6596ab4e6a625e55bdd1811ce2e9964b0af4b5b30410aeff89` |
| `broker.py` | `6480333ea4f6267cd55019fd7928077392bb5c052583dc07d582fc64620f20fd` |
| `evidence.py` | `0b134a59d623b638922b70ebf6b4f65b9a32d77ef682d4be08f488b0fd3c5a1c` |
| `runtime.py` | `253494be99c21c83743b384b2c06cd1627023ffaf54f0cbbd271bde80572f70a` |
| `worker.py` | `5ea89e882ea518d89b6c78e347d57f56b00434a80e41aa149fff078dfa331f5a` |
| `template-inputs.json` | `b569ff9ae69eb56e9b9635c3ed0849eaebbfa516f48304ade1790f802532bb63` |
| `reviewed-inputs.json` | `4c9a6e04c964145fad2da64e627ca0f06f576aec40f443e701cad930d916c38b` |

Disposition: **no open blocker from this bounded source/local review**. The
coordinator must retain actual same-job native outcomes, artifacts and teardown
before marking native build accepted. No old hosted image, mocked receipt,
source audit or passing fixture can supply that execution evidence.
