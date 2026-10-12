# Cachy-update native candidate independent review

October 12, 2026. Updated bounded source/data/mock review. This reviewer owns
only this document. Current roadmap, package inventory and the earlier
`cachy-update-build-review.md` were read. No source/shared manifest/workflow/Git
edit, network operation, host installation, updater/system-service call, Cargo,
compiler or Docker execution was performed.

## Historical materializer finding

### New materializer spawn-cancellation ownership gap

At materializer SHA256
`73172c0b0ecfcc978bd7750d6569d30f78688354cbd92a56cad2b89b5f24d30e`,
`run()` assigns `child = subprocess.Popen(...)` without blocking TERM/INT across
spawn and assignment. Cancellation after fork/session creation but before the
constructor returns can leave `child is None`; the finally block cannot signal
that process group. A bounded independent mock marked the owned group created,
then raised `Cancelled` inside Popen: terminal status was CANCELLED with **zero
killpg calls**. No process or network operation occurred in this reproduction.
The installed CPython Popen constructor's exception cleanup closes pipes but
does not terminate a successfully created child.

Required narrow correction: protect spawn/assignment with signal masking,
restore the prior mask in the exec'd child, then restore parent handling once
the child is tracked. Add a cancellation-at-ambiguous-spawn regression proving
owned process/group teardown. This is the same ownership pattern already used
by the reviewed client/ARM-C01 launchers. Current CANCELLED status is truthful
about interruption, but does not establish cleanup in this window.

## Prior findings closed in current source

### Coordinator closure of spawn/teardown correction

The historical `73172c0...` materializer is superseded by
`4e8a6111a70bdb93d2a5e75aa786c96ce099a54d0fcd5e4bba38177da4c2e964`.
The coordinator reviewed signal masking across spawn/assignment, restoration of
the child's prior mask before exec, tracked-group teardown/reaping and durable
cancellation after final persistence. All **18 materializer tests passed**, no
skips, including real TERM/INT/ALRM delivery after session creation but before
assignment; the owned group is absent, the child reaped, and both signal masks
restored. Tests also cover failed spawn, handler installation and late receipt
cancellation. This closes the reproduced materializer finding; it does not
accept native compilation or the separate hosted wrapper.

The coordinator independently rehashed all **63 owned and eight root inputs**
in dispatch map `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2`
without drift. Its runner-input lock remains
`ba869e80d9fa2bdeb9c5bf504dc9cbddff1b164f6276d3ab75516fc5985fa0ac`.
The earlier 120-test review below remains historical; the corrected materializer
adds its separately recorded 18-test closure. No archive materialization or
native build was repeated by the coordinator for this focused correction.

### Historical cancellation/status persistence finding — closed

`updater-native.py:206-277` initially saves STARTING provenance. Its successful
or failed launch attempts final cleanup with `docker rm -f`, but catches only
OSError/SubprocessError around that command. KeyboardInterrupt during cleanup
escapes before the final provenance write. The host adapter also installs no
SIGTERM cancellation handler; ordinary termination can bypass Python finally
entirely. `build():309-346` writes the authoritative pair result only on success,
with no encompassing failure/cancellation finalizer.

Independent `/tmp/updater-native-cancel-review.py` reused the native tests'
temporary synthetic recipe/entry/inventory and mocked delegate/package checks.
After a successful delegate it injected KeyboardInterrupt during container
removal. The persisted provenance remained `native_compilation: STARTING`, with
no cleanup failure recorded. No Docker command or actual package was executed.
This reproduces receipt loss; actual container absence is not established by
the mocked check.

Required narrow fix: handle/defer host termination and interruption, perform
bounded teardown of the fresh owned container, and always persist failed launch
provenance plus a top-level FAIL/cancelled result. Interrupted cleanup must not
retain a successful receipt or imply container absence. Add trial/cleanup
cancellation regressions and preserve the original failure independently of
cleanup failure. Refusal/cleanup behavior must remain confined to the selected
native daemon and fresh nonce-owned container.

Closed in current `updater-native.py`: CLI TERM handling, tracked launch attempts,
bounded fresh-name removal/absence queries, independent cleanup errors and atomic
terminal provenance/pair results are implemented. An independent rerun of the
exact prior cleanup KeyboardInterrupt now persists finalized FAIL, cancellation
and incomplete cleanup; absence is recorded only after its query. An ambiguous
Docker launch timeout still tears down the fresh name and queries absence,
preserving the original failure. Independent cancellation after a durable PASS
write rewrites authoritative FAIL. Native Docker/process cleanup was mocked;
the focused suite additionally exercises signals in its own private Python
fixture, not a real native worker.

### Historical coordinator identity finding — closed

`build():310-311` tests `os.getuid() != 0` but does not require matching nonroot
effective UID/GID. A bounded Linux/ARM mock with real UID 1000 and effective UID
0 reaches the candidate input reader instead of the promised nonroot refusal.
No input/command execution was needed for the reproduction.

Required correction: require ordinary matching real/effective UID greater than
zero and matching real/effective GID before inputs, outputs or daemon commands.
Add set-ID/root guard regressions. The existing ARM-C01 controller has this
same ordinary-user contract.

Closed: the controller and materializer require matching positive real/effective
UID/GID before input reads/output/commands. The exact prior real-UID1000/effective-
UID0 mock now refuses before reaching the input reader. Identity regressions pass.

## Current source/transport closure and bounded checks

Current focused suites independently executed: **120 PASS**, no skips: native
adapter 20, materializer 14, public projector 18, portable gzip 16, actual-input
gate 19, worker 22, patched input/notices 6 and emitted unit parsing 5. No Cargo,
compiler or Docker ran. The tests include bounded own-Python subprocess/signal
fixtures; source reconstruction tools execute only data transformations.

The complete `runner-ready-pins.json` file/root-input map was independently
rehash-checked with **zero drift**, including package/build helpers and the
authorized live `native_arm.py` checkpoint
`a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.
All top-level helper functions/classes except `main` are AST-identical to the
historical `2443ba8a...` fixture; `main` has the authorized optional callback.
No retained fixture is a runtime fallback. Data-only plan passes with the same
authenticated 354 inventory. All 22 current recipe source/pin pairs and the
materializer generator/local-file/transport lock close against actual bytes.

The earlier `87c272e5...` candidate and old compressed archive pins below are
historical. Current materialization uses reviewed `gzip-stored-v1`: sanitized
archive `86196b4d7be8336c321e3a033984a17e602a5e70ec5ea11126d1a249ddda8eab`
and vendor `e44dd795d5c392e37f44f63e041f25055924b75784b990788b24a80b442d5a9c`.
The transport-revision record retains exact decoded-tar/member/notice parity
against historical archives. Source audit changes only sanitized archive hash;
the original all-target Cargo audit and license findings remain unchanged.
Worker/controller notice-reader limits now accommodate the 323,117,153-byte
stored vendor archive with finite 512 MiB limits; no pin is skipped.

`materializer-generation.json` records actual owner-run reconstruction under
Python 3.12.14/stock zlib1.3.2 and Python 3.14.7/zlib-ng1.3.1 with identical exact
portable archive and decoded-tar hashes. One run fetched all 168 authenticated
inputs and the other used a private offline cache. The historical incompatible
compressed-generator run remains recorded FAIL. This reviewer verified the
generation/source pins and read the records; it did **not** repeat the network
materialization or relabel these records as its own execution/native evidence.

An independent public-projection check retained a terminal native FAIL while
dropping poison environment/error prose. Private vendor/cache/log/binary paths
were instrumented and never read. The unchanged generic text exporter accepted
the bounded projected receipt. Private/public selection regressions pass;
raw deletion remains a controller responsibility, not attested by projection.
No publication grant or distribution acceptance follows from transport parity.

## Earlier findings and input verification

- The earlier defmt-parser supplemental-notice refusal is corrected in current
  `linux-closure.py`. Supplemental bytes have an immutable evidence pin and
  allowed exact package/source identities. The four historical macOS notice
  blockers remain explicitly refused when selected. Current focused closure
  tests include supplemental drift and attempts to license other sources.
- PKGBUILD now pins and applies both behavior and Apple policy patches with
  zero fuzz and installs the original policy helper. No accepted policy/live
  collector or target update transaction is shipped. Runtime declarations remain
  present; private `--nodeps` compilation cannot accept an install transaction.
- The separate native adapter and readonly entry are implemented. Data-only
  `plan` independently passed with the exact authenticated 341+13 = **354**
  inventory and SHA256 `d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271`.
  Baseline replacements are refused. Plan success is not archive reauthentication,
  image creation or installation by this review.
- The historical first candidate tree matched every candidate input hash. Static
  recipe inspection passed with **22 source/pin pairs**, including both supplied
  archives; no recipe function was executed. Candidate SHA256:
  `87c272e5dac540f31c12b3d79a8e1b8b9a6724e5338e7ffaaef2949500c98066`.
- Fresh worker metadata/target cfg, original manifest/lock, all 167 vendored source
  ledgers, selected dependency kinds/features, reviewed scripts/helpers and tool
  aliases/content are checked before compilation. Full immutable recipe/source
  hashes are rechecked around copying and after generated outputs. Source gates
  allow only named manuals/translations and canonical Cargo target output.
- The 98-file patched ledger/modes are enforced before Makefile/check/package
  operations. Current real-data fixtures reconstructed **1,113 notice files,
  11,735,034 bytes** from the pinned immutable vendor archive, rather than mutable
  extracted notice copies. Missing/altered/extra inputs and unsafe output links
  refuse. Current fixture checks passed; no native build ran.
- `worker-build.py` uses the actual tray, offline/frozen/locked Cargo, private
  environment and target, then checks emitted unit IDs/features separately from
  metadata unions, gettext-system/system-deps restrictions, retained binary
  bytes and static AArch64/16K LOAD layout. The adapter requests two separate
  clean containers and compares installed contents, package metadata and bytes.
  Native evidence remains unavailable; source execution cannot be inferred from
  synthetic emitted-record tests.

## Historical first-pass checks and current reviewed hashes

At the historical first snapshot, five directly executed focused suites had
**78 PASS**, no skips: native adapter 10,
actual-input gate 19, Linux closure 38, patched inputs/notices 6 and emitted Cargo
unit parsing 5. An initial unittest-discovery command found zero tests because
the files use hyphenated names; direct script invocation ran the stated suites.
The owner's 227 aggregate is reported in its workstream; this reviewer did not
relabel that count as an independent aggregate run.

| File | SHA256 |
| --- | --- |
| `updater-native.py` | `031d4ae45d837fec0c0c4510552c18899380100583e8bff48e0c17aa05948200` |
| `native-entry.py` | `4be3120d02edc747c59cda7ca9b0b5779f04555115fab7ee92567b61f6564c9b` |
| `worker-build.py` | `dc8cd7a18756ac36598d8fcb3a63f5fea56c48a9ce423953599ada4c1981f599` |
| `build-gate.py` | `068493948809df43da5e3891cf3cefb7a7f899182ba3f0783b119a97e49174a7` |
| `worker-metadata.py` | `f54226c068f3f8a51556ed9185168b89f793c1c8f2219c81557246f587e0edf2` |
| `linux-closure.py` | `a73d7ba17018d2fd359e630675b7ca207965b01eca358f7574a80f690124d2a2` |
| `verify-updater.py` | `862b960338cdcf71dc4762e9a418192f12c31d13988758cd9283f90082cb1211` |
| `PKGBUILD` | `56b7d672a2bcc45f989159e7771d27777382c294217c5b0f7270005c342768c7` |
| `materialize-inputs.py` | `73172c0b0ecfcc978bd7750d6569d30f78688354cbd92a56cad2b89b5f24d30e` |
| `public-evidence.py` | `db3aa78381c0e5a6ff7272d3efbdbdb6a7f8cb22762bb86daff133e9ea9670bb` |
| `portable-gzip.py` | `ad049022c111aeafac20921e3d84f4ad16894deea85c65722ac07ffc4708ccb5` |
| `runner-inputs.lock.json` | `d34546f280c45e840f76d93acae643114994eeef1ca1b0b5d7259fdb01b24041` |
| `runner-ready-pins.json` | `42f7785e3fd055a24a2b8eadc64ba2cf72ab636b1492dc806c6754a32b43676d` |
| `materializer-generation.json` | `1c2f5ab6c86b736fbe1bd09d91fd333764354f5dd5e60698db506b754bd81de5` |
| `transport-revision.json` | `fab30d0a81aa5e94818ab7c30967750047ecaffd8cfebd939cb02b309e970cf6` |

Status: **prior findings closed; one narrow materializer spawn-ownership
cancellation correction required before final source freeze/native dispatch.**
Current source/notice/recipe/transport pins are coherent at this snapshot.
Native compilation, actual
unit traces, native cleanup, 16K loading, private-bus tray behavior, target
installation/lifecycle, physical 13/15-inch M2 updates/recovery and performance
remain **NOT RUN**.

The full all-target vendor's four unresolved historical notices remain visible;
full-vendor distribution and compiled-package publication are NOT ACCEPTED.
Excluded Cachy-branded artwork is not reintroduced. The selected-source record
remains inert, not independently buildable complete corresponding source. These
limits and required R1–R5 work cannot be removed by a private native build PASS.
