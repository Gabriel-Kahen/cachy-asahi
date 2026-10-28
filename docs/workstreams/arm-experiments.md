# ARM-C01 implementation handoff

October 11, 2026. Scope: `scripts/experiments/**`,
`docs/port/arm-experiments.md` and this work record. Coordinator alone owns
Git, source-freeze/workflow wiring, dispatch and shared inventories/status.
No Git, host package/account/keyring, release selection or workflow change was
performed here. Initial V01–V09 source freeze must exclude this active subtree;
the coordinator separately freezes it for the later ARM-C01 job.

## Delivered

- `arm_c01.py`: finite native Linux ARM/nonroot/local-Docker controller plus
  read-only-root/capability-free isolated trial; exact source/code/image/package
  bindings, owned temporary storage, device/socket/mount refusals and bounded
  cancellation/process/container cleanup. No host pacman or installation path.
- Two canonical-path clean baseline builds and two clean LTO builds of pinned
  zlib 1.3.2 local static library, `example` and `minigzip`; GCC archive wrappers,
  captured compile/link/configuration/tool/CPU evidence, LTO IR checks, retained
  upstream notices, ELF/load-layout/dependency records and exact rebuild equality.
- Deterministic bounded public corpus with a pinned upstream README held out,
  preserved generator/Python/zlib identity and input bytes/hashes. Every one of
  four artifacts compresses seven inputs at levels 1/6/9; every output is decoded
  by every artifact (336 checks). Every artifact rejects both declared corrupt
  gzip fixtures for every build entry (32 checks), with actual nonzero exit/stderr
  required. Filename mode and arbitrary gzip strictness are not claimed.
- Independent host receipt verification requires four retained artifact sets,
  actual artifact/log/corpus hashes, both rebuild pairs and the complete
  correctness matrix. Incomplete evidence or cleanup/cancellation cannot become
  accepted stage success. Trial exit and final result agree after cleanup.

Detailed method, candidate sequence, input cache and concrete CLI are in
[the ARM experiment design](../port/arm-experiments.md). ARM-C02/03/04 are
proposed follow-ups; this runner contains no PGO implementation or M2 tuning.

## Actual source audit and local verification

The upstream tarball was downloaded into a private temporary directory and
verified as 1,502,830 bytes with SHA-256
`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.
Retained at `/tmp/cachy-asahi-zlib-audit-5bqceen9/zlib-1.3.2.tar.gz`.
All 291 members were inspected: 254 regular files, 37 directories, no links or
special/path-escape entries. Selected source build/test paths and root Zlib
license were inspected. Actual local manual extraction passed with 254 files;
no upstream executable code ran.

Pure corpus tests and mocked controller/source/receiver tests exercise native
guard refusal before mutation, extraction/hash/mode boundaries, ELF correctness,
timeouts/group cleanup, missing license/LTO evidence, endpoint overrides,
corpus/check/log/artifact omissions and late cancellation. Mock tripwires forbid
real Docker, package, GPG, upstream build or arbitrary process signals.
An intermediate 36-test aggregate had one failing synthetic fixture after
production license preservation was added: the fixture omitted LICENSE and did
not reach its intended cleanup check. The fixture was corrected; production
license enforcement was retained. That intermediate run was not accepted PASS.

Two separate actual **x86 disposable-process** probes exercised this runner's
temporary Python print command and timed-out sleeping child. The first timeout
used the KILL fallback after 3 seconds, revealing that the child inherited blocked
TERM/INT during protected spawning. The single-threaded Linux launcher now
restores the child's prior signal mask before exec; the repeated timeout failed
as intended, verified group absence and retained failure evidence in 0.021 seconds.
This is process-control validation, not a native ARM or zlib build.

Peer source review found and corrected default-context/DOCKER_HOST disagreement,
discarded cancellation during cleanup/final serialization, misleading success
exit after cleanup failure, and receipt-only rebuild trust. The receiver now
recomputes retained pair equality. No unmeasured optimization claim was made.

## Gates and next execution

Final local aggregate: **54 tests PASS, 0.751 seconds**:

```text
python3 -B -m unittest discover -s scripts/experiments -p 'test_*.py' -v
```

This includes 48 runner/source/receiver tests and six corpus tests. CLI `--help`
was checked; source hashes below were rechecked after the aggregate. No skips or
actual native/upstream build were executed by that suite. The source below is
ready for coordinator review; no further worker edits are planned.

| File | Final SHA-256 |
| --- | --- |
| `scripts/experiments/arm_c01.py` | `b25f4fc385eb14c1bca975cadd91309b3f4300aaa9c018d4df89b964ff68bbca` |
| `scripts/experiments/corpus.py` | `e4eb86c157eec54c3e418c8e59e0753848dcec92cd791b4c62e76fdc92c7879e` |
| `scripts/experiments/test_arm_c01.py` | `dc263b4f7524b7ba0eea76ae931bf3a6d947c2bc459c89a4a7983ccf1fbeb9b9` |
| `scripts/experiments/test_corpus.py` | `2165640eeae99a8cf939962e1bff84f3d5cfb16d967bd6b8f84d031416cb7442` |

Coordinator should review this implementation, freeze its exact source and
retrievable inputs, then execute the CLI on the separate reviewed native builder.
Inspect actual command logs, LTO/plugin evidence, four artifacts, corpus checks,
cleanup and independent receiver results before native acceptance. Preserve any
failed/partial output and publish sanitized failure diagnostics explicitly.

**Native ARM build/correctness: NOT RUN.** ELF/16K execution: NOT RUN.
Neoverse performance measurement: NOT RUN. Both M2 Air performance and hardware
acceptance: NOT RUN. Production installation/release selection: false/NOT RUN.
PGO: design only. This implementation is one bounded R2 trial and does not
complete M7, A07/A14 or the full-port R1–R5 requirements.

## Same-job follow-up adapter: October 12 handoff

Coordinator requested `scripts/experiments/stage.py` so the subsequent trial can
use the native job's still-local immutable image. Only experiment code/tests and
this workstream/design are being edited. Original CI/controller/workflow files
and shared manifests remain coordinator-owned. The previous controller review
is historical: the initial source readiness and corrections are recorded in
`docs/reviews/virtual-integration-review.md` at lock `d01fbf28...`.

The follow-up preflight pins four original experiment source/test files, the new
stage adapter/test and the existing CI text exporter. Its separate lock accepts
either the exact 341-package base inventory or the exact base-plus-four 345
inventory. Installed mode requires six pinned handoff files: installed image,
installed lock, READY commit receipt, fresh committed-image verification,
restored configuration and verified container removal. Image/source/inventory,
original versions/payloads, complete configuration and cleanup identities must
agree. It performs no installation or image commitment itself.

The new independent review reproduced substantive omissions in the original
ARM-C01 host receiver despite the 54 local tests passing: a single unrelated
command, altered source-derived corpus/roles and an empty license could pass.
Those original hashes/test counts above are a historical implementation handoff,
not accepted complete receiver verification. Implemented corrections require the exact
485-command trial graph, argv/environment/exit and stream links, native guard
record, full build/configuration/ELF/LTO evidence, pinned source license/README
and independently regenerated corpus bytes/roles. No actual native trial has
been claimed from those synthetic fixtures. Updated source/tests are being
reviewed below and are separately frozen for coordinator review before dispatch.

The stage captures partial failure diagnostics and projects explicitly named
text through the pinned existing exporter; binary/corpus/private trees do not
enter that generic filter. Verified compiled zlib outputs, notices and public
corpus have a separate deterministic bounded development archive, never an
installed root/image or release package. Authoritative final stage status lives
in `result.json` and manifest-bound `public-status`; failed export, cleanup or
late cancellation cannot be accepted as stage PASS.

A separate pure-source probe of the current derived-image verifier
(`b2375e6e...`) found that alternate `/dev/alias-disk` and `/run/alias-control.sock`
names are not examined by its six-path device/socket check. This is a newly
exercised refusal-contract case, not an observed host exposure or a replay of
its corrected filesystem cases. Original CI source is not edited by this worker;
coordinator owns that correction/review. ARM-C01's own guard scans device/socket
types and identities before commands. Native and hardware gates remain NOT RUN.

### Concrete interface and export contract

Freeze is a local file operation; it never invokes Docker or a build:

```text
python3 -B scripts/experiments/stage.py \
  --source-root <absolute-accepted-checkout> \
  --freeze <new-experiment-lock.json>
```

The checked-in candidate is `scripts/experiments/stage.lock.json`, SHA-256
`729d172a2e52562779d87c41515c59be6329e74d6a11aebd7a84b3714a3a5381`.
It freezes the original four experiment files, `stage.py` and `test_stage.py`,
plus unchanged existing text-exporter SHA-256
`1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c`.
The zlib archive pin remains `bb329a0a...` above. Original native CI sources are
not imported or modified by this adapter; only the independently pinned exporter
is loaded from a copied snapshot. Source/lock/mode drift refuses before commands.

Installed-mode CLI, after successful initial integration while `Controller.installed`
and `Controller.installed_lock` still refer to the local verified image:

```text
python3 -B scripts/experiments/stage.py \
  --source-root <absolute-accepted-checkout> \
  --image <Controller.installed-sha256-ID> \
  --source-commit <accepted-GITHUB_SHA> \
  --source <retained-verified-zlib-1.3.2.tar.gz> \
  --base-packages <native-output/packages.lock> \
  --base-packages-sha256 <actual-base-lock-sha256> \
  --expected-packages <Controller.installed_lock> \
  --expected-packages-sha256 <actual-installed-lock-sha256> \
  --handoff-dir <integration-work/lifecycle-raw> \
  --handoff-pins <six-file-sha256-map.json> \
  --handoff-pins-sha256 <actual-map-sha256> \
  --lock <accepted-experiment-lock.json> \
  --lock-sha256 <accepted-experiment-lock-sha256> \
  --output <new-absolute-followup-directory>
```

The handoff map is one JSON object mapping the following exact relative filenames
to their actual SHA-256, derived from the already verified initial stage:
`installed-image.json`, `installed-packages.lock`, `commit-receipt.json`,
`committed-image/result.json`, `committed-config.json`, `container-removal.json`.
No selected versions are guessed. Base-only mode uses the accepted builder image,
passes the same exact base lock for both inventory arguments and omits all three
handoff arguments; it cannot claim installed baseline verification.

`run_stage(args)` is also callable with the CLI-shaped `argparse.Namespace`.
Prefer the explicit CLI under the coordinator's existing guarded child launcher,
with time reserved for the 900-second finite trial plus bounded fallback cleanup
and export (for example a 1,000-second outer allowance). Coordinator controls
overall workflow capacity/timeout; this worker did not change it. This must run
in the same Docker job before its private images disappear. Public inputs can be
retained/downloaded with the exact zlib pin before this offline experiment;
the desktop `/tmp` cache is not assumed to exist remotely.

Caller reads `<output>/result.json` and requires exit zero, stage status PASS,
verified container absence and evidence export PASS. Preserve/bundle each
directory separately through existing `log_evidence.py`:

- `public/`: selected native/launcher/configuration/command receipts and logs;
  `*-dependencies.log` becomes `*-link-inputs.log` with unchanged bytes/hashes
  and explicit producer-log name. No private tree or binary enters the filter.
- `public-status/`: authoritative final controller result plus exporter manifest.
  A late cancellation reseals this still-local provisional status before the
  synchronous stage returns; immutable native component records remain intact.
- `public-artifacts/`: explicit deterministic gzip/tar plus manifest for only
  38 approved development files: four builds' 12 binaries/archives and 16
  notices/configuration files, nine public corpus files and their manifest.
  Limits are 64 MiB uncompressed and 8 MiB compressed, with hashes rechecked
  against strict receiver results. This separate exporter is not a relaxation
  of the generic text filter and never exports an image/root/private state.

Failed trials retain local launcher/native logs, partial receipts and bounded
safe projection. Export failure is explicit and prevents PASS, including final
status export failure. Local `trial/`, `source/` and `selected/` are working
material, not generic public bundles. No image, package/trust installation,
hardware tuning, workflow or release promotion occurs in this adapter.

### Reproducibility control and final local checks

An actual **x86 own-source** probe compiled the same tiny C file twice at the
same path with `gcc -O2 -flto`: object hashes differed. Adding a fixed file seed
made that pair match. No upstream zlib code was compiled by that probe.
[GCC's primary guidance](https://gcc.gnu.org/onlinedocs/gcc-13.5.0/gcc/Developer-Options.html)
requires different seeds for different compiled files. Both experimental variants
now share `-frandom-seed=$@`: audited configure preserves the literal Make
automatic variable; the recursive Makefile expands it to each output target.
Thus object/link targets receive distinct stable seeds at the canonical path.
This is a common reproducibility control, not a measured ARM optimization; actual
native pair equality still must pass. Receiver checks effective configured flags,
including seed/ISA/optimization/LTO values and equal audited feature suffixes.

The corpus now uses a fixed stored-DEFLATE gzip reference and CRC32 rather than
version-dependent compressor output, permitting independent exact derivation
from pinned README and generator on host/container. Positive/corruption semantics
are still required to execute on native minigzip. Receiver record verification
is not command replay or cryptographic execution attestation.

Final aggregate: **89 local tests PASS in 3.178 seconds**, no skips:

```text
python3 -B -m unittest discover -s scripts/experiments -p 'test_*.py' -q
```

58 core tests, six corpus tests and 25 adapter tests use temporary files/mocks
with real Docker, package, GPG, upstream build and process-signal tripwires.
Separate own-process/own-source x86 probes above are explicitly nonacceptance
evidence. One intermediate adapter run had 20/21 pass while its success fixture
had not yet mocked the newly added artifact exporter; the fixture was updated
and actual artifact-export behavior is tested separately. No failed run was
relabeled native PASS. CLI help and concrete source-lock generation passed.

| Current file | Frozen SHA-256 |
| --- | --- |
| `arm_c01.py` | `b725639885740505a04fbdcab2e629e3201afb09cf948ac997c1309d91fe36cf` |
| `corpus.py` | `dbaf951adbb91d6769f40f8fb18c13044a42a3b5db11b4ad7d1f44afbed9ad8c` |
| `test_arm_c01.py` | `f3cb4674f28691367f1618643ca0cba0ae1f3da52ce294461c80ba9e35d264fc` |
| `test_corpus.py` | `c0d60f1006d158e8162a8fc78871be895e9d46e5098733f4a0321d7eac63f5a8` |
| `stage.py` | `2af8e84a4e6cff548d4477b506e4fdc0ade5c0dd695ee53294140f17414d9034` |
| `test_stage.py` | `ce9c92b69426a18b975d2709a2aca8c5da669679d14825b563e4c9655b7ab623` |

Independent coordinator review and actual same-job native trial are still
required. Native ARM-C01 build/correctness, native cleanup, 16K/M2 execution,
performance/energy gains and full R1–R5 acceptance remain **NOT RUN**. No further
worker source edits are planned at this candidate handoff.
