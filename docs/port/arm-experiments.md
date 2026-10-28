# Bounded native ARM compiler experiments

[Installable C01 experiment packages](installable-arm-experiments.md) now provide separate baseline/LTO prefixes, finite installed probes and a disposable native package lifecycle job. Nineteen host controls include real pinned-source builds and cross-decoder checks; these use host ISA and grant no native package, installed,16K/M2, performance or release acceptance. The retained341 lock is test input DATA, not an install list.

October 15, 2026. **ARM-C01–ARM-C04 passed hosted native build, correctness and within-variant byte reproduction.** The [C01](../validation/arm-c01-native-20261015.md) and [C02](../validation/arm-c02-native-20261015.md) actual records each cover four builds and the complete 505-command graph on a generic 4 KiB ARM builder. C02 baseline artifacts also match C01 exactly. [C03](../validation/arm-c03-native-20261015.md) additionally passes two public-input PGO training attempts and523 criteria, with both final builds bound to unchanged first-attempt raw profiles. [C04](../validation/arm-c04-native-20261015.md) also passes505 criteria and both byte pairs: GCC accepts the sole -mtune=apple-m2 change while retaining generic ISA/O2/no-LTO. Retained C01–C04 generic 16 KiB correctness also passes the four source-bound runtime records in [the accepted runtime matrix](../validation/arm-retained-generic16k-20261017.md). Native M2 execution, optimized package installation, physical validation and performance acceptance remain unfinished. This bounded M7/R2 work cannot complete R1–R5 or replace final-system A07 measurements. The original experimental contract below remains in force.

## First code workload and retrievable inputs

October 17 retained runtime: all four original cases passed 468 normal-loader commands each on actual 16384-byte pages in a generic TCG guest, source `ede3730ec5cabfa917a9d9be62f4ebc2edb9748b`. The [accepted runtime record](../validation/arm-retained-generic16k-20261017.md) binds the original eight artifact inputs, same-job native574 userspace capture (including ctypes/libffi), derived kernel, static page probe and ordered actor/producer cleanup. The source-only manual policy remains inert; it is separate from these specific accepted hosted records. Nothing was rebuilt or substituted. Generic VM correctness establishes no M2 performance, installation or hardware acceptance.

The proposed [paired zlib session runner](../performance/paired-zlib.md) composes the existing exact-artifact workload and benchmark APIs for correctness, excluded warmups and balanced timing. Its local executable fixtures are control-only. Exact ARM/M2 paired performance remains NOT RUN.

Select **upstream zlib 1.3.2, its local static library and upstream `minigzip`
example**, as a small integer/compression workload. Build an isolated experiment
artifact, never replace the system zlib or add it to the release inventory.
This tests compiler/build/profile plumbing before a larger release package.

The [upstream release page](https://zlib.net/) provides the versioned
[source tarball](https://zlib.net/zlib-1.3.2.tar.gz) with SHA-256
`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.
Retain the verified bytes in the coordinator's input cache before offline builds;
a recorded URL/hash alone is insufficient. Inspect the actual pinned tarball
before implementing extraction/build, including traversal, links and build hooks.
The tagged sources inspected for this design are
[configure](https://raw.githubusercontent.com/madler/zlib/v1.3.2/configure),
[Makefile.in](https://raw.githubusercontent.com/madler/zlib/v1.3.2/Makefile.in),
[README](https://raw.githubusercontent.com/madler/zlib/v1.3.2/README) and
[minigzip.c](https://raw.githubusercontent.com/madler/zlib/v1.3.2/test/minigzip.c).
The [zlib license](https://raw.githubusercontent.com/madler/zlib/v1.3.2/LICENSE)
permits redistribution; preserve notices and mark any source changes. No source
patch is proposed. Tagged web files are source audit, not proof of tarball identity.

Use the existing signed ALARM userspace/toolchain. At design time,
`scripts/ci/inputs.lock.json` hashes to
`7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41`;
it records GCC `16.1.1+r12+g301eb08fa2c5-1`, Make `4.4.1-3`, rootfs binutils
`2.46+r70+g155188ea10a7-1`, glibc `2.43+r22+g8362e8ce10b2-2` and system zlib
`1:1.3.2-3`. These are inventory facts, not live tool probes. Bind execution to
the successfully built immutable image and complete runtime `pacman -Q` lock.
Record compiler/linker/plugin versions, actual argv and ELF interpreter/dependencies.
No LLVM migration or extra packages are required by this first proposal.

## Finite candidate sequence

Use an explicit experimental baseline: `-O2 -g -march=armv8-a -mtune=generic`,
the same hardening/link flags and job count in every variant. It is not claimed
to be the shipped Asahi package recipe. Upstream GCC documents `-march` as ISA
selection, `-mtune` as tuning, and an `apple-m2` tuning target; **the locked
compiler must still demonstrate support**. Preserve Armv8-A in initial binaries;
do not use `-march=native`/`-mcpu=native` on a hosted runner or enable features
inferred from its Neoverse CPU. [GCC AArch64 options](https://gcc.gnu.org/onlinedocs/gcc/AArch64-Options.html)

| ID | One comparison variable | Intended check | Execution gate |
| --- | --- | --- | --- |
| ARM-C01 | Baseline versus added `-flto=2` | Build/link integration, output correctness, artifact reproducibility and build cost | Hosted correctness/reproduction PASS; M2 measurements NOT RUN |
| ARM-C02 | Baseline versus `-O3` replacing `-O2` | Correctness and throughput/code-size tradeoffs | Hosted correctness/reproduction PASS; throughput/M2 measurements NOT RUN |
| ARM-C03 | Baseline versus instrument/train/rebuild using GCC PGO; no LTO or O3 change | Profile identity, coverage failures, correctness and build/profile cost | After source-audited profile adapter |
| ARM-C04 | Baseline versus `-mtune=apple-m2`, same `-march=armv8-a` | Locked compiler recognizes target; target-specific measurement | Hosted compiler/correctness/reproduction PASS; performance acceptance requires each M2 Air |

LTO flags must reach compilation and final GCC-driven link; use `gcc-ar` and
`gcc-ranlib` for the local archive, capture plugin use and fail on missing plugin
or link/type diagnostics. Use the same archive wrappers in baseline. Combining
LTO/PGO/tuning is a later independent experiment.
[GCC optimization options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)

## Initial actual trial contract: ARM-C01

The narrow runner is `scripts/experiments/arm_c01.py`, with deterministic inputs
in `corpus.py`. The coordinator runs it separately from V01–V09; no workflow or
release recipe is changed here. Freeze this source separately for that later job;
the initial integration freeze excludes this active subtree.

Run native aarch64 only: nonroot container, immutable local image, no network,
all capabilities dropped, no-new-privileges, read-only root/inputs, private owned
tmpfs HOME/workspace and one explicit evidence output. Independently reject extra
mounts/devices/sockets before commands. Limit to **2 CPUs, 4 GiB memory, 256
pids, 900 seconds total**, with bounded process-group/container cleanup and
sanitized failure receipts. Failure/timeout is FAIL, never a silently skipped build.

Within that boundary, use four fresh trees at the same canonical container path:
baseline twice, LTO twice, retaining each tree's artifacts before replacement.
Proposed command sequence per tree is `./configure --static`,
`make -j2 static`, `make teststatic`; pass exact reviewed CC/CFLAGS/LDFLAGS,
AR/RANLIB in the environment/argv. Set `QEMU_RUN` empty and prohibit emulation.
Cap each configure/build/test phase at 180 seconds. The upstream target exercises
`example` and a gzip roundtrip; add explicit output checks below rather than
treating its pipeline status as complete correctness. No `make install`, pacman
transaction or target tuning occurs. [Upstream build/test targets](https://raw.githubusercontent.com/madler/zlib/v1.3.2/Makefile.in)

Generate and retain the declared corpus independently of candidate output:
empty input, 1-byte input, repeated
text, all-byte values, fixed-seed incompressible bytes, and separately selected
held-out pinned upstream README text. Total corpus <=16 MiB. Preserve generated bytes,
generator revision/seed/algorithm and input hashes; do not use uncontrolled random
or private files. Each candidate compresses levels 1/6/9 from stdin into isolated
outputs, then baseline and candidate both decompress each output. Require exact
original bytes/SHA-256 and zero exit, including empty and buffer-boundary cases.
All four artifacts decode every baseline/candidate compressed output. Include pinned
corrupt/truncated gzip fixtures with expected rejection derived from source and
validated on baseline; a changed rejection outcome fails the candidate.

Retain executable/library hashes, ELF metadata, symbols, complete compile/link
logs and output hashes for both clean builds. Compare bytes within the same
variant; report differences and their causes, not assumed reproducibility.
Different baseline/candidate executable hashes are expected. Require decoded
output identity across variants; compressed-byte identity is diagnostic, not a
substitute for decoding. Capture elapsed build cost and artifact size. The first
trial is correctness/build evidence, with no speedup claim and no performance
threshold adopted from this host.

## PGO follow-up contract

The C03 adapter uses `/tmp/profile` inside the existing private 2 GiB tmpfs, preserving the same canonical path for generation and both use builds. Configure feature probes use baseline flags; only final candidate objects use fatal missing-profile/coverage diagnostics. The initial native trial stopped before training because the frozen GCC package omits gcov-dump. The correction uses its shipped gcov-tool to decode separate diagnostic copies; final builds still consume untouched raw profiles. Focused synthetic checks pass; repaired native execution is pending.

ARM-C03 uses the same source, tools, ISA, baseline optimization and canonical
source/object paths throughout. Compile **and link** the training binary with
`-fprofile-generate=/tmp/profile -fprofile-reproducible=serial`; execute a frozen,
single-threaded training corpus in a fixed order. Hash every `.gcda`, training
binary, command, input and result. Retain the profile bundle as a build input;
rebuilding from that bundle and regenerating profiles are distinct checks.
[GCC instrumentation](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)

Remove build objects while retaining profiles, rebuild at identical canonical
paths using `-fprofile-use=/tmp/profile`, and make missing-profile and coverage
mismatch diagnostics fatal (`-Werror=missing-profile`,
`-Werror=coverage-mismatch`, subject to locked-compiler probe). Never downgrade a
missing profile to an accepted ordinary build. Keep training and held-out timing
inputs disjoint; correctness runs include both. Rebuild the final artifact twice
from the same retained profiles. Repeat training independently to assess profile
reproducibility; archive `gcov-dump` diagnostics. A hosted profile is labelled
hosted; it is not automatically an approved M2 distribution profile.
Allocate a separate **1,200-second** total cap, 180 seconds per build phase and
120 seconds training; retain partial profiles/failure reasons without publishing
private workspace state. Profile workloads never call system configuration tools.

## Hosted measurements and physical acceptance

Record actual CPU identification, native execution evidence, kernel/page size,
image, affinity/job limits and hosted interference. A Neoverse run establishes
behavior/cost on that recorded runner only. Even compiling `apple-m2` successfully
does not measure its effect on M2. Hosted timing, if added later, uses fixed
warmups, at least five valid trials/variant, counterbalanced order and held-out
inputs; noisy/overlapping results remain inconclusive. Use
[the existing methodology](../performance/README.md) and
[experiment record](../performance/experiment-template.md), rather than another
benchmark framework.

Record `getconf PAGESIZE` separately at build and execution. Inspect every final
ELF's PT_LOAD alignment and offset/address congruence for 16 KiB, interpreter,
DT_NEEDED closure and memory/page assumptions. Fix linker settings identically
for all variants before trials; do not tune page layout as another variable.
GNU ld exposes `max-page-size` and `common-page-size`; reducing the latter below
the runtime page size can weaken RELRO. Do not infer 16K compatibility solely
from AArch64 architecture or an ELF alignment check.
[GNU ld options](https://sourceware.org/binutils/docs/ld/Options.html)

Run the exact artifacts/dependency closure on a native 4K environment **and**
the accepted native 16K M2 userspace, recording actual page sizes. A 4K hosted
PASS leaves 16K execution NOT RUN. Static linking of local `libz.a` does not
make libc/loader compatibility disappear. Testing both page sizes is distinct
from performance acceptance on the 13-inch and 15-inch Air separately.

M2 trials require protected-platform baseline and recovery evidence, frozen
usefulness/regression budgets, correctness on every trial, responsiveness under
load, memory, energy/battery and sustained thermal observations. Keep failed
experiments and retain baseline when no candidate earns acceptance. Any retained
variant needs reviewed package lifecycle/removal and repeatable profile/update
provenance; M9 additionally repeats final-system tests on the integrated release.
No kernel, boot, Mesa, audio or speaker-protection changes belong to this trial.

## Concrete completion records

Coordinator/build owner supplies retained tarball, source/build audit, narrow
native runner and frozen plan; independent reviewer checks guard/cancellation,
profile bindings and failure evidence before dispatch. Native execution supplies
source/image/tool hashes, full inventories, command/exit/timeout/cleanup records,
four C01 artifacts, correctness outputs and reproducibility results. Performance
owner and physical operators supply later exact-machine plans and measurements.
Missing artifacts, profiles, hardware or sensors remain named unfinished gates.
Current results: **C01–C04 hosted native 4 KiB correctness/build/rebuild PASS; retained generic TCG 16 KiB correctness PASS; physical M2 execution and both M2 performance records NOT RUN; release selection false.** See the [actual C01 record](../validation/arm-c01-native-20261015.md).

The retained source cache is
`/tmp/cachy-asahi-zlib-audit-5bqceen9/zlib-1.3.2.tar.gz`; actual download hash
matches the pinned upstream digest. Archive inspection found 254 regular files,
37 directories, 3,579,037 unpacked bytes and no links/special/traversal entries.
No upstream configure/build/test code ran during that audit. The runner's manual
extractor subsequently reproduced 254 files locally without executing source.
Only the selected library and example are built; optional `contrib/` licensing
does not automatically inherit the root grant. Each retained artifact directory
includes the upstream license notice.

The controller rejects root/elevated identities, non-Linux/x86 hosts and Docker
endpoint/API overrides before creating output; later calls explicitly bind the
approved local Unix socket. Private tmpfs and output ownership, semantic null
masks, exact standard character devices, additional sockets and kernel filesystem
substitution are guarded. It retains generated Makefile/configuration, tool/CPU
logs, timestamps, LTO intermediate-representation evidence, ELF/dependency records,
all four artifacts and corpus bytes. Host acceptance recomputes artifact/log/corpus
hashes and both rebuild pairs and requires the complete cross-decoder/rejection
matrix. Cancellation and cleanup failure override success, including final receipt
writes. Build/run budgets reserve cleanup time within the 900-second trial cap;
missing tools, logs or checks fail rather than skipping coverage.

Actual native dispatch uses a **new absolute output directory**, an immutable
image from the reviewed builder and its exact complete package lock:

```text
python3 -B scripts/experiments/arm_c01.py \
  --image sha256:<accepted-local-native-image-id> \
  --source /tmp/cachy-asahi-zlib-audit-5bqceen9/zlib-1.3.2.tar.gz \
  --source-commit <accepted-project-40-hex-commit> \
  --expected-packages <absolute-builder-packages.lock> \
  --expected-packages-sha256 <64-hex-package-lock-hash> \
  --output <new-absolute-evidence-directory>
```

Placeholders are intentionally not runnable accepted pins. Copy/hash-check the
retained source into that future runner's input cache; this desktop `/tmp` path
does not exist automatically on GitHub. The controller produces `result.json`,
bounded `commands.json`/logs, pinned `inputs/` and container `raw/` evidence.
Keep raw binaries/corpus outside generic text export; project sanitized text
receipts explicitly and separately retain verified experiment artifacts. No
host installation, signing-key generation, workflow dispatch or release mutation
belongs to this CLI. See [the actual work record](../workstreams/arm-experiments.md)
for local tests and final source hashes.
