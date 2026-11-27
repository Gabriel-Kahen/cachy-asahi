# Standalone hosted native kernel job

The kernel trial selects the 341-package inventory derived from the current
signed input lock and the four recipes in this checkout. Its fifteen signed
kernel dependency additions produce an exact 356-package inventory. This is a
development build configuration. Native build-pair acceptance, boot,
installation, M2 hardware and performance remain open.

Run [38690790542](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38690790542)
recorded baseline build command exit 0 and output verification failure at
`CHECK_010`. The candidate did not run. Run
[38712796442](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38712796442)
later recorded the precise failed check: `INFO_RELATIVE` at entry index 3 in
a null-linked, allocated Image RELA section, with `r_info = 0` and
`r_offset = 0`. The pinned ARM64 relocator skips type-zero entries. The
verifier now accepts that Image RELA no-op, checks all eight bytes of each
writing RELA or RELR destination, and includes both relocation tables in
the full ELF-to-Image byte comparison.

Run [45698226968](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45698226968)
passed hosted SSH intake, producer, dependency acquisition, toolchain probe and
scoped Docker cleanup. The baseline build command exited zero. Output checking
stopped at `CHECK_010`, entry 28853 in the null-linked Image `.rela.dyn`.
Its `r_info` is `0x1c00000401` (symbol index 28, `R_AARCH64_GLOB_DAT`).
The runtime scan is bounded by `__pi_rela_start` and `__pi_rela_end`.
The bounded receipt omits those symbol values, so this entry's membership
in the runtime range is unknown. If the scan reaches it, the pinned ARM64
relocator skips it because the scan applies only `R_AARCH64_RELATIVE`.
That verifier revision admitted the observed GLOB_DAT form.

Run [45707773620](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45707773620)
passed the same intake, provisioning, probe and cleanup gates. Its baseline
build command returned zero. The verifier passed the prior entry and refused
the adjacent entry 28854 with `r_info = 0x1b00000101` (symbol index 27,
`R_AARCH64_ABS64`). The corrected verifier uses the pinned relocator's
low-32-bit type test for the allocated, null-linked ET_DYN Image table.
Only `R_AARCH64_RELATIVE` requires a canonical zero symbol index and a fully
mapped eight-byte destination. Other records remain in the full ELF-to-Image
byte comparison. The earlier receipts establish compilation command success
and verifier refusal. The clean native pair and boot remain pending.

Run [45717672590](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45717672590)
completed the baseline build command and the RELA scan. Its census counted
28,850 NONE, three ABS64, one GLOB_DAT and three RELATIVE entries, with full
aligned slots for all seven nonzero-type entries. The output verifier stopped at
`CHECK_059`, a defined symbol outside its allocated section. The receipt
omits the symbol name. The candidate did not start and scoped Docker cleanup
passed with all six preexisting images preserved.

The exact GNU AArch64 linker from the pinned rootfs reproduced the source's
post-BSS `_end` placement in a local QEMU user-mode linker fixture. It emitted
a zero-size global `_end` associated with `.bss` at a 64 KiB boundary beyond
the section and final load segment. The verifier permits this exact ET_DYN
Image anchor when its value also equals the verified Image entry plus the
effective Image size. Ordinary exports retain their section bounds. The
linker fixture establishes the layout behavior. Identifying the rejected
symbol from the hosted artifact and native pair qualification remain open.

Run [45726872408](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45726872408)
passed the baseline compile, Image projection, and embedded configuration
checks. The verifier then refused an ELF section in a relocatable module at
`CHECK_011`. The receipt does not identify the section. The candidate did not
start. The pinned GNU linker reproduced allocated module sections whose file
offsets were eight-byte aligned and whose declared destination alignments were
32 or 64 bytes. The verifier now separates those constraints for copied module
sections and keeps raw descriptor, symbol table, and RELA reads aligned.

Run [45757694585](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45757694585)
completed the baseline build command with exit 0. Output verification reached
the module dependency check and refused at `CHECK_071`. The candidate did
not start and the runner preserved all six initial Docker images. The pinned
Kbuild code writes original provider basenames in `depends` and uses an
underscored name for the module's `name` field. The verifier now matches the
original basenames and still refuses ambiguous module names, unknown providers,
duplicates and self-dependencies. The regression reproduces the mismatch.
The hosted receipt leaves the first failing module unidentified.
[Pinned dependency writer](https://github.com/AsahiLinux/linux/blob/94fb23346d522edf53722357c426a3e58030beea/scripts/mod/modpost.c#L1871-L1896)

On November 25, the pinned public mirror returned HTTP 404 for 210 of 501
producer input files. This included the bubblewrap, jbigkit and libtiff
archive/signature pairs. Eight extension archive/signature pairs were
also unavailable: clang, compiler-rt, libgit2, libxslt, lld, llvm, rust and
rust-src. On November 26, the remaining public route also returned HTTP 404
for the locked `gtk-update-icon-cache` and `libinput` archive/signature pairs.
The retained copies match all four original byte and signature checks.
The SSH route covers 230 files. The other inputs use the original locked
URLs and must pass the existing byte and signature checks.
[Kernel dependency pins](../../scripts/port/kernel-native-stage/dependencies.json)

Runs [45765124377](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45765124377)
and [45765742023](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45765742023)
both stopped in the producer before either kernel build. The producer exited
1 first and the acquisition child was cancelled. Both runs verified
preservation of all six original Docker images. Run-owned absence remained
unverified, and the published receipts could not identify the producer's
exact cause.

Run [45766930508](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45766930508)
passed retained input intake, producer, acquisition, provisioning and the
compiler probe. The baseline build command returned zero. The verifier refused
module 150 at `CHECK_011` and the candidate did not start. The section name
digest matches `.debug_aranges`. The section was an unallocated `ET_REL`
`SHT_PROGBITS`, with 192 bytes at file offset 1,336 and declared alignment 16.
The pinned GNU AArch64 linker reproduced that exact geometry with `ld -r`.
Its relocatable section layout caps file alignment at eight bytes while
carrying the declared address alignment in the section header. The verifier
now accepts this exact nonallocated section form and still checks its file
range and overlaps. The earlier 28,857-entry Image RELA census was retained.
Cleanup passed and all six original Docker images were preserved.
[Pinned linker layout](https://gnu.googlesource.com/binutils-gdb/+/155188ea10a7/bfd/elf.c#6888)
· [ELF section address alignment](https://gabi.xinuos.com/elf/03-sheader.html#section-header-table-entry)

Run [45774638440](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45774638440)
again passed acquisition, provisioning, the compiler probe and the baseline
build command. Its output verifier stopped with an unclassified exception.
The candidate did not start. Cleanup passed and all six initial Docker images
were preserved. The published receipt does not identify the exception.

The output verifier treated all `.modinfo` text as unformatted ASCII. Enabled
modules in the pinned source include UTF-8 author text and help strings with
tabs and line breaks. The verifier now accepts printable UTF-8, tabs and line
feeds in `author`, `description` and `parm`. It keeps ASCII keys and structural
metadata, and gives malformed display text a bounded refusal. A new output
diagnostic reports an unclassified exception's verification stage and a fixed
fault category.
[Pinned Apple SIO module](https://github.com/AsahiLinux/linux/blob/94fb23346d522edf53722357c426a3e58030beea/drivers/dma/apple-sio.c#L940)

For private SSH intake, dispatch with `retained_inputs=true` and
`retained_transport=ssh`. The authenticated intake step shallow-fetches
three exact refs from the private `Gabriel-Kahen/cachy-asahi-ci-inputs`
repository. Each ref must resolve to the pinned parentless commit, tree and
regular-blob inventory.

| Branch | Commit | Tree | Files |
| --- | --- | --- | --- |
| `native623-r1` | `b429266444c82238783044301ceb0f8d08bbf3f6` | `a8f1cd41e3aadeee9a25bc3b96e14c823de870aa` | 6 base, 16 extension |
| `native623-base-r2` | `6d2e0ee29159be52744c1fd8b8109dbce7f09c93` | `af22c8f7619135a3bc6a22f6f7d7e12723cbc1d8` | 26 additional base |
| `native349-r1` | `9d9e1ab7ce694e33238ec1152bef72270d4bf91f` | `cc6298d8dbbb5b0dd522de76b7140306d83bfe7a` | 182 base, one manifest |

The SSH step pins GitHub's Ed25519 host key and the fingerprint of the existing
read-only repository deploy key. Only this step receives
`CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY`. The step removes its key file before
checking out payload bytes and removes its temporary Git store before returning.
It leaves `native349-r1` intact and verifies that branch's manifest without
passing it to either child. The Git/SSH commands share a 210-second deadline
inside a four-minute workflow step. The native step retains its 346-minute
budget and the full workflow retains its 360-minute ceiling.

The same step supports `retained_transport=https` with the
`KERNEL_NATIVE_RETAINED_INPUTS_URL` Actions secret for the original 22
retained files. It accepts a single direct
HTTPS response for the 152391680-byte USTAR archive with SHA-256
`0a3e3661754e2c194895e5ada5e075866c99b3702b9361bb3b3395ae665c81fa`.
The intake step writes a private directory for this run attempt and exposes
only its GitHub Actions outcome to the next step. The native job independently
copies and verifies each file against its original size and SHA-256. The base
files seed the producer's private `alarm-cache`. Sixteen extension files seed
the acquisition child's `--reuse-cache`, which is removed when the parallel
children stop. Both children still enforce their original GPG signature
verification. Failed intake refuses both children. The final workflow step
removes the temporary runner handoff and publishes the bounded job status.

The manual [workflow](../../.github/workflows/native-arm-kernel.yml) runs only
in the public `Gabriel-Kahen/cachy-asahi` repository on `ubuntu-24.04-arm`.
It grants `contents: read`, uses the `native-arm-kernel` concurrency
group without cancelling prior jobs, pins checkout to
`3d3c42e5aac5ba805825da76410c181273ba90b1`, and disables persisted credentials.
There are no artifact/cache upload actions, host package installs, global Docker
prunes, scheduled runs or hardware acceptance claims.

## Source and input closure

[packet.py](../../scripts/port/kernel-native-job/packet.py) binds 76 recipe
files, the producer and its helpers, the 28-file kernel stage, the workflow
and the job sources. Each source row binds the SHA-256, byte length and
executable mode. The complete map is limited to 256 files, 8 MiB per file
and 32 MiB total. Directory walks stop at 1,024 entries and depth 16. Source
files must be single-link regular files with ordinary directory ancestors
and mode 0644 or 0755. Private receipts may use mode 0600.

| Input | SHA256 |
| --- | --- |
| Signed builder inputs | `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f` |
| Kernel job's four recipes | `56c53699b1c9a493798a071a537ae17d5b892ffa9618ca99a3465985a51fcef8` |
| 341-package inventory | `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25` |
| Fifteen-package extension | `aa5f5580f10256f5749bbc86ec0abc0420981d935f37e84672298fa38d72cfe4` |

The [kernel recipe lock](../../scripts/port/kernel-native-job/recipes.lock.json)
tracks the current Hyprland, Setup, Fish and Zsh source. The
[stage lock](../../scripts/port/kernel-native-stage/stage.lock.json) binds
the same inputs, recipe lock and inventory. The
[historical packet](../../scripts/port/kernel-native-job/packet.lock.json)
and its verifier are retained for the original qualification and the #622
producer binding. To replay the historical workflow, use its original
matching checkout, workflow revision and packet SHA-256.

The current workflow uses the
[successor packet](../../scripts/port/kernel-native-job-v2/packet.lock.json).
`packet_v2.preview(root)` reproduces its source map for review. It uses the
historical policy with the exact current package checker pinned independently.
The workflow and runtime both require the successor packet path. For a new
dispatch, independently review the successor SHA-256 and pass it as
`packet_sha256` on the matching committed workflow revision. The successor
source check does not establish a native result.

Before executing repository code, an inline standard-library bootstrap captures
and authenticates the packet and every source row, compares actual Git blobs and
modes, and requires checkout HEAD, `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` to
agree. The always-public step repeats source authentication and executes the
captured public helper bytes. The job independently repeats full closure/Git
validation and copies the source to a new private producer snapshot. Hashing
and JSON parsing use the same captured bytes; links, duplicate keys, nonfinite
numbers, mutation races and incomplete closures are refused.
The inline preflight copies only authenticated source rows into a fresh
bootstrap snapshot and launches the job there. Python's `-B` does not prevent
loading existing bytecode, so root checkout caches/extensions are deliberately
outside the execution tree. The original producer and kernel controller execute
from the fresh private producer snapshot; the kernel controller's `--root`
still names the actual Git checkout for its independent committed-source proof.

## Native commands and prerequisite refusal

The host must be a disposable hosted ARM Linux VM with an ordinary nonzero
UID/GID, zero effective/permitted capabilities, a root-owned canonical local
`/run/docker.sock`, and the canonical hashed `/usr/bin/docker`. Docker must be
native ARM/Linux, rootful, use host UID mapping and cgroup v2, and support the
controller's fixed Docker API 1.48 within its actual advertised minimum/maximum
range. The job reads both values from the same locally pinned daemon and refuses
a maximum below 1.48, a minimum above 1.48 or a malformed range. It does not
negotiate a different request version.
Initial container and image queries run independently with typed bounds.
Containers must be empty. Existing images are captured as protected borrowed
baseline B before the producer starts; failure to observe them is
UNVERIFIED, never an empty population. This is observed preservation on a
cooperative disposable VM, not enforced isolation against outside writers.
Require at least 15 GiB reported physical memory, 14 GiB available memory and
30 GiB initial free disk, with at least 8 GiB disk left before the kernel stage.
Existing Git, GPG, lscpu, zstd, Docker and Python executables are required.
Missing tools/resources are a visible refusal; no installation fallback runs.

The job executes the producer directly from the verified snapshot.

```text
/usr/bin/python3 -I -B <snapshot>/scripts/ci/native_arm.py build
  --inputs <snapshot>/scripts/ci/inputs.lock.json
  --inputs-sha256 <reviewed input hash>
  --recipes <snapshot>/scripts/port/kernel-native-job/recipes.lock.json
  --recipes-sha256 <reviewed recipe hash>
  --cache <private>/alarm-cache --output <private>/producer
```

There is no FDK producer override or integration mode. The child has an explicit
environment, private empty Docker configuration/home, the local endpoint and
`DOCKER_BUILDKIT=0`. It authenticates the 501 pinned inputs and builds the
four recipes twice with byte comparison. The job requires child exit
zero and captures the actual bound result/bootstrap/runner/image/inventory/input
receipts before accepting the base. The original producer's PASS establishes
those native builds; it does not establish original ARM-C01 experiment lifecycle
acceptance or hardware behavior.

In parallel, the held acquisition CLI fetches the kernel trial's 35 pinned
inputs into a separate new directory beneath the private snapshot's ignored
kernel-stage artifact root. It authenticates the fifteen extension archives
and materializes the exact embedded config and BIO slices. The job uses the
acquisition receipt's exact seven expected paths; child stdout cannot redirect
the subsequent controller. Kernel source/patch/config and archive signatures
are rechecked again by the held controller.

The frozen kernel controller runs from the clean private source snapshot,
checks the actual committed checkout, and receives
its exact lock pin, source commit, hashed Docker CLI/socket, accepted same-job
base image and captured base receipts, and seven acquired input paths. Its new
output directory is under the checkout's ignored kernel-stage artifact root,
as required by its held interface. It performs offline signed provisioning,
the nonroot source-derived logic probe and both complete nonroot builds.
Its full Image/vmlinux/FDT/config/module checks and uncertain-commit cleanup
rules are unchanged. See the [kernel-stage guide](kernel-native-stage.md).

## Aggregate deadline and resource boundaries

The six-hour hosted ceiling is allocated explicitly:

| Reserve | Seconds |
| --- | ---: |
| Checkout and inline source preflight | 600 |
| Job execution envelope | 20,760 |
| Always-public status projection | 180 |
| Hosted overhead guard | 60 |
| Total | 21,600 |

Inside the job envelope: source/host setup 300 seconds; original producer and
parallel acquisition 2,050; held kernel work 18,000 plus outer cleanup/signal
margin 240; base cleanup 150; guard 20. Before each phase, remaining wall time
must cover that phase and every later reserve. Insufficient time refuses launch.
The job clock starts before output creation and the initial durable receipt;
startup time consumes the same execution envelope.
These are caps and refusal rules, not guarantees that downloads or compilation
will finish. Slow original acquisition or package builds fail visibly rather
than reducing the held kernel's five-hour/two 7,200-second build budgets.

The process supervisor tracks both producer/acquisition groups before pending
cancellation can run, applies one aggregate parallel deadline, stops the peer
on failure, and kills/reaps owned groups on timeout/cancellation. Each child
has an 8 MiB output ceiling, 10 GiB address-space ceiling, 4 GiB file ceiling
and finite CPU/descriptors. Kernel compilation itself retains the held stage's
actual cgroup inspections: two CPUs, 14 GiB memory without swap, 512 PIDs and
12 GiB tmpfs. This job does not impose an unreviewed host compiler override.

## Ownership, cancellation and public status

The original producer predates nonce-owned bootstrap journals and has some
unbounded Docker calls. The outer process supervisor bounds its host process
group, but cannot prove asynchronous daemon work absent after interruption.
Such a producer failure remains uncertain FAIL, even when a current inventory
query is empty; the job never starts the kernel stage. The disposable VM's
teardown is the final residue boundary. No standalone recovery interface or
complete Docker build-cache acceptance is claimed here.

A bounded private journal binds source/packet/run/attempt/nonce, daemon and
CLI/socket identities to B's complete Config, architecture/OS, RootFS layers,
size, parent and all tag/digest references. Each query is capped at 128 KiB,
256 raw inventory rows/unique IDs; Config depth 16/nodes8,192/strings64 KiB,
256 references per ID of at most 512 bytes, and aggregate canonical projection
4 MiB. The receipt is at most 8 MiB, mode 0600, job-owned/single-link/no-symlink,
fsynced and atomically replaced before either child launch. Two complete bounded
passes must agree; counts alone cannot hide retagging or metadata drift.
An omitted empty RootFS Layers normalizes to []; full Config may be null and
unknown fields are preserved. Every observation uses its existing phase deadline.

An accepted producer IID must be absent from B and positively inspected as
ARM64/Linux before it can become a cleanup candidate. Cached baseline collisions
fail with no base ownership, deletion or kernel launch. Positive B observation
is repeated after producer acceptance and after scoped cleanup. Unknown newly
observed IDs never become owned through inventory subtraction and are never
deleted; cache/layer absence remains NOT_ESTABLISHED. A failed/interrupted
producer remains UNCERTAIN even if later inventories are empty or preserved.

Only the newly accepted, journaled immutable base ID may be removed, with an
immediate protected-ID exclusion, `--no-prune` and no force. The kernel helper
journals all pre-commit IDs (B, base and intermediates) before POST and refuses
returned/recovered collisions without speculative tag deletion. Every derived
tag/ID removal also disables ancestor pruning. The full accepted Config12,
layers, size, native architecture, nonce, recovery and uncertain-POST rules stay
mandatory. Positive base absence, empty containers and source/image/daemon-bound
kernel scoped cleanup records must all be established before owned absence PASS.
Final B identity/reference equality is separately required for cleanup PASS.
Missing final observation is UNVERIFIED; positively changed state is FAIL.

No global prune, preloaded-image removal, privileged daemon or host service
change runs. VM teardown does not replace scoped absence or baseline evidence.
These snapshots cannot prove absence of transient outside mutation or arbitrary
internal legacy cache changes. Shared/adversarial daemon enforcement would need
a separate reviewed transport/isolation closure; KSM216 is reference-only.

Initial authoritative FAIL receipts are written before work. Final publication
uses a finite allowlist; late cancellation rewrites FAIL, and publication errors
invalidate the two owned terminal receipt paths. The public helper reads only
one ordinary owned `public/status.json`, at most 16 KiB. Both receipts remain FAIL
while completed acceptance is held in memory through INT/TERM handler
restoration and final unmasking. An observed cancellation restores both prior
handlers before returning failure; termination by a restored default handler
in that window also leaves bound FAIL. PASS is published only after that guard
exits, using a publisher that installs no signal handlers. Raw receipt bytes are
still provisional until the native process succeeds: termination during or
after this last publication, hard kill and host loss may leave partial or stale
bytes. The workflow outcome gate rejects acceptance in these cases. The public
helper refuses unknown
fields/strings and inconsistent acceptance, binds commit/packet pins and gates
PASS against the native step's actual success outcome. Missing evidence emits
a fixed marker; it never fabricates acceptance.

Only fixed status fields enter workflow logs. Source trees, archive caches,
public-key homes, package/vendor/kernel binaries, compiler output and raw logs
remain private ephemeral local files. A recorded baseline PASS can survive in
an overall FAIL for diagnosis, while aggregate native compilation becomes
NOT ACCEPTED. Installation, kernel runtime and hardware stay NOT RUN;
performance stays NOT MEASURED and release selection stays false.

## Closed failure diagnostics

Historical schema version 3 has exactly 25 top-level keys. Current schema 4
adds `kernel_child` and permits bounded diagnostic fields for parallel,
acquisition and producer failures. The projector retains the schema-3
validation and outcome semantics. Schema 4 requires bound verified child
diagnostics and an actual zero child return for PASS. Versions 1 and 2 and
unknown fields are refused. Historical evidence is retained unchanged. The
16 KiB public-record bound, source/packet binding and actual native-step outcome
gate are unchanged. Diagnostics grant no execution or hardware acceptance.

For a producer-first exit 1, the diagnostic verifies the terminal result
against the observed producer command and its final output. It compares
the private acquisition receipt with all 501 locked inputs and reports
only the phase, acquisition state and counts for HTTP 404, other HTTP,
transport and other failures. The first failure and cleanup status retain
their original meaning.

When the ET_DYN Image RELA table has been scanned and output verification
fails, worker diagnostic version 6 adds a numeric census. It reports the
whole table's entry count, up to eight distinct low-32-bit types and a
combined count for the other types. Each type and the combined count report
entries, fully mapped eight-byte slots and the aligned subset. The first
failure remains authoritative, and the census contains no raw table bytes.

For `CHECK_059`, worker diagnostic version 7 records the failing ELF role,
section-relative or virtual-address coordinate system, count of rejected
symbols, and up to two bounded symbol records from that ELF's scan. It
retains the RELA census when available. Only fixed linker anchor names and
fixed section classes are exposed. Other symbol names are represented by
SHA-256 digests. A later scan error leaves the first failure intact and
marks the count incomplete.

For `CHECK_011`, worker diagnostic version 8 records the first failed file
geometry check and bounded section facts. It includes the module ordinal when
applicable. It retains the earlier verified Image RELA census on module
failures, and uses a fixed section label or a name digest. Version 9 uses the
updated `.debug_aranges` geometry rule. Historical version 8 retains its
original file-alignment rule.

Worker diagnostic version 10 reports a fixed fault category and verification
stage for unexpected output-verification exceptions after a successful build
command. It retains the original first failure. Raw exceptions, source text,
filenames and traceback details stay outside the public record.

`phase` remains the current lifecycle phase, including cleanup. The separate
`first_failed_phase` and `failure_reason` describe the first failure observed by
the controller. Cleanup, late cancellation and outcome projection cannot replace
that pair. Private receipts mirror the same pair in their bound status and
finite `failure_phase`/`failure_reason` fields. Unknown exception text is never
copied; only exact known timeout/output/preflight errors select a fixed code,
and other exceptions use the current operation's fixed fallback.

| First failed phase | Exact allowed reason codes |
| --- | --- |
| `NONE` | `NONE` |
| `preflight` | `PREFLIGHT_REJECTED`, `HOST_CAPABILITIES`, `HOST_MEMORY_RESERVE`, `HOST_DISK_RESERVE`, `HOST_TOOL_UNAVAILABLE`, `CANCELLED` |
| `source` | `SOURCE_REJECTED`, `DOCKER_REJECTED`, `DAEMON_OCCUPIED` (historical fallback), `DAEMON_CONTAINERS_PRESENT`, `DAEMON_BASELINE_UNVERIFIED`, `RETAINED_INPUTS_REJECTED`, `PRODUCER_TIME_RESERVE`, `CANCELLED` |
| `parallel` | `PRODUCER_EXIT`, `ACQUISITION_EXIT`, `BOTH_CHILDREN_EXIT`, `PARALLEL_TIMEOUT`, `PARALLEL_OUTPUT_BOUND`, `PARALLEL_RUN_FAILED`, `CANCELLED` |
| `producer` | `PRODUCER_RECEIPT_REJECTED`, `PRODUCER_BASELINE_ID_COLLISION`, `DAEMON_BASELINE_CHANGED`, `DAEMON_BASELINE_UNVERIFIED`, `CANCELLED` |
| `acquisition` | `ACQUISITION_RECEIPT_REJECTED`, `CANCELLED` |
| `kernel` | `KERNEL_TIME_RESERVE`, `KERNEL_DISK_RESERVE`, `KERNEL_OUTPUT_REJECTED`, `KERNEL_EXIT`, `KERNEL_TIMEOUT`, `KERNEL_OUTPUT_BOUND`, `KERNEL_RUN_FAILED`, `KERNEL_RECEIPT_REJECTED`, `CANCELLED` |
| `cleanup` | `CLEANUP_FAILED`, `DAEMON_BASELINE_CHANGED`, `DAEMON_BASELINE_UNVERIFIED`, `OWNED_ABSENCE_UNVERIFIED`, `CANCELLED` |
| `finalization` | `CANCELLED`, `PUBLICATION_FAILED` |
| `outcome` | `NATIVE_FAILURE`, `NATIVE_CANCELLED`, `NATIVE_SKIPPED`, `NATIVE_UNAVAILABLE` |

`daemon_baseline` has exactly eight keys: initial container/image ID counts,
pre/post protected identity hashes, preservation, owned absence, producer
mutation, and legacy cache status. Counts are null or actual integers 0–256;
hashes are null or lowercase 64-hex. No raw Config, reference or daemon output
enters this public record. Preservation and owned absence use
NOT_RUN/PASS/FAIL/UNVERIFIED; mutation uses NOT_STARTED/COMPLETE_ACCEPTED/
COMPLETE_REJECTED/UNCERTAIN; cache is only NOT_ESTABLISHED. Preservation PASS
requires positive equal pre/final hashes, initially empty containers and a known
image population; the empty projection has a real digest, not null.

NOT_STARTED binds producer NOT RUN and unobserved launch (NOT_RUN/null).
COMPLETE_REJECTED requires producer FAIL and an observed zero exit; receipt or
ownership rejection does not authorize deletion. Cancellation before owned
acceptance remains UNCERTAIN even with an observed zero exit. COMPLETE_ACCEPTED
requires producer PASS, zero exit, a new IID and positive post-producer B proof.
Cleanup PASS additionally requires preservation/owned absence PASS and accepted
complete producer mutation. Actual exits and the immutable first cause survive
all later cleanup/cancellation outcomes. Counts from a successful initial query
remain known even when its independently queried peer failed.

Each parallel child has exactly `kind` and `code`. Observed return codes are
classified as `EXIT_ZERO`/0, `EXIT_NONZERO`/1–255 or `EXIT_SIGNAL`/−64–−1.
`NOT_RUN` and `UNOBSERVED` require null codes. The latter means launch was
attempted but the supervisor did not return trustworthy child results, including
timeout/cancellation; it does not assert which child started or exited. When
results return, both classifications preserve their actual codes, including a
peer terminated by supervisor cleanup. `BOTH_CHILDREN_EXIT` does not infer which
parallel child failed earlier. A zero process exit alone is not producer or
acquisition receipt acceptance. PASS additionally requires both observed zero
exits and no first failure.

For example, codes `[1,0]` record `parallel`/`PRODUCER_EXIT`, while codes `[0,1]`
record `parallel`/`ACQUISITION_EXIT`. Both still retain cleanup FAIL when the
producer's daemon mutation is uncertain. Resource diagnostics have exactly four
keys: `mem_total_bytes`, `mem_available_bytes`, `initial_free_disk_bytes` and
`pre_kernel_free_disk_bytes`. Values are actual bounded integer readings
(0–2^60 bytes) or null when unobserved/unrepresentable. No threshold, estimate,
arbitrary string, path or log fills a missing measurement. Boolean/float values,
unknown keys, invalid reason pairs and malformed exit records are refused.

Initial and completed pending FAIL receipts may retain `NONE`/`NONE`: no failure
has been observed yet. If termination prevents the controller from recording a
cause, the public helper records only the actual external step outcome. It
preserves child observations and never guesses a cancellation exit code.

## Actual source checks

Source fixtures cover packet snapshots/Git/mode and immutable-read boundaries,
the full command plan, same-job producer/kernel receipt acceptance, deadline
refusal, partial/cancelled work, narrowly owned base removal, late failure
publication and public outcome gating. Runtime fixtures execute only tiny local
processes. No test creates a hosted producer, provisions Docker, compiles a
kernel or executes it.

The original 71/source-helper audit and read-only fixed 105-file Git proof passed.
The new job/workflow/doc remain pending the coordinator's committed source and
external packet registration. Final test counts and exact source hashes are
recorded in the handoff; source review does not replace the required hosted run.

The coordinator's API/start and diagnostic work produced the historical kernel24
lock above and job115 afdb packet used by run 38253531983. This correction
changes job/public/image code, their three test files, the two existing guides
and selected proposal. The coordinator owns subsequent kernel24 rebind,
packet.py's literal dependent pin, job packet and committed Git/mode/bootstrap
proof. Those registration files remain held; their old rows intentionally do
not authenticate the candidate source. The new helpers retain MIT attribution;
existing kernel/package source licenses and publication limits are unchanged.
