# Standalone hosted native kernel job

This is a source implementation for coordinator review and packet registration.
**Hosted execution, original producer execution in this job, native ARM fixture
execution and both full kernel compilations have not run.** Kernel execution,
installation, M2 validation and performance measurement remain pending. No
shared lock, original producer, platform tuple or recipe was changed by this
implementation. The separate API/start compatibility correction updates the
kernel image client and broker; its source maps require coordinator rebind
before execution. See [the compatibility record](kernel-docker-compatibility.md).

The manual [workflow](../../.github/workflows/native-arm-kernel.yml) runs only
in the public `Gabriel-Kahen/cachy-asahi` repository on `ubuntu-24.04-arm`.
It grants `contents: read`, uses the existing `native-arm-build` concurrency
group without cancelling prior jobs, pins checkout to
`3d3c42e5aac5ba805825da76410c181273ba90b1`, and disables persisted credentials.
There are no artifact/cache upload actions, host package installs, global Docker
prunes, scheduled runs or hardware acceptance claims.

## Source and input closure

[packet.py](../../scripts/port/kernel-native-job/packet.py) binds the exact
71 original recipe files, eight producer/source helpers, the frozen 24-file
kernel stage and its source lock, original input/recipe locks, and this job's
Python sources, workflow and guide. Overlap gives 105 fixed existing files;
new source files are added to the finite closure. The complete map is limited
to 256 files, 8 MiB per file and 32 MiB total. Directory walks stop at 1,024
entries/depth16. Files must be single-link regular files with ordinary directory
ancestors and mode0644/0755. Private captured receipts may use mode0600.

The immutable pins are:

| Input | SHA256 |
| --- | --- |
| Original signed inputs | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` |
| Original four recipes | `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63` |
| Accepted 341-package inventory | `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f` |
| Kernel24 source lock before API/start correction; rebind pending | `53d5c0dba0102413256552da3534b553ce5591ceaa747980e579d4fa1359bc5d` |
| Separate signed fifteen-package extension | `cf4d6eaa80ab15f1b1359d161b7b07e187f37df6071e5f628e235cb9689a93d6` |

The coordinator must create and independently review
`scripts/port/kernel-native-job/packet.lock.json`, commit every included source
file and register the workflow. The workflow requires the external packet hash
with no default. This task supplies `packet.preview(root)` and source fixtures,
but does not register a packet, mutate Git or dispatch a job.

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
Its initial image
and container inventories must be empty; an occupied daemon is refused.
Require at least 15 GiB reported physical memory, 14 GiB available memory and
30 GiB initial free disk, with at least 8 GiB disk left before the kernel stage.
Existing Git, GPG, lscpu, zstd, Docker and Python executables are required.
Missing tools/resources are a visible refusal; no installation fallback runs.

The original producer is executed directly from the verified snapshot:

```text
/usr/bin/python3 -I -B <snapshot>/scripts/ci/native_arm.py build
  --inputs <snapshot>/scripts/ci/inputs.lock.json
  --inputs-sha256 <original fixed input hash>
  --recipes <snapshot>/scripts/ci/recipes.lock.json
  --recipes-sha256 <original fixed recipe hash>
  --cache <private>/alarm-cache --output <private>/producer
```

There is no FDK producer override or integration mode. The child has an explicit
environment, private empty Docker configuration/home, the local endpoint and
`DOCKER_BUILDKIT=0`. It authenticates the original 501 inputs and builds the
four original packages twice with byte comparison. The job requires child exit
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

Inside the job envelope: source/host setup300 seconds; original producer and
parallel acquisition2,050; held kernel work18,000 plus outer cleanup/signal
margin240; base cleanup150; guard20. Before each phase, remaining wall time
must cover that phase and every later reserve. Insufficient time refuses launch.
The job clock starts before output creation and the initial durable receipt;
startup time consumes the same execution envelope.
These are caps and refusal rules, not guarantees that downloads or compilation
will finish. Slow original acquisition or package builds fail visibly rather
than reducing the held kernel's five-hour/two7,200-second build budgets.

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

A completed accepted producer's immutable base ID and daemon identity are
journaled before use. Cleanup can remove only that ID without force, verifies
its inspection identity and subsequent absence, and requires no remaining
containers. Held kernel cleanup must also have passed for overall PASS.
Additional private Docker build-cache/intermediate state remains on the
disposable VM; it is never globally pruned or published. Unknown producer
mutations, failed image removal, daemon loss, kernel-controller timeout or
cancellation force FAIL. Kernel-controller recovery beyond its held normal
cleanup remains a coordinator-owned gap.

Initial authoritative FAIL receipts are written before work. Final publication
uses a finite allowlist; late cancellation rewrites FAIL, and publication errors
invalidate the two owned terminal receipt paths. The public helper reads only
one ordinary owned `public/status.json`, at most16 KiB. Both receipts remain FAIL
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

## Actual source checks

Source fixtures cover packet snapshots/Git/mode and immutable-read boundaries,
the full command plan, same-job producer/kernel receipt acceptance, deadline
refusal, partial/cancelled work, narrowly owned base removal, late failure
publication and public outcome gating. Runtime fixtures execute only tiny local
processes. No test creates a hosted producer, provisions Docker, compiles a
kernel or executes it.

The original71/source-helper audit and read-only fixed105-file Git proof passed.
The new job/workflow/doc remain pending the coordinator's committed source and
external packet registration. Final test counts and exact source hashes are
recorded in the handoff; source review does not replace the required hosted run.

The API/start correction has not regenerated the 24-file kernel lock or job packet.
Their previous pins remain held until the coordinator integrates the reviewed
source changes, rebinds both closures and proves the committed Git bytes/modes.
The new Python helpers retain MIT attribution to the held runtime. Existing
kernel/package source licenses and publication limits remain unchanged.
