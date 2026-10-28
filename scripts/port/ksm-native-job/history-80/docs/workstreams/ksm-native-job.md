# Separate KSM native job

This workstream currently provides a **source-tested ownership preflight and
independent consumer/export contracts**. It does not provide an executable,
accepted end-to-end native job. The held original producer has no interface for
the required resource ownership, interruption recovery or per-operation Docker
bindings. The new workflow refuses before launching it and exits nonzero. Root
owns final source freeze, registration, Git acceptance and any dispatch.

The accepted 147-test KSM lifecycle implementation remains unchanged. Its source
checkpoint is not native signing/install/removal evidence. Earlier KSM package
builds are historical separate-job evidence; their image and receipts must not
be reused as proof of execution in this workflow. No new native producer, build,
signing, installation or removal was run for this workstream. M2, 16K execution,
KSM activation, system management and performance remain **NOT RUN**.

## Intended finite operation

The command contract selects the working `scripts/ci/native_arm.py build` CLI,
not the FDK producer's imported subprocess/function overrides. This CLI audits
the frozen signed inputs, creates the generic 341-package base, and runs the
four original recipe pairs and comparisons. It cannot select KSM as one of
those original recipes. Two separate calls to `scripts/build/build.py` would
then build the exact reviewed KSM recipe against the resulting image and lock,
offline at epoch `1791748800`, followed by `compare.py --require-bytes` and the
held KSM lifecycle controller. The lifecycle performs temporary development
signing, installation, diagnostic probes, removal, reinstall and final removal
inside its reviewed containers. It never activates KSM or writes host sysfs.

`consumer.py` constructs those exact commands and independently checks full
comparison equality, same-job ownership bindings, clean controller exit and
lifecycle cleanup. These
are pure-data interfaces: they launch no command and supply no execution proof.
`validate_ownership` describes a required future executor receipt; the original
CLI cannot emit it. `Deadline` prevents phase replay and preserves cleanup and
export reserves. No native executor or producer broker has been substituted.

## Concrete interface blocker

The held original producer at SHA-256
`a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`
has only inputs/recipe pins, cache and output CLI arguments. Its bootstrap
`docker build` uses an iidfile but no image reservation or ownership label. Its
inventory `docker run --rm` has neither a name nor an ownership label. There is
no job nonce, durable resource journal, interruption recovery callback or
explicit Docker CLI/socket/daemon binding. An iidfile left after success does
not establish ownership when bootstrap execution was interrupted.

The held package builder at SHA-256
`e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45`
records a random container name before execution, but has no reservation label
or recovery interface. Timeout cleanup ignores the removal return code and
does not prove absence. SIGINT/SIGTERM do not supply equivalent disposal.
Neither existing CLI forwards a scoped ownership interface. The lifecycle's
checked Docker boundary protects its own later containers and cannot recover
these earlier producer resources.

`job.assess` therefore returns `BLOCKED` after accepted source checks, with
all native phases and public export marked `NOT RUN`, and no owned resources.
Missing/drifted source, wrong job identity, cancellation or an expired source
deadline produces `FAIL`. The workflow has no producer/build/lifecycle/export
step after this refusal and no artifact uploader. Creating an approval packet
does not remove the interface blocker. A separately reviewed broker or producer
interface must make ownership and recovery concrete before native execution can
be enabled; that implementation remains unfinished.

## Source acceptance

The workflow requires an externally reviewed SHA-256 of
`scripts/port/ksm-native-job/packet.lock.json`. Root must generate and commit
that packet; this worker does not register or alter shared source manifests.
The packet schema is `schema_version: 1`, plus an exact `files` map whose rows
contain `sha256`, `size_bytes` and mode `0644` or `0755`. `required_paths.py`
declares the finite 125-path set, including this workflow, new helpers/tests,
the original producer/build dependencies and recipe inputs, the GPL 15-input
KSM recipe, the held lifecycle source/test checkpoints and its BASE/GUARD.
The packet excludes itself to avoid a self-hash cycle; its external digest and
committed bytes are verified separately.

`acceptance.capture` rejects missing/additional paths, traversal, symlink
components, hardlinks, special files, byte/size/mode drift and uncommitted
source. It checks actual committed blobs and modes with read-only Git calls.
`HEAD`, `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` must agree. Git uses a private
temporary HOME, no hooks/fsmonitor/global config/optional locks/replacements or
lazy fetch, ten-second per-call deadlines and eight-MiB output bounds. Captured
modules compile accepted bytes with explicit bound imports rather than reopening
source or consuming cached bytecode. This is execution of reviewed code, not a
sandbox or native execution attestation.

The fixed original input SHA is
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`,
the four-original recipe map SHA is
`20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`,
and the expected sorted 341-package lock SHA is
`89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`.
The KSM GPL 15-input map remains
`f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44`.
BASE remains `dc0c75969ed79548c3eb0ab1692f57ebffe7464d9192e591cdcf61aeaeb77154`;
GUARD remains `4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100`.
Source policy checks all six held lifecycle Python files and the current 147-test
receipt/checkpoint. The new packet never changes those accepted pins or broad
initial package maps.

## Budgets and ownership required before enabling execution

| Phase/resource | Maximum |
| --- | --- |
| Source acceptance, including initial workflow capture | 180 seconds |
| Original producer including acquisition and four original build pairs | 6,600 seconds |
| Two KSM builds | 360 seconds each, exactly two attempts |
| Comparison | 120 seconds |
| Lifecycle controller | 600 seconds |
| Final owned-resource cleanup | 180 seconds reserved |
| Curated public export | 30 seconds reserved |
| Aggregate operation | 8,460 seconds; workflow hard limit 150 minutes |
| Images / containers | One owned image; at most fourteen owned container operations |
| Source capture | 256 files maximum; 2 MiB each, 32 MiB aggregate |
| Private data | 16 GiB aggregate with 8 GiB disk reserve |
| Public data | Three files; 16 MiB per archive, 32 MiB combined plus 64 KiB evidence |

These maxima are declared acceptance requirements. The current preflight
enforces its source boundary; the independent exporter enforces public bytes.
Producer/container/private-disk limits are **not implemented by the held CLI**
and are additional reasons to refuse it. No phase may retry itself or extend
the aggregate deadline. A future accepted executor must capture the exact CLI
bytes and socket identity, check daemon/UID/GID before and after every operation,
reserve each resource durably before creation, bind labels to nonce/context/
image/contract, and recover only matching owned identities after cancellation.
Final cleanup must prove each owned container and image absent. Global pruning,
deleting by an unbound name, or treating CLI exit as absence is unacceptable.

## Curated exporter

`public.export` is an independently tested component, not a workflow upload.
It accepts a pinned, bounded consumer acceptance record and two pinned exact KSM
archives. All producer/build/comparison/lifecycle/cleanup statuses must pass;
same-job source/run/image/input/lock/recipe bindings must match explicitly. It
rechecks actual archives, exact package identity and the five approved regular
GPL payload files, retaining their LICENSE/NOTICE. Both archives must have equal
bytes and matching codec. The recipe snapshot and notice indicators are caller
validation assertions and require the future accepted native executor; they do
not confer additional source or publication grants.

Only `build-1/<exact package basename>`, `build-2/<same basename>` and newly
constructed `evidence.json` can be emitted. The exporter never recursively copies
private outputs and rejects unknown receipt fields. Raw logs, source snapshots,
controller state, signatures, key material and signing identity do not leave the
private workspace. Output must be fresh; cancellation or failure checks recorded
identities before removing its created files/directories. Detected namespace,
mode or content replacement refuses cleanup and invalidates retained evidence
to FAIL, preserving the foreign replacement. The private namespace requires a
cooperative coordinator: POSIX identity checks followed by unlink/rmdir do not
provide atomic compare-and-delete against a malicious same-UID writer. The
evidence keeps hardware, management,
performance, release and broader source-grant acceptance false/NOT RUN. No
accepted publication, source grant or actual native result is manufactured from
fixtures.

## Verification and remaining work

Run the independent source suite with:

```sh
python3 -B -m unittest discover -s scripts/port/ksm-native-job -p 'test_*.py' -v
```

The final suite passed **80 tests, zero failures/errors/skips**: 25 source/Git
acceptance, 11 consumer, 12 job refusal, two complete-packet/workflow fixtures
and 30 public export tests. Tests cover actual-byte/Git/mode capture, foreign bytecode/source replacement,
bound imports, finite budgets, exact commands, ownership mismatches, cancellation,
empty/partial comparison, lifecycle cleanup and strict public export. Temporary
Git repositories and synthetic package archives are fixtures, not native builds.
The separate source test receipt records each outcome. Actual SIGINT/SIGTERM
fixtures verify tracking before child assignment, owned Git child reaping,
deferred disposal and caller-handler restoration. The full-source Git fixture
uses an explicitly synthetic native identity only to verify terminal BLOCKED;
it creates no image or container. Workflow inline Python parses/compiles; a YAML
parser and GitHub dispatch validation were not available/run in this worker.

Remaining work: root source freeze/registration; a reviewed concrete producer
ownership and recovery boundary without the failing FDK override; connection of
the independent consumers/exporter to that executor; real same-job native
producer/build/comparison/lifecycle/cleanup execution; and separately required
Asahi/M2 hardware and release acceptance. None is marked complete here.
