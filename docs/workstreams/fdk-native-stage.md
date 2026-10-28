# FDK finite native development adapter

This separate stage consumes the accepted 341-package builder without changing
the original four-package build or lifecycle workflow. It is development
evidence only: installation, provider selection, repository publication, xHE
encoding, performance measurements and M2 hardware checks remain **NOT RUN**.
Native execution of this adapter is **NOT RUN** at this source checkpoint.

The coordinator owns its same-job native trial and any CI integration. The
adapter requires an ordinary native ARM Linux user with matching real/effective
nonzero UID and GID and no effective/permitted capabilities. It does not install
packages, invoke a host compiler, sign artifacts or publish binaries. Docker's
local daemon must already be accessible to that user.
Host prerequisites are Linux, Python 3.10 or newer, Git, the explicitly pinned
Docker CLI and `zstd` for the existing package inspector. Provisioning these
prerequisites belongs to the coordinator; the adapter never installs them.

## Reviewed inputs and source

| Input | Required SHA256 |
| --- | --- |
| Adapter `stage.lock.json`, 39 pinned files | `a7048064c0c20abd246a466035313abaf65590f3ed10d0f7927b21a346200ad6` |
| Exact 341-row sorted builder `packages.lock` | `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f` |
| Original builder `inputs.lock.json` | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` |
| Frozen 22-file template map, shipped beside the adapter | `b569ff9ae69eb56e9b9635c3ed0849eaebbfa516f48304ade1790f802532bb63` |
| Complete 23-file materialized map, shipped beside the adapter | `4c9a6e04c964145fad2da64e627ca0f06f576aec40f443e701cad930d916c38b` |
| Selected 900-file codec archive, regenerated during the stage | `1c4ade00f624c1e6f9e988cd17868a5e3faa78fea2522e9c302a89866d04cdd7` |

The selector fetches only the fixed upstream commit
`a68a51aa45d86a43c7b228e3d45624af09dcdd8d` through its bounded HTTPS fetcher,
requires the upstream archive SHA256
`ac9682b35f6e5f75e1f008a5ba2636ba6c9c77c70b78377b53992559e8bda806`,
and writes only the selected archive. No broad private source packet is an input.
The two full Fraunhofer notices and byte-preserved copyright grants accompany
the selected sources. Adapter and independent build/check sources are MIT;
codec terms and publication limits remain in [the FDK workstream](fdk-aac.md).
Runtime dependency is glibc; GCC, Python and binutils are already in the accepted
builder. No additional package or default repository trust is introduced.

`stage.lock.json` pins the adapter, its complete maps, the frozen template and
read-only copies of the existing builder, comparator, package checker, container
entry point and accepted bootstrap script. Its exact SHA256 must be supplied.
Every locked byte and executable mode must also match the supplied Git commit;
uncommitted source cannot be attributed to that commit. `GITHUB_SHA`, when
present, must match. The original native result has no source-commit field, so
the stage binds its accepted input, recipe and bootstrap-script hashes while
recording the current checkout/job commit separately.
This lock binds bootstrap script SHA256
`a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.
An older retained result with a different script hash cannot satisfy that gate;
use the fresh same-job result after committing the locked source and helpers.

## Executable interface

Use a new absolute output directory outside the repository and the accepted
image/bootstrap/result from the **same live job**. The accepted result must have
`native_build: PASS`; unrelated original lifecycle failures are neither hidden
nor inferred to pass. The inventory/input pins above are enforced internally.
The result, bootstrap, adapter lock and local Docker executable require explicit
SHA256 pins supplied by the coordinator:

```sh
python -B scripts/port/fdk-native-stage/stage.py --execute-native \
  --source-root "$CHECKOUT" --source-commit "$COMMIT" \
  --lock "$CHECKOUT/scripts/port/fdk-native-stage/stage.lock.json" \
  --lock-sha256 "$STAGE_LOCK_SHA256" \
  --accepted-result "$BASE/result.json" --accepted-result-sha256 "$RESULT_SHA256" \
  --bootstrap "$BASE/bootstrap.json" --bootstrap-sha256 "$BOOTSTRAP_SHA256" \
  --packages "$BASE/packages.lock" --inputs "$BASE/inputs.lock.json" \
  --image "$IMAGE_ID" --docker-endpoint unix:///var/run/docker.sock \
  --docker-binary /usr/bin/docker --docker-sha256 "$DOCKER_SHA256" \
  --output "$NEW_EXTERNAL_OUTPUT" --deadline 3000 --build-timeout 1200
```

`IMAGE_ID` must be `sha256:<64 lowercase hex>`; tags and remote Docker contexts
are refused. Allowed endpoints are the explicit `/run/docker.sock` socket, its
`/var/run/docker.sock` alias, or `/run/user/<uid>/docker.sock`. Canonical socket
identity, CLI bytes/inode, daemon ID/architecture and immutable image are pinned.
All launches, queries and removals use that endpoint and an empty private Docker
configuration, without inherited Docker environment/context settings.
Daemon identity comes from a bounded, fixed `GET /info` request over that pinned
Unix socket. The adapter avoids the CLI's `info` command because it enumerates
and executes plugin metadata helpers even with a formatted result; this behavior
is explicit in [Docker CLI's source](https://github.com/docker/cli/blob/v28.5.0/cli/command/system/info.go).
The remaining CLI calls are allowlisted builtin commands with pipe output, no
help/completion/plugin commands and no interactive plugin hooks.

The stage checks a fresh disposable container's UID/GID and exact live 341-row
inventory, regenerates and materializes the selected recipe, then requires the
complete 23-file map. It performs two separate network-disabled native builds
through the existing `scripts/build/build.py`, with a module-local command
broker. The existing checker and comparator run inside finite worker process
groups, including their `zstd` children. Acceptance requires byte identity,
installed payload identity, PKGINFO identity and BUILDINFO identity. A comparator
result that reports only payload identity is insufficient.

The build containers use the calling UID:GID, no capabilities, no new privileges,
a read-only root, private IPC/cgroup namespace, 512 PIDs, 4 GiB memory/swap limit,
four CPUs and a bounded 4 GiB temporary filesystem. Only the exact four approved
input/output mounts are permitted. Parent and worker subprocesses have finite
deadlines, output/file-size/memory/CPU/open-file limits, separate process groups
and direct-child parent-death handling. These controls apply to the pinned
builtin Docker CLI and inherited checker processes; they do not attest arbitrary
detached processes or daemon behavior under host failure.

## Receipts, cancellation and actual checks

Detailed evidence stays under `private/`: locked source snapshot, regenerated
source/map receipt, accepted and live base receipts, nonce container journal,
bounded logs, both builder provenance/validation/archive trees, compiler-command
records, ABI/smoke receipts and all four comparison gates. Parsed archive
metadata is checked again against the hash-bound recipe and actual inventory.
ABI evidence requires both AArch64 ELF libraries, expected SONAMEs, 18/63 exports,
glibc-only dependencies and 16 KiB ELF LOAD geometry. The smoke scope is classic
AAC-LC roundtrip plus xHE configuration lifecycle only. ELF geometry does not
establish runtime behavior on a 16 KiB M2 system.

Only `public/status.json` is suitable for automatic status publication. It
contains fixed, sanitized fields and no raw logs, paths, exception text, source
or binaries. It remains FAIL unless every required receipt and owned-container
absence passes. No unaccepted binary is copied to the public directory.

Names are durably reserved before create and bound to a per-stage nonce label,
image, user and mount/resource contract. Cleanup reloads the journal so the
parent can remove a worker's owned containers after cancellation. It never
prunes global containers or removes a name collision with unrelated ownership.
Cleanup has a separate finite 60-second budget. Daemon/socket/CLI drift,
unresponsive removal, or unresolved asynchronous create produces FAIL with
uncertain absence; it cannot honestly promise cleanup after a dead daemon.
Cancellation, including receipt publication/restoration windows, invalidates
acceptance. Normal command deadlines exclude at most three seconds of local
process-group termination/reaping; the stage deadline is 300–7200 seconds and
each build is 60–1800 seconds, with at least 300 additional seconds required.

Run the adapter fixture suite without a Docker daemon or native build:

```sh
python -B -m unittest discover -s scripts/port/fdk-native-stage -p 'test_*.py'
```

Runtime tests use real owned disposable child processes and descendants. Broker
tests use a fake CLI and owned Unix socket; evidence tests use explicitly
synthetic inspection callbacks; controller tests inject cancellation/receipt
failures. Those results establish orchestration regressions only. A coordinator
must separately record actual native command outcomes, artifacts and cleanup
before changing the development build status.

Actual final checkpoint: **73 tests PASS, no skips**, 9.732 seconds; the 39-file
lock has no byte/mode drift and the frozen 22-file template still matches its
approved map. Independent source/mock review passed after strict HTTP framing,
ambiguous-create recovery and late-cancellation corrections. The unchanged
original builder is loaded read-only; module-isolation regression verifies the
proxy does not replace the package checker's standard subprocess module.
