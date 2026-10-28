# Separate finite hosted FDK native job

The `scripts/port/fdk-native-job/` interface prepares a separate hosted ARM
job. It changes neither the initial/development packets nor the original
four-package acceptance. The coordinator owns the free public ARM workflow,
Git publication and dispatch. This checkpoint adds finite producer boundary
observations to the worker, controller and public workflow consumer, and prevents
owned image deletion from pruning unowned ancestors. Native
execution of this correction is **NOT RUN**; fixture passes are not build or
hardware acceptance. The coordinator must rebind the separate job source packet
before publication or dispatch. Shared manifests, the accepted adapter, original
helper, inputs and recipes remain unchanged by this correction.

The job verifies a separately and externally SHA256-pinned complete source map,
acquires and authenticates the actual original frozen inputs through unchanged
`native_arm.py build`, builds the actual 341-package image and all four original
build pairs, then consumes that same live image/result/bootstrap in the accepted
FDK adapter. It never substitutes an image ID from another job. The unchanged
producer result is retained before FDK starts. Original comparisons retain their
existing byte/payload/PKGINFO criteria; FDK separately requires BUILDINFO equality.
Neither path establishes installation, selected providers, codec publication,
performance or M2 hardware behavior.

## Source packet and immutable dependencies

| Input | Required SHA256 |
| --- | --- |
| Prior accepted separate job `packet.lock.json`, 128 files; successor rebind pending | `309fcd6fbec8b7e96c83ea049804ae3134e7190d2145e81afc66d28563097f44` |
| Original inputs, 501 acquisition items / 249 signed payloads | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` |
| Four original recipes, complete 71-file maps | `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63` |
| Accepted FDK adapter, unchanged 39-file lock | `b83ddb865d7651c748258ac570e64fb824caf5bced8b1f415694dff7f5c187f5` |
| Live 341-package builder inventory | `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f` |
| Unchanged native producer script | `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` |

The source epoch is exactly `1791748800`. The packet closure includes 116 fixed
files before this new subtree: accepted adapter/template/helpers, adapter lock,
input and recipe maps, all four recipe files, canonical setup source, root
licence and agent instructions. It also includes every new job source/test file.
The map excludes only itself and Python cache directories. It has a maximum of
256 regular files, 8 MiB per source file and 32 MiB total. Symlinks, hardlinks,
special files, missing/extra entries, ambiguous paths and nonstandard modes fail.
Every pinned byte and 0644/0755 mode must match both checkout and exact Git commit;
the copied external snapshot is rechecked. Commit all locked files before use.

The original helper runs from that verified external snapshot, where its entire
acquisition/audit/build and setup synchronization closure is present. The frozen
FDK adapter runs from the original verified checkout so its own strict Git/source
location checks remain intact. No synthetic Git repository, Git proxy or source
gate relaxation is used. The job does not regenerate or append entries to the
existing initial/development packets.

Job wrapper sources are MIT. Codec source and notices retain the accepted
[FDK source terms](fdk-aac.md). The helper retains original HTTPS size/hash pins,
full primary signer fingerprint checks, signed ALARM rootfs/package audits and
its offline pacman transaction with scriptlets/hooks disabled. No repository
trust or packages are installed on the host. Host prerequisites are Linux ARM,
Python 3.11+, Git, GPG, Docker, lscpu and zstd, provisioned by the coordinator.

## Exact executable interface

Use a new absolute external output directory, the committed checkout and a
reviewed SHA256 of `packet.lock.json`. Ordinary matching real/effective nonzero
UID/GID, zero effective/permitted capabilities, Linux ARM kernel, hosted
`RUNNER_ARCH=ARM64`, `RUNNER_OS=Linux`, matching `GITHUB_SHA` and at least 8 GiB
free space at the output filesystem are required:

```sh
python -I -B scripts/port/fdk-native-job/job.py --execute-native \
  --source-root "$CHECKOUT" --source-commit "$GITHUB_SHA" \
  --packet "$CHECKOUT/scripts/port/fdk-native-job/packet.lock.json" \
  --packet-sha256 "$REVIEWED_JOB_PACKET_SHA256" \
  --docker-endpoint unix:///var/run/docker.sock \
  --docker-binary /usr/bin/docker --docker-sha256 "$REVIEWED_DOCKER_SHA256" \
  --output "$NEW_EXTERNAL_JOB_OUTPUT" \
  --deadline 7200 --producer-timeout 3300 --fdk-timeout 3000
```

Only explicit `/run/docker.sock` and its `/var/run/docker.sock` alias are accepted
for the original helper. CLI bytes/inode, canonical socket identity, daemon
ID/architecture, user and immutable image remain pinned. Formatted daemon info
uses the accepted fixed, bounded Unix HTTP query rather than CLI plugin discovery.
The helper's context/info queries are routed to those pinned local facts; it
does not fall through to a default context. Empty private Docker configuration
and fixed command environments prevent inherited context/auth/plugin settings.

The wrapper uses the builtin legacy Docker builder with explicit
`DOCKER_BUILDKIT=0`. It records the actual command separately, adding only reviewed
nonce/context/Dockerfile labels, `--force-rm=true`, 4 GiB memory/swap limit and
four-CPU period/quota. The original helper's source, Dockerfile and result schema
remain unchanged. Labels make the final image unique to this job and bind its
context. Root must use a Docker version supporting these reviewed legacy flags;
unsupported versions fail rather than invoking buildx implicitly.

GPG uses the unchanged public-key import/detached signature logic with explicit
`--no-autostart` added to the actual command, the helper's fresh private key home,
`--no-options` and `--no-auto-key-retrieve`. Separate bounded stdout/stderr preserve
the actual signature status and diagnostics. Public import and local signature
verification should work without agent services based on
[GnuPG's option documentation](https://gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html)
and [2.4.8 signature verification source](https://github.com/gpg/gnupg/blob/gnupg-2.4.8/g10/pkglue.c);
this is a source-derived inference, with actual hosted GPG execution still pending.

## Budgets, ownership and cancellation

Default work deadline is 7200 seconds, producer 3300 seconds and FDK 3000 seconds.
Final cleanup has an independent shared 180-second absolute deadline; repeated
signals/journals cannot reset it. Configure the hosted workflow timeout at least
126 minutes to allow work, cleanup, local process termination and final bounded
publication. Accepted ranges are job 5400–9000, producer 1800–4200 and FDK
1800–3600 seconds, with at least 300 additional work seconds. The frozen adapter
chooses two separate build timeouts from its own budget.
Custom work deadlines need a hosted timeout of at least the selected deadline
plus cleanup and publication allowance; 126 minutes describes the defaults.

The pinned cache/context bytes are approximately 1.53 GB each; the rootfs alone
is 829,367,415 bytes. The new worker runner allows 2 GiB per file, 2 GiB address
space, 128 open files, no core dumps, finite CPU/time limits and 8 MiB combined
command output. CLI subprocesses retain the accepted 64 MiB file limit. Four
acquisition threads remain inside a bounded worker process group; threadpool
shutdown or slow HTTPS cannot escape the outer TERM/KILL deadline. The existing
package comparator's decompressor children inherit that owned worker group.
Final filesystem writes remain subject to normal host filesystem availability.

Image reservation is durably recorded before build. Recovery requires the
job nonce, exact reserved context/Dockerfile hashes and immutable IDs. Final
cleanup reloads original and FDK container journals, checks image/daemon/socket/
CLI/user binding and removes only verified owned containers before the image.
Image deletion uses exactly `image rm --no-prune` and one verified immutable
image ID, with no force flag. The broker refuses omitted/disabled `--no-prune`,
force flags, extra targets and non-cleanup deletion calls before invoking the CLI.
Fourteen argument controls cover both list and tuple argv.
Docker documents that [`--no-prune` preserves untagged parents](https://docs.docker.com/reference/cli/docker/image/rm/);
the prior default removal could delete an unowned ancestor despite naming only
the owned child. The source fixture demonstrates that prior behavior and verifies
foreign parent, grandparent and unrelated-image preservation after controller
reload, owned child removal and repeated cleanup. This is a mocked daemon check;
actual Docker cleanup of this correction remains NOT RUN.
It never prunes the daemon or force-removes images. A missing image ID
with unresolved asynchronous build, pin drift, contradictory ownership or failed
removal yields FAIL with uncertainty. A verified recovered ID is persisted before
removal so repeated cleanup remains valid. Cancellation invalidates acceptance
even when subsequent bounded cleanup verifies absence.

Legacy unlabelled intermediate cache is **NOT CLAIMED** as owned or cleaned.
`--force-rm=true` requests intermediate-container removal, but daemon failure or
an interrupted build can leave resources that this wrapper cannot safely identify.
The final receipt attests only the verified job image/container scope. No global
cleanup or complete-daemon-cleanliness claim is made; the coordinator's disposable
hosted runner remains the appropriate place for this trial.

## Public evidence and actual results

The private worker receipt now has an exact eleven-field `boundary` object:
`schema_version`, `last_recipe`, `last_command`, `last_command_zero`,
`comparisons_completed`, `native_delegate_zero`, `worker_status`,
`worker_cancelled`, `worker_cleanup_status`, `worker_cleanup_absence` and
`worker_cleanup_cancelled`. The schema version is integer 1. Recipe values are
the four original recipe names or `UNOBSERVED`; commands are `build-1`, `build-2`,
`compare` or `UNOBSERVED`. Comparison count is an integer from zero through four,
incremented once per recipe only after its exact original comparison command
returns integer zero. Unknown commands cannot create these observations.

Observed booleans distinguish actual returned values from `UNOBSERVED`. Missing
cleanup fields or cleanup exceptions leave their returned observations
`UNOBSERVED`; they do not manufacture an absence or cancellation result. Worker
status and cleanup status use `PASS`, `FAIL` or `UNOBSERVED`. The unchanged native
delegate's actual integer zero exit makes `complete/pass` durably reachable
before receipt validation. This records delegate completion, not receipt
acceptance.

The public `producer_boundary` has those eleven fields plus four controller-owned
fields: `worker_return_zero`, `outer_gate`, `outer_outcome` and `outer_reason`.
The gates are `worker-exit`, `worker-receipt`, `worker-status`, `worker-cancelled`,
`worker-cleanup-status`, `worker-cleanup-absence`, `producer-receipts`,
`original-result-retention`, `accepted` and `UNOBSERVED`. Outcomes are `STARTED`,
`PASS`, `FAIL` or `UNOBSERVED`. Failure reasons use a closed set of predicate
labels and exception classes; raw exception text never crosses this boundary.
Exact field sets, scalar types, enums and gate/reason consistency are validated
by both the evidence module and the workflow's independent static consumer.
Malformed or contradictory worker observations fail receipt acceptance, and a
worker cannot supply the controller fields.

The controller records the first failing gate while refreshing durable worker
observations after failure. Failed boundary saves record a finite `FAIL`; if the
retry save also fails, the original exception is preserved. Filesystem failure
can still prevent durable output. Original receipt validation and private image
binding remain strict. The `accepted` marker requires all four comparisons,
observed delegate and worker zero exits, worker PASS, no worker cancellation,
verified worker cleanup, accepted original receipts and retained original result.
It describes that producer prefix only: subsequent FDK, cancellation, cleanup or
publication failure still makes the authoritative job fail.

Historical fourteen-field public receipts remain consumable. A receipt supplying
the optional fifteenth `producer_boundary` field must satisfy its exact schema;
a new PASS also requires its `accepted` marker. All 802 historical producer
failure codes remain unchanged. These diagnostics add no public image ID,
command arguments, paths, raw logs, errors, signature bytes, source or binaries.

Private output retains the complete source snapshot, fetched cache/context/GPG
home, native result and its preserved original copy, bootstrap/audit/build data,
actual command ledger, image/container journals, FDK archives/source and logs.
No broad private source packet is consumed or published.

Only the new output's `public/` directory is intended for workflow publication:
authoritative `status.json`, sanitized `producer/` summary/acquisition/signature
receipts, exact public input/recipe maps and export manifest, plus `fdk/status.json`.
The finite producer allowlist contains no cache, context, key home, raw logs,
raw exception/response bodies, source archive or package binary. Failed/incomplete
acquisitions can expose only pinned filenames/hash/size, bounded status and HTTP
code. No unaccepted codec binary, or original configuration binary, is published.

Publication follows image cleanup. Source verification, complete producer and
FDK receipts, no cancellation and verified owned-image absence are all required
for final PASS. A malformed child PASS, stale producer PASS or interrupted final
write is downgraded; a failed rewrite retires stale owned exports. The retained
original producer result is not rewritten to add FDK requirements. Publication
failure/cancellation is represented in the separate authoritative job receipt.

Fixture command, requiring no Docker daemon or native/GPG/compiler execution:

```sh
python -B -m unittest discover -s scripts/port/fdk-native-job -p 'test_*.py'
```

Fixture suites cover source closure/Git byte-mode bindings, separate GPG streams,
legacy command policy, owned image/container recovery, producer failures and
publication/cancellation, finite boundary transitions, save failures, poisoned
schemas and returned-versus-unobserved values. The current full fixture suite is
**156 tests PASS, no skips**, 24.580 seconds, including the two image deletion
regressions. Native build/rebuild of this correction,
installation and M2 hardware validation remain **NOT RUN**.

The separate workflow-consumer harness passes **45 test methods** (30 retained
and 15 new), including 397 boundary schema cases and actual controller API
fixtures. The independent source review passes **87 checks** and replays the
102 producer/evidence/controller component tests. Actual YAML structural parsing,
three shell syntax checks and two embedded Python syntax checks pass; the
preflight and native execution step bytes remain unchanged. These are source and
fixture checks, with no native, Docker, GPG, install or dispatch execution.

Earlier actual trial `38248011223` failed with
`producer-after-original-compare-failed`; FDK was not run. That marker does not
identify a failed comparison command or prove all four recipes completed.
[The source diagnosis](fdk-original-compare-diagnosis.md) records five distinct
counterexamples and the limits of the available public evidence. No actual cause
is claimed. The successor boundary is intended to distinguish those later
boundaries on a future trial, after independent source review, canonical source
packet rebinding and coordinator publication. Dispatch remains coordinator-owned
after that source closure is verified.
