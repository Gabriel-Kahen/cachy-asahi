# Separate finite hosted FDK native job

The new `scripts/port/fdk-native-job/` interface prepares a separate hosted ARM
job. It changes neither the initial/development packets nor the original
four-package acceptance. The coordinator owns the free public ARM workflow,
Git publication and dispatch. **Actual native execution is NOT RUN** at this
source checkpoint; fixture passes are not producer/build/hardware acceptance.
No CI/workflow, shared manifest, accepted adapter or package template is edited.

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
| Separate job `packet.lock.json`, 128 files | `2e190f75594fe5550770aa567b7729637853a99d6c2ce3b137248ed3954cbe32` |
| Original inputs, 501 acquisition items / 249 signed payloads | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` |
| Four original recipes, complete 71-file maps | `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63` |
| Accepted FDK adapter, unchanged 39-file lock | `a7048064c0c20abd246a466035313abaf65590f3ed10d0f7927b21a346200ad6` |
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
It never prunes the daemon or force-removes unrelated images. A missing image ID
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
publication/cancellation. Actual native build/rebuild, host Docker/GPG acquisition,
installation, publication and hardware validation remain **NOT RUN** until the
coordinator dispatches and records the real job.

Actual final source checkpoint: **90 tests PASS, no skips**, 17.482 seconds.
Independent source/mock review passed. The 128-file packet contains 1,934,570
source bytes; the accepted adapter's 39 byte/mode pins and all 71 original recipe
hashes remain unchanged. No executable files changed after this checkpoint.
