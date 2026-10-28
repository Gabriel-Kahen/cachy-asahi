# FDK attached-start command correction

## Observed trial and confirmed source defect

Native trial `38239523997`, source
`756881b917ef68c614fcfb081debadf82282e80b`, failed with
`producer-base-probe-inventory-probe-base-lock-probe-inventory` before FDK
execution. Its public receipts record all 501 acquired inputs, failed producer
acceptance, and verified owned-image absence. The private inventory command's
return code and raw streams were not exported. The following source defect is
confirmed and reproduces that finite public code; it is not a claim to have
recovered the trial's unavailable private bytes.

The shared FDK broker invoked
`docker start --attach --sig-proxy=false CONTAINER_ID`. Docker's `start` command
has no `--sig-proxy` option. The previous fake CLI required that invalid argument,
so fixture success did not establish real CLI compatibility.

The correction removes only the unsupported flag from `Broker._launch` and
makes the fake CLI reject extra start arguments. Both the original producer's
`BaseBroker` and the FDK stage's direct `Broker` use this launcher. A producer-only
translation would leave the FDK probe and builds broken.

## Pinned CLI source and signal policy

The audited Docker CLI revisions are:

| Version | Commit | Primary start implementation |
| --- | --- | --- |
| 28.5.0 | `887030fbe83f5368566ec3b35e15a4ba13267a62` | [start.go](https://github.com/docker/cli/blob/887030fbe83f5368566ec3b35e15a4ba13267a62/cli/command/container/start.go) |
| 29.8.0 | `88096ef00576baf72a9cb45caa45c0544c40e0a7` | [start.go](https://github.com/docker/cli/blob/88096ef00576baf72a9cb45caa45c0544c40e0a7/cli/command/container/start.go) |

For a non-TTY container, attached `start` installs signal forwarding; it exposes
no switch to disable it. Our container creation does not request a TTY. Therefore
the corrected invocation can forward signals from the CLI to its container.
Forwarding is not disposal or absence proof. The unchanged finite runner still
handles worker cancellation, sends TERM to its owned process group, escalates
to KILL after its bounded grace period, and reaps owned descendants. The broker's
`finally` cleanup independently reloads durable reservations, validates daemon,
container identity, nonce and resource bindings, removes only owned containers,
and queries their absence. Cleanup failure and cancellation still prevent PASS.

The pinned [28.5.0 signal implementation](https://github.com/docker/cli/blob/887030fbe83f5368566ec3b35e15a4ba13267a62/cli/command/container/signals.go)
and [29.8.0 implementation](https://github.com/docker/cli/blob/88096ef00576baf72a9cb45caa45c0544c40e0a7/cli/command/container/signals.go)
subscribe to catchable signals and request container signal delivery. They skip
CHLD, PIPE and Go's Linux runtime URG signal. Attached `start` uses a background
context for forwarding and stops its signal subscription when it returns.
Runner TERM can consequently be handled and forwarded instead of ending the
CLI immediately; the existing bounded KILL escalation is necessary. KILL cannot
be caught or forwarded, so durable broker cleanup remains essential.

Actual x86-64 CLI parsers for Docker **28.5.0** and **29.8.0** both returned
125 for the removed option, with `unknown flag: --sig-proxy`. Both recognized
`start --attach` and reached the missing-container-argument check. The tests used
fresh configuration directories and nonexistent owned Unix socket paths; no
daemon, container or host Docker configuration was changed. The 28.5.0 binary
was extracted only under `/tmp` from Docker's official HTTPS static archive;
its locally computed digest is recorded, with no detached signature claim.
Daemon signal delivery is source-audited, not tested against a real Docker daemon.

## Verification and unchanged acceptance gates

- The corrected stage fixture suite passed **77 tests**, zero skips, in
  **17.112 seconds**. Its broker subset passed **22 tests** in **14.229 seconds**.
- The job fixture suite passed **118 tests**, zero skips, in **23.037 seconds**;
  its base-broker subset passed **24 tests** in **19.428 seconds**. Eight added
  controls bind the full frozen lock, exercise the real producer delegate and
  original helper, refuse malformed/private/unsorted/nonzero output, and require
  image/container cleanup. A syntactically valid extra package reaches the
  original helper's unchanged exact-set comparison and is refused. That last
  test uses explicitly synthetic cache bytes and signatures, never authenticated
  inputs or a native transaction.
  The coordinator of this correction independently replayed all 118 tests in
  **23.285 seconds**. A separate source reviewer replayed the three attached-stop
  tests in **7.566 seconds** and confirmed that restoring only the removed flag
  recreates the accepted baseline broker SHA256.
- New attached-start tests send actual SIGINT and SIGTERM to an owned worker and
  exercise a real command timeout. A fake CLI forwards TERM to its TERM-resistant
  child. Tests require both process IDs to disappear and owned-container absence
  to be verified. Existing foreign-nonce, resource-drift, unknown-create,
  cleanup-failure, cleanup-interruption and runtime resource/output tests remain.
- The temporary pre-correction counterexample passed eight controls, reproducing
  the observed public code with an unsupported-option exit and passing the exact
  341-package lock after removing only that option. These are fake CLI/Unix daemon
  fixtures; they do not establish a native build or hardware result.

The inventory remains 341 packages, 6,674 bytes, SHA256
`89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`.
No producer inventory syntax, sorting, newline, exit-status or original exact
name/version comparison was relaxed. No output lines are filtered or normalized
to pass a guard. The accepted CLI runtime's merged streams and 64 MiB file limit
remain intact; no stream-separation change is included. The native helper,
selected codec source, recipe packet, public schemas and failure-code allowlist
remain unchanged.

## Dependency closures and coordinator handoff

The owned change set is the shared FDK broker, its fake CLI/signal tests, the
corresponding job inventory tests, and this document. Packet manifests, source
constants, Git publication and dispatch are coordinator-owned and are not
refreshed by this worker.

- **FDK stage, 39 files:** `scripts/port/fdk-native-stage/stage.lock.json` must
  rebind `broker.py` and `test_broker.py`. Its membership and modes need no change.
- **FDK job, 128 files:** `scripts/port/fdk-native-job/packet.lock.json` must rebind
  those two stage files, its `test_base_broker.py`, the reviewed successor stage
  lock, and the coordinator's `packet.py` adapter-pin update. This document is
  outside the existing packet closure. No new execution grant is proposed.
- **Kernel stage, 24 files:** it pins FDK `evidence.py`, which is unchanged, and
  has its own forked `kernel-native-stage/broker.py`. None of the FDK files
  changed here is in that stage lock. Its fork still contains the unsupported
  start flag and requires correction by its owner; this patch does not repair
  or certify the kernel path.

Old source locks deliberately remain stale with respect to edited files until
the coordinator reviews and rebinds them. Fixture suite success is not source
closure acceptance. Native FDK compilation, installed lifecycle, publication,
and M2 hardware checks remain NOT RUN for this correction.

Proposed successor pins were calculated in memory only, preserving the existing
JSON serialization, membership and modes:

| Proposed binding | SHA256 |
| --- | --- |
| Stage lock, 39 files | `b83ddb865d7651c748258ac570e64fb824caf5bced8b1f415694dff7f5c187f5` |
| Job lock, 128 files, 1,982,280 source bytes | `309fcd6fbec8b7e96c83ea049804ae3134e7190d2145e81afc66d28563097f44` |
| Job `packet.py` after coordinator changes its adapter pin | `ae345e3608c0a99a6f372cd8b925c5fa5610f9b53037933768f214305c2ffbe9` |

These are proposals, not written or accepted locks. The row-level successor
hashes/lengths are retained in
`/tmp/fdk-start-cli-correction-audit/proposed-closure-pins.json`; CLI source pins
and actual parser outcomes are in `source-pins.json` and `parser-results.json`
in that same directory. `audit-receipt.json` records the independent source review
and distinguishes local fixture cleanup from untested real Docker signal delivery.

Replay from the repository root:

```sh
/usr/bin/python3 -B -m unittest discover -s scripts/port/fdk-native-stage -p 'test_*.py' -q
/usr/bin/python3 -B -m unittest discover -s scripts/port/fdk-native-job -p 'test_*.py' -q
/usr/bin/python3 -B /tmp/fdk-start-cli-correction-audit/parser_check.py
```
