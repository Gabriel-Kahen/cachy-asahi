# Payload diagnostics and failed-owner retirement successor v3

Source implementation/proposal only. No Root role, lease, grant, native actor,
Git push, Original GET, private key or secret access occurs here. Source68 and its
actual84 failure remain immutable. Native package pair, signing, installation,
M2/performance and release remain unaccepted.

## What the actual84 evidence establishes

Run44038704344/job133887761246 actually passed the scoped2GiB ARM Docker CLI:
command010 exits0, Architecture=aarch64, server28.0.4, zero containers/images.
This advances that finite startup check; it gives no native package-build credit.
The ordinary owner PID2961/start34644 was observed and then exited2. Its25-byte
owner.log contains only `HOLD_PAYLOAD: ValueError`. The operation remains HOLD,
with owner cleanup ValueError and owned_storage_absent=false. Daemon retirement
succeeded. No existing result is reclassified or marked cleanup PASS.

actual84.DATA.json pins the public inputs. Offline replay passes the complete
D.observation Source/ref/nonce/PID/start/cgroup declarations, owner/daemon limit
declarations and host-policy receipt hash. Actual payload Root-document, kernel,
filesystem and socket observations were not retained. Therefore no particular
payload guard failure is proven; this proposal adds the missing bounded evidence
instead of weakening a candidate guard or guessing a cause.

## Privacy-safe next-guard diagnostic

payload_diagnostic.py defines16 literal phase IDs around the existing payload
steps. Every admission/source/signature/domain/socket/filesystem/UID/namespace
predicate remains unchanged. On exception, owner.log receives one <=512-byte line:
phase, allowlisted exception class, UTF8 message byte length, SHA256 of at most the
first8192 bytes, prefix length and truncation boolean. No raw exception message,
private environment, path or value is emitted. Unknown exception class names map
to OTHER. The existing bounded owner.log retention path is reused; no private tree
or arbitrary new file is retained. Exit2 and HOLD are preserved. For ordinary
literal guard messages the nontruncated digest identifies the failed predicate
without publishing its text. Diagnostics do not execute any additional actor.

## Failed payload is distinct from stopped/empty service retirement

The old stop routine polls the exact owned unit, original PIDFD and cgroup, then
rejects every remembered Result except success. Actual84's loaded/failed unit
still records Result=exit-code/ExecMainCode=1/ExecMainStatus=2 after stop returns0.
This is consistent with the final result predicate rejecting a dead failed unit;
the public data does not independently prove every actual owner PIDFD/cgroup
observation, and the old cleanup HOLD remains unchanged.

The new narrow failed-owner path requires all of the following:

- Exact owner unit/nonce/Description, original observed positive PID and starttime,
  original canonical cgroup and an explicit original PIDFD identity ledger.
- The same loaded, already-failed state before and after stop: MainPID0, empty
  ControlGroup, Result=exit-code, ExecMainCode1, and the same canonical exit1..255.
- Original PIDFD type/dev/inode unchanged, poll reports POLLIN with no ERR/NVAL.
  A closed, foreign or reused descriptor is not an exit proof.
- Two separate original-cgroup censuses with populated0 AND empty cgroup.procs,
  plus original PIDFD exit. A genuinely absent cgroup is accepted only after
  lstat raises FileNotFoundError; permission/unknown failures never mean absent.
  Kernel-file reads are bounded/no-follow, duplicate event keys refuse, and the
  cgroup directory identity is rejoined during each present-path census.

Only then may cleanup record STOPPED_EMPTY_FAILED_OWNER with payload_exit retained,
payload_success=false and unit_reset=false. Active, unknown, foreign, unobserved,
signaled, timeout/OOM or changed-exit cases refuse. No reset-failed call exists.
The existing storage cleanup body is byte/AST identical and still runs only with
zero service/log errors, then verifies the exact owned mount/device/backing file
before unmount/detach. The primary ordinary-payload-success predicate and final
HOLD/PASS logic are byte/AST identical. A retired failed owner can never make the
payload or native pair successful.

## Source construction and inverse

```sh
python3 -I -B scripts/ci/llhttp-reference-native-source/successor_v3/prepare.py \
  --parent /absolute/exact-Source68 --output /absolute/fresh-Source76
```

The constructor requires the exact68-file/980464B public parent, map
00a7b3ced2bbf21303734d32cf9dde10e7db5e724b0c1b4857f7ab7e5a685998 and tree
ff40c38eb5062ace3b46cb2f2c4c8c32fc010a00. It adds two finite helpers, five complete
before-bodies under previous-v2 and a marker; only payload/controller, explicit
policy declarations, owner-program and Source-map change. The inverse reconstructs
every original68 body/mode, byte total, map and Git tree, then its held62 inverse.
The new Source has76 files and remains below the unchanged <80 namespace cap.
The signed349/Core closure, ordinary inner2GiB limits, scoped Go VA selection,
zero-host-APT, normal dependencies/recipe checks, workflow and all numeric resource,
storage/output/deadline/cancellation/retirement limits remain unchanged.
All actual selectors, admission and runtime fields remain NULL. Root must review,
publish/read back, bind a new caller and issue new actual operands separately.

## Controls and limits

Seven actor-fenced DATA controls pass with actual retained Source68/public84
inputs. They cover complete76/68/62 inverse and resource preservation, payload
hash privacy/truncation, the actual public observation replay, the unchanged
cleanup/main/setup/run bodies, and the actual projected stop function across
failed/active/foreign/missing-custody models. Predicate controls refuse changed
unit/exit, missing start/FD, live FD, one/unknown/nonempty census, signal-style exit,
unknown permissions and duplicate event fields. No systemd/cgroup actor is run.
Missing external genuine-material fixtures report explicit SKIP, never success.

A separate real local tiny Python child control opens/retains its actual PIDFD
and start identity. While alive it refuses retirement. It then exits2 naturally
and is REAPED/EMPTY_TWICE without signals/timeouts; the original PIDFD reports exit,
foreign/closed identity refuses, and explicit MODEL unit/cgroup rows produce only
STOPPED_EMPTY_FAILED_OWNER/payload_success=false. The service rows and temporary
cgroup files are synthetic, not a native systemd retirement qualification.
No Root role/shared lock, network, real cgroup mutation or native actor is used.

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/llhttp-reference-native-source/successor_v3/test_data.py
python3 -I -B -Werror::ResourceWarning scripts/ci/llhttp-reference-native-source/successor_v3/test_real_pidfd.py
```
