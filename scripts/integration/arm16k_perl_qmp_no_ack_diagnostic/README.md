# Source310 r83 QMP no-ACK diagnosis and observation proposal

The actual r83 run remains HOLD. The public report records a complete44-byte
quit request,20idle polls, zero received bytes/messages and the unchanged
five-second deadline. Both qemu.json and guest-HOLD-retired.json are absent;
the later docker-wait helper required SIGTERM and forced cleanup followed.
This does not establish QEMU natural retirement or explain why it did not reply.
The earlier two-second read fix operates as designed but is insufficient here.

The request's AST value is valid JSON with actual final0a LF, not literal backslash-n.
The same controller connection successfully negotiates qmp_capabilities using LF
before the guest journey. Source310's unbuffered SocketIO consumes one complete
line without reader-ahead, and the peer/start/argv/parent/pidfd gates run again
before the cleanup send. No framing change, ACK waiver or timeout increase is
supported by this evidence. Local socketpair controls exercise the exact emitted
request and fragmented/event-prefixed replies, not a real QEMU implementation.

Serial is not drained during QMP cleanup. The saved redacted capture ends at a
complete guest HOLD frame, with no captured flood. Unread later serial output or
a QEMU main-loop/vCPU/blocking/resource stall remains possible; the saved log cannot
rule either in or out. Process-group reaping happens after QMP quit and cannot
explain the missing reply on its own. No QEMU stdout/stderr bytes or retirement
receipt were written before forced cleanup. Missing receipts do not prove an
ownership loss; the actor can be killed before its finally block writes them.

Neither qemu-system-aarch64 nor qemu-system-x86_64 is available in this host PATH.
A real diskless -machine none/-S QMP-only probe is NOT RUN. No QEMU was installed,
no Docker actor/image was queried and no guest disk, raw image, credential,
private key, lease or network endpoint was accessed. The exact r83 report,
redacted serial, public argv and wait receipt pins are in inputs.DATA.json.

## Confirmed failure-observation bug

The frozen owned-process supervisor uses os.waitstatus_to_exitcode. A signaled
child can therefore have exit-15 or-9, but the Source310 failure-only observer
accepts only0..255. It also rejects genuine UNKNOWN ownership and several frozen
supervisor group census states. A safe, canonical forced-retirement receipt then
becomes REFUSED and loses the already verified public file pin. Controls reproduce
this with real wait-status decoding; this is an observation bug, not the r83 cause.

The exact-pin proposal corrects that observation range/state vocabulary and keeps
a safe whole-file pin even if optional field decoding refuses. It never changes
R.natural(), wait ownership, RSS, signals, deadlines or acceptance. A before-forced-
fallback and after-cleanup journal keeps prior receipt observations if a later
file disappears or becomes unavailable. Missing actual receipts remain ABSENT;
no ACK, QEMU receipt or natural-HOLD retirement is fabricated. Every observation
retains NULL VM/Root acceptance. Existing primary guest error/fallback stays intact.

## Evidence for the next separately admitted attempt

Read-only zero-timeout socket snapshots record FIONREAD, Linux SIOCOUTQ kernel
accounting, socket buffer sizes and readiness on the original checked FD, before
and after the write and at exit. They perform no receive/send, SO_ERROR read
(which would clear error state), serial drain, process signal or new wait.
AF_UNIX SIOCOUTQ includes kernel bookkeeping and is not an exact application-byte
counter or proof QEMU parsed a command. Persistent output accounting vs drained
output/no reply separates two useful observations; neither diagnoses the cause.
Sampling failure is nonfatal and cannot replace transport failure or ACK checks.

If Root later has an already qualified host system-QEMU binary and owned execution
helper, a separately admitted finite diskless/networkless -machine none/-S QMP
probe can test the same capabilities/quit bytes. It must retain real CPU/RAM/PID/
time and natural retirement receipts. That probe would still not reproduce r83's
ARM guest, serial activity, disk, actor cgroup or process-group behavior. If future
actual queued bytes remain pending, inspect same-identity QEMU thread/wchan/RSS/
cgroup and serial readiness under a separate public observation review; do not
increase the quit or90-second whole cleanup budget to hide the failure.

## Scope and validation

Only this new family is authored. proposal.transform() requires exact Source310
controller/helper pins and returns three proposed leaves: controller.py,
hold_cleanup.py and qmp_observations.py. The generated helper and controller.patch
are review artifacts. No Source310, constructor, guest metadata, initialized guard,
Root authority/runtime, shared manifest or workflow changes. Root owns any future
versioned composition, whole-Source cap check and separate admission.

Run12 focused controls with explicit immutable Source input:

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/arm16k_perl_qmp_no_ack_diagnostic/test_proposal.py \
  --source /absolute/Source310 -v
```

Controls cover whole proposal inverse and syntax, immutable-input refusal, exact
44-byte/LF framing, fragmented/event-prefixed valid ACK, error/wrong-ID/no-ACK
refusals, unchanged bounded timeout, nonconsuming socket queue reads, observation
failure, negative exit/state pin loss, malformed-field pin retention, before/after
journal preservation, absence and unsafe receipt refusal. No test is called QEMU
or guest success. Actual r83 cause, next actual execution, M2 and release remain
unknown/NOT RUN. Performance is not measured.
