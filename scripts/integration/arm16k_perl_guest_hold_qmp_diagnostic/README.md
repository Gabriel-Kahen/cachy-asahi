# Guest HOLD / QMP metadata diagnostic proposal

No causal QMP bug is proved. The Source339 trace proves that serial reading stops when `GuestHold` interrupts the journey and that buffered read-ahead may remain; it does not prove serial backpressure caused r86's no-reply stall. `TRACE.md` records the call sites and limits. Tiny r88's two actual ACKs establish only the minimal helper path, and its original HOLD remains unchanged.

`observe.py` is an optional, fixed-schema metadata observer, not an actor or authority entry. Bind `Binding(peer, serial)` immediately after the original authenticated serial connection is wrapped, before the journey. It borrows the original QMP socket, serial socket and existing QEMU pidfd. It opens only its own bounded metadata descriptors. It never receives, sends, peeks, drains, hashes or discards serial content, reads SO_ERROR, reconnects, duplicates/closes original descriptors, signals or waits for a process.

At most three ordered calls are permitted: `sample('HOLD')`, `sample('BEFORE_QUIT')`, `sample('DEADLINE')`. Each returns numeric/enum DATA only:

- Original QEMU PID/start/parent/group/session, live pidfd observation, bounded thread states and process/thread CPU ticks. No comm, cmdline, environ, credentials, stack or thread names are emitted.
- The same derived cgroup's `cpu.stat`, `memory.current`, `memory.events` and optional `memory.events.local`, using fixed counter keys. Counters belong to that cgroup and can include its actor or other members; they are not per-QEMU attribution. Missing fields remain null, never fabricated zero.
- Readiness, FIONREAD, SIOCOUTQ kernel accounting and buffer sizes from the original QMP and serial sockets. SIOCOUTQ is not an application-byte count or proof of parsing.
- Only serial buffer length, offset and their difference. Read-ahead may include CRLF or a prompt; the count does not identify pending protocol.

Original descriptor/peer credentials/pidfd/process-start/cgroup identity are checked around observations. A ready pidfd records `pidfd_live=false` before further process reads. An identity mismatch or unavailable observation is not a causal diagnosis, successful retirement or acceptance. The existing `peer.check()`, five-second quit deadline, QEMU exit0/original reap and EMPTY_TWICE guards remain authoritative and unchanged.

Bounds are fixed: 32 threads, 4096 bytes per metadata read, the existing1MiB serial buffer count bound, a checked50ms metadata budget per binding/sample, 16KiB canonical snapshot and at most64KiB canonical report component. These are cooperative deadline checks around nonblocking kernel metadata reads, not a claim that kernel scheduling cannot delay a syscall. Only fixed proc/cgroup paths derived from the already authenticated original process are used; there is no arbitrary-path API or path output.

`integration.UNISSUED.patch` is **unapplied**, pinned to the genuine Source339 `controller.py` in `integration-basis.DATA.json`. A future composer would copy `observe.py` as `hold_state_observations.py`, include it in the new closed source manifest, and apply the reviewed hook to the matching controller:

1. Bind after original Serial construction.
2. Capture HOLD after the existing `GuestHold` classification.
3. Capture BEFORE_QUIT after the existing peer check and before constructing the original five-second deadline.
4. Capture DEADLINE only after the existing progress reports `DEADLINE_EXPIRED`, within the already reserved cleanup tail, before fallback. No quit retry or extension occurs.

The hook bounds the complete canonical diagnostic report component at65536 bytes before appending. Observation failure records only a fixed unavailable flag and cannot replace a protocol/cleanup failure. A future Root composition must account for that component inside its existing certified log/output budget; this proposal changes no resource cap or grant. It is optional and does not gate the independent cache fix or Source387 delivery.

Verification uses mocked descriptors/proc/cgroups/sockets and an in-memory application of the source-pinned hook. The proposed controller compiles without execution, and the original quit invocation and normal retirement requirements are compared structurally. The exact combined command, results and pins are in `validation.DATA.json`.

No actor, VM, lease, Root truth, Original GET, private home, Raw or serial transcript was exercised. No Source339 file, current case manifest, runtime/profile/nonce/output or shared package inventory was changed. This directory is an unissued proposal; it grants no execution or package/VM/M2/release acceptance.
