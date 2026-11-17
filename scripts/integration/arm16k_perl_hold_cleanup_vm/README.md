# Proposed bounded guest-HOLD cleanup successor

The actual r80 run remains HOLD: installed_metadata failed, the quit request was
fully written44bytes, the first read timed out after2seconds, fallback dockerwait
was signaled, and neither qemu.json nor guest-HOLD-retired.json was present.
Root independently closed the owned actor/scope with exact absences and custody.
Those closure observations do not validate normal QEMU retirement or the guest.
The cause of QEMU's missing first response remains unknown.

The code offers the already allowed five-second whole quit window without a
fatal two-second per-read boundary. Merely retrying SocketIO.readline is unsafe:
real socketpair controls reproduce partial-byte consumption and permanently
poisoned timed-out file reads. The replacement requires the actual original
healthy unbuffered SocketIO, then uses the same original socket with select,
nonblocking IO and an explicitly owned bounded partial-line buffer. Source9dd's
buffering=0 greeting/capabilities reader does not read ahead; a real socketpair
control proves unread next-line bytes stay on the original socket. No buffered
stream or previously timed-out file can be substituted. The original timeout is
restored on every exit.

Exactly44 request bytes must finish; only a matching error-free ACK passes.
EOF, malformed/duplicate JSON, unmatched IDs,16message/64KiB caps, guard failure
and the same whole deadline still refuse. No quit ACK or natural receipt is
waived. Real2.1second delayed ACK passes within the original five-second window;
this host control does not prove QEMU would have answered in r80.

Same peer/actor pidfd, start/argv/connection, nonce/authority/image/mount identity,
marker, natural actor exit1, same QEMU natural reap/group absence, exact marker
and receipt joins, owned-only removal and independent absence gates remain.
Normal cleanup keeps its25second budget and reserved40second fallback tail.
Primary GuestHold, cleanup errors, fallback and all acceptance fields remain HOLD.
The proposed finally block records fixed qemu/HOLDreceipt presence/pins and typed
counters, plus the existing sanitized actor failure, even if cleanup throws.
These observations never authorize completion or export argv/exception text.

`proposal.transform(controller_bytes)` requires the exact immutable9dd controller
pin and returns two proposed execution leaves: controller.py and hold_cleanup.py.
`controller.patch` is the reviewable controller delta; helper bytes are in
hold_cleanup.py. Root owns composition into a NEW explicitly versioned constructor
and Source with fresh qualification. This family never constructs or modifies a
Source, authority, runtime, nonce, packet or guest file. Do not run old9dd packets
against changed code. The separate installed-metadata worker owns that issue.

Run `python3 -I -B -m unittest discover -s . -p 'test_*.py' -v` in this family.
Twelve focused tests include real local sockets and a modeled full normal-HOLD
cleanup using unchanged actor retirement validation; forced/wrong/missing joins
still fall back and retain the original guest failure. Two unchanged original
QMP peer/pidfd controls were also replayed successfully. No Docker, QEMU, VM,
credential/private-key/raw-image access, lease, push or rerun occurred.
