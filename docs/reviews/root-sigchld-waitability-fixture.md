# Owned host SIGCHLD waitability fixture

Root executed an original C/CPython fixture on this x86_64 development host,
kernel `7.2.7-1-cachyos`. The three commands—pkg-config, GCC and the fixture—
returned zero naturally and were reaped. Their recorded command/fixture interval
was 0.206098588 seconds within its original 30-second envelope. Later provenance
hashing and publication are outside that measured interval.

The fixture first installs SIGCHLD `SIG_IGN | SA_NOCLDWAIT` in its own process.
Its first child exits immediately; `waitid` observes `ECHILD`, corroborating
automatic reaping. The embedded Python public API then sets SIGCHLD to
`SIG_DFL`. Public C `sigaction` observation confirms the default handler and
that `SA_NOCLDWAIT` is cleared. A second owned child exits immediately: two
`WNOWAIT` observations return the same terminal child/status, followed by one
explicit final reap and `ECHILD`. No explicit signal targets any PID.

Receipt `71491751d88ede61517701d60f8643fc3f12788a0ab8ea9cc10021f871452a86`
binds ten retained files under
`artifacts/reviews/root-sigchld-waitability-fixture-20261013/`. The result records
the exact C source, compiled binary and GCC/pkg-config/Python identities.
Linked-libpython and header identities were added by passive post-run hashing;
they are not live mapping proof. Per-child limits were CPU10 seconds, AS512MiB,
FSIZE1MiB, FD64 and core0. Recorded stdout/stderr are bounded observations;
resource caps are not usage measurements.

This supplies current-host public-primitive evidence for a waitable-child
controller prerequisite. It does not prove an entire loader/kernel Source
closure, absence of every future competing reaper, failure-path cleanup or a
hard wall-latency bound. The fixture's ordinary subprocess helper exercised
only natural exits. Independent retained review `f89bcec8…` authenticates 22 leaves and four
corruption controls; Root verified that complete index. See the
[peer guide](root-sigchld-waitability-fixture-root-review.md).

No updater query, GPG signer, package operation, ARM build, Asahi installation,
16K execution, M2 behavior, performance or release gate is accepted by this
fixture. The full R1–R5/M5–M9 goal remains active.
