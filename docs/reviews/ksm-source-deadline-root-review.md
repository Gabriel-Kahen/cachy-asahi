# KSM source deadline: independent review

October 12, 2026. **Changes requested before adoption.** The absolute caller
cutoff is propagated correctly, but buffered source writes can still reach disk
during stream close after a deadline refusal. This review owns only this new
document and `artifacts/reviews/ksm-source-deadline-root-peer-20261012/**`.
Runtime sources, shared maps, workflow, repository Git state and native dispatch
remain unchanged. The roadmap and package inventory were read.

## Exact held checkpoint and closure

Checkpoint SHA-256:
`63734bc9458b7fe25a615fd7eb5f723442d3a257b23c9ba519a5b90f6efa389c`.
All declared checkpoint artifacts and six owned source/document rows match
their hashes, sizes and modes. The four Python rows are:

| File under `scripts/port/ksm-native-job` | SHA-256 |
| --- | --- |
| `acceptance.py` | `f50c0d563bab378d697e1b99ba9c3f7a8694db2d47518676b47a17b50e22e740` |
| `test_acceptance.py` | `df10fb6379278523004ec4932c94db08b6c12535a951354772a00be743b25319` |
| `executor.py` | `a0b93c590092937b9ab5eae2426c4b6e8b69526e8e4890fa72133d06da6051a7` |
| `test_executor.py` | `997d1cb56c22c3ee95aee85aa3343d6b2ea3cf1c3ca07909f95bad1edb6e3a3e` |

The prospective map `760514ec90f72a02659f37edf61f65ad0623a38b2ab427260edd95d668660881`
contains152 rows /2253645 bytes. Seven rows differ and145 remain identical to
adopted map `65a7ab50f5e9b085278a1f2094771d2f705a2e768ab74300698ce451b858d24e`.
The seven include the previously accepted broker/test-broker baseline-B changes,
not seven new deadline corrections. Those two files are byte-identical to the
accepted baseline-preservation capture. The source packet remains held.

## Confirmed behavior and causal evidence

Production computes `source_end = started_at + 180` once, before ordinary host
checks. It passes that exact cutoff into capture, directory traversal/file reads,
Git queries, copying/final verification and launcher preparation. Startup checks
also surround source policy, module/CLI loading, daemon readiness, baseline
capture, broker/RPC setup and transition to the producer. Git's ten-second cap
is clipped to remaining caller time. Explicit caller deadlines are not renewed;
standalone capture's optional finite180-second default remains a distinct API.

After the producer and each build, `check_source_tree` receives the existing
`producer_end` or `build_end`; it does not borrow a fresh source interval. All six
protected executor function ASTs (`owned_cleanup`, `baseline_observe`,
`invalidate_public`, `context_digest`, `save_status`, `owned_output`) are exactly
unchanged versus the accepted pre-correction copy.

The independently authenticated152-file copy passes **eight focused tests,
zero failures/errors/skips** with Python `-I -B -S` and resource warnings treated
as errors. These include six new causal controls plus existing Git/deadline
controls. Source bytes/modes remain stable and neither fresh corrected nor
old-runtime control copy contains PYC/cache directories. The author's working
and fresh261-test PASS logs were hash-verified; the full suite was not repeated.

The old and corrected causal functions were replayed in separate fresh copies,
using real tiny committed Git fixtures and injected monotonic clocks. Old
capture renews its cutoff to359 and copies two files at181; corrected capture
receives180 and refuses before any source copy, backend or producer. The two
existing nonrenewable cleanup-reserve controls also pass. Native/daemon/backend
conditions remain modeled; no Docker, package installation or native KSM ran.

## [P2] Buffered close writes after the cutoff refusal

In `executor.source_tree` at lines192–198, `os.fdopen(fd, 'wb', closefd=False)`
uses buffered writes. A small `stream.write(data)` returns with the bytes still
in the Python buffer. If the clock crosses180 before the following
`acceptance.alive(deadline)`, that check raises, but exiting the `with` block
flushes the pending bytes while closing the stream. This is a new filesystem
write after refusal, not an already-running kernel write merely returning late.

The [independent probe](../../artifacts/reviews/ksm-source-deadline-root-peer-20261012/buffered-close-probe.py)
uses the exact authenticated copied function, a real file/BufferedWriter and an
injected179→181 clock. Disk size is0 after `write` and immediately before context
close; it becomes24 bytes during close at181. The recorded reason remains
`acceptance aggregate deadline exceeded`, and no next file or native operation
runs. A second read-only agent independently reproduced the same edge with a
real BufferedWriter and in-memory sink.

Use unbuffered checked writes, including bounded chunks and short-write handling,
so an exception closes only the descriptor and cannot flush queued source bytes.
Add the causal regression at the post-write cutoff boundary and assert no raw
write occurs after refusal. Preserve the permitted cleanup/finalization work and
all baseline/ownership predicates. The existing fsync-overrun test checks that
no second file is copied, but does not cover buffered context exit.

This is a source-budget gap with no false PASS or native mutation observed. It
blocks adoption of the advertised source-deadline closure until corrected and
reviewed. Installation, hardware/M2/16K, performance and new native lifecycle
acceptance remain **NOT RUN**.

The [review receipt](../../artifacts/reviews/ksm-source-deadline-root-peer-20261012/review.json)
retains source pins, map delta, focused results, old/new causal records and the
finding. Private temporary fixture trees were removed. Captured source copies
remain as review evidence only; they do not constitute coordinator registration.
