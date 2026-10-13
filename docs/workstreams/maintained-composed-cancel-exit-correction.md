# Maintained cancellation exit: bounded source investigation

No causal cancellation defect is established, and this proposal changes diagnostic attribution only. Actual run38449904816 at SourceCommit `5a41a3da7ed9aab99035794b4de3def005396b82`, DataCommit `59332b3ab112c0b05c6dbe7ef160d67698bbe738`, retains `construct-services / TYPE_ERROR / SERVICE_CANCEL_EXIT`, native hook false, cleanup PASS, controller exit1 and initial exit null. Completion SHA256 is `33125f36241f6080adbfa8d0f86592b9baa23d1f7c874ade819a98c87a1d008b`. The marker names an authenticated Source exit region; it does not identify a signal operation, disposition, restoration cause or inner predicate. The precise hosted predicate remains UNKNOWN. Neither this investigation nor a future diagnostic backfills the prior actual03 record.

The owned proposal namespace is [maintained-composed-cancel-exit-correction-proposal-20261013](../../artifacts/reviews/maintained-composed-cancel-exit-correction-proposal-20261013/). Its existing completed local probe was inspected before further work and was not rerun after the app restart. The authoritative result records one owned child, PID2104670, normal exit0 in0.0472 seconds and successful reap without TERM/KILL. There was no unresolved live handle in that retained completion. This is retained process evidence, not a fresh PID inspection or replay.

The probe compiled exact held `common.py`, SHA256 `92ca41005397c6cccfd70497646c0de1f2ac88a697e0fcbec4165bf5326cfc08`, inside local isolated/no-site/no-PYC Python3.14.7. The original SIGINT/SIGTERM dispositions were CALLABLE/DEFAULT; mask and pending queries returned sets. An empty `defer_cancellation` body completed normally. A synthetic body TypeError propagated as the same object. Both handlers, the initial mask and the empty pending registry were restored; an initially absent real timer stayed absent. The child caps were CPU2s, address space128MiB, file size64KiB, descriptors64 and core0. Its supervisor had a5s deadline and separate4096-byte stdout/stderr caps; observed output was467/0 bytes. No signal delivery, timer creation, service, socket, foreign process, Docker, network or GPG actor occurred. Hosted Python3.12 is NOT RUN. This local API result cannot explain or clear the actual hosted failure.

The audited helper blocks kernel delivery, captures both original dispositions before mutation and installs the supplied callback. Its exit blocks delivery again, attempts both original setters with at most two attempts each, checks the resulting dispositions, consumes newly pending transition events only for signals originally unblocked, restores the original mask in a nested finally, replays consumed events to the callback and raises the first retained restoration error. `defer_cancellation` separately removes its pending registry entry and transfers or raises remembered cancellation. The exact runtime helpers are unchanged in this proposal.

The existing Source guard also remains unchanged. `Sources.graph_namespace` accepts the declared standard `contextmanager` wrapper only with its exact standard code/globals, sole `func` closure, wrapped-function identity and empty defaults. It then checks the unwrapped function against whole-source compiled code in the exact captured module namespace. `Sources.class_state` applies corresponding wrapper checks to decorated class methods. `Session.execute` captures the graph before service construction and uses the authenticated collector wrapper. These facts establish source boundaries, not the live signal values or the hosted failing predicate. No source-freezing guard relaxation or general exception workaround is justified.

The private change narrows `Session.service_failure_site` only after its existing exact builtin TypeError, construct-services phase, Source hash, plain filename, whole-source code, exact globals and64-frame checks succeed. Seven fixed AST expressions from `_signal_handlers` finally regions map to closed labels:

| Site suffix after `SERVICE_CANCEL_EXIT_` | Authenticated Source expression |
| --- | --- |
| `BLOCK` | `signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)` |
| `SET_HANDLER` | `signal.signal(number, original)` |
| `HANDLER_CHECK` | `signal.getsignal(number) == original` |
| `PENDING_CHECK` | `number not in mask and number in signal.sigpending()` |
| `PENDING_WAIT` | `signal.sigwait({number})` |
| `SET_MASK` | `signal.pthread_sigmask(signal.SIG_SETMASK, mask)` |
| `REPLAY` | `handler(number, None)` |

These label source statements and whole predicates. In particular, a handler-check label does not distinguish its query from equality evaluation; a pending-check label does not distinguish mask membership, pending query or pending membership. A traceback outside the seven expression regions retains the existing enter/exit or OTHER label. The deepest authenticated frame still wins, including the original setter location when a retained restoration error is raised later. No frame locals, handler values, raw exception, path, line number, argument, environment or traceback is emitted. Optional attribution failure keeps the original error and existing metadata rule.

Three new focused model methods pass, together with the existing cancellation model whose one expected exit enum is narrowed. The models compile the complete captured common source to obtain exact function code; all signal/mask/pending operations are inert seams. They inject the same TypeError object at all seven statements, verify untouched exception args/traceback, retain an empty model pending registry where applicable, reject foreign globals, filename and hash drift, and preserve the closed nine-field FAIL/source-refused/cleanupPASS projection, false hook and1024-byte cap. An attribution KeyboardInterrupt leaves the first failure intact. The actual proposed issuer namespace check also passes without calling native entry. The original suite was not replayed.

Conservation checks preserve the entire handoff module AST except `Session.service_failure_site` and the closed enum in `Session.startup_projection`, all55 other function/method declarations, `startup_failed`, `Session.execute`, all14 inherited test classes except the single expected diagnostic enum literal, all263 selected Source rows outside handoff/test/bridge and all metadata14. The bridge changes only its existing handoff hash literal; the packet changes exactly those three source rows; the outside workflow changes only its packet literal. Source3 bootstrap, controller, earliest J, first cause, cancellation, publication endpoint, grant/runtime/callback/view contracts, receiver/profile/authority and original159/generated125/build/signature counters remain unchanged.

The exact private cascade is:

| File | SHA256 | Bytes |
| --- | --- | ---: |
| handoff | `066c14d0b46ef7b7989ff85b7d5d05fec8edc510b2b0fee0f0746c9ea8818249` |141431 |
| test | `93cd21f54a59e99c212da855f94bd4151b18e816379137726c9d8c8bdcc5206e` |113467 |
| bridge issuer literal | `6a9a7efbcd464b098019812c918867f5e71b9d28597376136dca98b04efedf3a` |22061 |
| Source266/metadata14 packet | `216a4dccda4524909df756cc47bbaad91bcc904b2ebfd131b9fe4a90c161c688` |94735 |
| outside workflow packet literal | `4c349eb38458bb5010e14e238d9a6575c789c11aded371aee13d6345fe8fb8e5` |10056 |

The baseline packet is `68d2fccba47a35798a442c4e0f134951c34618899d25f62d22c47a243cdddbd3`. Captured Source266, packet, workflow, retained actual04 completion/marker, existing completed probe, proposal, guide and focused results are indexed by the final sealed receipt. Final hashes are also in `proposed-registration.json`. No primary/managed/shared source, workflow, Git, Root registration folder or goal was mutated by this lane. The earlier constructor and service-attribution receipts remain separate.

Root owns independent review, adoption, a new exact Source/Data/plan binding and separately selected actual trial. A concrete runtime correction requires evidence of the actual predicate first. This sealed proposal supplies no grant or actual execution authority. R1–R5/M5–M9, full package coverage and maintenance, protected Asahi integration, installation/recovery, measurements and both M2 Air sizes remain unfinished; neither the local probe nor these source models constitute native or hardware acceptance.
