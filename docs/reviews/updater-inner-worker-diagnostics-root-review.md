# Independent review: held updater inner-worker diagnostics

October 12, 2026. **BLOCKED for worker diagnostic correction.** All 155 held targeted tests replayed successfully, but fresh causal controls show lost cancellation/first-failure observations, a durable finalization mismatch and an accepted contradictory cancellation record. No false native/compiler/package acceptance was demonstrated. This review does not inspect or accept the moving parent integration.

## Frozen scope and evidence

The sole reviewed hold is `artifacts/reviews/updater-inner-worker-diagnostics-20261012/final-review.json`, SHA-256 **0803198d81c9d13bdf39e8f053f0e099cd79c6f22e14cf937719ce84301e8536**. All **86 files / 4,124,001 bytes** in its `fresh-source/` and all nine held source/test references were verified by size/hash/mode and copied into this review namespace. Thirteen retained artifact hashes were checked, including the interface proposal **02e020de199c76f37ede68e311cb1bef1af6b0ed695d40c9d0565b53785c34d0**. The reviewed sources are the frozen copies, never the moving live updater tree.

Key held source identities:

| Source | SHA-256 |
| --- | --- |
| worker-diagnostic.py | `5d9815992ab8425fac86dc43c5eb88da91037015e18433a4441707391ac43d11` |
| worker-metadata.py | `dd0bc0a6a6343ced98db19abe117ca51924feed92155401b05b66090154e9206` |
| public-evidence.py | `8bdb628f62ce3b9633036cb21e80406d21030769ff9eb57ded6451c6e2f72f8f` |
| worker-build.py | `29108f15b9c1d5f9917b6b363ffe1cc179c106e84c8d12309e95429b8a13f5d0` |
| native-entry.py | `50186df3e771b041b6f53265fdfcc5a5b4b627dede8ea70333a8e6a6e273682b` |

All line references below refer to these exact held bytes beneath this review's `fresh-source/packages/tools/cachy-asahi-update/`. No updater source was edited. Resolver/camera handoffs and historical FAIL/NOT RUN boundaries remain preserved. Root's separate helper/selector selection is context; source/recipe/workflow admission, actual parent reader integration and native acceptance are outside this held worker-side review.

## Blocking findings

1. **[P2] Cache issued command facts and first failure before diagnostic log I/O.** `worker-diagnostic.py:320–341` calls `_logs` inside the update action before the natural return, command or first failure is cached (`_update:209–217`). A real harmless Python actor returns7; an injected KeyboardInterrupt during diagnostic log hashing replaces the original nonzero failure. The persisted record becomes UNKNOWN/Cancelled with `return_observed=false` and null returncode, although the private command receipt records actual exit7. Cache the already-issued minimal command/return/first cause before any diagnostic read, then attach bounded log observations. Later cancellation can be latched without discarding that first cause. This directly contradicts the held cache-before-I/O claim.

2. **[P2] Preserve cancellation delivered during command cleanup.** `worker-metadata.py:392–431` catches BaseException at cleanup points and reduces it to a string. A naturally returned0 harmless actor plus injected KeyboardInterrupt at group cleanup raises ValueError/command-cleanup and records `cancelled=false`. With an earlier returned7 nonzero error, its first cause survives but the later cancellation remains unrecorded. Track control exceptions separately from ordinary cleanup errors, finish bounded owned cleanup, retain the observed natural return and any earlier business cause, and propagate/record cancellation rather than relabeling it. No cleanup reap may manufacture a natural compiler return. These are controlled interruption points around real harmless Python actors, not an actual native worker signal trial.

3. **[P2] Final close failure must not leave an authoritative durable PASS.** `worker-diagnostic.py:261–284,346–351` commits the record before closing its lock/root descriptors. Injecting an ordinary OSError on the final root close leaves disk `PASS/diagnostic_write_failed=false`, while memory becomes `FAIL/diagnostic_write_failed=true`; `finish(true)` returns normally. The public reader only has the durable bytes and cannot learn the failed finalization. Preserve that failure durably or make incomplete finalization explicitly nonauthoritative before parent adoption. This models an ordinary owned-descriptor close failure; it does not demonstrate a native package passing.

4. **[P2] Enforce cancellation flag coherence in both schema copies.** `worker-diagnostic.py:74–80` and `public-evidence.py:501–507` accept `status=CANCELLED`, `cancelled=false` whenever an ordinary OSError first failure is present. The no-first branch checks the flag, but the first-present branch bypasses it unless the first error kind itself is Cancelled. The same contradictory record passes the actual trusted-binding function with modeled valid launch/state facts and the actual projector. Enforce `status=CANCELLED → cancelled=true` outside those branches, preserving the original first failure and independently observed later cancellation. Projection still declares publication NOT ACCEPTED/hardware NOT RUN; no native false PASS is inferred.

## Additional custody findings and model limits

Three fresh controls reveal narrower custody weaknesses. They use an actively interposed **same-UID writer/path mutation in owned temporary directories**. They are not evidence that an actual isolated worker had a hostile writer, and same-UID authenticity is not established by file ownership alone. Review the intended concurrency/threat boundary separately from the ordinary cancellation/finalization blockers above.

- `worker-diagnostic.py:248–266`: replacing the random temporary name before os.replace publishes different valid PASS/no-first bytes while Recorder memory retains FAIL/source-pins and write_failed=false. The temporary inode is checked during abandoned-file cleanup, but not bound to the successful publication. Validate the intended temporary object at publication and state the noncooperating-writer limitation; a cooperative flock is not authentication against an actor ignoring it.
- `worker-diagnostic.py:175–227`: an ancestor alias inserted after the initial link checks can create a lock in an owned foreign sibling before the later regular-record read refuses the alias and marks FAIL. This is an out-of-namespace write despite eventual diagnostic refusal. The default /out has protected ancestors; this does not establish that exact mounted root can be redirected by the worker UID.
- `worker-diagnostic.py:121–139,197`: an ancestor alias inserted between link checking and regular() open allows reading owned foreign log bytes. This is a standalone primitive proof; it does not establish that the full two-stream `_logs` path later accepts both aliased logs. Descriptor-relative no-follow traversal and ancestor identity checks would strengthen the declared namespace invariant.

## Confirmed behavior and limits

The closed private/public vocabularies and field sets agree. Fresh mutation controls reject unknown/private fields, raw prose, invalid enum/boolean/return/log shapes, duplicate JSON keys, NaN/infinities/exponent overflow, oversized data, wrong trusted launch identities and malformed container-state fields. Only fixed finite log lengths/hashes are projected. Operation labels locate source boundaries; they are not predicates, compiler-launch proof or explanations of opaque output.

Harmless actor controls distinguish natural return from timeout/cleanup reaping, including a self-terminated child and an EOF-without-exit timeout. Nonzero makepkg/source-verification retains the observed return with inner predicate UNKNOWN. A child-first modeled compiler cause survives actual harmless outer-process failure, later cleanup and finish(true), with FAIL preserved. Synthetic compiler controls also preserve compilation acceptance after a later packaging failure while refusing overall package acceptance, and preserve a child unit-source refusal through an opaque enclosing makepkg failure. The compiler acceptance call follows the existing compiler/ELF/unit/copy gates and compile-result write; its actual commands were never invoked.

One additional surrounding-path characterization combines compiler cancellation with an ordinary compile-result write failure: the existing receipt-finally path raises OSError instead of the original KeyboardInterrupt, while the diagnostic retains CANCELLED/Cancelled and unobserved compiler return. This is separate from item2's diagnostic loss and does not establish an instrumentation-induced regression. It remains a limit of broad cancellation-propagation claims across original receipt I/O.

`bound_worker_diagnostic` is an explicit identity-binding function, not a successful-container/compile gate. The standalone projector sanitizes a syntactically valid wrong-controller diagnostic, while trusted binding refuses it. Actual parent integration must call trusted binding with independently validated launch/controller/image/entry and inspected state; this review neither ran nor accepted that moving adapter. Diagnostic PASS cannot replace original source/metadata/compiler/ELF/package/pair/comparison/cleanup proofs.

## Execution and preservation

The four held suites replayed with `-I -B -S -Werror::ResourceWarning`: native56, public41, compiler14 and worker44, **155 total, zero skips**. The initial review wrapper used a2MiB RLIMIT_FSIZE, wrongly truncating the worker suite's intentional16MiB fixture logs; its two harness-caused failures are retained. Only that suite was rerun with a16MiB file ceiling. Child wall/CPU limits were60seconds, address space2GiB, core dumps disabled; selected stdout/stderr remained below2MiB. These bounds are fixture execution limits, not performance measurements.

**39 fresh independent controls** are separately recorded under `public/`, `metadata/`, `helper/` and `compiler-controls.json`. Characterization controls intentionally retain reproduced bad behavior; their checker PASS does not mean the held implementation satisfies the selected contract. No actual compiler/Cargo, Docker, GPG, package actor, download, service/module/sysfs/hardware or Git action occurred. Only inert files, controlled mocks and bounded harmless local Python/signals were used. Source copies and old held inputs are rehashed after execution, with no bytecode or temporary-fixture leftovers retained.

The root receipt indexes this new review's evidence and the frozen input bindings. The hold remains BLOCKED for worker-side correction; moving parent integration, real source admission/native trial, installation/runtime/M2/16K/performance/distribution acceptance remain unreviewed or NOT RUN.
