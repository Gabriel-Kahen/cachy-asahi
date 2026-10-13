# FDK inner phase observation

This author lane implements finite observations inside the existing FDK recipe and compiler adapter. It provides source and harmless fixture evidence; it does not repair or rerun the eighth native trial. That trial remains failed with container exit 4 and no public evidence identifying its inner phase or compiler invocation. See [the frozen diagnosis](fdk-container-exit4-diagnosis-38289669230.md).

The review packet is [fdk-inner-phase-observation-20261012](../../artifacts/reviews/fdk-inner-phase-observation-20261012/). Ownership is exactly ten source files, including four additions. The primary `PKGBUILD`, `.SRCINFO`, shared source maps, workflow, and Git adoption remain with the coordinator. The proposed recipes in this packet are artifacts; they are never sourced or executed by the review.

## Issued facts

The proposed recipe calls `inner_observation.py phase PREPARE`, `BUILD`, `CHECK`, and `PACKAGE` immediately after each original container/aarch64 guard. A phase means the operation was entered. It does not mean its checks passed. Without a source-issued marker the phase is `UNKNOWN`; missing evidence cannot establish that a compiler was not run.

The compiler adapter records an attempt immediately before the original `subprocess.run(command, check=True, timeout=180)`. A natural event comes only from its actual returned result or `CalledProcessError` return code. Timeout, cancellation, and spawn errors have no invented natural return. The 395 compile and two link command arrays, their order, four-worker pool, and original source checks remain intact. Counts and first events are diagnostic facts, not a replacement acceptance gate or proof that all 397 commands ran.

The exact private schema has twelve fields: `schema_version`, `bindings`, `phase`, `first_failure`, `cancelled`, `write_failed`, `compiler_attempted`, `compiler_attempt_count`, `compiler_natural_count`, `first_compiler_attempt`, `first_compiler_natural`, and `publication`. Publication is always `NOT ACCEPTED`. Bindings contain the entry, recipe, observer, selected archive, and layout SHA256 values. A command event contains only `kind`, `index`, `natural`, and `returncode`; no argv or paths. The first failure contains only phase, finite predicate, finite reason, and nullable command event.

Predicates are `UNKNOWN`, `SELECTED_PATH`, `SELECTED_BYTES`, `SELECTED_GRANT`, `COMPILER_NONZERO`, `COMPILER_CALL`, and `COMPILER_TIMEOUT`. Reasons are `UNKNOWN`, `NONZERO`, `TIMEOUT`, `CANCELLED`, `IO`, and `INVALID_DATA`. Exact types, bounds, first-event identities, counts, and nonzero implications are checked. Duplicate JSON fields, nonfinite values, and extra fields are rejected.

## Publication and capture

Facts enter memory before observation I/O. Natural nonzero returns latch their first failure atomically with the return event. Cancellation adds a sticky flag without replacing an earlier business failure. Ordinary observer errors preserve the original business outcome; control exceptions propagate. An ordinary loader failure leaves unavailable evidence and cannot supply modern completion evidence.

The fixed private output is `/out/fdk-inner/observation.json`, in an owned mode-0700 directory with mode-0600 record and lock. Serialized records are bounded at 2048 bytes; parent capture is bounded at 4096. Descriptor-relative nofollow traversal, bounded regular-file reads, exact temp inode and bytes checks, and atomic replacement constrain custody. A publication or final-close failure revokes the identified record and writes a bounded refusal snapshot into `.lock`. Later processes merge its original failure, compiler facts, cancellation, and `write_failed`; the marker cannot become healthy evidence. Parent capture rejects a nonempty lock or `write_failed` record. These controls do not establish authenticity against a noncooperating process with the same UID.

The parent captures the record once, using the helper bytes authenticated against its reviewed source pin. It retains the original broker's already validated stopped-container State; it adds no inspection query, retry, clock, or polling loop. The private `inner_context` has eleven fields: schema version, existing worker binding, five source bindings, container ID/name, image, nonce, status, running flag, exit code, and inspection hash. Its canonical digest binds the normalized observation. The receiver checks the existing config, source pins, observed outer command results, and original captured builder provenance. It does not reread the child record.

The public `inner` group contains exactly `availability`, `reason`, `raw_sha256`, and `observation`. Availability is `UNKNOWN` or `BOUND`; reasons are `NOT_OBSERVED`, `MISSING`, `UNAVAILABLE`, `SOURCE_INVALID`, `INVALID`, `UNBOUND`, and `OBSERVED`. Unknown evidence has a null observation. A bound observation replaces private bindings with the context digest. The raw hash remains the hash of captured bytes, distinct from the normalized projection. Private paths, context, config, nonce, prose, and argv are excluded.

## Completion and coordinator adoption

The worker runs every original artifact verification before the new inner-completion check. Missing evidence becomes a saved failure receipt through the existing failure and cleanup path. It cannot interrupt saving by failing late projection after a premature PASS. An earlier source, command, artifact, or cleanup cause remains the first cause.

Modern build completion requires `BOUND/OBSERVED`, a known raw hash, coherent binding, an attempted compiler and a natural zero sample, with no first failure, cancellation, or diagnostic write failure. All original container, source, ELF/ABI, smoke, package, paired comparison, and cleanup gates remain required. Compare retains the exact default `UNKNOWN/NOT_OBSERVED` inner group because it has no builder record. The historical absent-inner shape can still parse for old evidence; it cannot authorize a new PASS. Modern callers must use `validate_workers(..., require_complete=True)` for proposed PASS.

Coordinator adoption must reconcile recipe/checksums, the helper's eleven-module standard-library grant, template/reviewed/stage/job/ready registrations, and the authenticated consumer. The proposed counts are 23 recipe source entries, 24 template files, 25 materialized recipe files, 44 stage source rows, and 133 job source rows. The shared `evidence.finalstatus_public` needs the modern completion requirement; its historical parsing call alone remains insufficient. Recipe/checksum and source-map proposals are in the packet. An independent combined review and exact committed-source authentication remain necessary before any subsequent native trial.

## Validation scope

The final held source passes 189 strict tests with zero skips and zero bytecode files: observer 14, compiler 24, source 58, publication 14, capture 12, worker 27, and projection/receiver 40. Recipe syntax, 23 source/checksum pairs, and the 25-file materialized recipe set pass static validation. Removing only the phase callbacks and restoring the original source/checksum declarations reproduces the original recipe exactly.

Tests exercise source refusals, natural zero/nonzero returns, timeouts, cancellation, concurrent events, diagnostic I/O failures, final-close failure, inode substitution, ancestor aliases, strict schema and projection, once-only capture, private-context mutation, original artifact failures, and cleanup. Independent review exposed a modeled close error before descriptor release that could retain the lock and obstruct refusal publication. The final helper explicitly releases its flock before closing; the failing original model and corrected replay are retained. This does not claim recovery from arbitrary persistent combinations of filesystem faults.

The frozen corrected-updater packet and its source snapshot remain intact. Four current updater files differ from that hold; preservation records their hashes and does not attribute those edits to this lane or restore them. The eighth FDK native diagnosis and original universal entry/build scripts retain their recorded hashes.

Logs and exact source hashes are in the review receipt. All compiler and container outcomes in these tests are explicit fixtures. No native compiler, makepkg, Docker, GPG, package installation, or hardware actor is invoked by this lane. Installation, M2 compatibility, 16K runtime behavior, reproducibility, performance, and distribution acceptance remain unestablished.
