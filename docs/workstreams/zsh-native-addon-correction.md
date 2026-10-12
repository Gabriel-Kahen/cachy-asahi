# Zsh native addon correction

This is a source correction of the six blockers accepted in the Root review. It is not native ARM build evidence, an installed overlay, M2 validation, or CI integration. The original four-package pipeline remains the prerequisite. The coordinator must review and register the final captured sources before any native dispatch.

## Scope and custody

Only `scripts/ci/development/zsh_addon.py` and its test file are implementation edits. This document and `artifacts/reviews/zsh-native-addon-correction-20261012/` hold the correction evidence. No runtime manifest, controller, source map, workflow, package source, or Git ref is changed. The original proposal contract remains the same artifact-only contract.

The accepted Root review receipt is `9a3130a3a808e2b7edddc9f0926e23ce7086dcd33bffad080400b70b01a7ad70` (216 indexed artifacts). The original author receipt is `9e86e8e75a73353599cff088134df9bda56606fdc61b2937f1133b61debd3976` (24 records). All indexed rows have been authenticated and retained here, with the original two source files supplied by the before-source capture rather than their edited live paths. The original helper is `4d1169effd60254cccc0dbd0cbe867d2326469f302d7416907d919f8c0ca7c33`; original tests are `c10d2d181afaed1fd0aad7eae539a321f7a4d40e185b8638e9777074da12dfa0`.

## Corrections

- Loaded execution state binds global values, relevant imported module attributes, mutable positional and keyword defaults, class descriptors, wrapper closures and code identity. Only exact declared runtime changes are accepted. Opaque external objects retain identity; their arbitrary internal state is not claimed to be frozen.
- Authority derives file rows, immutable buffers and module paths from the original serialized packet and its supplied digest. Public ledgers are detached or read-only. A coordinated change to a returned packet, paths and buffers cannot redefine the accepted bytes.
- Original authority and loader entry points, class descriptors/bases, and private loader fields are checked before loading a new module. Module names must match their registered path or the unchanged direct-alias whitelist. The guard derives its own dependency chains from actual bytecode without reopening its source. Callback access requires the captured native producer, captured controller and private consumer frames; caller-owned booleans and instance methods cannot grant access.
- Disposal continues TERM, KILL, bounded reap and group-absence checks after an ordinary TERM error. The first work/control failure is retained. A separate typed process-disposal proof is retained on the original error; UNKNOWN keeps the stage cleanup UNKNOWN even if container absence is proved. Disposal errors cannot claim successful cleanup.
- Receipt writes use exclusive temporary files with observed inode custody. Failure reconciliation tries every selector independently and removes only a matching owned stale record when a FAIL rewrite cannot complete. The fsync controls require every selector to become FAIL or absent. If identity cannot be proved or the filesystem refuses invalidation, the selector is explicitly UNAVAILABLE, the live result is FAIL and its public list is empty; physical erasure is not claimed. The original interrupt survives reconciliation faults.
- A present CID file without owned intent is contradictory custody. Cleanup refuses it without treating the CID alone as removal authority or issuing Docker queries.

## Test boundary

Tests execute only inert synthetic source graphs, mocked processes/signals and local temporary receipt files. The original 55 test method bodies are retained; the finalization fixture now calls the real `finalize_stage` receipt boundary directly, because fabricating an unregistered SourceAuthority is intentionally refused. Synthetic native/controller fixtures provide actual captured inert callback frames. This fixture adjustment does not bypass actor preflight to authorize a native build.

The original 15 new causal controls all fail on the authenticated prior helper. The final captured replay passes **94 tests, zero skips**, with no PYC files: the original 55 method bodies and 39 appended controls. It includes actual captured `common.py` digest/default controls, private loader fields and cached Path mutation, class/method changes, registered module paths/direct aliases, callback lifetime, context re-entry and typed process cleanup. A cached-native pre-dispatch control also fails on the preceding 93-test helper and passes after verification is added before calling `native.main`. The correction receipt records the source hashes and links every retained replay. A passing model is evidence for these finite controls, not proof against arbitrary Python reflection or hostile memory writes.

## Preserved boundaries and unfinished work

The original 4 packages / 71 reviewed inputs / 159 initial source files / 125 generated fixture records / 160-file initial view remain the baseline. The 12 addon package inputs, six local source entries and six payloads are unchanged. Planned registration remains 15 additional source rows (211 to 226), with any separately held SVG change accounted for by the coordinator. The helper has 21 standard-library top-level dependencies, adding `ast`, `dis` and `weakref` to the previous 18. No third-party Python dependency or additional runtime source file is introduced. Guards explicitly handle the CPython pathlib `_parts` and `_raw_paths` representations; only the captured local Python runtime has been exercised. Native runner verification remains pending.

The deadline remains 1200 seconds total, 1080 seconds work and 120 seconds cleanup. Same-job Linux ARM runner identity, image ID, package lock, source commit and epoch checks remain required. Archive acceptance still requires both installed-content and archive byte comparison. The Docker exception remains the exact retained build helper `run --rm` grammar adapted to create, inspect, start and retained-container disposal; no image removal or pruning is added.

The trusted host assumption remains observational CLI/interpreter owner, mode and digest checks before/after use. This does not establish immutable execution-file-descriptor custody against hostile host replacement. Python guards enforce a cooperative in-process protocol, not a hostile-process sandbox.

Root admission, aggregate `require_complete=True`, native ARM execution, hardware tests, installation/removal, publication and release acceptance remain unfinished. No native compiler, makepkg, Docker daemon, GPG, kernel namespace, service, network or real signal actor is run by this correction. Signals are mocked for the entire test suite, including the newly protected receipt writer.

## Final source hold

- Helper: `66dbd5d73140a7e1fb976cb63e5ae458f73d37a5755de19985cc0d51a9a06f2e`.
- Tests: `b14d4dee776a291846b54b879bce3a92eed8347b6a918b31218718acbc63349f`.
- Strict final model receipt: `0a66ca032caab906b0a36e32ff429d49bbc61807f2eaa88f95a3ba8a57f46d34` at `test-peer/green-final-b/receipt.json`. Its 226 captured records were rehashed after the run, as were both live source files. The captured-record count is test custody, not a performed runtime registration.
- Root handoff: `artifacts/reviews/zsh-native-addon-correction-20261012/review-receipt.json`. This hold reports source correction and finite inert validation; independent Root admission remains pending.
