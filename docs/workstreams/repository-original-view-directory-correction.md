# Original-view directory receipt correction

The original-view hold `b340a6470c615914f76f02a83f44e4b71d61608c48298c93b91bfc9b1406c263`
remains historical and BLOCKED by its independent peer. Replacing the modeled
Session's private receipt and SHA with canonical bytes containing an extra
`directories['ghost']` or `directories['../ghost']` row was accepted by actual
`original_context`. The copied tree itself stayed unchanged. The former visited
count upper bound did not require every receipt row to describe an actual copied
directory. This is a concrete receipt validation defect; these cooperative
fixtures do not establish hostile same-UID memory isolation.

Only `Session.verify_view` changes in production. It derives the exact directory
set from the parents of the 160 locked files, including the sole root name `.`.
Every other receipt name must satisfy the existing canonical relative-name rule:
no empty, absolute, trailing-slash, doubled-slash, `.` or `..` components. The
receipt's directory keys must equal that derived set before traversal. The walk
retains the existing depth, ownership, mode, device, node, deadline and cancellation
checks; its visited directory set must also equal the derived set. Its count stays
bounded. Existing exact file membership, copied-node/source-node checks and final
source guard remain.

Three new actual-context tests cover an extra canonical row, seven malformed
aliases, and missing/replaced directory keys. All prior 92 test bodies are AST
identical to the preserved hold. The two authority files and their 17 tests are
byte-identical. Working and fresh captured suites each pass 95 tests with zero
skips. The separate old-red/new-green replay changes only canonical receipt bytes
and the matching SHA: eight surplus/malformed names ACCEPT before and REFUSE after;
valid actual contexts ACCEPT before and after, and missing rows continue to refuse.
Artifacts and exact source hashes are retained under
`artifacts/reviews/repository-original-view-directory-correction-20261012/`.

The candidate capture retains 255 selected source paths: two changed rows and 253
unchanged rows. It preserves original159, the initial lock, view160, four recipes,
71 recipe files, schema2 grant/API, status22/live12, actual single namespace graph,
sole producer, argv binding, fixed E, cleanup reserve and all acceptance gates.
The earlier hold/captures/proposal and implementation guide are untouched. Root
owns new packet registration, shared maps, controller, workflow, grants and Git.

This is a source/fixture candidate for independent review. Actors, original native
execution, external authority issuance, Docker, compilation, packages, signing and
hardware validation are NOT RUN. No valid native main/run positive is claimed.
