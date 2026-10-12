# FDK bootstrap IID compatibility correction

The actual hosted FDK trial `38260525391`, at source commit
`44a3e001da2fdfb95f15dd6898de67158a1af1c3` and 128-file packet
`c459d749bbb8a319e2a9243852deddf30f3b79947cbe6dae1c4cf832dfe1ee87`,
failed original producer receipt acceptance. Its verified public boundary records
four successful original comparisons, native delegate and worker zero exits,
worker PASS without cancellation, and worker cleanup PASS with verified absence.
The rejection is `outer_gate=producer-receipts`, `outer_reason=producer-bootstrap`;
the historical error code is `producer-after-complete-failed`. All 501 acquisitions
passed. FDK did not run. This locates the acceptance predicate; the private FDK
bootstrap and IID bytes were not exported and are not invented here.

## Exact unchanged writer and retained counterexample

The original `scripts/ci/native_arm.py` remains SHA256
`a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.
Its successful writer at lines 416–422 emits exactly these bootstrap keys:
`command`, `dockerfile_sha256`, `inputs_sha256`, `image_id`,
`packages_lock_sha256`, `hook_policy` and `status`. The status is
`image-provisioned`. The input and package inventory hashes bind the actual
`inputs.lock.json` and `packages.lock`. Its prior `bootstrap-starting` and
`failed` records are incomplete states and remain unacceptable.

Docker creates the `--iidfile`. The original helper reads its text with `.strip()`
to obtain an immutable image ID and does not rewrite the file. The job's accepted
base broker likewise reads the IID file and validates its immutable identity
without rewriting its bytes. The successful native writer already matches the
consumer's status, image, input and inventory predicates.

Independent actual broader run `38259350917`, at source
`0e0ebb96b17041e1eed41f1769f3d19c99584e50`, retains the same original helper's
`development-native/native/bootstrap.json` and `image-id`. That bootstrap has the
successful seven-field schema. Its IID file is exactly the matching ASCII image
ID, **71 bytes with no terminal LF**, SHA256
`10112f71989c14ff7ad151747c51cd6837365ebd48e78b60b91b99d4cc5cdf3f`.
The prior consumer required exactly `image + LF` (72 bytes), so these valid
retained bytes causally fail its `producer-bootstrap` conjunction even though
every other member passes. The synthetic evidence fixture had always added LF
and concealed this compatibility gap. This is an actual retained counterexample
from the same writer, not a claim about the unexported FDK IID file or earlier
private failure causes.

## Narrow accepted grammar

Only the IID byte comparison changes. The bounded ordinary-file read still
requires the already verified immutable image ID and accepts exactly:

- The 71 ASCII bytes of that ID.
- Those same bytes followed by one LF.

No general whitespace stripping is introduced. Empty, truncated, foreign-ID,
uppercase, leading/trailing whitespace, CR/CRLF, extra LF, multiline, NUL,
non-ASCII or oversized content remains rejected. The 256-byte read cap and
single-link/no-follow/race checks remain intact. Bootstrap status, image ID,
input pin and 341-package inventory pin remain required. Original source,
signatures, recipe/build/comparison receipts and private image binding are not
relaxed. No command, Dockerfile, worker, broker, workflow, accepted stage39,
input/recipe lock, packet source constant or shared manifest changes.

## Inert verification and remaining gates

The evidence test evaluates only the successful dictionary expression extracted
from the SHA256-pinned original writer, using fixture-local paths and read-only
SHA calls. It runs no native helper, Docker, GPG, compiler or package operation.
The old predicate rejects the canonical bare IID; the corrected complete receipt
validation passes it. The default evidence fixture now writes the bare IID.
Separate controls preserve all required identity/hash/status fields and accept
only the two exact byte forms, with sixteen malformed IID controls.

The evidence suite passes **23 tests, no skips**; the complete job suite passes
**159 tests, no skips**, 25.277 seconds. Independent source review and successor
packet rebinding remain coordinator gates. Native execution of this correction, FDK compilation,
installation and M2 hardware checks remain **NOT RUN**. A source/fixture pass
does not promote trial `38260525391` or establish a successful successor trial.

The root-owned retained trial records are under
`artifacts/ci/38260525391/root-public-verification.json` and
`artifacts/ci/38260525391/decoded/public/status.json`. The retained writer
counterexample is under
`artifacts/ci/38259350917/development-decoded/development-native/native/`.

## Literal check against retained native producer data

The corrected, SHA256-held `evidence.validate_producer` was called unchanged
against that actual broader native directory, its immutable image, original
helper pin and exact recipe lock. It refuses at `producer-result`: the retained
result has `mode=integration` and
`status=native-builds-and-virtual-integration-pass`, while the separate FDK
producer requires `mode=build` and
`status=native-builds-and-byte-comparison-pass`. The unchanged native writer
sets mode from its invocation and updates the later status only after its
integration controller succeeds. This refusal preserves the intended contract;
the result is not rewritten and the acceptance schema is not widened. Full
producer acceptance is therefore not established by this literal check.

Separate unchanged data-only evidence APIs and exact downstream predicates pass
on the retained records: 501 acquisition rows, 249 recorded zero-exit primary
signature statuses, 248 package metadata audits, the 341-package inventory,
successful bootstrap with its bare 71-byte IID, all eight original build records,
four independent-container pairs and all four original comparison records.
Every required original artifact/environment/recipe byte is retained; no missing
private file or additional writer-schema mismatch is found. These separate
checks do not substitute for the refused full validation result.

The consumer was copied byte-for-byte into a fresh reviewer-owned source path,
with Python bytecode disabled. No helper function, source root, receipt field or
schema was patched. All 260 retained native files hash identically before and
after review. The finite receipt and replay are in
`artifacts/reviews/fdk-actual-native-compatibility-20261012/`.
