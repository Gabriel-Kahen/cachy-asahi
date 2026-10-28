# Narrow KSM inventory caller budget proposal

**Proposed only; no production implementation or actor admission.** Root selects
the finite inventory budget and assigns implementation/review ownership. The
R1–R5/M5–M9 roadmap remains authoritative; this correction advances a disposable
development producer, not release or hardware acceptance.

KSM5 run `38303811300` retained an RPC6 RUN processing observation of 67,529 ms,
then a failed reply after broker return0 with the exact 6,674-byte341-package
inventory digest. The original inventory caller requests timeout60. The shim's
2600-second limit cannot extend that parent subprocess timer. This supports a
practical correction to the one mismatched caller budget. The original caller
exception was not exported; `TimeoutExpired` is a source/model inference, not an
observed actual exception. The independent actual-run review is
[native-ksm-execution-38303811300.md](../reviews/native-ksm-execution-38303811300.md).

## Minimal ownership and source interface

A bounded implementation owner would add only
`scripts/port/ksm-native-job/producer_driver.py` and its
`test_producer_driver.py`. Root's integration owner would adapt only the producer
command construction in `consumer.producer_command` and `executor.pipeline` to
select that authenticated driver. Root owns the final packet, RequiredPaths,
workflow and source-policy bindings. Two newly admitted Python files would add
two packet rows if root chooses this layout; no new count or hash is granted by
this proposal. No production files are edited in this review lane.

Suggested driver interface:

```text
python3 -I -B -S producer_driver.py
  --packet-sha256 ROOT_ADOPTED_PACKET
  --producer-end EXISTING_ABSOLUTE_MONOTONIC_CUTOFF
  --inventory-seconds ROOT_SELECTED_INTEGER_AT_MOST_180
  -- ORIGINAL_NATIVE_ARM_BUILD_ARGUMENTS
```

The driver authenticates the existing accepted KSM packet/captured-source closure
and exact native module graph before executing captured strings. It needs the
original `native_arm.py` and its `package_checks` import, with explicit captured
project imports and isolated standard-library imports. It must not execute
project PYC, use arbitrary caller modules, import unbound project paths, or
grant code by filename alone. The original159 source bytes remain immutable;
they are not a request to add a separate159-source grant to KSM.

Frozen actual source pins at commit
`59af52fba548a89330fc2d915c3bd627d1485655`:

| Source | SHA-256 |
| --- | --- |
| `scripts/ci/native_arm.py` | `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` |
| `scripts/checks/package_checks.py` | `e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8` |
| `scripts/port/ksm-native-job/consumer.py` | `53323c45a63d7bbf989c33421dfb521ef29b4a3fff1d42c670ae4aca2a81f15e` |
| `scripts/port/ksm-native-job/executor.py` | `4a37f501827091be5cea9262814379f8487f474c7c967754c7a467ddada08440` |

New driver/test and resulting map pins cannot exist before implementation. Root
must bind them after independent source and fixture review.

## Exact permitted adaptation

Load the original native module privately, save its original `run`, and replace
only that private global function with a same-signature wrapper. Invoke the
unchanged captured `native.main` once. Do not monkeypatch the global subprocess
module, the Docker shim, broker operations or the original source file.

Override the caller timeout only when `log is None`, the supplied timeout is the
original nonboolean integer60, and the complete command is exactly:

```text
docker run --rm --pull=never --network=none --cap-drop=ALL
  --security-opt=no-new-privileges --read-only --entrypoint=/bin/cat
  SAME_PRODUCER_IMMUTABLE_IMAGE_ID /builder-packages.lock
```

The immutable `sha256:` ID must equal the bounded, no-follow, stable bytes in the
current producer's private `image-id` artifact; syntax or a family label alone
is insufficient. The output location must be the original command's root-bound
producer directory. Extra flags, reordered options, another image, another
command, a logged call or another timeout retain their original arguments and
timeout. Matching confers no new broker ownership or acceptance.

For the single matched call, use
`effective_timeout = min(root_inventory_seconds, producer_end - monotonic())`.
Validate finite deadlines and a nonboolean integer budget greater than60 and no larger than180;
refuse a nonpositive remaining allowance before launching the call. Root may
choose180 as a candidate; it remains a finite cap, not an estimate or guarantee
that every hosted request completes.

Reuse the producer cutoff already computed by the executor:
`producer_end = now + min(6600, aggregate_end - now - 1650)`.
Do not create a fresh producer deadline, enlarge6600, borrow the1650 later-phase
reserve or restart the aggregate8460 budget. The existing broker separately
protects180 seconds for aggregate cleanup. Passing the existing producer cutoff
already preserves that later reserve; do not silently double-subtract a new
reserve or add a fresh cleanup clock.

All original input, architecture, immutable-image, inventory equality, baseline,
resource, ownership, exit, cleanup and consumer acceptance checks remain. The
full broker request must finish before its reply; no early reply, retry, skipped
check or private raw log export is proposed. Actual KSM5 stays FAIL and its
cleanup and uncertain mutation are not repaired retroactively.

## Required bounded acceptance

Use exact frozen original `run`, shim and service source in harmless fixtures.
An explicitly scaled60-versus67.529 processing control must fail at the parent
timer and later fail reply; the same completed request under the proposed finite
caller budget must deliver the exact inventory and return0. Also require refusal
at an exhausted cutoff, failure when the request exceeds the clipped cutoff,
and unchanged forwarding of every nonmatching call/timeout/log.

Before any native rerun, independently verify original source159 preservation,
the complete adopted new closure, exact command selection/image binding, shared
absolute deadlines and reserved cleanup, and all unchanged operations/guards.
Root selects the budget and implementation/peer route after reviewing this
proposal. No additional diagnostics framework is required for this correction.

Root subsequently selected180 seconds clipped to the existing `producer_end`.
Separate source-only driver implementation is authorized after the actual KSM5
review is sealed; no native actor admission follows from that selection.
