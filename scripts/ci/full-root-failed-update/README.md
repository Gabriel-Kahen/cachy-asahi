# Full587 controlled failed-update/disposal lane

**Native case PASS at frozen Source001f0484 in actual38885492612.**
It establishes one verified precommit-exit86 case, zero commits, unchanged
checkpoint/source, complete owned-copy disposal and outer resource absence.
[Exact evidence and limits](../../../docs/validation/full-root-precommit-failure-native-20261016.md)
keep normal upgrade and hardware recovery separate. Earlier observation/XZ
failures are retained; later source revisions need their own execution evidence.

Adopt `integration.patch` at **`scripts/ci/full-root-failed-update/`**. This adds
three MIT-licensed modules, two focused test modules and a separate lane config.
The held package/source license and provenance checks are reused unchanged. **No existing
core, production policy, shared manifest or normal-success caller changes.**

## One boundary and recovery contract

The normal full-root driver remains the parent and owns its existing complete
copy/initialization/disposal context. Its actual setup4 repository constructor,
explicit actual-release selection, signature verification, dependency/ownership,
link/helper/capacity policy and strict before587/after587 locks are reused.
Only the update execution is delegated to one supervised child.

A private Runtime subclass calls every existing precommit check first. It then
requires the exact initial587 inventory, prepared setup0.1.0-3 ->0.1.0-4
addition/no removals, existing live ALPM lock and unchanged root identity; writes
one fsynced nonce/source/spec-bound witness; and calls `os._exit(86)`. No commit
call is reached and no policy refusal is bypassed. A returned callback, earlier
refusal, wrong exit, missing witness, timeout or uncertain retirement cannot
satisfy the case. There is one child attempt and no automatic retry.

The parent uses the held process runtime's cancellation/group cleanup. It checks
complete copied-root bytes/modes/ownership/literal links/closed hardlinks against
the initialized pre-child baseline. The sole allowed difference is the exact
stale `var/lib/pacman/db.lck`: empty, mode0000, root-owned, matching the witnessed
node. This shape follows the retained effective libalpm `_alpm_handle_lock`
source, which uses O_CREAT|O_EXCL and mode0000 without writing bytes. The lock is
never overridden to reopen ALPM or reuse the copy. Database records, user files,
trust, package payload, helper/cache closure and empty checkpoint state must
remain unchanged. The whole owned workspace, including its stale lock, is then
disposed through the existing descriptor/mount-checked lifetime.

This lane privately binds the unchanged Runner's exact128-descriptor request to
8192, after requiring an inherited hard limit of at least8192. Other limits and
other Runner callers remain unchanged. This covers the observer's bounded4096
hardlink groups plus directory/temporary descriptors. Four controls check the
private binding, unchanged other limits, insufficient capacity and source drift.

Both full-root selections now allow16MiB of decoder memory. The exact retained
setup4 XZ archive refuses at8MiB with `Memory usage limit exceeded` and parses
all13 nodes/six regular payload files at16MiB. The archive reader, package bytes,
signatures and all other archive bounds remain unchanged. Normal retry38880148414
reached prepare and failed this budget before commit; copy/source disposal passed.

The original pre-copy persistent source is independently re-observed and must
match throughout. Its raw cache bytes stay unchanged; only the disposable copy
receives the existing one-shot cache initialization before the failure baseline.
The outer hook also repeats the normal persistent source/ownership postcheck.
Failures preserve stage/commit uncertainty and the original driver/child result.
Expected case PASS requires confirmed copy disposal and source preservation;
outer container/image/volume cleanup is a separate required result.

This advances M3/M8's full-composition software failure prerequisite. It provides
no postcommit interruption, downgrade/rollback, resumed transaction, service/boot
restoration, macOS journey,16KiB or M2 hardware recovery credit. Those remain
required later. The existing tiny-root postcommit/checkpoint failure controls
remain unchanged and are not relabeled as this full587 case.

## Concrete dispatch handoff

Use a **separate development workflow/selection** with the normal full-root
job's same authenticated native/FDK/setup4 pair and checkout/cache bindings:

```sh
python3 -B "$UPGRADE_CODE/scripts/ci/full-root-failed-update/launch.py" \
  --preparation-source "$PREPARATION_CHECKOUT" \
  --upgrade-code "$UPGRADE_CODE" \
  --upgrade-config "$UPGRADE_CODE/scripts/ci/full-root-failed-update/lane-config.json" \
  --updater-v2-source "$UPDATER_V2_CHECKOUT" --setup4-pair "$SETUP4_PAIR" \
  --product "$PRODUCT_CHECKOUT" --updater "$UPDATER_CHECKOUT" \
  --desktop "$DESKTOP_CHECKOUT" --native "$CORE341_PAIR" --fdk "$FDK_PAIR" \
  --cache "$COMPOSITION_CACHE" --output "/tmp/full-root-failed-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
```

`launch.py` verifies selected source pins, privately imports the unchanged
composition owner and binds only its private caller source directory to three
checked files: unchanged container/persistent-scope code and this separate hook.
Its normal actors, capabilities, volume custody, package preparation and cleanup
are retained. Private hook sources are removed only after the coordinator reports
cleanup PASS and owned volume absence; otherwise their path is retained/reported.

The separate config has53 source pins. It keeps the normal package/version,
platform/link/helper/archive/root policies and limits; chooses a distinct TEST
release/repository/namespace; selects only `precommit-exit86`; and uses2400s
within the existing driver ceiling. Child1200s and each verification600s remain
finite; existing source-stage/copy/outer owner budgets still apply and can refuse.
`source-freeze.json` records all unchanged core/input hashes. Root owns adoption,
source/workflow publication, native dispatch and any deliberate rebase of pins.

The existing composition transport retains its legacy `full_root_upgrade` JSON
key. Interpret the nested explicit scope/case: case-level status PASS,
failure_cases1, committed_transactions0, all three commit/checkpoint flags false,
original_source_preserved=true and copy_cleanup PASS. The preserved normal driver
and controlled child reports remain FAIL. This is a successful negative case,
not a completed upgrade. Missing/unknown flags, cleanup failure or source drift
make the lane FAIL. Outer coordinator cleanup and volume absence must also pass.

Run `python3 -B -m unittest discover -s scripts/ci/full-root-failed-update -p 'test_*.py'`
after adoption. `verify_candidate.py` additionally runs the unchanged14 internal
runtime,5 empty-record and12 current-driver controls:32 lane +31 existing =63.
All signing/process/package actions in the new controls are mocks; native
hardware execution remains **NOT RUN**; the exact frozen native case above has separate acceptance.
