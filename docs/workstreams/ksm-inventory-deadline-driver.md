# KSM inventory caller deadline driver

This source-only correction implements the coordinator's selected 180-second inventory caller cap, clipped to the existing `producer_end`. It is held for registration and peer review. It has not been exercised by a native ARM job, Docker, GPG, package installation, a namespace actor, or M2 hardware.

The retained KSM5 run `38303811300` failed. Its inventory request returned successfully after 67.529 seconds, followed by `BrokenPipeError` while replying to the caller. The original private producer log and caller exception were not exported; an actual `TimeoutExpired` remains unobserved. The recorded evidence and causal model are sealed separately in [the actual-run review](../reviews/native-ksm-execution-38303811300.md) and [the bounded proposal](ksm-inventory-deadline-proposal.md). This driver does not revise those receipts or the held caller-diagnostic baseline `7edea844d5b52fd6cf29a98c71ea1e3cc99e2e23de62288ec5cdc48f793bb3a8`.

## Wiring and timer

`executor.pipeline` passes its already computed `producer_end` to `consumer.producer_command`. The existing producer allowance of 6600 seconds, later-phase reserve of 1650 seconds, aggregate budget of 8460 seconds, phase scope, service callback, cleanup, and admission checks remain in place. No new phase clock or reserve is introduced.

The concrete command preserves the original build arguments and appends the driver's three arguments after one delimiter:

```text
/usr/bin/python3 -I -B -S <private-source>/scripts/port/ksm-native-job/producer_driver.py \
  build <all-original-native-build-arguments> -- \
  --producer-end <existing-monotonic-cutoff> \
  --producer-output <private>/producer --inventory-seconds 180
```

The sealed proposal showed a prefix interface. The implemented trailer keeps the original build argument positions, including the existing orchestration fixtures. Without a `producer_end`, the pure command helper retains its previous result; the production pipeline always supplies the cutoff.

Only this exact original call is adapted: a list containing `docker run --rm --pull=never --network=none --cap-drop=ALL --security-opt=no-new-privileges --read-only --entrypoint=/bin/cat <immutable-image-id> /builder-packages.lock`, with `log is None` and integer timeout 60. The image argument must equal the bounded private `producer/image-id` contents. Its effective caller timeout is `min(180, producer_end - monotonic())`, and a nonpositive remainder refuses before forwarding. Source and image custody are checked again after return under the same cutoff; an expired result cannot become success. Other calls keep their original command, log and timeout arguments. The original `native.main` and `native.run` perform the build and subprocess work; the driver does not replace global subprocess functions.

## Source, imports and private output

The complete project import graph is two source files, captured and authenticated before project compilation:

| Source | SHA-256 | Mode |
| --- | --- | --- |
| `scripts/ci/native_arm.py` | `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` | `0644` |
| `scripts/checks/package_checks.py` | `e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8` | `0644` |

The source capture requires regular, single-link, current-user files; no-follow traversal of the complete directory chain; bounded reads; exact bytes and modes; and stable file/directory identities. Guards remain active through loading, imports, native calls and exit. `wrap_run` requires the actual live graph grant, guard, cutoff and original `native.run` identity. A filename, module label or SHA argument alone cannot grant execution.

The production parent already authenticates the complete selected packet and constructs the private source copy. That copy excludes `packet.lock.json`, so the driver authenticates the two-file graph directly rather than requiring an absent map. Registration of the driver itself remains the coordinator's responsibility. The original 159-source repository baseline receives no new grant and is not edited.

The startup premise is trusted Python and system standard-library initialization under `-I -B -S`; this is not authentication of the host Python installation. During graph execution, caller standard-library cache entries, paths, finders, hooks, importer caches and import/compile/exec callables are quarantined. The fixed loader hook uses source bytes for Python modules and the initialized extension loader, with no sourceless loader. The initialized builtin `_signal` reference is retained: reinitializing that C module can change signal-handler bookkeeping even after restoring the Python module cache. The sole project import is the original `package_checks.recipe` import from the captured native module. Caller import state and `native.run` are restored on success and failure.

The output is bound to the original `--output` argument and must initially be absent, outside the source tree, below a stable current-user `0700` private parent. The original native producer creates it. Its directory must remain owned and non-writable by group/others. `image-id` must remain a regular, single-link current-user file, bounded to 128 bytes, mode `0600` or `0644`, with stable bytes and identity. These checks bind the adapted call to the private immutable image rather than an arbitrary command label.

## Evidence and registration boundary

The initial author hold captures 30 passing driver test methods from both primary and fresh copied sources, with zero skips. Controls cover exact matching and nonmatching calls, clipping and expiry, forged graph grants, source/output/image custody, import-state poisoning and restoration, and the trailer wiring. The parent combined run exposed the `_signal` reinitialization leak; its failed 322-method run and preceding author hold are retained as historical evidence. An isolated unchanged-runtime control passed all 74 methods. The corrected author hold adds the signal-state regression and is the controlling source hold.

Three scaled trials use the actual authenticated driver wrapper, original `native.run`, Python shim and broker handler: old 60 seconds reproduces a model `TimeoutExpired` and reply `BrokenPipeError`; selected 180 seconds returns; a short producer cutoff refuses a late result. The scale is 1/20. The dummy payload has the observed 6674-byte length; it is not the actual inventory or its hash. Docker operations use a fake backend, so these trials do not establish native compatibility or complete production broker admission.

The corrected hold has 31 passing driver methods from both primary and fresh copied sources, with zero skips. The parent's complete fresh prospective suite passes all 323 methods in 21.612 seconds, with zero skips. Thirteen additional pure command-wiring controls pass. The initial combined failure and its too-narrow harmless-actor whitelist are retained; the final harness admits only Python fixtures, temporary Git fixtures, and sealed benign `true`/`yes` ELF fixtures. Nested Python startup fixtures have explicit actor tripwires.

The parent validates the held wiring using a fresh copied prospective packet. This private proposal adds only the driver and its test to the 152 selected source paths, yielding 154. It rebinds the two wiring rows and a copied `required_paths.py`; the live shared map, RequiredPaths and workflow remain coordinator-owned. The guide is outside that proposed selected set unless the coordinator selects it separately. The unchanged workflow takes an explicit dispatch `packet_sha256`; it does not adopt this proposal. The coordinator must register the selected rows and dispatch the chosen pin before a native job.

The controlling author receipt, fresh integration log, prospective row proposal, preservation checks and final hold are under `artifacts/reviews/ksm-inventory-deadline-driver-20261012/`. Registration, independent peer review and a new native run are still required before native admission.
