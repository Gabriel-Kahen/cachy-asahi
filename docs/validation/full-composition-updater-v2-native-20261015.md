# Complete development composition with updater v2, native ARM — 2026-10-15

[Run 38784336897](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38784336897) passed the disposable **v1→v2→v1** updater exercise in the full ten-package development composition. The retained container and coordinator records report `status=PASS`, `phase=completed`; the nested updater result reports a signed upgrade, all seven installed Check/refusal cases, normal inert-fixture removal and a signed v1 rollback. Scoped cleanup reports PASS with no failures.

This establishes actual generic ARM software behavior for updater4.4.2-2 alongside the other nine selected project packages. It does not establish an `arch-update` upgrade commit, an Asahi target transaction, setup4, platform recovery, physical hardware or release acceptance.

## Tested source and package identities

| Selection | Exact identity |
| --- | --- |
| Workflow Source | `474284e6a47a57379e1bf064148a89736fa0b92d` |
| Adopted composition code/provider checkout | `1bf2f739dc14293456e93d06d08020befd8f4d3b` |
| Original ten recipes/product | `a58fca33c4db5f2ab3ea6111f4d7842a932cc336` |
| Original updater implementation | `1aea667aec50a62ba0ab2dad44be24a4dc3bd098` |
| New updater implementation | `480053c0866a922138d85af2b9880fb0e10d7b2c` |
| Runtime-base builder | `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2` |
| v2 PKGBUILD SHA256 | `251009c63e3a9c2e62cd899b077c70f0f6a418ba38beac00a0323e3bf60dafa0` |
| v2 materializer/runner-input lock SHA256 | `601283adb9deeca949a857ee136896e8d1559ab4ecf6fed3928531059965c6f9` |
| Both fresh v2 package SHA256 | `88e6ebad51700499bc2f0c608409e06983b0146ebf555101b526c7a32d5ba4f6` |
| Retained original v1 package SHA256 | `5902153ed1a7798ca533ad1e8cdab124c6355549797048982193fbe4cabfa968` |

The workflow revision differs from the adopted composition revision only in `.github/workflows/native-arm-build.yml`. Retained checkout logs identify the exact composition and v2 source revisions; the actual caller command includes `--updater-v2-source` and retains the original product/updater/desktop selections. The workflow's initial bootstrap checkout remains the separately pinned original builder source, rather than being mistaken for the composition code checkout.

Both fresh v2 workers report finalized `PASS-private-native-package-static-checks`, worker exit zero, no worker failure, completed removal and verified container absence. Both package reports identify aarch64 `cachy-asahi-update 4.4.2-2`, GPL-3.0-or-later/MIT, exact package bytes above and zero static errors. Comparison reports equal bytes, installed contents and package metadata with zero errors. The same-job compiler image is `sha256:af8edbf03dffba99a662b525c7ade4f107ec41bf77b96f89a35a277ff31ab94b`; its exact354 inventory SHA256 is `5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee`. This is a fresh pair in this job, on one native builder/daemon; no independent-machine reproduction is claimed.

The runtime-base report records native aarch64 host/daemon,574 packages, no acquisition failures, build return code zero and `PASS_NATIVE_OFFLINE_574_TRANSACTION`. Its image is `sha256:0ad0ecf91dc5cd58037bd4844d200786ac80283bc549d93302d9842a0b645de4`. The initial14 incoming archives are the same ten original project selections and four missing signed upstream packages as the [earlier complete composition](full-composition-native-20261015.md). Exact xdg-utils was already present; upstream FDK is replaced by project FDK. The arithmetic remains **574 + four − upstream FDK + ten = 587**. Setup remains0.1.0-3 throughout this run.

## Actual inventory transitions

| Stage | Count and SHA256 |
| --- | --- |
| Original runtime base | 574 — `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac` |
| Initial v1 composition | 587 — `c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463` |
| Signed updater4.4.2-2 upgrade | 587 — `2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7` |
| Installed inert Check baseline | 588 — `5f19414df2f992fc6ed10701f587c0b5f545b5c620f7b065a05389541b36cf40` |
| Normal inert-fixture removal | 587 — exact v2 inventory above |
| Signed updater4.4.2-1 rollback | 587 — exact original v1 inventory above |

The v2 lock changes only `cachy-asahi-update 4.4.2-1` to4.4.2-2; all other587-lock entries remain equal. The588 hash is exactly the v2 lock plus `cachy-asahi-check-fixture 0.1.0-1`. These relationships were independently recalculated from the pinned source locks during this read-only review.

The initial required-signature14-package transaction passed exact inventory, `-Dk`, actual dependencies through `-T`, all-ten `-Qkk`, payload types/symlinks and owners, native pyalpm import/Handle construction and both installed project FDK library loads. It did not add a separate direct installed-file hash pass at that initial stage; `project_sha256` identifies the input archive hashes.

One ordinary local `pacman -U` then upgraded only the updater. The source requires equal dependency/provider/conflict metadata, exact v2 inventory, database consistency, dependencies and **all ten** installed payload maps. At v2 and again after v1 rollback, the reused payload helper directly checks regular-file SHA256, modes, root UID/GID, symlink types/targets and package ownership, alongside `-Qkk`. No dependency waiver or forced dependency removal was used.

After the Check cases, ordinary dependency-aware `pacman -R` removed the inert baseline and required exact587v2 plus absence of its payload. A required-signature `pacman -U` restored the retained original v1 archive, exact587v1, database/dependency consistency and all ten original payloads. The final state is the original **composed587** selection, not the pre-composition574 base. The enclosing disposable container was subsequently removed.

## Seven actual installed Check cases

The fixture runs installed `/usr/bin/arch-update --check` as unprivileged alarm with clean private HOME/XDG directories, actual checkupdates/fakeroot/pacman and a signed local `file://` repository. Its separate private TEST signer is distinct from the host composition signer; the user's verifier has public material only and cannot read the private signer. Package/database signatures remain required. AUR, Flatpak, notifications and ALHP checks are disabled; no network repository or service activation is used.

It normally installs only the inert0.1.0-1 data package, creating588 packages. Candidate0.1.1-1 is signed and advertised but **never installed**.

| Case | Exit | Enforced result |
| --- | ---: | --- |
| pending-versioned | 0 | Exact `cachy-asahi-check-fixture 0.1.0-1 -> 0.1.1-1` result, combined state, available icon and current timestamp |
| invalid-signature-preserves-pending | 20 | Prior state entries preserved by content, mode and mtime |
| missing-signature-preserves-pending | 20 | Same preservation with the required database signature absent |
| no-updates-clears-pending | 0 | Empty package result, cleared pending state, up-to-date icon and current timestamp |
| pending-no-version | 0 | Package-name-only pending state, available icon and timestamp |
| missing-signature-preserves-no-version | 20 | Prior NoVersion state preserved after failed sync |
| unconfigured-full-update | 21 | Actual installed full updater refuses its unconfigured Apple-policy preflight |

All seven passed. The final case selects the installed real run0 prerequisite through ordinary configuration, without policy/observation overrides. Source ordering and the observed policy refusal establish that the later privileged full-update path was not reached. No temporary-database allocation failure was induced in this run.

Across these cases the fixture requires exact588 inventory, unchanged pacman tree names/link targets/file hashes, unchanged inert payload and hashes of updater-owned regular files including the Apple-policy helper. It restores the original container pacman configuration, stops the public verifier agent and removes private fixture files; each reports PASS. The signature cases authenticate database-check behavior and preserve state. Check does not download/verify or install the advertised candidate archive, so these results do not establish a complete updater commit or target update recovery.

## Hook/scriptlet scope

The initial composition, v2 upgrade, inert removal and v1 rollback commands use the composition's required-signature configuration, explicitly pass `--noscriptlet`, and use masks populated from observed base/incoming hook names. The real-Check fixture temporarily uses **`/builder-disabled-hooks`**, the frozen574 builder mask directory, rather than that composition mask directory. Its handbuilt baseline install does **not** pass `--noscriptlet`; the inert archive consists only of `.PKGINFO` and one ordinary data file, with no hook or install scriptlet.

The earlier [read-only hook-scope inspection](../../artifacts/development/full-composition-updater-v2-20261015/HOOK-MASK-NOTE.md) directly checked the exact four addition archives and nine retained project member maps: none introduces a `.hook` or `.INSTALL`. Before temporary signing, exact composition Source1bf2 also requires the fresh v2 archive to pass Sourcea58's package checker with no errors and exact88e6 bytes; that checker rejects every `.hook`/`.INSTALL`. Reaching the actual Check stage enforces the same zero-hook condition for v2. This latter conclusion follows the executed source gate, not a new direct read of a retained v2 binary or full v2 member map.

Consequently, switching to the fixture's frozen builder masks misses no hook introduced by these selected incoming packages. The aggregate `hooks=MASKED`/`scriptlets=DISABLED` fields must be read with the separate fixture behavior above. This review does not independently prove completeness of every base-system mask, observe every hook execution, or provide target hook/service acceptance.

## Retained evidence, cleanup and next increment

Root collected [logs.zip](../../artifacts/development/full-composition-updater-v2-run38784336897/logs.zip) once: **3,424,354 bytes**, SHA256 **`f5eb88ff08eb63463d230be2de76c0dc0cfcfa954d01b954aec222d429e76d51`**. This pass decoded the original `public` frame in `native/17_Retain bounded development composition metadata.txt` in memory, verified **181,749 compressed bytes**, SHA256 **`1b089c94c0624cc60e9d382ed4eb0c4b6bd8db9e28d40c090f3c7d7647f16c98`**, and inspected its **74 regular members**. No run was recollected or replayed.

The bundle contains matching coordinator/container results, original package identities, bounded build diagnostics, both sanitized updater build pairs and the complete524,204-byte composition transaction log. That log records three composition `-U` calls, inert `-R`, four `-Dk`, three dependency tests, three all-ten integrity checks and3,755 package-owner queries. Fixture subprocess success output and raw intermediate inventory/file snapshots are not separately retained. Detailed equality, payload and case credits follow the exact tested source's enforced gates and completed results, rather than an independently retained snapshot for each stage.

`diagnostics/updater-v2-summary.json` says `composition_upgrade=NOT RUN` because the host writes it during input preparation. The later terminal nested updater result and coordinator both establish actual upgrade/Check/rollback PASS; the preparation-time field is not the terminal outcome.

Container cleanup stops its private composition trust agent and removes its temporary workspace. The Check signer is stopped and removed separately. Coordinator cleanup checks the named composition container absent, removes and checks absent the selected owned builder images, stops scoped GPG homes and removes private trial files. The two updater builders produce the same image ID here; the source deduplicates that ID only after verified removal, while protecting the borrowed original core builder. Cleanup reports PASS and an empty failure list. No global cache, parent-layer or whole-daemon erasure is claimed; binaries and private signing material are not retained in the public frame.

This actual result requires no updater-composition correction. It supplies the combined v2 software evidence needed to consider explicitly selecting4.4.2-2 in the next setup4 proposal. It does not itself execute or approve that later composition. The setup4 patch remains separate under `artifacts/development/full-composition-setup4-20261015/`; measurement integration remains a proposal pending the accepted Tools adapter.

Independent source/evidence review found no remaining blocker to this bounded result. No build, test suite, package transaction, Check command or runtime helper was rerun for this document. Only this uniquely assigned validation document was changed canonically; shared manifests, defaults, publication and dispatch remain coordinator-owned.

An actual `arch-update` upgrade commit, setup4/enrollment, the selected Asahi platform transaction, source/configuration migration, live hooks/services/application sessions, target or boot recovery, physical16KiB execution, either M2 Air size, maintained signed publication and measured performance remain **NOT RUN** here. Publication remains **NOT ACCEPTED**, release selection remains false, and [full R1–R5/M5–M9 completion](../roadmap.md) remains open.
