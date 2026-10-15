# Updater actual Check validation, 2026-10-15

[Run 38776212071](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38776212071) completed successfully for exact Source `480053c0866a922138d85af2b9880fb0e10d7b2c`. It built and installed **cachy-asahi-update 4.4.2-2**, then exercised the actual installed Check command against a signed local repository. All seven recorded cases and scoped cleanup passed. No advertised candidate upgrade or target system update was performed.

## Identity and retained evidence

| Item | Observed value |
| --- | --- |
| Control and product checkout Source | `480053c0866a922138d85af2b9880fb0e10d7b2c` |
| Package | `cachy-asahi-update 4.4.2-2`, aarch64 |
| Both fresh package SHA256 | `88e6ebad51700499bc2f0c608409e06983b0146ebf555101b526c7a32d5ba4f6` |
| PKGBUILD SHA256 | `251009c63e3a9c2e62cd899b077c70f0f6a418ba38beac00a0323e3bf60dafa0` |
| Same-job compiler image | `sha256:3d0f86f316d2e82baa4b556de17e83b59ddd8628aa988e482050e2e5d6cf5753` |
| Exact354 compiler inventory SHA256 | `5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee` |
| Exact360 runtime inventory SHA256 | `1b8e0653fd0063d09f5818d86cb3b77fdc7f667f2aa78c2eca4a29c6209ae5ad` |
| Exact361 fixture inventory SHA256 | `f5da642972908cf9d7510ae4dac4cae706db61de44af621a3e1d9e0c8b75f8b5` |

Both checkout logs show the full Source above. Root retained the logs once at [`artifacts/development/updater-real-check-run38776212071/logs.zip`](../../artifacts/development/updater-real-check-run38776212071/logs.zip), SHA256 `df927d463bced26dd813ed8f4e33c63546acf365ddedd297fc0ced2c21a146d5`. This note reads that ZIP without recollecting the run. The final evidence step contains these public gzip-tar frames; their decoded byte counts and SHA256 were verified locally:

| Frame | Compressed bytes | SHA256 |
| --- | ---: | --- |
| build | 54,448 | `9defd33cb920b1ed17775e76d7bae4d088a75ad24e4a722406f22b133fabb7ba` |
| runtime | 1,674 | `8a11150b93cc3109d2fb75b04b5ea22468a6ddb222ba06217cfc8475e7f8f7dd` |

These are sanitized result metadata, not retained private binaries or raw command logs. This inspection executed no new build, installation, Check case or hardware test.

## Build and actual installation

Both native workers report `PASS-private-native-package-static-checks`, exit zero, no worker failure code, completed removal and verified container absence. Package inspection reports `artifact-static-pass` with zero errors. The comparison reports equal package bytes, installed contents and package metadata with zero errors. These are two clean launches on one authenticated native image/daemon; no independent-machine reproduction is claimed.

The job kept the freshly built package private and consumed it before cleanup. In a separate network-disabled disposable container, one ordinary Required-signature transaction installed the updater and its five missing official runtime additions: htmlq 0.4.0-3, pacman-contrib 1.13.1-1, archlinux-contrib 20261009-1, xdg-utils 1.2.1-2 and pyalpm 0.12.0-1. All354 prior versions were preserved and the resulting inventory matched the exact360 lock. `pacman -Dk`, all18 actual package dependency relations through `pacman -T`, and native pyalpm import/Handle construction passed without dependency waivers. The compiled updater used disposable TEST signer `C195EFDADA3819C6F4E97F7D9F9FE80E5686D806`; this was not release signing or repository publication approval.

The fixture then used ordinary required-signature `pacman -U` to install only **cachy-asahi-check-fixture 0.1.0-1**, an inert package with one non-platform data file and no dependencies, hooks or scriptlets. That real baseline installation produced361 packages. Candidate0.1.1-1 was signed and advertised in the local repository but **never installed**. The subsequent Check and refusal tests preserved the installed baseline, full inventory, actual pacman tree names/link targets/file hashes and updater-owned regular payloads including the Apple policy helper.

## Actual installed Check cases

The fixture ran the installed `/usr/bin/arch-update --check` as unprivileged alarm with fresh private HOME/XDG directories. It used actual checkupdates, fakeroot and pacman, not a Check recorder or substituted library. The container's temporary pacman configuration selected only a TEST-signed `file://` repository and required both package and database signatures. Each updater invocation allocated a fresh private check database. AUR, Flatpak, notifications and ALHP checks were disabled; no `--enable`, user-service activation, news request or network repository was used.

| Actual case | Exit | Required observed result |
| --- | ---: | --- |
| pending-versioned | 0 | Exact line `cachy-asahi-check-fixture 0.1.0-1 -> 0.1.1-1`, combined state, available icon and current timestamp |
| invalid-signature-preserves-pending | 20 | Prior state entries preserved by content, mode and mtime checks |
| missing-signature-preserves-pending | 20 | Same preservation after missing required database signature |
| no-updates-clears-pending | 0 | Empty package result, cleared combined pending state, up-to-date icon and current timestamp |
| pending-no-version | 0 | Package-name-only result, combined state, available icon and timestamp |
| missing-signature-preserves-no-version | 20 | Prior NoVersion state preserved despite failed sync |
| unconfigured-full-update | 21 | Existing Apple-policy preflight refused the actual installed full updater |

Every row passed. The pending/no-update cases validate real repository metadata checking and state updates. The signature failures validate the4.4.2-2 error propagation/state-preservation fix, including the NoVersion branch. The temporary-database allocation-failure guard has focused local regression coverage, but allocation failure was not induced in this native run.

For the final row, the actual installed run0 prerequisite was selected through ordinary config, with no policy or observation overrides supplied. The installed updater returned21 at its unchanged Apple-policy preflight. Source ordering plus this refusal establishes that the later privilege command/update stages were not reached; no authorized or synthetic-policy full transaction was tested. The result explicitly records `real_update_transaction=NOT RUN`, `target_safety=NOT ESTABLISHED` and no protected platform changes.

The signed database authenticates the metadata used for checking. Check does not download/verify the advertised candidate archive or commit its upgrade. This trial therefore does not establish full-update transaction binding, rollback/recovery, Apple platform safety or live service restart behavior.

## Cleanup, integration and limits

The fixture records config restoration, public-verifier agent cleanup and private fixture-file removal PASS. It records unchanged actual inventory/database, inert baseline payload and updater/Apple-policy payloads. The enclosing runtime records `test_signing_state_removed=true`. Outer cleanup reports PASS, no failures and `private_data_removed=true` for the owned containers/image, build GPG home and private trial data. Both build workers independently report completed removal and verified absence. Whole-daemon disposal remains **NOT ATTESTED**.

This result is for the v2 package bytes above. The earlier [v1 runtime/tray note](updater-runtime-native-20261015.md) tested4.4.2-1/Source1aea and an installed private-D-Bus tray with Check routed to a recorder. This run supplies real Check coverage for4.4.2-2; it did not repeat the tray protocol/rendering test. Neither run proves a complete target installation/removal or the selected full development composition.

At report time canonical baseline `98a7fea506bda1e69abb0fa7c8a9b23cbcb6c3a8` still holds v1. The exact v2 product-only adoption delta is11 updater-package files. After those copies, all65 package files equal tested Source480053; all8 READY root dependencies already equal that Source, and package64/root8/materializer21 pins are coherent. The integration proposal is separate from adoption; this note does not claim those copies have been committed. No repeat build is implied merely by moving identical tested files.

The hardware stack was absent from this generic compiler-derived runtime and builder hooks were disabled. Real target hooks/services, package lifecycle, coordinated platform updates, protected-package transitions, boot/recovery,16K-page-kernel execution, corresponding-source/license publication closure and M2 hardware remain unverified. Hardware is **NOT RUN**, publication **NOT ACCEPTED**, and release selection false. Shared inventory/status edits remain with Root; only this unique validation document was changed canonically for this report.
