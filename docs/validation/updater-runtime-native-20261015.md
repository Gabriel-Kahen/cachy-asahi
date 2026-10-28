# Updater native runtime validation, 2026-10-15

[Run 38768816017](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38768816017) completed successfully. The retained public frames report a fresh native build pair, a complete signed disposable runtime installation, native pyalpm import, real installed tray/private-D-Bus behavior and owned cleanup **PASS**. The tray's Check action reached a private recorder; the real updater check and all system update operations were **NOT RUN**.

## Exact inputs and retained evidence

| Item | Observed value |
| --- | --- |
| Workflow/runner Source | `51567df9b302bd827014f6d214407ae7ec9c50ad` |
| Fixed product Source | `1aea667aec50a62ba0ab2dad44be24a4dc3bd098` |
| Updater | `cachy-asahi-update 4.4.2-1`, aarch64 |
| Both fresh package SHA256 | `5902153ed1a7798ca533ad1e8cdab124c6355549797048982193fbe4cabfa968` |
| Both compiled tray SHA256 | `04f52d9c37eb71718613fc21703aa761887bdf6754205da7bfe17bd68d943857` |
| Same-job compiler image | `sha256:7d0052534c8dc1637fa74528ef4655302b078b57b3d0ef90bb58fd432ce58bcd` |
| Exact354 compiler inventory SHA256 | `5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee` |
| Exact360 installed inventory SHA256 | `0710e19a2eee96baef53529f91ae2c6f02688f95a52d5b00c0d2e5bae1ff34b0` |
| Five-addition archive/signature lock SHA256 | `9a8064cde23ad90c2352395bdd1f6f5a8e843b3db3468cd2cc5a90829dc32704` |

Root collected the logs once at [`artifacts/development/updater-runtime-run38768816017/logs.zip`](../../artifacts/development/updater-runtime-run38768816017/logs.zip), SHA256 `61ce318178d4e4c64bf0e4663ffef1143baad35de48da1986426639dadf39bf4`. This note reads that retained ZIP; it did not download the run again. Both checkout logs show the full commits above. The final cleanup/evidence step contains two base64 gzip-tar public frames whose decoded byte counts and SHA256 were verified locally:

| Public frame | Compressed bytes | SHA256 |
| --- | ---: | --- |
| `build` | 54,409 | `353e369c94c605846e2cb977b5404ce96cd7edc2e123de432c2a1e047f1313f4` |
| `runtime` | 1,220 | `2dbfe8c4dc4ba11e9f2d3cca7e367761143226674bdb9127eaad330822def669` |

The public records are projected metadata, not retained private binaries or raw transaction logs. The digests and results below come from those records plus inspection of the exact runner Source. No native package or tray binary was retained for local re-execution.

## Native pair and complete runtime installation

The job used the tested product's unchanged materialize/freeze/native-build CLI and the exact354 compiler gate. Both clean workers report `PASS-private-native-package-static-checks`, exit zero, no worker failure code, completed worker removal and verified absence. Both package inspections report `artifact-static-pass` with zero errors. The comparison reports equal package bytes, installed contents and package metadata, with zero errors. The compiler image is fresh for this job; two builds on one image/daemon do not establish independence across machines.

The freshly compiled private package was consumed in the same job before cleanup. In a separate writable, network-disabled disposable container, the initial inventory had to equal the exact354 compiler inventory. The fixture was compiled there before changing that package set. One ordinary `pacman -U` installed the updater and the five pinned official additions:

| Addition | Version | Reason |
| --- | --- | --- |
| htmlq | 0.4.0-3 | Direct updater dependency |
| pacman-contrib | 1.13.1-1 | Direct updater dependency |
| archlinux-contrib | 20261009-1 | Direct updater dependency |
| xdg-utils | 1.2.1-2 | Direct updater dependency |
| pyalpm | 0.12.0-1 | archlinux-contrib dependency |

Archive and signature hashes were checked against the fixed lock, and the existing official signer was authenticated before installation. Pacman required signatures for every local package; no `--nodeps`, assumed dependency, fake provider or overwrite waiver was used. The upstream packages retained their official signatures. The compiled development updater was signed inside this container with a new disposable TEST key, fingerprint `9CF35A730DD79A394C824DE2566307E254C575EE`; this was not a release key or published repository trust decision.

`installation=PASS-disposable-container` follows successful installation, exact360 inventory equality and verification that all354 original package versions remained unchanged. `dependencies=PASS-no-waivers` follows `pacman -Dk` and `pacman -T` for all18 dependency relations read from the actual freshly built package. `pyalpm=PASS-native-import` follows an actual isolated Python import and construction of a pyalpm Handle against the installed database. This establishes the complete runtime transaction for this disposable base, separately from the compile-only worker's makepkg dependency waiver.

The exact runner used a private transaction keyring and disabled builder hooks. No systemd user manager, real desktop session or Asahi platform transaction was started. It did not test installation with target hooks/services enabled or package removal/reinstall.

## Installed tray and Check boundary

The real installed `/usr/lib/arch-update/arch-update-tray` ran as unprivileged alarm, with package ownership/version checks, a fresh private HOME/XDG tree and a private `dbus-run-session`. The native GIO fixture provided a StatusNotifierWatcher and interacted with the tray over that bus. The runtime record reports:

| Actual installed behavior | Result |
| --- | --- |
| StatusNotifierItem registration | PASS |
| SNI identity, category, status, icon and tooltip properties | PASS |
| Actual D-Bus menu retrieval and required action entries | PASS |
| Actual Check menu activation to exact private recorder | PASS |
| Actual Exit menu activation and tray exit zero | PASS |

The update list was synthetic private state containing one fixture package. The fixture checked the tray's properties, requested the real menu, activated Check, observed exactly `--check` at its private `arch-update` recorder, then activated Exit and required the real tray process to exit zero. The recorded `tray_process_exit=0` and `tray_session=PASS-installed-tray-private-DBus` establish native binary loading and this real protocol interaction.

The recorder deliberately replaced the updater command in the tray's private PATH. **The installed `arch-update --check` implementation was not invoked**, no repository update check occurred and no system upgrade was attempted. The result explicitly records `check_action="private recorder only; updater not invoked"`, `real_update_check=NOT RUN`, `target_update=NOT RUN` and `rendering=NOT RUN`. There was no compositor, visual panel/tooltip rendering, notification service or user timer test. Static16K ELF segment checks passed during the build, but execution on a 16K-page kernel was not tested.

## Cleanup and remaining limits

The inside result records `test_signing_state_removed=true`. The coordinator records cleanup PASS, empty failures and `private_data_removed=true` for its owned runtime container, builder image, build GPG home and private trial data. Both compile-worker status records separately report completed container cleanup and verified absence. The always step retried scoped cleanup and emitted only the bounded public records. Whole-daemon disposal remains **NOT ATTESTED**.

This result advances generic native ARM runtime installation and installed tray protocol behavior. It does not validate the full selected development composition, target installation/removal, a real updater check, signed repository upgrade, interruption/rollback, activation of user services, real notifications/rendering, corresponding-source/license publication closure, 16K-page execution, Apple platform policy or boot/recovery. Hardware remains **NOT RUN**, publication **NOT ACCEPTED**, and release selection false. See the earlier [native build/adoption note](updater-current-native-20261015.md) for exact product integration history; this run additionally tests the fixed product in the runtime described here.

