# Complete development composition lifecycle, native ARM — 2026-10-15

[Run 38780072830](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38780072830) passed the complete disposable **v1** package/configuration lifecycle. The retained container and coordinator records both report `status=PASS`, `phase=completed`; the nested lifecycle reports PASS, 21 named setup/preservation checks and final restoration of the original **574-package** inventory. Scoped cleanup reports PASS with an empty failure list.

This supplies actual generic ARM install, controlled upgrade, removal, reinstall and setup-recovery evidence for the frozen ten-package composition. It does not establish an Asahi target transaction, updater v2, a real upstream migration, power-loss recovery or physical hardware behavior.

## Tested source and version set

| Selection | Exact identity |
| --- | --- |
| Workflow/control Source | `1ec1705fa32b96b30133883d9e546120c53f6522` |
| Adopted lifecycle code | `1bb2178d352b5b96c00fc8948188e187a5ca4350` |
| Original ten recipes/product | `a58fca33c4db5f2ab3ea6111f4d7842a932cc336` |
| Updater build implementation | `1aea667aec50a62ba0ab2dad44be24a4dc3bd098` |
| Runtime-base builder | `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2` |
| Original 574-package inventory SHA256 | `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac` |
| Installed/reinstalled v1 587-package inventory SHA256 | `c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463` |

The workflow and adopted lifecycle revisions differ only in `.github/workflows/native-arm-build.yml`. The checkout log identifies the full control Source above, and the actual composition command includes `--lifecycle`. The runner retains its three original product/updater/desktop source selections. This run still uses **cachy-asahi-update 4.4.2-1**, archive SHA256 `5902153ed1a7798ca533ad1e8cdab124c6355549797048982193fbe4cabfa968`. Canonical adoption and separate Check evidence for 4.4.2-2 do not change this historical selection.

The original ten package versions and archive hashes match the earlier [complete composition result](full-composition-native-20261015.md). The runtime-base report records native aarch64 host/daemon, 574 packages, zero acquisition failures, build return code zero and `PASS_NATIVE_OFFLINE_574_TRANSACTION`. Initial installation adds the same four missing upstream packages—htmlq, pacman-contrib, archlinux-contrib and pyalpm—replaces upstream FDK and installs the ten originals. Exact xdg-utils was already present. The arithmetic remains **574 + four − upstream FDK + ten = 587**.

The job also built four explicit **DEVELOPMENT ONLY** upgrades using the existing core fixture generator and native 341-package builder. The fixture summary identifies generator SHA256 `c1a634b0d0c8d900d8809241c55ab12c09a03c3eb07ba20a6fc545cb2472252a` and original-four recipe lock SHA256 `a5fb287b4dda2a90bf61d4fa8cbbc5d666dad8bb450a70544d00545b091f36e3`.

| Controlled upgrade | Version | Actual archive SHA256 |
| --- | --- | --- |
| cachy-asahi-fish-config | 0.1.1-1 | `92ac4adcc457ba24b1bbe37c178a7406f64f99fa72ed6cfcc71bb17748235a1f` |
| cachy-asahi-hyprland-settings | 0.1.1-1 | `ac4e4c1e0d2ed7a9d88c14f9bbf6ae5ab6f28abbb78d3f8ee0612d30f3c7852e` |
| cachy-asahi-setup | 0.1.1-1 | `0003afc3de75ad9290e6ae0ae8910bbc3c608813d799e0f96ebb8d0d0ea3ce44` |
| cachy-asahi-zsh-config | 0.1.1-1 | `f4ccde7ac10c9baaa0a2539c79ec28000300ba4c25aa424e59b9d7e726de0002` |

These fixtures change controlled template comments and setup-helper identity, retaining dependency/provider policy and license attribution. The fixture result explicitly keeps `selected_for_release=false` and source migration **NOT RUN**. They exercise changed installed configuration/helper bytes and package versions; they are not real upstream migrations or a maintained subsequent release. Each fixture was built once here, rather than receiving a new reproducibility pair.

## Actual lifecycle stages

The same network-disabled disposable native ARM container ran the stages below. Required signatures applied to package installation; original and upgrade project archives shared the temporary composition TEST signer. Upstream archives retained their official signatures. Scriptlets remained **DISABLED**, and observed installed/incoming hooks remained **MASKED**. No dependency waiver or forced dependency removal was used.

| Stage | Retained result and enforced checks |
| --- | --- |
| Initial signed installation | All 14 original incoming archives installed; exact v1 587 inventory, database/dependency checks, project ownership, native pyalpm import/Handle and both installed FDK library loads passed |
| Initial lifecycle payload verification | All ten projects checked by `-Qkk` and direct file SHA256/mode/root UID/GID/package-owner checks; symlink types and targets checked |
| Fresh/existing setup | Fresh preview left file snapshots unchanged; repeated activation was idempotent in both homes; existing Fish/Zsh prefixes and modes were preserved |
| Controlled signed upgrade | The four original packages upgraded to 0.1.1-1; count remained 587, with exact derived inventory and other versions held; `-Dk`, dependencies and all ten project payloads passed |
| Configuration refresh/preservation | Fresh unmodified desktop copy refreshed to the changed template, with a changed hash; the existing edited desktop copy was preserved |
| First removal/restoration | Nine project packages removed normally; the original signed upstream FDK replaced project FDK; four runtime additions removed normally; exact 574 inventory and upstream library identities restored |
| Original-v1 reinstall | All 14 original archives reinstalled, restoring exact v1 587 inventory, dependencies and all ten original payload maps |
| Setup deactivation | Fresh managed files removed; existing shell blocks removed surgically while surrounding edits and modes survived; the edited desktop file remained |
| Injected activation/removal recovery | Both installed-helper faults retained a journal, had a read-only recovery preview, completed recovery and reached the expected presence/absence of all three component targets |
| Final removal/restoration | The same dependency-aware project/FDK/addition removal sequence restored exact 574 inventory again; user-file snapshots and both original upstream FDK identities matched |

User fixtures were two private homes under the container's temporary work directory, with setup commands demoted to UID/GID 65534. No user accounts or login shells were changed. Existing-home fixtures contained Fish/Zsh configuration and a separate base Hyprland configuration. The test added shell prefixes/suffixes and a desktop edit, then compared preservation through the actual package and setup operations. The base session configuration remained unchanged.

The preservation snapshots compare regular-file hashes, modes and UID/GID. They do not establish preservation of a real user's complete home, directory metadata, timestamps, extended attributes or all possible edits inside managed blocks. No login shell, PTY, graphical session or live user service was exercised by this composed lifecycle.

Both interruption cases reuse the existing fault wrapper around the **actual installed** setup helper: it completes a Fish configuration atomic write, then calls `os._exit(75)`. The runner requires exit 75, a retained mode-0600 journal, unchanged snapshots during recovery preview, successful `recover --apply`, journal disappearance and final component-state checks. This is actual deterministic process-exit recovery in the disposable environment. It does not simulate power loss, filesystem failure, pacman interruption, reboot or boot/session recovery.

## Upstream FDK and final state

The runner captured both upstream identities before the first project installation and required equality after **each** restoration. The retained lifecycle result records:

| Upstream SONAME | Restored owner and resolved file | SHA256 |
| --- | --- | --- |
| libfdk-aac.so.2 | libfdk-aac, `/usr/lib/libfdk-aac.so.2.0.4` | `aea9c8eadd91840d3e1670f1e246a2390b95bba4762a533de0591963a49b869d` |
| libfdk-xhe-aac.so.0 | libfdk-aac, `/usr/lib/libfdk-xhe-aac.so.0.0.0` | `c39c21d060f81f4ebf413b0aa994039e54c166f807c54676692fc118c63f464c` |

All original/new project non-directory payload paths had to be absent after restoration, except shared FDK paths explicitly listed by the restored upstream archive and owned by `libfdk-aac`. This does not independently hash every upstream package file. The two resolved FDK library hashes above are compared directly. Codec callbacks and upstream/candidate codec behavior remain separate [provider/PipeWire evidence](fdk-provider-native-20261015.md).

The result's `package_count=587` and `installed_inventory_sha256=c309aa…` describe the **initial installed composition**. Its separate `final_package_count=574` and `final_inventory_sha256=cfd4c7…` describe the **restored final state**, with all project packages absent. The lifecycle summary repeats the final count/hash. It does not leave a composed installed image for later use.

## Retained evidence and cleanup

Root collected [logs.zip](../../artifacts/development/full-composition-lifecycle-run38780072830/logs.zip) once; ZIP SHA256 is `65d3e71e761c3130a06cbc82d33c29d82d8b36c792b430fdb6211a6808f183b4`. This documentation pass decoded only the retained `public` frame in `native/16_Retain bounded development composition metadata.txt`, verified **138,394 compressed bytes** and SHA256 **`3b503ea7f657701b541ce9b9c1f6a97ff697712aaa283d7b4df749eea9b4e295`**, and inspected its **47 regular members** in memory.

The bundle contains the matching coordinator/container results, package identities, fixture summary, bounded build diagnostics and sanitized updater records, plus the complete **714,947-byte** transaction log. That log records the signed install/upgrade/reinstall and both removal/replacement sequences, five `-Dk` calls, three dependency-test calls, four project-integrity calls, 5,057 owner queries and setup command output. Successful pacman stdout and separate raw intermediate inventory/file snapshots are not retained; detailed equality/payload credits follow the exact tested runner's enforced gates and completed result. The reported project hashes match the earlier composition record; the four fixture hashes above match the retained fixture summary.

Container cleanup stopped its private trust agent and removed the temporary work directory, including fixture homes/journals. Coordinator cleanup checked the named composition container absent, removed and checked absent its two new builder images, stopped scoped GPG homes and removed private trial files. The borrowed original builder remained protected. The coordinator reports cleanup PASS and no failures. No global daemon/cache/parent-layer erasure is claimed. Updater records use the existing public projection; private updater output, package binaries and signing material are not retained in this public frame.

No logs were recollected, and no test suite, build, package transaction or runtime helper was rerun for this note. Shared manifests, defaults and status files remain Root-owned.

## Next composed software increment and limits

This successful actual result requires no lifecycle correction. It establishes the v1 caller/container and payload-check base used by the isolated updater-v2 proposal in `artifacts/development/full-composition-updater-v2-20261015/`. That proposal keeps the tested v1 path and adds a separate opt-in Source480053 upgrade/real-Check/rollback mode; it does not combine the two modes or claim the new one ran here. Its v2 587 lock changes only updater4.4.2-1 to4.4.2-2. The [separate v2 Check result](updater-real-check-native-20261015.md) remains the evidence for that newer recipe until a combined successor run is reviewed.

Actual composed updater-v2 execution, an `arch-update` commit, real source/configuration migration, live target hooks/services, application/session interaction, Bluetooth/daemon audio behavior, the selected Asahi platform transaction, physical 16 KiB execution, either M2 Air size, power-loss or boot recovery, maintained signed publication and measured performance remain **NOT RUN** here. Release selection remains **false**, publication **NOT ACCEPTED**, and [full R1–R5/M5–M9 completion](../roadmap.md) remains open.
