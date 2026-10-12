# CachyOS settings audit

Audited October 11, 2026. **Source-audited only: no package build, installation, ARM execution, M2 hardware test, or performance measurement.** Proposed manifest decision: defer the monolithic `cachyos-settings`; select **no system defaults** for M1. This directory deliberately has no PKGBUILD or executable installer. Read-only source retrieval occurred in `/tmp`; no source script, systemctl operation, sysctl write, udev reload, package installation, or package hook was executed.

## Exact inputs and evidence

- [CachyOS-PKGBUILDS revision](https://github.com/CachyOS/CachyOS-PKGBUILDS/tree/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-settings): `c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`.
- [Recipe](https://raw.githubusercontent.com/CachyOS/CachyOS-PKGBUILDS/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-settings/PKGBUILD): `1:1.4.1-1`, `arch=('any')`, signed Git tag source, expected makepkg source checksum `977bb6eb2ed5b56517cdb7cd1a911c3576a7d67d6d48313f9b0997f217ee2427`. This Git-source checksum is not the archive checksum below; makepkg verification was not run.
- [Settings revision](https://github.com/CachyOS/CachyOS-Settings/tree/764693fe2863bc2b00db6ad6f4c1d57cded739f2): `764693fe2863bc2b00db6ad6f4c1d57cded739f2`, resolved from tag `1.4.1`, annotated tag object `aee04010110418486ec9ddce7f7e938972b5a45f`. GitHub's API reported tag verification `verified=true`, `reason=valid`; no local keyring/trusted-key verification was performed. Recipe permits signer fingerprints `E8B9AA39F054E30E8290D492C3C4820857F654FE`, `B1B70BB1CD56047DEF31DE2EB62C3D10C54D5DA9`, and `2B033E756C46663D2689ED83C335EA290EE4C75B`.
- [Downloaded full-commit archive](https://codeload.github.com/CachyOS/CachyOS-Settings/tar.gz/764693fe2863bc2b00db6ad6f4c1d57cded739f2): SHA256 `d2f369663ff71b9f23149da84de2933c324e6b2d9ad8aa59aee8c563388b8b5d`.
- `upstream-inventory.json` records the recipe and install-hook hashes plus all 49 installed files, modes, lengths, and content SHA256 values. The package copies `etc/` and `usr/` recursively; there are no compiled files in this source tree. Architecture-neutral text does not establish ARM compatibility.

Actual retrieval: `curl -L --fail -s` against the GitHub commit/ref/tag APIs, raw pinned recipe/hook URLs, and the codeload full-commit archive; `tar -xzf` into `/tmp/cachy-settings-audit`; Python/pathlib text and mode inventory; `sha256sum` of the archive. Every installed file was read. Primary upstream pages were also browsed; the moving master README was not used as the pinned payload specification.

## Licensing and attribution

The [pinned source license](https://github.com/CachyOS/CachyOS-Settings/blob/764693fe2863bc2b00db6ad6f4c1d57cded739f2/LICENSE.md) is the GPL **version 3** text. The recipe declares `GPL-1.0-only`, a material mismatch. The tree does not resolve whether unannotated project files are GPL-3.0-only or GPL-3.0-or-later. Clarify the grant and correct package metadata before redistribution; do not adopt GPL-1.0-only from the recipe. Its `cp` packaging excludes root `LICENSE.md` and supplies no explicit license-install command.

Four installed files explicitly identify **ISC** provenance: `usr/lib/iw-set-regdomain`, `usr/lib/udev/rules.d/85-iw-regulatory.rules`, and the regulatory `.service`/`.path` units. The script embeds the ISC permission text and credits Thomas Duckworth (2025), Red Hat (2009–2014), and Velocity Limitless (2025); the units credit Duckworth. Preserve these individual notices and install an ISC notice if extracting the components. The script points to [iw-setregdomain upstream](https://gitlab.com/VelocityLimitless/Projects/iw-setregdomain); its vendored bytes are pinned by the settings commit, but the original upstream revision is not recorded in this tree.

No other per-file license/copyright declarations were found in the installed tree. The CachyOS SVG has no separate attribution/license metadata; establish the artwork's grant and acceptable branding before copying. No transitive downloaded assets are fetched by `prepare()`/`package()`. Runtime dependencies are separate packages, not bundled code, and require their own notices if redistributed. `dlss-swapper` requests an NVIDIA NGX updater at application runtime; that downstream binary delivery/license is not audited and the tool is rejected for this target. No NVIDIA files were downloaded.

The required `cachyos-ananicy-rules` is another unaudited payload for selection purposes. At the same packaging revision its recipe is `1:1.1.49-1`, declares GPL-3.0-or-later, and copies a Git tag's contents into `/etc/ananicy.d`; recipe metadata does not prove that every rule's provenance/license is complete. No dependency recipe or rule tree is imported here. Missing licensing work remains explicit rather than silently treating this dependency as complete.

## Dependency availability and packaging behavior

Declared build dependencies: `coreutils`, `git` (plus normal makepkg build-environment tools). Declared runtime dependencies: `zram-generator`, `ananicy-cpp`, `cachyos-ananicy-rules`, `inxi`, `systemd>=256`, `iw`, `wireless-regdb`; optional `libluv`, `lua-luv`, `power-profiles-daemon`. `provides=('ntsync-common')` is a package-level alias, not evidence that the target kernel contains the module.

Primary [Arch Linux ARM package catalog](https://archlinuxarm.org/packages) observations on the audit date:

| Dependency | aarch64 catalog result | License metadata / remaining gate |
| --- | --- | --- |
| [systemd](https://archlinuxarm.org/packages/aarch64/systemd) | 262-1, core | LGPL-2.1-or-later, CC0-1.0, GPL-2.0-or-later, MIT-0; selected Asahi snapshot still unknown |
| [zram-generator](https://archlinuxarm.org/packages/aarch64/zram-generator) | 1.2.1-1, extra | MIT; existing target generator/configuration unknown |
| [ananicy-cpp](https://archlinuxarm.org/packages/aarch64/ananicy-cpp) | 1.2.0-1, extra | GPL-3.0-or-later; behavior and rules on selected base not tested |
| [inxi](https://archlinuxarm.org/packages/aarch64/inxi) | 3.3.41.1-1 | GPL-3.0-or-later |
| [iw](https://archlinuxarm.org/packages/aarch64/iw) | 6.17-1 | Catalog says GPL; exact upstream grant not re-audited |
| [wireless-regdb](https://archlinuxarm.org/packages/aarch64/wireless-regdb) | 2026.09.03-1 | LicenseRef-custom; exact notices not re-audited |
| [cachyos-ananicy-rules](https://archlinuxarm.org/packages/aarch64/cachyos-ananicy-rules) | Catalog URL returned HTTP 404 | No availability claim; requires selected-repository database resolution or separately audited recipe |
| [libluv](https://archlinuxarm.org/packages/aarch64/libluv), [lua-luv](https://archlinuxarm.org/packages/aarch64/lua-luv) | Both 1.52.1-1 | Apache-2.0 catalog metadata; actual Lua ABI relationship must be resolved for topmem |
| [power-profiles-daemon](https://archlinuxarm.org/packages/aarch64/power-profiles-daemon) | 0.30-1 | GPL-3.0-only; service/platform integration untested |
| [coreutils](https://archlinuxarm.org/packages/aarch64/coreutils), [git](https://archlinuxarm.org/packages/aarch64/git) | 9.12-2 and 2.56.0-1 | GPL-3.0-or-later/GFDL-1.3-or-later and GPL-2.0-only |

These catalog observations establish published aarch64 entries, not a pinned dependency solution, installation state, clean build, 16K-page compatibility, or M2 support. A page-level 404 is not a proof of absence from every possible overlay repository.

Additional command/config consumers not declared directly by the recipe include `bash`, `sh`, `grep`, `sed`, `awk`, `procps-ng` (`pgrep`, `ps`), `gzip` (`zgrep`), `curl` (paste upload), `hdparm` (udev rule), `pciutils` (`setpci`), `sbctl`, Lua interpreter plus `luv`, NetworkManager, `tzdata` (`zone.tab`), PAM (`limits.d`), rtkit, GDM/GLib schema handling, Xorg/libinput, and Mesa/GLVND for Zink. Several normally belong to a base installation; that does not justify omitting dependency review when extracting a tool. Catalog entries for hdparm 9.65-3, pciutils 3.15.0-1, sbctl 0.18-2, curl 8.22.0-1, lua 5.5.1-1, rtkit 0.14-1, tzdata 2026e-1, xorg-server 21.1.25-1, xf86-input-libinput 1.5.0-1, glib2 2.90.1-1, and gdm 51.0-1 were retrieved; no architecture suitability follows for the PC tools.

The [install hook](https://raw.githubusercontent.com/CachyOS/CachyOS-PKGBUILDS/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-settings/cachyos-settings.install) enables `ananicy-cpp`, `systemd-resolved`, and `systemd-oomd`, plus the regulatory-domain path when `iw` exists. Upgrade restarts active copies of those three services. An upgrade from `1:1.3.5-1` through versions below `1:1.3.5-2` additionally migrates X11 keyboard layout via `localectl set-x11-keymap` if unset. There is **no removal hook**, no tracking/restoration of previous service enablement, and no `backup=()` protection for either `/etc` file. Standard dependency hooks may compile GLib schemas, reload units/rules, or apply tmpfiles/sysctls; enumerate their exact behavior from the selected base before installing any derived package. Package file deletion alone would not restore live kernel/sysfs settings, deleted coredumps, altered service state, DNS integration, or administrator preferences.

## Individual default decisions

**Include** would mean justified for the initial overlay. No item meets that threshold before the base inventory. **Defer** means an individually scoped future experiment or optional tool with named gates. **Reject** means omit this upstream behavior from the Apple overlay. All paths below are installed paths; see the JSON for exact hashes.

### Sysctl file: `/usr/lib/sysctl.d/70-cachyos-settings.conf`

| Default | Decision | Reason / evidence needed |
| --- | --- | --- |
| `vm.swappiness=100` | Defer | Compare target swap topology and baseline; kernel documents cost-dependent tuning. Test memory-pressure latency, CPU, power and OOM behavior. |
| `vm.vfs_cache_pressure=50` | Defer | Changes reclaim balance; measure build/file workloads and constrained-memory behavior. |
| `vm.dirty_bytes=268435456` | Defer | Absolute 256 MiB writeback threshold; evaluate memory size, storage and tail latency. |
| `vm.page-cluster=0` | Defer | Suppresses swap readahead; suitability depends on zram versus disk swap and actual page size. |
| `vm.dirty_background_bytes=67108864` | Defer | Absolute 64 MiB background threshold; test independently before combined writeback policy. |
| `vm.dirty_writeback_centisecs=1500` | Defer | 15-second writeback interval changes write timing; measure power/latency and document persistence implications. |
| `kernel.nmi_watchdog=0` | Reject | PC-focused rationale; key may not exist on selected ARM kernel. No measured M2 need. |
| `kernel.unprivileged_userns_clone=1` | Defer | Security/base policy and kernel-specific key; first record sandbox/container requirements and current value. |
| `kernel.printk=3 3 3 3` | Reject | Hides console diagnostics during an unvalidated platform bring-up. |
| `kernel.kptr_restrict=2` | Defer | Security/debugging policy; establish selected-base policy and diagnostic requirements before tightening. |
| `net.core.netdev_max_backlog=4096` | Defer | Needs a reproduced packet-drop/load case and memory/latency comparison. |
| `fs.file-max=2097152` | Defer | Global limit is unrelated to an observed target failure; inventory actual defaults and workload need. |

The [kernel VM sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/vm.html) describes these as policy tradeoffs, not universal performance wins. The two byte thresholds replace corresponding ratio controls; removal needs restoration of the captured effective baseline, not an invented universal default.

### Other configuration files and units

| Installed path | Behavior | Decision / gate |
| --- | --- | --- |
| `/etc/debuginfod/cachyos.urls` | CachyOS symbol service URL | Defer: verify symbols for actual ARM package build IDs and explicit network-use policy; no utility proven for the selected base. |
| `/etc/security/limits.d/20-audio.conf` | Audio group rtprio 99, nice -11 | Defer: preserve Asahi audio/rtkit/speaker-protection policy; inspect PAM applicability and test bounded realtime workloads. |
| `/usr/lib/NetworkManager/conf.d/dns.conf` | `dns=systemd-resolved` | Defer: resolver/service and `/etc/resolv.conf` baseline required. Enabling resolved alone does not establish working DNS. |
| `/usr/lib/iw-set-regdomain` | `/etc/iw-regdomain` override, otherwise timezone-to-country via zone.tab | Reject automatic timezone inference: timezone is not physical location. Defer a separate explicit-country tool only after Asahi wireless driver/regulatory interaction and legal configuration requirements are established. |
| `/usr/lib/modprobe.d/amdgpu.conf` | Forces amdgpu SI/CIK; disables equivalent radeon support | Reject: AMD PC driver selection is outside initial target. |
| `/usr/lib/modprobe.d/blacklist.conf` | Blacklists iTCO_wdt/sp5100_tco | Reject: Intel/AMD watchdog assumptions. |
| `/usr/lib/modprobe.d/nvidia.conf` | Disables NVIDIA memory clearing | Reject: irrelevant GPU and explicitly documented security cost in source. |
| `/usr/lib/modules-load.d/ntsync.conf` | Loads ntsync at boot | Defer: prove actual module availability and application need; prevent missing-module boot noise and duplicate `ntsync-common` ownership. |
| `/usr/lib/systemd/journald.conf.d/00-journal-size.conf` | `SystemMaxUse=50M` | Defer: establish diagnostic retention need and actual log rate; tiny cap can remove acceptance evidence. |
| `/usr/lib/systemd/system.conf.d/00-timeout.conf` | System start 15s, stop 10s | Reject global shortening: can kill slow firmware/audio/startup or shutdown work. If a specific service is defective, scope its repair. |
| `/usr/lib/systemd/user.conf.d/00-timeout.conf` | User start 15s, stop 10s | Reject global shortening: risks user services/application cleanup; no reproduced need. |
| `/usr/lib/systemd/system.conf.d/10-limits.conf` | NOFILE soft 2048/hard 2097152 | Defer: measure actual fd needs and compare base policy. |
| `/usr/lib/systemd/user.conf.d/10-limits.conf` | NOFILE soft 1024/hard 1048576 | Defer: compare current user manager/application behavior. |
| `/usr/lib/systemd/system/cachyos-iw-set-regdomain.path` | Watches `/etc/localtime` | Reject with automatic timezone inference; see explicit-country alternative above. |
| `/usr/lib/systemd/system/cachyos-iw-set-regdomain.service` | Runs regulatory script | Reject as an automatically activated policy; standalone explicit-country proposal remains deferred. |
| `/usr/lib/systemd/system/pci-latency.service` | Executes root setpci helper | Reject: PC PCI latency assumptions and broad mutation. |
| `/usr/lib/systemd/system/rtkit-daemon.service.d/override.conf` | LogLevelMax info | Defer: preserve diagnostic evidence until audio validation complete; prove need before suppressing logs. |
| `/usr/lib/systemd/system/session.slice.d/10-ignore-session-slice.conf` | ManagedOOMPreference omit | Defer: combined OOM policy affects which tasks can be killed; test workload/cgroup layout and recoverability. |
| `/usr/lib/systemd/system/system.slice.d/10-oomd-per-slice-defaults.conf` | ManagedOOMSwap/MemoryPressure kill, pressure 80% | Defer: impacts system-service survival; validate interaction with Asahi critical services under controlled memory pressure. |
| `/usr/lib/systemd/system/user-.slice.d/10-oomd-per-slice-defaults.conf` | Same OOM policy for per-user slices | Defer: test scope, application/session preservation and target oomd baseline. |
| `/usr/lib/systemd/system/user@.service.d/delegate.conf` | Delegates cpu/cpuset/io/memory/pids | Defer: inventory cgroup v2 manager defaults and container need; redundant policy is not a performance result. |
| `/usr/lib/systemd/timesyncd.conf.d/10-timesyncd.conf` | Cloudflare primary, Google/Arch fallback NTP | Defer: retain selected base's time-service and network/privacy policy. |
| `/usr/lib/systemd/zram-generator.conf` | zstd, logical size=RAM, swap priority 100 | Defer: check existing generator, RAM, compression support, disk swap, OOM and suspend interaction. Test independent of swappiness first. |
| `/usr/lib/tmpfiles.d/coredump.conf` | Removes coredumps older than 3 days | Defer: not an optimization; retention policy needs actual diagnostic/storage requirements. Removal cannot recover deleted dumps. |
| `/usr/lib/tmpfiles.d/thp.conf` | THP defrag `defer+madvise` at boot | Defer: test actual allocator/workload, compaction latency and power on target kernel; sysfs must exist. |
| `/usr/lib/tmpfiles.d/thp-shrinker.conf` | `max_ptes_none=409` at boot | Reject unmodified threshold; defer a kernel/page-geometry-specific experiment. The source's 409/512=80% rationale assumes geometry not demonstrated on 16K-page Asahi. |
| `/usr/share/X11/xorg.conf.d/20-touchpad.conf` | Enables libinput tapping | Defer as optional X11 preference; does not configure Hyprland's Wayland touchpad behavior. |
| `/usr/share/glib-2.0/schemas/zz_cachyos.org.gnome.login-screen.gschema.override` | GDM logo override | Reject: unrelated to Hyprland minimum overlay and implies CachyOS branding. |
| `/usr/share/icons/cachyos.svg` | CachyOS logo artwork | Reject from initial overlay; grant/branding requirements and an actual UI need remain unresolved. |

The [NetworkManager DNS documentation](https://www.networkmanager.dev/docs/api/latest/NetworkManager.conf.html) identifies resolver-specific integration; DNS and its symlink/state need an explicit migration/removal design. The [kernel THP documentation](https://docs.kernel.org/admin-guide/mm/transhuge.html) says page geometry varies by architecture and provides `hpage_pmd_size`. Capture `getconf PAGESIZE`, that size, available THP controls, kernel revision/config and baseline values before deriving a threshold. Do not replace `409` with another unmeasured constant. Different kernel versions also differ in THP/mTHP behavior.

### Udev rules

| Installed path | Behavior | Decision / gate |
| --- | --- | --- |
| `/usr/lib/udev/rules.d/20-audio-pm.rules` | snd_hda_intel power saving; assumes BAT0 | Reject: PC audio/battery assumptions; preserve Asahi audio. |
| `/usr/lib/udev/rules.d/30-zram.rules` | On initialized zram0, swappiness 150 and disables zswap | Defer: two global side effects; separate measurements and availability checks, including missing zswap parameter path. |
| `/usr/lib/udev/rules.d/40-hpet-permissions.rules` | rtc0/hpet group audio | Reject hpet; defer rtc0 independently only with real application need and security review. |
| `/usr/lib/udev/rules.d/50-sata.rules` | SATA link policy max_performance | Reject initial overlay: peripheral-specific power change with no measured need. |
| `/usr/lib/udev/rules.d/60-ioschedulers.rules` | Rotational sd=bfq; nonrotational sd/mmc=mq-deadline; nvme=kyber | Defer **each class separately**; retain target baseline. Rule has no explicit scheduler availability guard and can match external devices. Verify actual offered scheduler and measure latency/power/throughput. |
| `/usr/lib/udev/rules.d/69-hdparm.rules` | ATA rotational disk APM254, spin-down0 | Reject initial overlay: unrelated internal storage, peripheral power changes, undeclared direct hdparm dependency. |
| `/usr/lib/udev/rules.d/71-nvidia.rules` | NVIDIA runtime PM on bind/unbind | Reject: irrelevant GPU assumption. |
| `/usr/lib/udev/rules.d/85-iw-regulatory.rules` | Starts timezone-derived regulatory policy on Wi-Fi add | Reject automatic policy; explicit-country alternative deferred. |
| `/usr/lib/udev/rules.d/99-cpu-dma-latency.rules` | Audio-group 0660 cpu_dma_latency access | Defer: exposes a power/latency control; establish device availability and measured realtime need, then assess battery impact. |

### Optional command-line tools

| Installed path | Behavior | Decision / gate |
| --- | --- | --- |
| `/usr/bin/cachyos-bugreport.sh` | Root journal/dmesg/inxi report, partial redaction, optional upload | Defer extraction: remove x86 repository assumptions, target CachyOS support branding, prove sanitization (IPv6/serials/log secrets are not comprehensively filtered), declare curl/paste dependency, preserve local review before any upload. Source was read, not run. |
| `/usr/bin/dlss-swapper` | NVIDIA/DXVK preset vars, runtime NGX updater | Reject: unsupported target use and unaudited runtime binary source. |
| `/usr/bin/dlss-swapper-dll` | NVIDIA/DXVK preset vars, no updater | Reject: no initial Apple GPU requirement. |
| `/usr/bin/game-performance` | Performance profile; systemd-inhibit unless override set | Defer: power-profile backend availability, target thermals/battery, inhibition semantics and cleanup after application exit require hardware checks. |
| `/usr/bin/kerver` | Kernel/disk report plus x86 loader/config probes | Reject unmodified: executes `/lib64/ld-linux-x86-64.so.2`, irrelevant config filters. A separately designed architecture-neutral diagnostic can be proposed later. |
| `/usr/bin/paste-cachyos` | Uploads input to CachyOS paste service | Defer: no automatic network tool in initial overlay; requires curl and explicit support/privacy design. |
| `/usr/bin/pci-latency` | Broad setpci writes, including sound-class devices | Reject: changes all PCI latency timers; no Asahi audio relevance demonstrated. |
| `/usr/bin/sbctl-batch-sign` | Signs PC EFI files with sbctl, assumes /boot ESP | Reject: Asahi boot-chain assumptions are explicitly protected. ARM availability of sbctl does not justify this behavior. |
| `/usr/bin/topmem` | Lua/luv reads process RSS/swap/KSM and groups by executable | Defer as isolated optional diagnostic: resolve Lua/luv ABI, license grant and process-read race/error behavior. No system tuning or performance benefit implied. |
| `/usr/bin/zink-run` | Forces Zink/Mesa/GLVND environment | Defer as optional graphics experiment: confirm actual Mesa/Zink/Vulkan/GLVND versions and accelerated renderer; run functional/latency/power tests, never change session default. |

## Proposed experiments and remaining gates

For coordinator manifest reconciliation: set `cachyos-settings` to deferred with the full commit pin and this audit path, citing mixed PC defaults, license mismatch, unknown base state, irreversible retention side effects, and service/removal behavior. Do not add `ananicy-cpp` or `cachyos-ananicy-rules` transitively merely to satisfy this candidate. No replacement settings recipe is selected yet.

Later experiments should have separate recipe names and owned paths rather than a broad settings bundle: optional `cachy-asahi-topmem` diagnostic after licensing/Lua gates; one zram compression/size experiment; separate swappiness/page-cluster studies; one THP policy experiment after measured geometry; per-device scheduler tests; explicit-country wireless configuration only if Asahi requires it; optional Zink wrapper only for a validated application. Each requires captured baseline/effective settings, a documented restoration procedure, acceptance criteria before trials, raw repeated results, and target service/hardware checks. Global DNS, audio permissions, OOM handling, or power-profile changes additionally need platform-stack review and independent review.

**Blockers:** source-license grant clarification; unrecorded artifact provenance for the artwork and rule dependency; exact selected base/repository snapshot and conflict/ownership inventory; native ARM clean builder and repeat-build evidence if any recipe is selected; M2 13-inch/15-inch baseline access; service and configuration rollback tests; actual THP geometry and kernel controls; individual benchmark evidence. None is marked passed by this source audit. Documentation-only work has no implementation-test requirement; inventory completeness and checksums were verified below.

Local evidence check: Python loaded the JSON, asserted 49 distinct payload paths, checked each appears in the audit, verified the archive SHA256, and compared every file's bytes with the full pinned archive: **PASS**. An initial mode-equality assertion failed because GitHub archive modes include group-write bits filtered by extraction umask; the inventory now records `archive_mode`, `extracted_mode`, and Git executable-bit mode separately. None is presented as a built-package mode. No implementation or hardware check was run.
