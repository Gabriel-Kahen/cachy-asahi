# M6 / R4: tools, defaults and shell functionality

October 11, 2026, America/New_York. **Source audit and proposed implementation
matrix; not a delivered port or A13 acceptance.** Read `goal.md`, the expanded
roadmap, outline, acceptance matrix and current inventory before this audit.
R1–R5 remain mandatory. The four native-built original packages are a useful
foundation; their templates do not implement the complete CachyOS experience.

October 13 implementation update: Root registers the separately licensed opt-in
`cachy-asahi-fish-bang-bang` package after independent source and host Fish review.
It provides `!!` and `!$` editing-buffer expansion with guarded bindings and seven
package-owned files. Six focused Root controls pass on x86 Fish 4.9.3; retained
independent terminal controls also pass. Native builds, package lifecycle, the
declared Fish 4.0 floor and both Air sizes remain untested. The original Fish
template and deferred whole-configuration disposition remain unchanged.
[Review](../reviews/fish-history-module-root-review.md) and
[implementation](../workstreams/fish-history-module.md) record the exact pin,
notices, opt-in behavior and limitations.

This work owns only this document. Sources were read from primary upstream
repositories into temporary directories. No source script/PKGBUILD was executed,
package built/installed, service/sysctl changed, key imported, or shared manifest
edited. All newly proposed tools below are **not built, not installed, not
hardware-tested**. Both exact M2 Air sizes, lifecycle/recovery and maintained
release evidence remain required.

October16 implementation: the original MIT `cachy-asahi-mirrors` candidate now
checks explicit asahi-alarm/aarch64 catalogs and ranks mirrors only after exact
selected-snapshot database byte matches. It writes a separate0600 candidate,
never modifies pacman configuration, and refuses redirects, wrong snapshots and
existing output. Twelve mocked-network controls and exact four-file isolated
host staging pass. No live mirror ranking, native package build, catalog trust,
activation/restoration, target or complete mirror-management acceptance is
claimed. See [candidate source](../../packages/tools/cachy-asahi-mirrors/README.md).

# Proposed required-function coverage note

Root owns edits to `docs/port/tools-functionality.md` and shared inventories.
Keep the overall shell feature rows and target/integration gates open.

Add a bounded progress note to the history/search/keybindings and individually
licensed module coverage: `cachy-asahi-zsh-history-substring-search` now has a
complete unchanged BSD-3-Clause runtime from commit
`a0bdb0d47dbaba31dba2db7af8c48a5d9c74049a`, an independent MIT interactive opt-in
wrapper, a local-source recipe and real x86_64 Zsh 5.9.2 PTY evidence. It performs
literal substring search over in-memory history, including multiline/quoted
cases. Existing public/private substring namespaces, ordinary custom Up/Down
bindings and unrelated widgets are preserved; repeated source and noninteractive
source do not activate it. Bindings are explicitly manual and documented.

Six host controls pass, including actual ZLE editing and coexistence with the
staged pinned syntax-highlighting module loaded first. The recipe's five-case
check body and seven-file pure staging pass. These are host source/staging
results, not native ARM packages, a package-manager lifecycle, a selected full
composition, 16-KiB/M2 operation or release admission. No whole Cachy Zsh config
or unresolved source grant is reused.


October16 implementation: the mirror candidate0.2.0 now has explicit activation
and restoration for caller-selected paths, a durable prior-state journal and
conflict refusal. All29 host controls pass, including real tempfile CLI and
SIGKILL recovery. Locks are advisory; external writers must stop during an
operation. POSIX bytes/mode/uid/gid are covered; ACLs/xattrs/timestamps, storage
power loss and actual base integration remain outside this evidence.

The separate MIT Fish autopair candidate retains the exact audited upstream pin
and five unchanged editing helpers. An independent opt-in wrapper avoids upstream
startup/rebinder hooks and preserves existing keys/namespaces. The worker's14
real host Fish4.9.3 controls/57 editor snapshots and eleven-file staging pass;
no native/package-manager/16K/M2 acceptance is claimed. Older hosted Fish gets
source/syntax checking only. Whole Fish configuration and M6 remain open.

October16 implementation: the separate Fish Done MIT adaptation now provides
explicit foreground completion and single-process background watching, private
notification text by default, bounded notification-command execution and preserved
existing hooks/bindings. Root replays all18 real host Fish4.9.3 PTY controls using
a local notify-send recorder. This establishes invocation/failure/timeout handling,
not real D-Bus or visible notifications. Eight-file staging passes separately;
native package/lifecycle, generic16K and M2 remain open. Full upstream source and
reviewable adaptation are retained in the package provenance.

## Scope and decision vocabulary

Coverage includes the pinned Cachy-branded tool/configuration recipe catalog,
associated management/boot/scheduler tools, the complete 49-file settings tag and
its 12 sysctl entries, Fish/Zsh functions, and the M6 user workflows. Compiler,
browser/application rebuilds and kernel patches belong to M5/M7; installation
implementation belongs to M8. Their required user-facing functions are routed
here rather than silently omitted. This is a finite audit snapshot, not a claim
that every Arch recipe or GitHub repository has been audited.

**PORT** means reuse a licensed implementation substantially intact; **ADAPT**
means preserve its useful function with reviewed changes; **REPLACE** means
provide the function through a different implementation; **EXCLUDE** means the
specific implementation/behavior is inapplicable. These are proposed decisions,
not past-tense completion claims. Excluding PC behavior never excludes a required
Apple user workflow. Optional tools cannot be enabled simply to match a feature
list. Until their gate passes, the selected Asahi baseline remains in force.

Owners below are accountable workstream roles for coordinator assignment:
**T** tools/defaults, **D** desktop, **P** platform/performance, **B** ARM build,
**R** release, **I** installation, **C** coordinator. Named ongoing humans and
capacity are still required by A08; an agent assignment supplies no permanent
maintenance or signing custody.

## Pinned sources and renewed license findings

Packaging master was fetched live and remained
[`c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`](https://github.com/CachyOS/CachyOS-PKGBUILDS/tree/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f).
The complete nontruncated GitHub tree response SHA256 is
`41f9e9c31af2753ed549babde7e865056809e3a957149c3c8022cbf21c24d825`.
Recipes were fetched as inert text. Their architecture declarations and license
fields are observations, not ARM execution or complete source-license audits.

| Source | Full revision and primary evidence | License finding / gate |
| --- | --- | --- |
| Fish v16 | [`cc78c7f7a8a7a623aaaa9283994b64ce4fc50d6a`](https://github.com/CachyOS/cachyos-fish-config/tree/cc78c7f7a8a7a623aaaa9283994b64ce4fc50d6a) | Four-file tree has no grant for the main configuration; recipe MIT does not resolve that gap. `done.fish` carries MIT notices for Francisco Lourenço/Daniel Wehner, 2016. |
| Fish history component | [`ec991b80ba7d4dda7a962167b036efc5c2d79419` LICENSE](https://raw.githubusercontent.com/oh-my-fish/plugin-bang-bang/ec991b80ba7d4dda7a962167b036efc5c2d79419/LICENSE) | Direct plugin MIT grant credits Aerys Bat/Derek Stavis, 2015; preserve it if separately reused. It does not license the entire Cachy config or establish its copied revision. |
| Zsh v1.0.3 | [`79c20770964110b873a4c0429c2a560fd28d33ac`](https://github.com/CachyOS/cachyos-zsh-config/tree/79c20770964110b873a4c0429c2a560fd28d33ac); refreshed master [`27c5494d687f63e844d20697ac0a5ceb0358a2d1`](https://github.com/CachyOS/cachyos-zsh-config/tree/27c5494d687f63e844d20697ac0a5ceb0358a2d1) | Neither three-file tree supplies a main-source grant. Master changes orphan cleanup behavior, not licensing. Recipe GPL-1.0-only remains insufficient source evidence. |
| Settings 1.4.1 | [`764693fe2863bc2b00db6ad6f4c1d57cded739f2` LICENSE.md](https://github.com/CachyOS/CachyOS-Settings/blob/764693fe2863bc2b00db6ad6f4c1d57cded739f2/LICENSE.md); refreshed master [`e27ea45cc5afa45d2454f7c06d57d30c30c5d569`](https://github.com/CachyOS/CachyOS-Settings/tree/e27ea45cc5afa45d2454f7c06d57d30c30c5d569) | GPLv3 root licensing evidence is present and unchanged. Do not call the whole repository unlicensed. Correct the GPL-1.0-only recipe mismatch; clarify only/or-later for final SPDX, retain individual notices and modified-source terms. Artwork branding is a separate question. |
| Regulatory components | [Pinned `iw-set-regdomain`](https://github.com/CachyOS/CachyOS-Settings/blob/764693fe2863bc2b00db6ad6f4c1d57cded739f2/usr/lib/iw-set-regdomain) | Four files explicitly carry ISC provenance, including Duckworth, Red Hat and Velocity Limitless notices. Reuse only with those notices and an explicit-country policy. |
| Welcome v0.28.1 | [`efd467041a9accb461bc3bf8a096a6627f795293`](https://github.com/CachyOS/CachyOS-Welcome/tree/efd467041a9accb461bc3bf8a096a6627f795293) | Root GPLv3 text and Cargo `GPLv3`; recipe declares GPL-3.0-or-later. Resolve exact package SPDX and dependency/asset notices before redistribution. Cargo pins `chwd` at `e99ec339715f2b5724a1adc100ea55b94e59df5a`; disabling a button alone does not remove that dependency. |
| Package installer v1.6.2 | [`9b1ed3da1589b87000aae5120504366408ccef10`](https://github.com/CachyOS/packageinstaller/tree/9b1ed3da1589b87000aae5120504366408ccef10) | GPLv3 root text; inspected C++/Rust files have explicit GPL-2.0-or-later notices. Retain them and complete UI/assets/dependency BOM. Qt/polkit code is source-audited, not ARM-built here. |
| Kernel manager v1.19.0 | [`6b4a373e6a4e7295a0803034e597c4f2a055a411`](https://github.com/CachyOS/kernel-manager/tree/6b4a373e6a4e7295a0803034e597c4f2a055a411) | GPLv3 root text, inspected source GPL-2.0-or-later. Recipe declares aarch64 and depends on chwd/scx-manager; that does not make its kernel/boot operations safe for Apple. |
| chwd 1.24.1 | [`e99ec339715f2b5724a1adc100ea55b94e59df5a` Cargo.toml](https://github.com/CachyOS/chwd/blob/e99ec339715f2b5724a1adc100ea55b94e59df5a/Cargo.toml) | Cargo explicitly GPL-3.0-only; recipe says GPL-3.0-or-later. Correct the mismatch rather than broadening the grant. Profiles/library/dependency notices still need a complete BOM. |
| Sysctl manager v1.2.0 | [`fe92490bdb1ac522357581a51bf389ac276bb17f`](https://github.com/CachyOS/sysctl-manager/tree/fe92490bdb1ac522357581a51bf389ac276bb17f) | GPLv3 root text; inspected source explicitly GPL-2.0-or-later. Qt/polkit implementation needs a supported-key policy and transactional restoration. |
| cachy-update | [`e2b1b7144be71cf392809f48d1440f8da1d9c81a`](https://github.com/CachyOS/cachy-update/tree/e2b1b7144be71cf392809f48d1440f8da1d9c81a) | GPL-3.0-or-later source/recipe evidence; recipe declares aarch64. Broad update/autostart behavior needs adaptation; no ARM artifact was built here. |
| cachy-chroot 1.3.0 | [`c87f36a4650fc3a592f2e4ea6e85042e2b492429`](https://github.com/CachyOS/cachy-chroot/tree/c87f36a4650fc3a592f2e4ea6e85042e2b492429) | BSD-3-Clause source evidence; x86-only recipe is not proof source cannot port. Mount discovery/recovery behavior needs an Apple-aware integration review. |
| rate-mirrors v0.31.0 | [`98ac2a2698b1c7aed4c4ad15817b710d62ef3b31` LICENSE](https://github.com/westandskif/rate-mirrors/blob/98ac2a2698b1c7aed4c4ad15817b710d62ef3b31/LICENSE) | CC-BY-NC-SA-3.0, including noncommercial terms; do not mislabel MIT or assume unrestricted maintained-distribution use. Resolve distribution terms or replace. |
| Cachy mirror wrapper | [Pinned executable](https://github.com/CachyOS/CachyOS-PKGBUILDS/blob/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-rate-mirrors/cachyos-rate-mirrors) | Explicit GPL-2.0-or-later header, despite GPL-1.0-only recipe. Automatic Arch/Cachy/x86-v3/v4 mirror writes and timer/hooks are unsuitable unchanged. |
| ananicy rules 1.1.49 | [`03ef03fbf7e834385377432ccecaedd32e3414bb`](https://github.com/CachyOS/ananicy-rules/tree/03ef03fbf7e834385377432ccecaedd32e3414bb) | Root GPLv3 text found; recipe GPL-3.0-or-later. Per-rule attribution/coverage and measured Apple priority policy remain open; not imported transitively. |
| KSM control source | [Pinned `ksmctl`](https://raw.githubusercontent.com/CachyOS/CachyOS-PKGBUILDS/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-ksm-settings/ksmctl) | Explicit GPL-2.0-or-later, Vasiliy Stelmachenok/CachyOS 2024–2025. Clear bounded derivative candidate; source SHA256 below. |

Signed recipe tags were resolved through primary GitHub records or archive PAX
commit metadata. GitHub verification metadata is not local trusted-key
verification. No upstream tag signature was verified in this audit. Moving
`-git` recipes must be frozen to full commits before packaging; a branch or a
README's support statement cannot substitute for native ARM execution.

## Management and user-workflow matrix

Welcome's actual [CLI actions](https://github.com/CachyOS/CachyOS-Welcome/blob/efd467041a9accb461bc3bf8a096a6627f795293/src/cli.rs),
[privileged actions](https://github.com/CachyOS/CachyOS-Welcome/blob/efd467041a9accb461bc3bf8a096a6627f795293/src/actions.rs),
and [six tweaks](https://github.com/CachyOS/CachyOS-Welcome/blob/efd467041a9accb461bc3bf8a096a6627f795293/src/tweak.rs)
were read, rather than treating the application's name as a complete feature
specification. Every fix/tweak family has an explicit destination below.

| Function / source | Decision, reason and required alternative | Owner / next evidence |
| --- | --- | --- |
| Welcome/help/documentation/application launch | ADAPT Hello UI/CLI with independent-port identity, supported release catalog and actual support links; remove chwd embedding and PC installer/repair actions. | T/D/B: licensed asset/dependency BOM, native GTK/Rust build, accessible Hyprland journey. |
| Application selection/install/remove (`cachyos-packageinstaller`, Shelly) | ADAPT package installer first; catalog contains only supported ARM/native applications and approved repositories. No hidden x86 groups/AUR fallback. Shelly is an alternative after its own Zig/GTK/ALPM audit, not a second compulsory GUI. | T/B/R: full dependency closure, signed fresh/install/remove transaction and useful error recovery. |
| Update notifier/system upgrade (`cachy-update`, Hello UpdateSystem) | ADAPT CLI/full-system update workflow; optional per-user timer/tray. Preserve upstream pacman dependency consistency and include coordinated Asahi platform changes; never silently choose Cachy x86 repositories. | T/R/P: source/notice closure, CLI native build, actual repository update and restart/recovery evidence. |
| Reinstall native packages | ADAPT as a reviewable repair plan using the recorded supported inventory/signatures. No blind reinstall from moving or wrong-architecture repositories. | T/R: failure injection and restored inventory/payload/permissions. |
| Reset keyrings | REPLACE indiscriminate reset with pinned base/project trust verification and documented recovery/rotation. Retain valid base trust and independent signing custody. | R: staging revocation/rotation plus actual public trust bootstrap. |
| Remove database lock | REPLACE direct `rm db.lck` with transaction-aware diagnosis and an explicit stale-lock recovery procedure after proving no live package transaction. Never a login alias. | T/R: concurrent-pacman and interrupted-process tests. |
| Clear cache/remove orphans | ADAPT preview/list and explicit selected cleanup; retain known-good rollback archives. Package ownership/dependencies decide candidates, not an unguarded shell substitution. | T/R: no-op, cancellation, active transaction and recovery-cache tests. |
| Mirror ranking (`cachyos-rate-mirrors`) | REPLACE upstream endpoints/NC dependency with a licensed ARM-compatible checker/ranker over the selected base/project mirror catalog; candidate file first, atomic explicit activation with prior-state restoration. | T/R: resolve replacement grant, signature/hash validation and base repository compatibility. |
| DNS plain/DoT/DoH/DoQ, custom servers, latency tests and DHCP reset | ADAPT per-connection NetworkManager workflow with prior settings/service journal and undo. Keep baseline DNS initially; optional blocky needs its own ARM/license/dependency audit. No global resolver migration just to enable a button. | T/P: active Wi-Fi/VPN/IPv4/IPv6, offline/failure and restore checks. |
| Bluetooth toggle | ADAPT existing BlueZ service/UI; report support from the tested Apple platform, preserve prior enabled/active state and user pairing. | D/P: both-model radio/pairing/resume lifecycle. |
| Profile-sync-daemon toggle | ADAPT optional browser profile workflow only after package availability, user-state safety, memory and crash/recovery checks; default remains disk-backed profile. | T/P: loss/interruption/restart and memory-pressure tests. |
| oomd toggle | ADAPT a separately measured cgroup/OOM policy with exclusions for critical platform/session services; preserve baseline initially. | P/T: controlled memory pressure, application preservation and rollback. |
| ananicy-cpp/rules toggle | ADAPT selected attributable rules per workload; no automatic wholesale priority service. Baseline scheduler/priorities are the alternative until measurements justify changes. | P/T/B: rules BOM, native dependency closure and latency/energy trials. |
| bpftune toggle | ADAPT optional experiment only if supported kernel/BPF controls, native dependencies and measured effect pass; no blanket default. | P/B: kernel config/verifier/16K/correctness and removal evidence. |
| KSM control/status | ADAPT status first, as specified below. Merge/unmerge/pause and session-wide enablement remain gated M7 experiments; retain baseline KSM state. | T/P: native CLI, absent-feature/error handling; separate mutation/energy/OOM tests later. |
| Sysctl editing | ADAPT manager with available-key discovery, named experiments, preview and baseline restoration. Omit assumed x86 keys and unmeasured universal presets. | T/P/B: native Qt/polkit, permission/state/interruption tests and M7 measurements. |
| Kernel list/install/build/remove and sched-ext GUI | REPLACE generic kernel/chwd action backend with Apple compatibility-set management; retain GUI concepts only if useful. Preserve a bootable known-good Asahi kernel and its headers/driver stack; refuse last-known-good removal. | P/T/R: architecture/build/16K gates, both-model boot/update/failure recovery; source-built kernel interface separate from general apps. |
| Hardware detection/profiles (`chwd`) | REPLACE automatic PCI/USB driver installation with capability inventory for supported Apple model/version sets and maintained Asahi packages. Peripheral information may be read; it must not select PC GPU profiles. | P/T: exact-model fixtures and hardware observations, unknown-model refusal, protected-package transaction checks. |
| Initramfs/boot hooks, sdboot/GRUB/Limine/EFI signing | REPLACE upstream PC boot management with the selected Asahi installation's established boot/update interface. Exclude new PC bootloader/theme/EFI signing automation; retain an existing supported loader if the Asahi base uses it. | P/I/R: capture actual boot chain, non-destructive update plan, verified fallback and physical recovery. |
| Recovery chroot/root filesystem mounting | ADAPT cachy-chroot only after Apple volume/boot layout and explicit selected-root handling; existing documented Asahi recovery plus `arch-chroot` is the initial alternative. Never auto-mount arbitrary discovered roots. | I/P/B: image fixtures, encrypted/fs cases, clean unmount and actual recovery. |
| Snapshots/Snapper and bootable rollback | ADAPT data snapshots only when selected filesystem/layout supports them. REPLACE GRUB/Limine snapshot boot integration with proven Asahi recovery; ext4 uses retained packages/data backup instead. Snapshot existence is not boot recovery. | I/R/P: failed-upgrade restore and actual boot/session recovery. |
| Kdump/crash diagnostics | REPLACE assumed PC loader/kexec integration with safe journal/pstore/local report first; [boot-report source candidate](../../packages/tools/cachy-asahi-boot-report/README.md) implements explicit boot selection and private local export; native/target/crash recovery NOT RUN; optional crash-kernel capture requires actual kernel/boot support and recovery testing. | P/T: target capability evidence, sanitized local report, no automatic uploads. |
| KWin debug console | EXCLUDE KDE-specific invocation from Hyprland. Provide Hyprland/session/portal/log diagnostics instead. | D/T: actual compositor diagnostic workflow. |
| Winboat/Windows applications | EXCLUDE as baseline requirement; x86 Windows/container/VM acceleration is not established Apple-native functionality. Offer audited native applications; any VM/emulation support needs separate M5 architecture/licensing/workload evidence. | C/B: finite supported application inventory. |
| Gaming meta/app bundles, VRAM/dmemcg/Plasma booster | EXCLUDE unmodified lib32/Steam/Proton/NVIDIA/Plasma bundles on Apple Hyprland. Offer supported native ARM application catalog; evaluate optional game/graphics workflows individually without claiming compatibility. | C/B/D/P: app-specific ARM/graphics/license and measured policy gates. |
| Hyprland session: rendering/scaling/brightness/input/audio/network/lock/resume | ADAPT applicable licensed desktop behavior and integrate Asahi services; current original template/watchdog/setup is partial. No alternate desktop bundle can replace the required coherent session. | D/P: both-size A02 cycles and independent terminal/editor/native-build/application journey. |
| First setup, customization, migration, removal/reinstall | ADAPT original packaged setup/helper contract to the eventual licensed feature set with owned edits/journals and restoration. No wholesale `/etc/skel` overwrite or forced login shell. | T/D/R: A04 fresh/existing/interrupted/repeated/upgrade lifecycle plus both-size target tests. |

## Shell functionality: required coverage beyond current helpers

Pinned config source/notice and dependency details remain in
[the consolidated audit](../audits/tools-defaults.md). The original Fish package
implements only two namespaced helpers; original Zsh supplies completion and an
optional plain prompt. They are not feature-equivalent Cachy config ports.

| Cachy shell function | Decision / replacement and gate | Owner |
| --- | --- | --- |
| Interactive startup vs noninteractive execution | REPLACE main ungranted config with independently authored guarded setup; scripts/SSH/compiler jobs must not run greetings/notification/profile side effects. | T |
| History/search/keybindings and bang-bang | PORT separately licensed upstream plugin when selected, preserving exact pins/notices; ADAPT bindings opt-in without overwriting existing choices/history. | T/B |
| Prompt/theme/greeting (`fastfetch`, pure, Powerlevel10k) | ADAPT optional explicit choices from licensed component sources. Plain prompt is usable alternative; no mandatory theme/font/network downloads. Full module source/dependency BOM before packaging. | T/B |
| Completion, autosuggestions, syntax highlighting, substring search | PORT individually licensed upstream modules after selected-base ARM resolution and input/terminal tests; preserve user modules/order. | T/B |
| Autopair/Fisher/plugin acquisition | ADAPT pinned packaged modules; no first-login moving network install. Until module grant/recipe is resolved, use standard shell editing. | T/B |
| Long-command `done.fish` notification | PORT MIT component separately with original Lourenço/Wehner notice, then ADAPT desktop notification/session detection, noninteractive guard, privacy and cancellation; optional until tested. | T/D |
| PATH, profile sourcing, environment | ADAPT user-controlled additive integration with quoting, duplicates/space handling and migration journal. No global universal-variable rewrites. | T |
| File listing/create-and-enter convenience | ADAPT namespaced helpers; existing user functions/aliases win. Current original implementations are foundation evidence for this subset only. | T |
| bat/eza/fzf/pkgfile/expac/tealdeer convenience | PORT tool functions via maintained ARM packages; ADAPT aliases explicitly and preserve standard command semantics. Resolve package/source licenses and complete closure. | T/B |
| Make/Ninja parallelism | REPLACE forced CPU-count overrides with explicit per-workload settings informed by RAM, thermal and build measurements; default upstream tools otherwise. | T/P |
| Package/update/cache/orphan aliases | REPLACE broad destructive aliases with the management workflow above; no source-time orphan scan or lock deletion. | T/R |
| `grubup`, PC boot/mirror aliases | EXCLUDE those implementations; required update/recovery goes through the Apple platform backend and selected ARM repository catalog. | T/P/R |
| Fonts, terminal/editor defaults | ADAPT explicit licensed preference packages; retain user terminal/editor choices. Font/theme asset grants and selected ARM app closure required. | T/D/B |
| Colored manuals, backup/archive/navigation helpers and package-size/history/error diagnostics | ADAPT separately specified helpers with declared dependencies, safe quoted arguments and read-only diagnostics. Existing standard utilities are the initial alternative. | T/B |
| History persistence/filtering and completion/correction policy | ADAPT shell-native options explicitly, preserving existing history and choices; validate actual Fish/Zsh behavior rather than importing Bash-oriented variables. | T |
| Existing-user upgrades/removal/login shell | ADAPT guarded source/migration/undo for all selected functions; no automatic shell change, skeleton-only migration or deleting user edits. Running shell state lasts until restart and must be documented. | T/R |

Separately inspected direct-source grant pins for the missing module recipes:

| Component | Primary source grant and full pin | Remaining gate |
| --- | --- | --- |
| Done | [MIT `b86292a52a2b8f646ef8d25daa3cc01ccab60b62`](https://github.com/franciscolourenco/done/blob/b86292a52a2b8f646ef8d25daa3cc01ccab60b62/LICENSE) | Notification/session behavior and opt-in lifecycle. |
| Autopair | [MIT `4d1752ff5b39819ab58d7337c69220342e9de0e2`](https://github.com/jorgebucaran/autopair.fish/blob/4d1752ff5b39819ab58d7337c69220342e9de0e2/LICENSE.md) | ARM recipe and user keybinding preservation. |
| Pure Fish | [MIT `820a96a1b0c18daf54ee188566aaa467cd03d842`](https://github.com/pure-fish/pure/blob/820a96a1b0c18daf54ee188566aaa467cd03d842/LICENSE) | Prompt dependency and customization lifecycle. |
| Fisher | [MIT `791da644d33d392216f6b1a9b5fc1e470db6d7f2`](https://github.com/jorgebucaran/fisher/blob/791da644d33d392216f6b1a9b5fc1e470db6d7f2/LICENSE.md) | Package reviewed pins, no automatic startup download. |
| Oh My Zsh | [MIT `106f9874a22ec8cfa1e69ae8e1143d8720f087dc`](https://github.com/ohmyzsh/ohmyzsh/blob/106f9874a22ec8cfa1e69ae8e1143d8720f087dc/LICENSE.txt) | Selected plugins' individual grants/dependencies. |
| Powerlevel10k | [MIT theme `d05a1b00f9a61f9578bf9dc19b8451942dde8734`](https://github.com/romkatv/powerlevel10k/blob/d05a1b00f9a61f9578bf9dc19b8451942dde8734/LICENSE); [gitstatus GPLv3](https://github.com/romkatv/powerlevel10k/blob/d05a1b00f9a61f9578bf9dc19b8451942dde8734/gitstatus/LICENSE) | Separate daemon license/native ARM/16K checks; do not call whole package MIT. |
| Autosuggestions | [MIT `85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5`](https://github.com/zsh-users/zsh-autosuggestions/blob/85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5/LICENSE) | Opt-in startup/order and editing tests. |
| Syntax highlighting | [BSD-3-Clause `e6683f20e5c38d3e5447f45845d04ddda75d0f23`](https://github.com/zsh-users/zsh-syntax-highlighting/blob/e6683f20e5c38d3e5447f45845d04ddda75d0f23/COPYING.md) | Startup-order and module coexistence. |
| Substring search | [BSD-3-Clause header `a0bdb0d47dbaba31dba2db7af8c48a5d9c74049a`](https://github.com/zsh-users/zsh-history-substring-search/blob/a0bdb0d47dbaba31dba2db7af8c48a5d9c74049a/zsh-history-substring-search.zsh) | Existing bindings and history preservation. |
| Zsh completions | [Zsh permissive grant `6661b4b68173784ba31ef10ce4b5cb1c9ecfdcac`](https://github.com/zsh-users/zsh-completions/blob/6661b4b68173784ba31ef10ce4b5cb1c9ecfdcac/LICENSE) | Root license explicitly gives file-specific provisions precedence; inspect selected files. |

Font evidence must concern the font: [Powerline font tree
`a029626780dd4af32f15a3e708a5b00528c22f1d`](https://github.com/powerline/fonts/tree/a029626780dd4af32f15a3e708a5b00528c22f1d)
contains 26 family-specific license files and no blanket root grant. A Powerline
program license does not clear those fonts. Select an individually licensed font
or use the plain prompt and baseline fonts.

## Complete tagged settings disposition

The [49-file byte/mode inventory](../../packages/settings/upstream-inventory.json)
and [full behavioral audit](../../packages/settings/AUDIT.md) remain the evidence
for tag `764693fe…`. Every path appears below. **ADAPT** is an individually
gated function, not permission to install the monolithic bundle. First-party
GPLv3 source context and individual ISC notices must follow any derivative;
original artwork/branding is excluded. Owners are T with P for platform/default
effects, D for session effects and R for retention/update behavior.

| Installed path | Decision / reason and required alternative |
| --- | --- |
| `/etc/debuginfod/cachyos.urls` | ADAPT only to a symbol service serving actual ARM build IDs; baseline debugger/local symbols otherwise. |
| `/etc/security/limits.d/20-audio.conf` | REPLACE broad audio-group priority limits with tested Asahi audio/rtkit policy; preserve speaker safety and bounded application permissions. |
| `/usr/bin/cachyos-bugreport.sh` | ADAPT a local reviewable report, selected ARM repository/version probes and proven redaction; uploading is a separate explicit action. |
| `/usr/bin/dlss-swapper` | EXCLUDE NVIDIA presets/runtime NGX download; native supported graphics applications are the alternative. |
| `/usr/bin/dlss-swapper-dll` | EXCLUDE NVIDIA/DXVK preset wrapper; no established Apple use case. |
| `/usr/bin/game-performance` | ADAPT optional per-process profile/inhibition only after actual backend, cleanup, power/thermal and sleep tests; ordinary application launch otherwise. |
| `/usr/bin/kerver` | REPLACE x86 loader/config probes with Apple-compatible kernel/platform/version report. |
| `/usr/bin/paste-cachyos` | REPLACE with local export and separately requested support upload to the project's selected endpoint; preserve user review/privacy. |
| `/usr/bin/pci-latency` | EXCLUDE broad PCI latency writes; retain Asahi/per-device baseline. |
| `/usr/bin/sbctl-batch-sign` | EXCLUDE automatic PC EFI signing; supported Apple boot/signing/recovery path is the alternative. |
| `/usr/bin/topmem` | REPLACE with original MIT `cachy-asahi-topmem` development candidate: current-UID RSS inspection, safe output and visible race/error/truncation counts. Source13 controls and independent checks pass; native builds/install/lifecycle/both-model runtime remain open. [Registration](../reviews/topmem-source-registration-root-review.md). |
| `/usr/bin/zink-run` | ADAPT opt-in application experiment only with validated Mesa/Vulkan/GLVND; retain Asahi renderer defaults. |
| `/usr/lib/NetworkManager/conf.d/dns.conf` | ADAPT per-connection DNS migration/undo; keep existing resolver/service integration initially. |
| `/usr/lib/iw-set-regdomain` | ADAPT ISC component for explicit physical country when the supported driver requires it; EXCLUDE timezone inference. |
| `/usr/lib/modprobe.d/amdgpu.conf` | EXCLUDE AMD PC GPU selection; maintained Apple GPU stack instead. |
| `/usr/lib/modprobe.d/blacklist.conf` | EXCLUDE Intel/AMD watchdog blacklist; retain actual Apple kernel policy. |
| `/usr/lib/modprobe.d/nvidia.conf` | EXCLUDE NVIDIA security/performance option; maintained Apple GPU stack instead. |
| `/usr/lib/modules-load.d/ntsync.conf` | ADAPT only for a selected compatible native application/kernel module; omit automatic loading otherwise. |
| `/usr/lib/sysctl.d/70-cachyos-settings.conf` | ADAPT individual justified keys as experiments, not the bundle; per-key dispositions below. |
| `/usr/lib/systemd/journald.conf.d/00-journal-size.conf` | ADAPT retention to measured log/storage needs; preserve acceptance/recovery evidence. |
| `/usr/lib/systemd/system/cachyos-iw-set-regdomain.path` | EXCLUDE localtime-triggered country changes; explicit country workflow instead. |
| `/usr/lib/systemd/system/cachyos-iw-set-regdomain.service` | REPLACE automatically invoked policy with explicit ISC-derived country operation and recorded prior state. |
| `/usr/lib/systemd/system/pci-latency.service` | EXCLUDE blanket PCI writes at startup; retain platform baseline. |
| `/usr/lib/systemd/system/rtkit-daemon.service.d/override.conf` | REPLACE blanket log suppression with targeted diagnostic policy after audio validation. |
| `/usr/lib/systemd/system/session.slice.d/10-ignore-session-slice.conf` | ADAPT only within measured complete cgroup/OOM policy, preserving session/workload behavior. |
| `/usr/lib/systemd/system/system.slice.d/10-oomd-per-slice-defaults.conf` | ADAPT only with critical platform service survival tests and restored OOM baseline. |
| `/usr/lib/systemd/system/user-.slice.d/10-oomd-per-slice-defaults.conf` | ADAPT only with application/session memory-pressure and recovery tests. |
| `/usr/lib/systemd/system/user@.service.d/delegate.conf` | ADAPT only if an audited container/workload needs delegation absent from baseline. |
| `/usr/lib/systemd/system.conf.d/00-timeout.conf` | EXCLUDE blanket 15s/10s timeout shortening; fix a reproduced service defect individually. |
| `/usr/lib/systemd/system.conf.d/10-limits.conf` | ADAPT file limits only for observed application requirements; baseline limits otherwise. |
| `/usr/lib/systemd/timesyncd.conf.d/10-timesyncd.conf` | ADAPT time-source choice without replacing working base time service; explicit network policy. |
| `/usr/lib/systemd/user.conf.d/00-timeout.conf` | EXCLUDE blanket user timeout shortening; preserve application cleanup/session work. |
| `/usr/lib/systemd/user.conf.d/10-limits.conf` | ADAPT only for observed user/application fd needs; preserve baseline otherwise. |
| `/usr/lib/systemd/zram-generator.conf` | ADAPT independently measured size/compressor/priority; do not replace an existing generator/config blindly. |
| `/usr/lib/tmpfiles.d/coredump.conf` | ADAPT retention with debugging/storage requirements; deleted dumps cannot be restored by package removal. |
| `/usr/lib/tmpfiles.d/thp-shrinker.conf` | REPLACE 409/512 page-geometry assumption with actual target geometry and measured threshold; baseline initially. |
| `/usr/lib/tmpfiles.d/thp.conf` | ADAPT only after available control, allocator/compaction latency/power and restoration tests. |
| `/usr/lib/udev/rules.d/20-audio-pm.rules` | EXCLUDE snd_hda_intel/BAT0 policy; preserve Asahi audio/protection and actual battery devices. |
| `/usr/lib/udev/rules.d/30-zram.rules` | ADAPT swappiness and zswap policy as separate experiments, with optional-path handling. |
| `/usr/lib/udev/rules.d/40-hpet-permissions.rules` | EXCLUDE HPET; optional actual rtc access requires a separate need/permissions audit. |
| `/usr/lib/udev/rules.d/50-sata.rules` | EXCLUDE global SATA max-performance policy; any supported external-device tuning is separately measured. |
| `/usr/lib/udev/rules.d/60-ioschedulers.rules` | ADAPT separately for actual offered internal/external schedulers; no unavailable scheduler writes. |
| `/usr/lib/udev/rules.d/69-hdparm.rules` | EXCLUDE automatic ATA/APM/spindown writes; peripheral-specific user need must be assessed separately. |
| `/usr/lib/udev/rules.d/71-nvidia.rules` | EXCLUDE NVIDIA runtime PM; Apple platform power management instead. |
| `/usr/lib/udev/rules.d/85-iw-regulatory.rules` | EXCLUDE automatic inferred country on Wi-Fi add; explicit country workflow instead. |
| `/usr/lib/udev/rules.d/99-cpu-dma-latency.rules` | ADAPT only if actual device/application needs and energy/permissions budgets justify access. |
| `/usr/share/X11/xorg.conf.d/20-touchpad.conf` | REPLACE for Hyprland with its Wayland libinput preference; Xwayland is not an Xorg input session. |
| `/usr/share/glib-2.0/schemas/zz_cachyos.org.gnome.login-screen.gschema.override` | EXCLUDE GDM branding override from Hyprland release; chosen greeter/accessibility is separately integrated. |
| `/usr/share/icons/cachyos.svg` | REPLACE with original licensed independent-port artwork; source code license is not affiliation permission. |

| Sysctl setting in the tagged file | Decision / baseline alternative and individual gate |
| --- | --- |
| `vm.swappiness=100` | ADAPT only after swap topology, pressure/OOM, latency and energy comparison. |
| `vm.vfs_cache_pressure=50` | ADAPT only after reclaim/build/filesystem workload comparison. |
| `vm.dirty_bytes=268435456` | ADAPT absolute writeback bound only after RAM/storage/tail-latency tests. |
| `vm.page-cluster=0` | ADAPT only for actual zram/disk topology and page size. |
| `vm.dirty_background_bytes=67108864` | ADAPT as a separate background writeback experiment. |
| `vm.dirty_writeback_centisecs=1500` | ADAPT only after persistence/latency/power comparison. |
| `kernel.nmi_watchdog=0` | EXCLUDE PC assumption; report actual ARM controls instead. |
| `kernel.unprivileged_userns_clone=1` | ADAPT available key only to reviewed sandbox/security policy. |
| `kernel.printk=3 3 3 3` | EXCLUDE unexplained diagnostic suppression; retain bring-up/recovery evidence. |
| `kernel.kptr_restrict=2` | ADAPT only to selected-base security/debugging needs. |
| `net.core.netdev_max_backlog=4096` | ADAPT only after a reproduced packet/load problem and measured effect. |
| `fs.file-max=2097152` | ADAPT only for actual fd demand; no universal performance claim. |

Current Settings master is a different input, not part of these 49 tagged files.
It adds `xswap-generator` with an explicit GPL-2.0-or-later header and
`audio-pm-ctl` in the existing GPLv3 project context. Inventory their complete
paths/dependencies/lifecycle separately before any next-version recipe. The new
audio/power controls do not override the requirement to preserve tested Asahi
audio and speaker protection. No moving-master additions are silently bundled.

## Smallest first licensed executable candidate

Propose **`cachy-asahi-ksmctl`**, a GPL-2.0-or-later read-only adaptation of
the explicit-grant `ksmctl` source above. The audited executable is **2,606 bytes**,
SHA256 `cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9`,
at the full packaging commit `c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`.
Retain Stelmachenok/CachyOS copyright, full source notice, a GPL license copy,
origin hash and reviewable patch. The existing project's MIT root must not be
misrepresented as relicensing this derivative.

This adds actual optional system-state reporting beyond templates, with no
compiled binary, GUI/toolchain closure, installation hook, default service,
polkit policy or root capability. Proposed runtime dependencies: Bash plus
coreutils for bounded reading; final recipe must declare what the derivative
actually calls. Installed ownership should be only `/usr/bin/cachy-asahi-ksmctl`,
its documentation and license/origin record. Build/check/package staging must be
pure; removal deletes only package-owned files.

Minimal patch scope: keep only read-only status/help/version handling; remove
enable/disable/pause paths and all writes; handle absent/unreadable/malformed KSM
state explicitly with nonzero diagnostic status; never claim missing controls
mean disabled or healthy. Report 0 as stopped with merged pages potentially
retained, 1 as running, and 2 as stopped/unmerge requested, without asserting
that unmerge completed. The [kernel KSM interface](https://docs.kernel.org/admin-guide/mm/ksm.html)
defines these controls and requires CONFIG_KSM for availability. Whether the
selected Asahi kernel exposes them is **NOT VERIFIED**. If unavailable, the tool
reports unsupported and the system retains its baseline; it must not install a
different kernel merely to enable this optional function.

Tests for the eventual implementation: temporary 0/1/2/unknown/missing/unreadable
state fixtures; argument/error behavior; no write commands or state changes;
independent source/notice review; two isolated native ARM package builds and
archive/payload/ownership checks; actual target read-only run with observed
kernel/model. No KSM enablement or speed/memory-saving claim is part of this
candidate. That remains a separate M7 experiment with latency/energy/security
and unmerge/OOM recovery evidence.

`ksmstats` is smaller (1,843 bytes) but has no individual grant header and divides
page counters by 256, assuming 4 KiB. Do not copy it as the first cleared source
or apply that conversion to a 16 KiB target. Any future statistics implementation
needs source-grant resolution and actual page-size-aware arithmetic. The
monolithic KSM recipe's global service overrides are not part of this proposal.

The next substantial management candidate is CLI-only `cachy-update`: native
recipe architecture includes aarch64 and source licensing is explicit, but it
has a much broader closure. `WITH_TRAY=false` disables tray compilation; the
Makefile still installs tray desktop/user units, so a CLI-only package must
explicitly omit those and global autostart. Review news, keyring, mirror, cache,
optional AUR/Flatpak and privilege paths before calling it Apple-ready. A notifier
cannot substitute for actual coordinated full-system upgrade/recovery tests.

## Catalog coverage and explicit exclusions

All **74 recipe paths** in the finite scope below were fetched/read as inert
text at `c7cf5b4f…`: Cachy-prefixed recipes (including nested Calamares), chwd,
six nested scx recipes, and the listed related boot/package/power/handheld tools.
The recipes link to the [pinned catalog tree](https://github.com/CachyOS/CachyOS-PKGBUILDS/tree/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f).
Rows group alternatives/variants; they do not claim unreviewed assets licensed.
Moving sources require new exact pins/BOM before any implementation.

| Recipe paths | Disposition and required function/alternative | Owner |
| --- | --- | --- |
| `cachy-chroot` | ADAPT recovery mounting; explicit Apple target layout and existing supported recovery first. | I/P/T |
| `cachy-update` | ADAPT full-system update CLI and optional notifier; supported signed ARM/platform transaction. | T/R |
| `cachyos-hello`, `cachyos-hello-git` | ADAPT Welcome functions above; prefer pinned stable source, no PC/chwd fallback. | T/D |
| `cachyos-packageinstaller`, `shelly` | ADAPT one curated ARM application frontend; resolve Shelly's own GPLv3/Zig/GTK/ALPM graph before selection. | T/B/R |
| `cachyos-kernel-manager`, `cachyos-kernel-manager-git`, `chwd` | REPLACE unsafe generic kernel/driver actions with Apple compatibility/recovery backend. | P/T/R |
| `cachyos-sysctl-manager`, `cachyos-sysctl-manager-git` | ADAPT supported-key preview/undo, individually measured policies. | T/P |
| `cachyos-settings` | ADAPT individually licensed/gated functions above; no blanket default/service installation. | T/P |
| `cachyos-ksm-settings`, `cachyos-ananicy-rules`, `power-profiles-daemon` | ADAPT status first and measured optional memory/scheduler/power integration; no automatic KSM/priority/scx enablement. | T/P/B |
| `scx/scx-manager`, `scx/scx-manager-git`, `scx/scx-scheds/scx-scheds`, `scx/scx-scheds/scx-scheds-git`, `scx/scx-tools/scx-tools`, `scx/scx-tools/scx-tools-git` | ADAPT optional sched-ext experiment only after kernel/BPF capability, dependency/source pins, native builds and measurements. Manager/scheduler aarch64 declarations do not clear the x86-only loader recipe or establish M2 execution. | P/B/T |
| `cachyos-rate-mirrors`, `rate-mirrors`, `cachyos-mirrorlist` | REPLACE mirror endpoints/ranking/activation with reviewed ARM sources and a licensed implementation; split v3/v4 outputs excluded. | T/R |
| `cachyos-keyring`, `cachyos-hooks` | REPLACE project trust/hook policy for actual independent signed ARM releases; do not grant Cachy x86 trust or import broad hooks automatically. | R/P |
| `cachyos-kdump-tools` | REPLACE PC crash/boot assumptions with target diagnostics; optional crash kernel separately validated. | P/T |
| `cachyos-drm-awaiter` | EXCLUDE PCI GPU chain-load generator/failure behavior; integrate Apple DRM/session readiness using actual supported devices/services. | D/P |
| `cachyos-snapper-support`, `grub-btrfs-support` | ADAPT filesystem-dependent explicit snapshots; REPLACE PC snapshot boot flow with proven Asahi recovery. No automatic root config deletion/cleanup enablement. | I/R/P |
| `systemd-boot-manager`, `limine`, `dracut-cachyos`, `cachyos-grub-theme` | EXCLUDE importing PC loader/theme/initramfs policy; preserve whichever tested boot/initramfs interface the chosen Asahi base actually uses. | P/I |
| `cachyos-calamares`, `cachyos-calamares/deckify`, `cachyos-cli-installer-new`, `cachyos-cli-installer-new-git` | REPLACE PC/handheld partition/chwd/boot flows with supported Asahi installer plus complete project integration (M8). New CLI explicitly configures x86/x86_v3; moving Calamares branch must be pinned. | I/P/C |
| `cachyos-fish-config`, `cachyos-zsh-config` | REPLACE unresolved whole-config reuse with licensed components/original function implementations, preserving user configuration. | T/B |
| `cachyos-alacritty-config`, `cachyos-micro-settings`, `cachyos-firefox-settings` | ADAPT optional terminal/editor/browser preferences only after actual asset grants, ARM package/portal closure and edit-preserving lifecycle. User choices and baseline apps remain alternatives. | T/D/B |
| `cachyos-hyprland-settings`, `cachyos-hypr-noctalia` | ADAPT coherent licensed Hyprland experience; choose one frontend/session set, pin shell/bar/portal assets and test exact Asahi graphics. | D/T/B |
| `cachyos-gnome-settings`, `cachyos-kde-settings`, `cachyos-i3wm-settings`, `cachyos-openbox-settings`, `cachyos-qtile-settings`, `cachyos-wayfire-settings`, `cachyos-xfce-settings`, `cachyos-niri-settings`, `cachyos-niri-noctalia`, `cachyos-jay-noctalia`, `cachyos-mango-noctalia`, `cachyos-mangowc-dms` | EXCLUDE parallel desktop bundles from this Hyprland release; preserve required session/accessibility/workflows in chosen desktop. Additional supported editions require their own finite closure and tests. | C/D |
| `cachyos-nord-gtk`, `cachyos-nord-kde`, `cachyos-wallpapers`, `cachyos-themes-sddm` | REPLACE default branding with original licensed independent-port assets; optional themes require exact grants/attribution and chosen toolkit/greeter compatibility. | D/C |
| `cachyos-plymouth-bootanimation`, `cachyos-plymouth-spinner`, `cachyos-plymouth-theme` | EXCLUDE unvalidated boot decoration from initial platform integration; retain visible diagnostics and tested boot path. Optional animation needs its own DRM/boot/lifecycle gate. | P/D |
| `cachyos-samba-settings` | ADAPT optional deliberate file sharing with declared network/auth/firewall policy and prior service/config restoration; no automatic Samba enablement. | T/R |
| `cachyos-gaming-meta`, `cachyos-gaming-applications`, `dmemcg-cgroup/dmemcg-booster`, `dmemcg-cgroup/kcgroups` | EXCLUDE unmodified lib32/x86/Plasma/dmemcg policies. Supported native ARM application catalog and measured graphics/memory experiments are alternatives; dmemcg-booster recipe even declares unknown license. | C/B/P |
| `handheld/cachyos-handheld`, `handheld/cachyos-vapor`, `handheld/gamescope-session-cachyos`, `handheld/steamos-powerbuttond` | EXCLUDE Steam Deck/handheld firmware, gaming-session/power-button policies; tested M2 Hyprland/input/power workflow provides required functions. | C/D/P |
| `cachyos-benchmarker` | ADAPT applicable workload concepts under the existing M7 harness, not x86 benchmark/software assumptions or an automatic performance verdict. | P/B |

The [upstream custom-application description](https://wiki.cachyos.org/cachyos_basic/why_cachyos/)
was cross-checked to avoid omitting boot management from the branded recipe
filter. License/architecture-specific Proton/Wine builds and compiler/browser
optimizations are M5/M7 package tracks, not required x86 application support on
Apple; the declared release application closure still needs coordinator signoff.

## Apple-safe management design

Use one coordinator-reviewed platform interface shared by the adapted GUI/CLI,
package updater and installer. It must have a read-only capability/status layer
and a separately reviewed privileged transaction layer; packaging/research/build
scripts must never call the latter. Neither GUI names nor `uname -m` establish
exact-model compatibility.

1. **Discover and report:** exact device-tree/model identity, running kernel and
   page geometry, boot/platform package versions, known-good recovery artifacts,
   actual graphics/audio/protection/service versions and supported optional
   controls. Match a release-bound compatibility record for each Air size.
   Unknown models/controls produce unsupported diagnostics, not PC profile
   fallback or a passing check.
2. **Plan:** resolve against the supported signed base/project snapshot, bind
   versions/artifact hashes/dependency closure and protected Asahi components,
   enumerate file/service/boot changes, free space and required restarts. Do not
   import Cachy x86/v3/v4/multilib repositories or install arbitrary AUR kernels.
   Preserve coordinated full-system upgrades; reject incompatible plans instead
   of maintaining an untested partial upgrade.
3. **Apply through narrow privileges:** structured allowlisted operations,
   package-manager locking, pinned state recheck and explicit user action in the
   shipped tool. No arbitrary shell from GUI text, no raw `rm db.lck`, and no
   automatic hardware-profile install. Optional tuning keeps prior effective
   values/service enablement and owns only documented new configuration.
4. **Verify and recover:** versions, hashes, filesystem types/modes/owners,
   service state and restart results; retained baseline packages/platform and
   backup data remain available. A filesystem snapshot alone cannot certify
   Apple boot recovery. Block stable promotion until failure/recovery and
   both-model boot/graphics/audio/input/lock/resume checks actually run.
5. **Preserve customization:** per-user opt-in, migration/undo journals,
   interruption/repetition tests, edit-preserving removal and reinstall. DNS,
   autostart, shell/plugin and power-policy disable actions restore only state
   the tool actually owns, not imagined universal defaults.

The [Asahi platform interoperability specification](https://asahilinux.org/docs/platform/open-os-interop/)
is the platform contract to consult. The actual chosen ALARM boot/update route
must be captured from the target; do not assume a PC ESP, GRUB replacement, EFI
signing command, or Fedora-specific package command. Reusing established Asahi
platform tooling is a required integration choice, not a waiver of R3/R5.

## Build inputs, maintenance and implementation queue

Hello's pinned `build.rs` fetches Cachy RSS during build: capture and pin that
input or remove it from the reproducible build. Package/kernel manager CMake and
Rust dependency acquisition also require frozen library/crate inputs and notices;
top-level tag pins alone do not close that graph. Source code includes MIT
`ini.hpp`; retain its notice instead of assuming one root GPL label covers every
file. These are build/provenance tasks before ARM acceptance, not passed gates.

Suggested coordinator-owned batches, in order:

- **T01:** freeze and implement the bounded KSM-status derivative and licensed
  recipe, with B building/rebuilding and another reviewer checking notices and
  no mutation. Keep its optional unsupported behavior explicit.
- **T02:** license/pin individually chosen shell modules, then extend guarded
  setup/lifecycle to match the shell function matrix. Resolve grants for whole
  Cachy configs or keep functionally specified original replacements.
- **T03:** audit/package CLI update workflow against the selected actual ARM
  base; retain complete install/update/rollback archive and trust evidence.
- **T04:** implement the capability/platform management backend with P/R/I;
  adapt package/Welcome frontends only after structured contracts and protected
  transaction tests are stable.
- **T05:** individually evaluate settings/scheduler/memory/power experiments
  under M7; unchanged baseline is the result when a candidate lacks a measured
  useful effect. License resolution does not justify defaults by itself.
- **T06:** integrate accessible Hyprland/development/application workflows and
  independent onboarding; execute A04/A13 and the unchanged both-size acceptance
  counts against the shipped complete-port release.

Coordinator must reconcile package ownership/selection into shared manifests,
name real maintenance capacity, and freeze the finite supported application set.
This report changes none of those shared records and creates no release package.

Actual audit validation: all **49/49 tagged payload paths** and **74/74 scoped
recipe paths** occur exactly once in their respective disposition tables;
all 74 recipes were retrieved as source text; all **12 sysctl controls** are
individually classified. Temporary primary-source receipts are under
`/tmp/cachy-asahi-m6-audit-iv8cmjna` and
`/tmp/cachy-asahi-m6-tools-py63m18s/source-observation.json`; pins/URLs in this
document are the durable retrieval path. Temporary evidence is not a release
artifact. Documentation-only work requires no implementation test; no native
build, installation, hardware or performance test was run for this audit.


October18 management implementation: the original MIT DNS candidate provides exact-UUID, explicitly selected family/address settings, preview, saved prior state, guarded apply and conflict-preserving undo. Real nmcli offline apply/restore and21 controls pass; these are stored-profile settings, with no claimed live DNS effect or host connection mutation. The original MIT sysctl candidate provides one available key, vm.swappiness, with named baseline/target plans, inspect, durable intent and explicit apply/undo. Nineteen private-tree controls pass on Python3.12/3.14, including a real fixture SIGKILL and recovery. No preset, persistent boot setting, host sysctl write or performance gain is supplied. Both packages stage five owned files; native ALPM, live integration, Qt/polkit/wider key policy and both-model acceptance remain open. See the package READMEs for exact limits and operating steps.

## Explicit KSM scanning implementation

The same-name upgrade alternative [ksmctl2](../../packages/tools/cachy-asahi-ksmctl2/README.md) implements named preview, apply, inspect and undo for global scanning values0/1. It retains the original read-only reporter and saves a durable baseline and intent before a kernel write. Undo restores the scanning scalar; it does not restore memory sharing. It adds no service, defaults or unmerge action.

The source and staged helper pass26 new private-filesystem controls and18 retained read-only/provenance controls on Python3.12 and3.14. Native package builds, signed installation/removal, actual kernel writes, both M2 Air sizes and performance/security/energy effects remain unverified. The selected package manifest still uses the existing reporting recipe until integration validation is recorded.
