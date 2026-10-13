# M5 / R1 desktop and application coverage

Source/metadata audit, October 11, 2026 local / October 12 UTC, after roadmap
commit `506f2596d674a26de8c947ef44728118cd9e2455`. **Proposed finite desktop and
application scope; not an accepted release inventory or installation plan.**
M5/R1 requires broader maintained ARM packages and a complete supported dependency
transaction. The four initial configuration/setup packages remain a foundation.
No package, service or host configuration was installed or changed in this audit.
Only this file is owned by this workstream; shared inventory changes go to the
coordinator. A bounded read-only subreview audited the compiled candidates.

The reviewed maintained-builder successor is now available as
[proposed metadata](../../manifests/proposals/maintained-desktop-v1.json), with the
[finite source/evidence responsibilities](source-evidence-responsibilities.json).
It preserves the existing roots and providers, updates the maintained Vim pair
and corrects the descriptive editor versions. It has no fresh dependency-resolution,
installation or release admission. The earlier observations below remain historical.
See [reconciliation review](../reviews/full-port-coverage-reconciliation-root-review.md).

## Current evidence and the target boundary

The [manifest](../../manifests/packages.toml) selects four development candidates,
all MIT original project material: desktop templates, Fish templates, Zsh
templates and the setup helper. All four passed two native ARM builds with
identical archive bytes at `ebd5812640b0b69f5c09a47752b739e37e338754`; see
[native evidence](../validation/native-arm.md). No candidate is selected for
release. These data/stdlib-script packages introduce no ELF objects.

The exact builder lock has **341 packages**, SHA256
`7f40e51da419514c3ffe4fc9ed5bd9d6f242e576a585347c4799cd20bfd32104`, from
`artifacts/ci/38189520114/decoded/native-evidence/packages.lock`. It was used on
a hosted aarch64 Neoverse-N2 runner with 4096-byte pages. The image is a generic
ALARM build environment, with generic kernel/firmware packages inert inside
Docker. It is neither an Asahi installation image nor a 16K-page M2 test.

It contains Hyprland `0.56.2-4`, Aquamarine `0.15.1-1`, stock Mesa
`1:26.2.4-1`, libinput `1.32.0-1`, systemd `262-1`, D-Bus `1.16.2-1`,
dbus-broker `37-3`, PipeWire `1:1.6.9-1`, WirePlumber `0.5.18-1`, Alacritty
`0.17.0-1`, Wofi `1.5.3-1`, Swaylock `1.8.6-1`, brightnessctl `0.5.1-3`,
Fish `4.9.3-1`, Zsh `5.9.2-1`, Python `3.14.8-1` and base-devel `1-2`.
Installed presence does not prove a running session or working service.
Terminal editing/debugging is already represented by Vim + vim-runtime
`9.2.1164-2`, Nano `9.2-1` and GDB `18.1-1`. The existing onboarding worker uses
actual Vim; this audit does not claim that terminal editors or a C compiler are
missing. A separate GUI editor is outside the proposed minimum.

No accepted exact-machine target inventory, Asahi-compatible graphics provider
transaction or launch/service contract exists for this audit. The preserved
boot/kernel/firmware/Mesa/audio combination must come from the actual supported
Asahi target. Builder packages cannot fill that evidence gap. Both M2 Air sizes,
their 16K runtime, accelerated sessions and A02/A12/A13/A15 remain unaccepted.

## Proposed minimum user experience and direct package roots

This proposal covers a usable development laptop: graphical login, a coherent
Wayland desktop, wireless connectivity, protected audio, safe locking/sleep,
files/browser/editor/terminal work, screenshots/clipboard, native C/C++/Python
development and project package rebuilds. Each row is required functionality;
the named implementation is proposed and may be replaced only by a reviewed
working equivalent. The preserved platform and full base are additional roots,
not supplied by this desktop list.

| Required workflow | Proposed package/function set | Current 341-package builder / integration gap |
| --- | --- | --- |
| Boot, accounts, login and recovery | Actual Asahi boot chain, kernel, firmware and graphics set; base pacman/keyring/PAM/systemd/accounts; retain validated TTY login, with base session launcher | Base tools exist; Asahi platform packages and accepted boot/recovery image are absent. Do not substitute GRUB, PC hardware detection or a generic kernel |
| Accelerated desktop and input | Hyprland + Aquamarine + compatible Asahi Mesa/libdrm/Wayland/libinput closure; existing seat/logind authority | Parser/version tools exist; no physical GPU/input/scaling/notch proof. Stock builder Mesa is not a target selection |
| Session lifetime and environment | Preserve the actual base launcher; propose UWSM only if needed and accepted, systemd user graphical-session lifetime and D-Bus activation | UWSM absent; actual base manager unknown. Retain upstream start-hyprland wrapper when that is the selected launch path |
| Terminal, launcher and shell | alacritty, wofi, fish, zsh, Python; four original templates/helper | Binaries present; template activation, user login/environment and integrated desktop remain unaccepted |
| Status and notifications | waybar, mako; one lifecycle owner for each | Both absent; current template autostart is opt-in/commented. Full-port defaults need actual modules/notification behavior and duplicate-process prevention |
| Authorization, file dialogs and screen sharing | polkit + hyprpolkitagent; xdg-desktop-portal + Hyprland backend + GTK fallback, explicit backend selection | All absent; service activation, exported session environment, browser dialogs/capture and authorization must be tested |
| Wi-Fi, DNS and Bluetooth | networkmanager, its wpa_supplicant backend, network-manager-applet/connection editor; bluez, bluez-utils | All absent; actual radio firmware/driver and NetworkManager/bluetooth service behavior are target gates. Do not run competing network managers |
| Speaker/headset/microphone and routing | Existing Asahi audio/UCM/DSP/plugins/speakersafetyd; compatible PipeWire audio, Pulse interface and WirePlumber; pavucontrol | PipeWire core/WirePlumber alone present. pipewire-audio, pipewire-pulse, pavucontrol and Asahi safety/DSP packages absent; no protected audio result |
| Brightness, lock, idle and lid sleep | brightnessctl, swaylock with base PAM; swayidle if required by chosen session; reviewed logind/lid/inhibitor policy | Manual bindings exist. Automatic locking, inhibitor readiness, lid ordering and resume preservation are not supplied or tested by the templates |
| Clipboard, screenshots and fonts | wl-clipboard, grim, slurp; noto-fonts, noto-fonts-emoji and ttf-dejavu for explicit mono coverage | All absent. Requires tested keybindings, readable fonts, selection/capture and privacy of saved images; no imported wallpaper/theme licensing assumption |
| Browser and editor | Firefox; existing Vim/Nano satisfy terminal editing, with Neovim as a proposed supported addition; xorg-xwayland for declared legacy compatibility | Vim/Nano and Xwayland present; Firefox/Neovim absent. Browser rendering/audio/portal capture and integrated editor clipboard need actual application tests; adding Neovim adds a LuaJIT/16K runtime gate |
| Files, application launch and credentials | Thunar + gvfs for trash/removable files; xdg-utils, xdg-user-dirs; gnome-keyring as explicit secret-service/PAM/session choice | All absent except libsecret. Credential storage/unlock, MIME/default handlers, home-directory preservation and user-consented removable-media behavior must work |
| Native development and rebuilding | git, base-devel (GCC/make/binutils/pkgconf), Python, cmake, meson, ninja, man-db | GCC/make/base-devel/Python present; other named roots absent. Actual clone/edit/build/run/rebuild workflow and docs missing; Rust/Clang may be separately pinned candidate-build extensions |

This expanded proposal has **46 generic direct roots** (listed below), plus the
four project packages and the actual target base/platform set. Neovim is an
additional supported application choice; retaining only existing Vim/Nano is
sufficient for the minimum editing function and removes that extra root and its
unique dependencies when resolving the release. Eleven generic roots occur in the
builder lock; 35 do not. Missing roots are not automatically installed by an
audit script. Accessibility/input-method/localization requirements must be
declared with intended languages/users before release; native AT-SPI dependencies
alone do not demonstrate a usable accessible session. Games, CUDA/x86 binaries,
third-party AUR automation, elaborate themes, wallpaper bundles, hibernation and
additional languages/toolchains are outside this proposed minimum application
set. This does not waive any core hardware or lifecycle acceptance requirement.

Hyprland's [primary utility guidance](https://wiki.hypr.land/Useful-Utilities/Must-have/)
supports treating notification, portal and authorization integration as explicit
desktop work. [UWSM's upstream contract](https://github.com/Vladimir-csp/uwsm)
provides environment/session lifecycle rather than a new display/login manager.
This proposal does not require a new greeter: keep the working base login path
until a separately audited graphical greeter is justified.

Asahi's [audio integration requirements](https://asahilinux.org/docs/sw/audio-userspace/)
require coordinated DSP/protection/kernel deployment. A working generic Pulse
interface, volume limit or package-name provider is insufficient. Preserve the
base's tested DSP, safety daemon and microphone processing; freeze all their
plugin dependencies with the platform owner. A missing core platform function is
a corrective task, not an optional upstream limitation.

## Dependency graph and provenance limits

A read-only fetch of official ALARM core/extra metadata produced a **name-only
graph of 586 records**, including every virtual-provider alternative reachable
from those 46 roots, with no missing package names. This graph is not an
installable closure: it ignores version solving, conflicting alternatives,
repository priority, source/ABI compatibility and target Asahi replacements.
For example `opengl-driver` expands to stock Mesa, Mesa Amber and NVIDIA;
`ttf-font`, JACK and several SONAMEs also have alternatives. None is automatically
selected. The final closure must pick one compatible provider set and retain
the complete actual native libalpm transaction against the target base.

The metadata observation was `2026-10-12T02:22:34.246306+00:00`:

| Official metadata | SHA256 | Bytes |
| --- | --- | --- |
| [core.db](https://fl.us.mirror.archlinuxarm.org/aarch64/core/core.db) | `5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08` | 256696 |
| [extra.db](https://fl.us.mirror.archlinuxarm.org/aarch64/extra/extra.db) | `66cfbeae024c325e19ba7334afcb0ff2ab892ba4f0789216b358648f7647b480` | 10613897 |

The normalized graph, direct dependencies, provider alternatives, versions,
package filenames/content hashes, metadata licenses and upstream URLs are retained
locally at `/tmp/cachy-desktop-coverage-3m_2ggoq/arm-metadata.json`, SHA256
`4d669e76b33fef6152af14405174f302c54adb77c2f2acd25c8d98af910f1d65`.
The live URLs may change. This temporary audit cache is not a published release
snapshot, retained package bytes or authenticated install input. Newly observed
packages/signatures were not downloaded or verified. The independently signed
341-package builder inputs retain their separate existing audit/evidence.

Package version and license fields below are repository metadata observations,
not a file-by-file license audit or an immutable upstream source revision. Each
project-built recipe needs exact source commits/archive hashes, notices, patch
licenses, vendored dependency/license closure, toolchain and two clean builds.
Each upstream-supplied package needs retained authenticated archive/signature
bytes, precise version/provider identity, source recipe/BUILDINFO provenance and
compatible update ownership. No floating page or architecture label closes those
gates. The web Neovim page lagged at 0.12.5 while the captured database has 0.12.6;
the table reports the database observation, not an assumed reconciled snapshot.

## Package and integration ownership

| Package class | Proposed source/build responsibility | Project responsibility |
| --- | --- | --- |
| Four original MIT packages | Project builds and signs its own pinned inputs | Recipe maintenance, migration/ownership, user lifecycle and target compatibility |
| Next compiled Cachy-derived package | Project-owned aarch64 recipe following separately audited Cachy source/packaging | Clean builds, signed artifacts, source/licenses/patches, 16K execution and any enabled behavior |
| Generic desktop/app/library roots | Maintained ALARM ARM packages initially, with retained pins/signatures; no claim that untouched inputs are project optimized | Freeze complete provider/version closure, test integrated workflows, monitor updates and coordinate promotion |
| Apple boot/kernel/firmware/Mesa/audio | Actual maintained Asahi-derived target stack, coordinated with Asahi ALARM/platform maintainers | Exact both-model compatibility, update sequencing, regression response and known-good recovery |
| Session/default integration | New reviewed project integration only where the base lacks required functionality | Ordered activation, session lifetime, no duplicate agents/daemons, configuration preservation and hardware checks |
| Cachy upstream desktop/shell/settings assets | Currently deferred, unresolved grant/notices and obsolete/platform-specific behavior | Obtain clear upstream terms or supply independently licensed adaptations; original MIT does not relicense excluded assets |

Do not count a downloaded upstream ARM binary as project-built or optimized.
Do not count an original template as completed porting of all Cachy behavior.
Roles in this audit are workstream assignments; permanent named package/platform/
release custodians remain a coordinator requirement for sustained maintenance.

The existing [desktop audit](../audits/desktop.md) still governs excluded Cachy
assets: source tag `1.4.4` at `449635e3718f4f178503682b29b159b0a758e5e7`, recipe
commit `c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`. Recipe GPL-1.0-only metadata
does not establish the grant for all bundled configurations/scripts/assets. No
license resolution is invented here. The manifest/native evidence supersedes
the audit's older native-build NOT RUN statements only for the four original
recipes; its source/platform/license findings still apply.

Immutable audited API references: Hyprland v0.56.2
`efb50993780079460b0cbed1363e2166a2de1d9f`
([BSD-3-Clause license](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/LICENSE)),
Aquamarine v0.15.1 `f31c47a1b9d300847d8fc3108ad959448103dfc1`
([BSD-3-Clause license](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/LICENSE)),
and Asahi ALARM repository `9821995723fa3326553d0d942d0b900173462ea8`
([base description](https://github.com/asahi-alarm/asahi-alarm/blob/9821995723fa3326553d0d942d0b900173462ea8/README.md)).
The latter describes minimal/GNOME/Plasma choices; it is not a shipped project
Hyprland release. Target kernel/firmware/Mesa/audio source revisions and all
remaining app source pins are outstanding release-inventory work.

## Next compiled package proposal

Propose **cachy-update 4.4.2** as the next compiled Cachy-derived development
recipe. It combines Bash orchestration with an actual Rust tray executable; keep
the tray enabled so this is not another scripts-only milestone. This is the
smallest qualifying candidate inspected by compiler/GUI dependency scope, not
a measured smallest binary or performance result. Recipe/manifest remain unchanged.

| Audited input | Immutable identity / authoritative source |
| --- | --- |
| Cachy recipe | [c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachy-update/PKGBUILD](https://github.com/CachyOS/CachyOS-PKGBUILDS/blob/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachy-update/PKGBUILD), SHA256 `7086b008bbb19aaf68dde600b00ff08cf300dca2834576c305182422e48a7ebc` |
| Cachy source | [e2b1b7144be71cf392809f48d1440f8da1d9c81a](https://github.com/CachyOS/cachy-update/tree/e2b1b7144be71cf392809f48d1440f8da1d9c81a) |
| Derived-source evidence | Actual Antiz96/arch-update fork; [comparison](https://github.com/CachyOS/cachy-update/compare/f4381b711a1bd81529a12790ee340a53a17a503a...e2b1b7144be71cf392809f48d1440f8da1d9c81a) against upstream v4.4.2 `f4381b711a1bd81529a12790ee340a53a17a503a` is five commits ahead; changes include compiled tray title, icons, notifications and timer |
| License | [LICENSE](https://github.com/CachyOS/cachy-update/blob/e2b1b7144be71cf392809f48d1440f8da1d9c81a/LICENSE) and inspected Rust/Bash SPDX headers: GPL-3.0-or-later. Full artwork/dependency attribution still needs packaging review |
| Cargo inputs | [Cargo.toml](https://github.com/CachyOS/cachy-update/blob/e2b1b7144be71cf392809f48d1440f8da1d9c81a/src/tray/Cargo.toml), Rust edition 2024; [Cargo.lock](https://github.com/CachyOS/cachy-update/blob/e2b1b7144be71cf392809f48d1440f8da1d9c81a/src/tray/Cargo.lock) SHA256 `0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753`, 168 package entries, external entries from registries |

The [Makefile](https://github.com/CachyOS/cachy-update/blob/e2b1b7144be71cf392809f48d1440f8da1d9c81a/Makefile)
builds the GLib/GIO/gettext/ksni D-Bus StatusNotifier tray, translations and
manpages; no Qt/GTK runtime is required by the tray. Direct build requirements
are Cargo/Rust, Git, scdoc, gettext/msgfmt, pkg-config and GLib development
inputs; Bats runs upstream checks. The current builder needs a separately
pinned extension, including an offline Cargo source/license closure. Full
application runtime roots declared by the recipe are Bash, systemd, pacman,
pacman-contrib, archlinux-contrib, curl, fakeroot, util-linux, htmlq, diffutils,
hicolor-icon-theme, glibc, libgcc, glib2 and xdg-utils. These are an additional
candidate closure, not already supplied by the desktop root set.

The recipe declares aarch64; inspected tray/build source has no demonstrated
x86-only instruction requirement. Neither fact is a build or M2 result. Require
two fresh native builds, vendored dependency license/source checks, complete ELF
alignment/loading checks, isolated private-D-Bus tray tests with mocked command
endpoints, and actual 16K-page execution before target selection. Preserve
GPL attribution/notices and corresponding sources. No speedup is claimed.

The first development recipe should use DESTDIR, omit the upstream recipe's
global `/etc/xdg/autostart/arch-update-tray.desktop` copy, and enable no user
timer/service. Ordinary `--check` differs from `--check --enable`, which enables
the timer. Audit `/usr/bin/arch-update` conflicts/ownership and all tray action
endpoints: the full updater can run pacman -Syu, removal/cache operations,
service restarts and reboot requests. Kernel reboot detection checks
`/usr/lib/modules/$(uname -r)/vmlinuz`; that assumption is unverified for Asahi.
This package cannot be accepted as an Apple-safe updater merely because its
tray compiles. Repository/trust/update actions need a dedicated R4/R5 review and
the project's compatible base+platform transaction contract. Do not add optional
AUR/Flatpak helpers or enable update automation as a side effect of packaging.

| Other inspected compiled candidate | Pin / audit result | Decision |
| --- | --- | --- |
| ananicy-cpp | Canonical v1.2.0 `cf5ac2eb7b9660794f26f274975066f33359c63e`; C++20, fmt/spdlog/JSON; used by Cachy but no derivative recipe found in complete pinned Cachy PKGBUILDS or observed aur-derived `d2a849f7987d38e37ea75c78b70f89c5e0f592bb` trees | Smaller build-first alternative, but not established as Cachy-derived; later maintained-upstream/performance candidate with activation and measured priority/scheduling/OOM/cgroup tradeoffs |
| cachyos-sysctl-manager | v1.2.0 `fe92490bdb1ac522357581a51bf389ac276bb17f`; [C++23/Qt6 build](https://github.com/CachyOS/sysctl-manager/blob/fe92490bdb1ac522357581a51bf389ac276bb17f/CMakeLists.txt), root Bash bridge and fixed /tmp file; copied Garuda helper attribution requires precise license provenance | Resolve privilege/tempfile and copied-source terms first; no invented clearance |
| cachyos-packageinstaller | v1.6.2 `9b1ed3da1589b87000aae5120504366408ccef10`; [Qt6/C++ plus Rust/libalpm build](https://github.com/CachyOS/packageinstaller/blob/9b1ed3da1589b87000aae5120504366408ccef10/CMakeLists.txt), GPL recipe/LICENSE, Polkit and multiple fetched dependencies | Larger privileged transaction surface; later applicable-tool port |
| cachyos-hello | v0.28.1 `efd467041a9accb461bc3bf8a096a6627f795293`; [GTK3/Rust/libalpm/chwd manifest](https://github.com/CachyOS/CachyOS-Welcome/blob/efd467041a9accb461bc3bf8a096a6627f795293/Cargo.toml), GPL recipe/LICENSE, recipe x86_64 only | Broader Apple-aware tool adaptation; architecture label changes do not suffice |
| rate-mirrors / Cachy wrapper | Compiled upstream tool with Cachy patches has CC-BY-NC-SA-3.0 terms; wrapper is shell/systemd configuration | Not selected as straightforward freely redistributable compiled milestone; no assumed relicensing |

Candidate subreview retained temporary primary sources under
`/tmp/cachy-compiled-candidate-audit`. All candidate results are source audits;
no build, install, updater, privilege action or service activation was run.

## Coordinator tasks and acceptance

| Proposed task | Owner role / prerequisite | Concrete completion evidence |
| --- | --- | --- |
| D01 Freeze finite release roots and actual target inventory | Coordinator + desktop/platform; exact machines/base access | Base pacman lock, protected stack, source/provider/version set, supported application functions and accountable maintainers |
| D02 Resolve full target transaction | Build/release + platform; D01 | Native libalpm dry-run then disposable/target staging execution; no protected replacement; full dependency/conflict/file/hook closure, signed retrievable package bytes |
| D03 Audit and build first compiled Cachy candidate | Package/build + independent reviewer; immutable source/licenses and separately pinned builder extension | Reviewable recipe, actual aarch64 clean build pair, ELF/dependency/ownership checks, 16K runtime gate and retrievable provenance; no performance claim |
| D04 Implement coherent session integration | Desktop + tools; D01/D02 launch contract | One owner per session service, portal/auth/audio/notification/bar/network readiness, lock-before-sleep ordering and user config preservation |
| D05 Exercise actual application/development workflows | Desktop/validation + independent user; installed full candidate | Browser page/video/mic/portal capture; files/trash/removable media; clipboard/screenshot; clone/edit/C++/Python build/run and package rebuild on both Air sizes |
| D06 Maintain next complete dependency/security release | Named release/package/platform maintainers; D02–D05 | Updated pinned package set, rebuilt owned artifacts, signed promotion, subsequent actual upgrade/recovery and regression records |

D03 can begin before physical access with honest runtime gates. D01/D02 must
precede target mutation; adding all 586 graph records is not an implementation.
Both models must independently meet A02/A03/A04 and A12–A15 on the same full-port
release, with the existing boot/lock/lid/lifecycle repetition counts preserved.
Parser checks, a virtual GPU session and hosted 4K ARM builds cannot substitute
for those checks. M5 and full-port acceptance remain incomplete.

## Generic root metadata observation

All rows are proposed maintained-upstream inputs, except the separate next
project-built candidate. Source links are upstream URLs reported by ALARM.
`custom`/`LicenseRef` terms require their actual license text in the later source
audit; `GPL` without a version is retained as observed rather than guessed.

| Root / authoritative upstream | Observed ARM package version | Metadata license | Builder |
| --- | --- | --- | --- |
| [hyprland](https://github.com/hyprwm/Hyprland) | `0.56.2-4` | BSD-3-Clause | Present: `0.56.2-4` |
| [alacritty](https://github.com/alacritty/alacritty) | `0.17.0-1` | Apache-2.0, MIT | Present: `0.17.0-1` |
| [wofi](https://hg.sr.ht/~scoopta/wofi) | `1.5.3-1` | GPL-3.0-or-later | Present: `1.5.3-1` |
| [swaylock](https://github.com/swaywm/swaylock) | `1.8.6-1` | MIT | Present: `1.8.6-1` |
| [swayidle](https://github.com/swaywm/swayidle) | `1.9.0-1` | MIT | Absent |
| [wireplumber](https://pipewire.pages.freedesktop.org/wireplumber/) | `0.5.18-1` | MIT | Present: `0.5.18-1` |
| [pipewire-audio](https://pipewire.org) | `1:1.6.9-1` | MIT | Absent |
| [pipewire-pulse](https://pipewire.org) | `1:1.6.9-1` | MIT | Absent |
| [brightnessctl](https://github.com/Hummer12007/brightnessctl) | `0.5.1-3` | MIT | Present: `0.5.1-3` |
| [waybar](https://github.com/Alexays/Waybar/) | `0.15.0-3` | MIT | Absent |
| [mako](https://mako-project.org) | `1.11.0-1` | MIT | Absent |
| [xdg-desktop-portal](https://flatpak.github.io/xdg-desktop-portal/) | `1.22.1-2` | LGPL-2.1-or-later | Absent |
| [xdg-desktop-portal-hyprland](https://github.com/hyprwm/xdg-desktop-portal-hyprland) | `1.4.1-2` | MIT | Absent |
| [xdg-desktop-portal-gtk](https://github.com/flatpak/xdg-desktop-portal-gtk) | `1.15.3-1` | LGPL-2.0-or-later | Absent |
| [polkit](https://github.com/polkit-org/polkit) | `127-3` | LGPL-2.0-or-later | Absent |
| [hyprpolkitagent](https://github.com/hyprwm/hyprpolkitagent) | `0.2.0-1` | BSD-3-Clause | Absent |
| [uwsm](https://github.com/Vladimir-csp/uwsm) | `0.27.0-1` | MIT | Absent |
| [networkmanager](https://networkmanager.dev/) | `1.58.1-2` | LGPL-2.1-or-later, GPL-2.0-or-later | Absent |
| [wpa_supplicant](https://w1.fi/wpa_supplicant/) | `2:2.12-1` | BSD-3-Clause | Absent |
| [network-manager-applet](https://gitlab.gnome.org/GNOME/network-manager-applet) | `1.36.0-2` | GPL-2.0-or-later | Absent |
| [bluez](http://www.bluez.org/) | `5.87-2` | GPL-2.0-only | Absent |
| [bluez-utils](http://www.bluez.org/) | `5.87-2` | GPL-2.0-only | Absent |
| [wl-clipboard](https://github.com/bugaevc/wl-clipboard) | `1:2.3.0-1` | GPL-3.0-or-later | Absent |
| [grim](https://gitlab.freedesktop.org/emersion/grim) | `1.5.0-2` | MIT | Absent |
| [slurp](https://github.com/emersion/slurp) | `1.5.0-2` | MIT | Absent |
| [noto-fonts](https://fonts.google.com/noto) | `1:2026.10.01-1` | OFL-1.1-no-RFN | Absent |
| [noto-fonts-emoji](https://www.google.com/get/noto/) | `1:2.051-1` | OFL-1.1-no-RFN | Absent |
| [ttf-dejavu](https://dejavu-fonts.github.io) | `2.37+18+g9b5d1b2f-8` | custom | Absent |
| [xorg-xwayland](https://xorg.freedesktop.org) | `24.1.14-1` | LicenseRef-Adobe-Display-PostScript, BSD-3-Clause, LicenseRef-DEC-3-Clause, HPND, LicenseRef-HPND-sell-MIT-disclaimer-xserver, HPND-sell-variant, ICU, ISC, MIT, MIT-open-group, NTP, SGI-B-2.0, SMLNJ, X11, X11-distribute-modifications-variant | Present: `24.1.14-1` |
| [neovim](https://neovim.io) | `0.12.6-1` | Apache-2.0, LicenseRef-vim | Absent |
| [firefox](https://www.firefox.com/) | `157.0.1-1` | MPL-2.0 | Absent |
| [thunar](https://docs.xfce.org/xfce/thunar/start) | `4.20.10-1` | GPL-2.0-or-later, LGPL-2.1-only | Absent |
| [gvfs](https://gitlab.gnome.org/GNOME/gvfs) | `1.62.0-3` | LGPL-2.0-only | Absent |
| [pavucontrol](https://freedesktop.org/software/pulseaudio/pavucontrol/) | `1:6.2-1` | GPL-2.0-or-later | Absent |
| [git](https://git-scm.com/) | `2.56.0-1` | GPL-2.0-only | Absent |
| [base-devel](https://www.archlinux.org) | `1-2` | GPL | Present: `1-2` |
| [cmake](https://www.cmake.org/) | `4.4.4-1` | BSD-3-Clause | Absent |
| [meson](https://mesonbuild.com/) | `1.12.1-2` | Apache-2.0 | Absent |
| [ninja](https://ninja-build.org/) | `1.13.2-3` | Apache-2.0 | Absent |
| [python](https://www.python.org/) | `3.14.8-1` | PSF-2.0 | Present: `3.14.8-1` |
| [man-db](https://gitlab.com/man-db/man-db) | `2.13.1-2` | GPL-2.0-or-later AND GPL-3.0-or-later | Absent |
| [xdg-utils](https://gitlab.freedesktop.org/xdg/xdg-utils) | `1.2.1-2` | MIT | Absent |
| [xdg-user-dirs](https://www.freedesktop.org/wiki/Software/xdg-user-dirs) | `0.20-1` | GPL-2.0-or-later | Absent |
| [fish](https://fishshell.com/) | `4.9.3-1` | GPL-2.0-only AND BSD-3-Clause AND ISC AND MIT AND PSF-2.0 | Present: `4.9.3-1` |
| [zsh](https://www.zsh.org/) | `5.9.2-1` | custom | Present: `5.9.2-1` |
| [gnome-keyring](https://gitlab.gnome.org/GNOME/gnome-keyring) | `1:51.1-1` | GPL-2.0-or-later, LGPL-2.1-or-later | Absent |

Reviewed local inputs: roadmap/goal/outline/acceptance, manifest, desktop audit
and upstream inventory, exact successful native builder lock, current desktop
templates/workstream, and prospective lifecycle/handoff controls. Documentation
only; no implementation tests, package builds, session activation or hardware
checks were required or performed for this coverage audit.
