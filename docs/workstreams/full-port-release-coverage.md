# Full-port release coverage: reconcile the existing plan

## November 28 coverage reconciliation

The [desktop scope](../port/desktop-coverage.md), [tool dispositions](../port/tools-functionality.md)
and [installation route](../port/installation-route.md) define the required
functions. The maintained generic metadata query resolves 45 roots and four
provider bindings on a 341-package builder, for a 574-package result. A
separate Asahi metadata replay resolves 60 proposed roots and four provider
bindings in the 629-package candidate from a 261-package Asahi Minimal seed.
The Asahi scope includes the earlier 55 target pins and five Preview 1
packages under the three proposed maintenance updates. The composition
remains **unapproved**.
[Reviewed generic query](../reviews/maintained-desktop-resolution-actual01-root-review.md#selection-and-exact-bindings)
· [Asahi coverage replay](../distribution-feasibility.md#november-25-package-coverage-replay)
· [Earlier Asahi targets](supported-composition.md#actual-results-and-next-decisions)
· [Asahi629 selection](supported-composition-maintenance.md#november-25-offline-selection-and-custody)

The November 27 TEST-signed rehearsal advanced from 261 to 629 packages in
offline emulated AArch64 with 16 KiB pages and the generic R132 kernel.
Reversal retained 629 packages and restored the original NetworkManager,
Perl and Python versions. All 362 protected boot and mount entries matched,
and the original initramfs was restored. The scoped project Qtbase 6.12.0-3
swap on that reversal inventory passed software probes before and during
replacement and restored the official provider and exact inventory.
Post-restoration Qt runtime and the 6.12.0-4 parity trial remain open.
Default Asahi boot and recovery, accelerated graphics, and release
validation on both physical Air sizes remain open.
[Asahi629 run](supported-composition-maintenance.md#november-27-offline-installation-and-reversal)
· [Qt 6.12.0-3 result](../../scripts/integration/qt612_r132_replacement/README.md#corrected-scoped-guest-trial-november-27)
· [Qt 6.12.0-4 parity](../../scripts/integration/qt612_r132_replacement/PARITY-TRIAL.md)

The package inventory contains 55 entries, including 49 candidates and six
deferred upstream entries. Fourteen candidates are selected for development,
and stable selection is open.
The October ten listed below are joined by DNS, Sysctl, Maintenance and
Session Diagnostics. All 14 have recorded native build and scoped lifecycle
evidence in the inventory. Asahi629 installed four of them, the Hyprland
settings, Fish config, Zsh config and Setup packages. It also installed
First Login 0.1.0-3 as a Preview package. First Login's graphical journey
is still open, and the other ten development-selected packages fall outside
that rehearsal.
[Package inventory](../../manifests/packages.toml)
· [Lock-to-manifest reconciliation](remaining-development-audit-20261127.md#next-engineering-work)

Release coverage still needs a decision on the applicable management and
shell packages, the PipeWire AAC provider, and exact protected audio and
graphics versions. Bind each selected package to its archive and signing
authority, corresponding source and notices, update owner, and installed
dependency, ABI and hook evidence. Record the unresolved Python and Perl
recipe custody, identify maintenance and signing custodians, and measure
actual build and repository capacity. M5/A12 and B15/A11 remain incomplete.
[Source custody](supported-composition-update-sources.md)
· [Implementation status](../implementation-status.md)

M9 requires the shipped complete-port release and A01–A15 evidence,
including both physical Air sizes, independent onboarding, measured final
systems, production trust and maintained ownership. The subsequent stable
full-port release must demonstrate an actual upgrade and recovery against
the same acceptance process. Local promotion signs the gate record and
selects a staged bundle on disk. Production distribution and full-port
acceptance require separate evidence.
[Acceptance and signoff](../acceptance.md#evidence-and-signoff)
· [Local release gate contract](../release/interface.md#stable-gate-envelope-version-1)

## October 13 crosswalk and proposal

The October source-only audit joined the desktop coverage, generic
resolution, tool dispositions and installation route. It recorded
`coverage-reconciliation.json`, `checks.json` and `receipt.json` under
the private directory `artifacts/reviews/full-port-release-coverage-proposal-20261013/`.
The tracked independent review authenticates the 37 leaves, the original
guide and the historical receipt
`15dcd1924bd69182bd894981b179f65de74ad3a9aae90613697c28f1679e5eac`.
The original guide is preserved at commit `d8cb157f5`.
[Independent October review](../reviews/full-port-release-coverage-root-review.md)
· [Maintained-input successor](full-port-coverage-reconciliation.md)
· [Generic resolution](port-resolution.md)

### Exact inputs and their different scopes

| Input | Exact identity | What it supplies / leaves open |
| --- | --- | --- |
| Maintained native input lock | `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f` | Successor source/build inputs; not a target release. Retained native results are reported separately in current status |
| Maintained builder inventory | `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`, 341 rows | Generic native build baseline, Vim/vim-runtime `9.2.1178-1`; contains stock Mesa and no linux-asahi/protected audio |
| Existing refreshed desktop proposal | `d7189a0526cfaa09d75011f06cdb6a5811dbd70a7b419784681ea669fa76b131`, 45 roots | Binds earlier input `3c16c37d…` and 341 inventory `89bdb06f…`; must be explicitly reconciled to maintained inputs rather than silently relabeled |
| Generic metadata resolution | `b7f53cc24eb8e12119050c76554f78f7daa215d6fa048c2c4336037f824b2deb`, 574 records | Earlier 341 plus233 additions; metadata resolution is separate from installation, source correspondence and Asahi compatibility |
| Generic addition identities / historical data receipt | Lock `96bce50d99ebcc10ac3897f17f05e66ec185aad85e807e5d09928c1cbfa5c9a8`; receipt `0d172a7aed58660115ae087a31faf4bb57f564b799f5920273589a3cc339bc40` | 233 exact archive/signature identities and previously recorded authentication. This audit hashes/reads their metadata; it repeats no signature or archive operation |
| Retained Asahi minimal-image inventory | `5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941`, 261 records | Image metadata, not either Air's installed inventory; no Mesa/PipeWire/WirePlumber/asahi-audio/speakersafetyd |
| Coordinated target metadata candidate | Inventory `6662edebe748b7ea2d72f0236e5fbe96d6ab2b40e6e5b2980ae9575b4bad41f1`; report `bdf171c691f88340079d9632b801190d7866d06e3822c5cb83c7086245a8a030`, 624 records | All45 roots appear, but the alternative is explicitly unadopted and every transaction/runtime/hardware acceptance flag remains false. Its metadata prepare PASS cannot authorize installation |

The crosswalk confirms 11 of45 roots in maintained341 and34 absent; seven in retained261 and38 absent. Two existing image root versions differ from the proposal: NetworkManager `1.58.1-1→1.58.1-2` and Python `3.14.7-1→3.14.8-1`. Every root's exact proposed, maintained, image, generic574 and unadopted624 version is recorded individually. These counts are membership observations, not missing-function or dependency-installation results.

Only Vim/vim-runtime changed between the earlier and maintained 341-package
inventories (`9.2.1164-2` to `9.2.1178-1`). The earlier proposal described
Vim `9.2.0849-1` and Nano `9.1-1`. Its actual generic574 metadata had Vim
`9.2.1164-2` and Nano `9.2-1`. The image/624 alternative had
Vim/vim-runtime `9.2.1046-1` and Nano `9.2-1`. The maintained successor
corrected the editor descriptions to Vim `9.2.1178-1` and Nano `9.2-1`.
Neovim remains optional.
[Maintained desktop proposal](../../manifests/proposals/maintained-desktop-v1.json)

### Named coverage to retain

The following are the existing45 generic root proposals, with exact versions and available archive identities in the crosswalk. They are upstream-supplied candidates initially; none is selected for release by this audit.

| Existing function group | Named roots |
| --- | --- |
| Desktop/session/input/lock | hyprland, alacritty, wofi, swaylock, swayidle, brightnessctl, waybar, mako, uwsm, xorg-xwayland |
| Authorization/dialogs/capture | polkit, hyprpolkitagent, xdg-desktop-portal, xdg-desktop-portal-hyprland, xdg-desktop-portal-gtk |
| Audio user services | wireplumber, pipewire-audio, pipewire-pulse, pavucontrol; protected Asahi audio is an additional platform obligation |
| Network/radio | networkmanager, wpa_supplicant, network-manager-applet, bluez, bluez-utils |
| Clipboard/screenshots/fonts | wl-clipboard, grim, slurp, noto-fonts, noto-fonts-emoji, ttf-dejavu |
| Applications/files/credentials | firefox, thunar, gvfs, xdg-utils, xdg-user-dirs, gnome-keyring; existing Vim/Nano supply terminal editing |
| Development/shells | git, base-devel, cmake, meson, ninja, python, man-db, fish, zsh |

UWSM and swayidle are conditional implementations in the existing functionality plan even though its current45-root proposal includes them. Decide against the actual base launcher/idle contract, then re-resolve any changed root set. Do not remove session lifetime or lock-before-sleep requirements when excluding a particular package.

The additional base is the retained261 image plus the existing eight proposed protected roots: `asahi-meta 5-6`, `grub 2:2.16-3`, `mkinitcpio 42.1-1`, `lzfse 1.0-1`, `alsa-ucm-conf 1.2.16.1-1`, `linux-firmware 20260916-1`, `archlinuxarm-keyring 20240419-2`, `archlinux-keyring 20260909-1`. Their existing all-witness protected graph is201 records. That preservation proposal is metadata, not an accepted platform policy. GRUB is observed in this Asahi image; preserving its established loader is distinct from importing PC bootloader/hardware-detection assumptions.

Named observed platform inputs include `linux-asahi 7.1.13.asahi3-2`, `m1n1 1.6.1-1`, `uboot-asahi 2026.07.asahi2-1`, `asahi-scripts 20260127.1-1`, `asahi-fwextract 0.9.2-1`, `asahi-alarm-keyring 20241216-1`, `asahi-configs 20251217-1`, `alsa-ucm-conf-asahi 10-1`, `asahi-meta 5-6` and inherited `tiny-dfr 0.3.7-1`. An inherited Touch Bar package is not a required M2 Air feature. Required missing audio candidates remain `asahi-audio 4.1-1`, `speakersafetyd 2.0.1-1`, `bankstown 1.1.0-2`, `triforce-lv2 0.3.2-1` and their complete declared dependencies. The624 metadata alternative contains these additions and Mesa `1:26.2.4-1`; it supplies no accepted graphics-driver/source/ABI/protection binding or running session.

The October inventory selected ten project development candidates. The audit captured their recipe hashes, declared upstream revisions and then-current evidence pointers:

| Candidate class | October packages / source responsibility | Release work identified in October |
| --- | --- | --- |
| Original integration packages | cachy-asahi-hyprland-settings, cachy-asahi-fish-config, cachy-asahi-zsh-config, cachy-asahi-setup; project-authored MIT recipes | Four native build pairs exist; target transaction, coherent session, configuration lifecycle and maintained releases remain unfinished |
| Executable management | cachy-asahi-ksmctl (adapted Cachy source), cachy-asahi-update (pinned `e2b1b714…`), cachy-asahi-topmem (original) | KSM inventory records a native pair; updater/Topmem inventory records native NOT RUN. Current signer/start and composed-service failures are not successful addon or full-system results. Compiled updater/tray, safe update behavior and lifecycle remain required |
| Individually packaged shell modules | cachy-asahi-zsh-autosuggestions `85919cd1…`, cachy-asahi-fish-bang-bang `ec991b80…` | Licensed component packaging and source/host controls do not close native builds, existing-user lifecycle, declared shell floors or both-Air workflows |
| Source-built dependency correction | cachy-asahi-fdk-aac `a68a51aa…` | Resolve source delivery/notices and exact binary recipe correspondence; build/rebuild the selected source packet; verify explicit libfdk-aac provider substitution, actual ELF/ABI/AAC-plugin and lifecycle evidence |

The crosswalk records inventory declarations from October. The tool
dispositions cover 74 recipes and 49 settings paths. They exclude
unmodified PC driver/boot/handheld/x86-multilib/default bundles, unresolved
whole Fish/Zsh/desktop asset reuse, extra desktop editions, automatic
AUR/first-login downloads and unmeasured blanket tuning. Preserve each
required function through its specified licensed component, original
implementation or Apple-compatible backend.

### Source, dependency and maintenance responsibilities

For project-built packages, retain the exact recipe/source/patch/dependency/license set, source-delivery materials, toolchain/build image, two clean native artifacts, logs and reproducibility limits. Use the existing build, review and promotion interfaces. The October proposal identified the updater Rust tray and CLI as an early compiled milestone, with a separately pinned 354-package builder extension and Cargo source and license closure. The current inventory records the later updater native build pair and scoped guest lifecycle.

For upstream-supplied ALARM desktop/apps/libraries, preserve precise versions/providers, retained archive and detached-signature identity, key/source authority, BUILDINFO/recipe/source correspondence, notices and coordinated update responsibility. Historical authentication of233 generic additions is one data input; neither floating repository metadata nor its license field establishes release terms. The FDK upstream archive's authenticated bytes and its incomplete source/notice/correspondence obligations remain separate findings. Choose and re-resolve the already documented project-source provider or reviewed non-AAC PipeWire alternative; do not silently change providers.

For Apple boot/kernel/firmware/graphics/audio, keep the maintained Asahi implementation and explicit compatibility/update/recovery owner. Complete261 input/issuer joins, installed-payload correspondence, ABI/16K, hook/account effects and exact source provenance precede release admission. Current retained platform work advances those gates but does not close them; two metadata intake packages are not full261 acceptance. The current unmatched selected PKGBUILD hashes/generated constants need the existing parser/dispatcher-to-binary correspondence work, not another coverage inventory.

One release must bind the complete base+project transaction, repository priority, all versioned dependencies/providers/conflicts/replacements, file ownership, hooks, account/service/boot effects and required functions. Keep generic341 build-only packages and generic574 metadata separate from the target runtime selection. The unadopted624 candidate is a useful existing input, not a release package count. Do not turn permanent partial upgrades or stale protected pins into maintenance policy. Each later upstream dependency/security change needs a pinned coordinated candidate, owned rebuild where applicable, independent review, staging/promotion, retained previous artifacts and update/recovery evidence.

### Finite successor work runnable without either M2

| Task / suggested existing owner role | Exact starting input | Finite result before target acceptance |
| --- | --- | --- |
| COV1 Reconcile the generic proposal — B16 build/desktop + coordinator | d718 proposal, 89bdb earlier inventory, fc853 maintained inventory and beca inputs; this45-row crosswalk | Separate successor proposal with correct editor descriptions and explicit builder binding; repeat the existing bounded metadata/provider resolution if adopted. Preserve historical574/233 records and reject baseline changes outside the documented Vim pair. No new root catalog |
| COV2 Reconcile the Asahi transaction/source inputs — B18 platform + B19 installation/release | Pinned261 inventory,201 protected graph and unadopted624 alternative/report | Explicit coordinator decision for the coordinated Python/platform/provider set; one complete metadata transaction and finite remaining source/archive/ABI/hook/account ledger. Use current correspondence/intake outputs, keep all unclosed gates false; no installer/account effect or target mutation |
| COV3 Close the existing source-built candidates — B16/B17 package owners and reviewer | Updater recipe/Cargo closure + exact13-input354 extension; FDK selected source/notice/provider proposal; current shell-module/Topmem caller selections | Reviewed immutable source/dependency/license inputs, then separately authorized bounded clean native build pairs/lifecycle. Existing signer and service diagnostics must first establish and correct their actual cause; do not replay failure as acceptance. No physical16K or performance claim |
| COV4 Prepare one release evidence/source index — B16 build + release/custodian role | Existing45 roots, ten candidates, selected platform metadata, retained build/source/receipt references | Finite per-package source/build/upstream responsibility, binary/source/notice retention pointers, exact accepted-vs-unfinished evidence and coordinated update groups. Complete owner/source/provenance gaps rather than downloading every Arch package or making a generic new registry |
| COV5 Measure operational cost from actual selected jobs — B15 build/release | Retained native baseline job records and future reviewed compiled/provider jobs | Actual wall/CPU time, peak memory, work/cache/artifact/log bytes, clean rebuild/retry cost and bounded retention/export requirements. Record runner reservations/quota/storage/backup and security-update turnaround. Baseline template builds and input-byte caps do not establish full-port capacity |
| COV6 Establish ongoing ownership/custody — coordinator + human maintainers | Existing role tables and A08/A11/A12/M8/M9 requirements | Named consenting ongoing package/platform/release/support maintainers; builder/repository/hardware windows; key custody/rotation, dependency/security monitoring, incident response and subsequent-release commitment. Unassigned roles remain explicit; an agent lane supplies no permanent custody |

COV1/COV4 are immediate metadata/document tasks. COV2 can continue source/policy/correspondence work while machines are unavailable. COV3 preparation can run concurrently in separately owned package trees; actual jobs depend on their reviewed input and recovery gates. COV5 can extract retained software evidence now and add compiled costs when those jobs actually run. COV6 requires real human commitments; this audit cannot invent them. None of these tasks requires a physical M2 merely to start, and none can pass final installation/boot/16K/measurement requirements without the target evidence.

The reviewed records establish hosted native engineering progress but supply no named ongoing signing custodian, release incident coverage or reserved complete-port throughput. Repository endpoint, retained-source delivery, release/backup costs and update response capacity remain unestablished. Hardware/operator windows for both Air sizes remain a separate missing resource. These gaps keep B15/A11 and M5/R1/A12 unfinished even when this source coverage proposal is reconciled.

The October validation covered metadata parsing, duplicate names and counts,
inventory and root joins, and byte, mode and SHA-256 capture. The private
checks and receipt above describe the source-only scope. The coordinator
owns changes to the shared manifests and stable package selection.
