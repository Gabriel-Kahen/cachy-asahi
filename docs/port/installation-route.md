# M8 / R5 installation route audit

Primary-source audit, October 11, 2026 local (October 12 UTC). **Proposed route;
not a supported installer or a completed installation.** No installer, partition
operation, package transaction or target boot was executed. M8/A15 require the
complete port, including the maintained package coverage from M5–M7, on both M2
Air sizes. The four original configuration/setup packages are a foundation.

## Route to implement

Reuse the established Asahi macOS installer for Apple platform preparation,
then integrate a release-defined Asahi ALARM base with the project's complete
signed package transaction and first-login configuration. This is the nearest
candidate to the repository's existing ALARM packaging work. It is not an
accepted base selection. The [community ALARM site](https://asahi-alarm.org/)
advertises Desktop first-boot Calamares with a Hyprland choice, Minimal, and BTRFS
variants. Freeze and test one image/first-boot path before writing user commands;
the pinned repository README describes older desktop choices.

For a later project-owned installation medium, Asahi's UEFI-only setup can
prepare the Apple boot environment and free space for ARM media. Its
[distribution guidelines](https://asahilinux.org/docs/alt/policy/) prefer this
method and also describe image-based installation. Either route retains Asahi's
APFS preparation rather than introducing a PC partitioner. Those guidelines
describe eligibility for upstream listing/endorsement; our independent port's
engineering acceptance does not claim that status. Hosting, support and a
maintained release remain project responsibilities.

## Audited inputs and reproducibility gap

| Input | Observed pin / SHA-256 | Meaning |
| --- | --- | --- |
| Community source repository | [`9821995723fa3326553d0d942d0b900173462ea8`](https://github.com/asahi-alarm/asahi-alarm/tree/9821995723fa3326553d0d942d0b900173462ea8) | Source snapshot, not an installed base |
| Served and commit-pinned `installer-bootstrap.sh` | `395dc40a6923a5a8609397e426fb81f2bb3ecc67c91cec731b8ad01a6d524325` | Both observed copies match; bootstrap declares MIT |
| Served `latest` | `11ef3020fd8f26c94d86e77b8f7affb9cfc742fa665e86ce006d2b5dc6294cd6` | Value `v0.9.2` plus newline, mutable endpoint |
| Served `installer_data.json` | `46cfe9ef67271b3437132c9d53bbb5db77bf099552f590c247b94efe26f33d26` | Mutable image/firmware selection data |
| Upstream installer `v0.9.2` | [`dffbb38ef0c00c0431c609ecd8a00f42deb5b24c`](https://github.com/AsahiLinux/asahi-installer/tree/dffbb38ef0c00c0431c609ecd8a00f42deb5b24c) | Reference source, not proof of served archive identity |
| Upstream tag `src/main.py` | `894fb8cd2ffc672bb96a14969ee9de2879d250c8c5990fee122ccf66d9b50024` | Normal minimum macOS `13.5`; expert minimum `12.3` is not our route |
| Served `installer-v0.9.2.tar.gz` | `b35fdd7e5e700003bf4f43d2a484eca618ad971dd4266207315cbfa6fe826fad` | Retained 22,215,962-byte archive; flattened `./main.py` matches the upstream tag |

The [reviewed bootstrap](https://github.com/asahi-alarm/asahi-alarm/blob/9821995723fa3326553d0d942d0b900173462ea8/installer-bootstrap.sh)
follows `latest`, downloads the installer/data, extracts the archive and invokes
its installer with sudo. It contains no explicit archive digest/signature
verification. Image URLs such as `asahi-base.zip` and `asahi-desktop.zip` are
unversioned; the reviewed data has no image checksum/signature fields. Same-channel
hashes identify observed bytes but do not independently authenticate their owner
or establish freshness. Do not convert the site's live pipeline into our
reproducible installation guide without closing this gap.

The actual community installer fork is
[`asahi-alarm/asahi-alarm-installer`](https://github.com/asahi-alarm/asahi-alarm-installer/tree/3cfef52bc372a7b84b59823027c75327e129d6ec),
whose `v0.9.2` resolves to `3cfef52bc372a7b84b59823027c75327e129d6ec`.
Its `src/main.py` and MIT license match the audited upstream files. Matching one
source file does not establish correspondence for the complete served archive,
including its bundled Python runtime, or independent archive authenticity.

Retain installer/data/image bytes, source correspondence and licenses, complete
installed-package inventory, upstream package signatures/key identities and the
matching protected platform tuple. Record capture dates and mutable URL origins.
Authenticate the selected bytes through a documented source and custody process;
a captured rootfs checksum alone cannot satisfy this gate. A generic ALARM Docker
builder or a repository availability DB is not the installed Asahi baseline.

## Supported models and prerequisites

| Candidate target | Apple identifier / product / SoC | Source status | Project status |
| --- | --- | --- | --- |
| M2 Air 13-inch, 2022 | `Mac14,2` / `J413AP` / `T8112` | Asahi installer: yes | Fresh installation, runtime and recovery NOT RUN |
| M2 Air 15-inch, 2023 | `Mac14,15` / `J415AP` / `T8112` | Asahi installer: yes | Fresh installation, runtime and recovery NOT RUN |

Identifiers come from the [device list](https://asahilinux.org/docs/hw/devices/device-list/).
The [M2 support table](https://asahilinux.org/docs/platform/feature-support/m2/)
records installer support and Asahi availability for core display/input/audio and
sleep, while Thunderbolt/DP Alt Mode remain WIP and Touch ID TBA. Its availability
legend refers to Fedora Asahi Remix. It does not certify our ALARM snapshot,
Hyprland integration, or either machine's acceptance.

Keep a working internal macOS installation and usable local-owner credentials;
the [Asahi FAQ](https://asahilinux.org/docs/project/faq/) explains why external
macOS and an entirely external boot installation are insufficient. Record actual
macOS/RecoveryOS versions, backup/recovery availability, model and disk layout
before installation. Use the normal installer version floor above, then validate
the selected release's exact supported versions. `supported_fw` values in image
data describe firmware choices, not permission to use an older host macOS or a
tested Linux ABI. Let the retained installer determine APFS resize feasibility;
there is no invented universal free-space allowance in this audit.

## Ownership and stage contracts

These are required roles, not named maintainers already established. Assign real
ongoing owners before publishing the route.

| Stage | Responsible integration | Required evidence before advancing |
| --- | --- | --- |
| macOS preparation | Installation owner + physical operator | Exact model/OS, backup and recovery check, retained installer inputs, reviewed disk plan |
| Apple stub/ESP and RecoveryOS step | Established Asahi installer; platform owner validates integration | Completed upstream handoff, machine-specific boot policy, identified install ESP; interruption/resume result |
| First ALARM boot and account setup | Base/platform owner | Selected image inventory, hardened non-root account, networking and package trust; retained working console/session |
| Complete signed project transaction | Package/release owners and signing custodian | M5 full closure, authenticated base/project inputs, protected versions, actual complete libalpm transaction and logs |
| First Hyprland login | Desktop/setup owner + intended user | Validated base launcher, portals/authentication/audio protection, configuration ownership and accelerated login |
| Updates and recovery | Platform/release/support owners | Previous and candidate compatible sets, retained artifacts, failed-update boot/session restoration, baseline rerun |

The [boot guide](https://asahilinux.org/docs/alt/boot-process-guide/) separates
installer-managed, machine-signed m1n1 stage 1 from distro-managed stage 2, device
trees, Asahi U-Boot and EFI loader/Linux. Stage 1 identifies this installation's
internal ESP by PARTUUID. Preserve that identity and coordinate subsequent
boot/kernel/device-tree updates. Do not use global PC NVRAM/`efibootmgr`
assumptions or replace another installation's ESP. The
[interoperability design](https://asahilinux.org/docs/platform/open-os-interop/)
also covers stub RecoveryOS and vendor-firmware provisioning. Preserve the
selected firmware extraction/manifest arrangement and audit redistribution terms.

Trust has separate boundaries: macOS installer transport, Apple firmware,
ALARM/community package signers, and project release keys. The
[release interface](../release/interface.md) can stage and verify local bundles;
the [development client](../release/client.md) cannot authorize production
installation. No production project endpoint, independently authenticated public
key/custody arrangement or accepted complete release is supplied by this audit.
Document key bootstrap, freshness, rotation/revocation and incident recovery
before adding a repository to a target.

## Configuration and first desktop

After the accepted full package transaction, retain the working base desktop and
activate the original setup helper as the intended non-root user. The existing
[overlay procedure](../installation.md) previews with
`cachy-asahi-setup activate --components fish zsh hyprland` and applies with
`--apply`. Select only installed components. This does not change the login shell
or start a compositor. Verify the copied configuration, then use the tested
base session launcher with that configuration; preserve its service/environment
integration. Launcher-specific instructions belong to the selected release,
not an assumed GRUB, display manager or UWSM configuration.

The [desktop coverage proposal](desktop-coverage.md),
[generic dependency preview](../workstreams/port-resolution.md) and
[tool audit](tools-functionality.md) expose work beyond these templates: complete
applications/development tools, portals, authorization, radio services, protected
audio, locking/lid policy and applicable Cachy management functions. Generic
metadata resolution and disposable native integration do not establish the
Asahi target transaction or a first physical login.

## Recovery boundaries

Keep the internal macOS, system recovery and known-good installation artifacts
usable. The [partition guide](https://asahilinux.org/docs/sw/partitioning-cheatsheet/)
identifies protected iBoot/SystemRecovery containers and explains failed-install
cleanup. Record real identities rather than hardcoding `disk0sN`. An interrupted
second-stage handoff needs the installer's recovery/resume path, not blind
repartitioning or an invented automatic uninstaller.

For a Linux update failure, distinguish user-config conflict, service/session
failure and boot/platform failure. Use helper preview/recovery with its original
path options to preserve edits; use the retained base session/console for session
repair. Boot recovery needs the matching known-good platform artifacts and this
install's ESP. Test those operations physically before publishing specific write
commands. Retaining an archive or BTRFS snapshot is not a successful recovery.

For firmware recovery, [Apple's current guide](https://support.apple.com/en-us/108900)
requires another Mac running macOS 14 or later and a suitable USB-C data cable.
Revive preserves data; Restore erases the machine. Include the exact-model DFU
port/procedure in the eventual emergency guide and preserve that distinction;
neither operation was exercised here.

## Remaining implementation and acceptance

1. Freeze/authenticate the installer and actual ALARM image/platform snapshot;
   review source correspondence, licenses, package identities and retention.
2. Resolve the full target dependency transaction and platform providers, then
   supply the maintained M5–M7 package/function set. Builder stock Mesa cannot
   stand in for the selected Asahi graphics stack.
3. Integrate authenticated production repository setup, account/first-boot
   setup, the retained base launcher and configuration migration into a
   versioned guide. Retain logs without passwords/private keys.
4. Exercise the complete macOS-to-desktop journey independently on each model,
   plus interrupted installation, previous-release upgrade, failed update,
   boot/session restoration, removal/reinstall and configuration preservation.
5. Close A01–A15 against the same complete release and demonstrate a subsequent
   maintained full-port release with named owners and real key custody.

[Acceptance](../acceptance.md) already requires per-model 3 cold boots/logins,
20 lid resumes (10 battery/10 external power), 10 lock/unlock trials and 5
install/remove/reinstall cycles for fresh and existing configurations; supported
display modes have 5 reconnections. Core hardware and preserved applications
must pass. Optional upstream limitations stay explicit. Native Docker checks
cannot supply these physical records or the final performance measurements.

The next safe implementation is a data-only capture/validator: explicit retained
inputs and observed hashes, bounded downloads/archive reads, offline package
metadata and boot/platform inventory, and an honest authentication report. It
must never run the installer, install packages, mount/write a target filesystem
or change boot policy. Its output can advance source/base review; it cannot
approve installation or hardware compatibility.

The candidate [`scripts/platform/capture.py`](../../scripts/platform/capture.py)
now implements that narrow data path. Its pinned source manifest retains
community repository signatures, source/notice files and the installer; optional
minimal-image capture uses a private 8-GiB upper bound. It reads image package
descriptors with read-only `debugfs`, without mounting the filesystem. The
[workstream](../workstreams/installation-route.md) records actual capture status,
tests and unresolved authentication/rebuild issues. This tool is not an installer.

## Kernel source correspondence correction

The signed `linux-asahi 7.1.13.asahi3-2` package corresponds to the historical
[`d585b07f4526f6c2d263ec8270387e684545a57f` recipe/config](https://github.com/asahi-alarm/PKGBUILDs/commit/d585b07f4526f6c2d263ec8270387e684545a57f),
not the later captured recipe pin. Its declared recipe hash matches that source
exactly; both config checksums and both retained kernel-source archive checksums
match. The later September 29 config/checksum update kept the package version,
and the October 6 config change left recipe checksums stale. The later pin is
still not rebuild-ready; this does not make the historical signed package's
recipe/config correspondence unresolved.

The [checksum-bound report](../../scripts/platform/kernel-correspondence.json)
records those revisions, the retained source archive and remaining gates. The
image's kernel binary matches its retained signed archive member. Its embedded
config differs from the historical supplied config only in pahole version
131→132, consistent with `.BUILDINFO`'s declared pahole package. The ARM64 header
declares 16K pages using the
[pinned kernel boot protocol](https://raw.githubusercontent.com/AsahiLinux/linux/94fb23346d522edf53722357c426a3e58030beea/Documentation/arch/arm64/booting.rst).
These are byte/metadata observations; no kernel was built or executed.

The five signed boot/firmware packages already in the 261-package image have
the same versions as the retained archive snapshot. `asahi-audio` and
`speakersafetyd` are absent. A subsequent transaction must supply protected
audio/graphics/desktop dependencies, preserve the observed baseline, and review
file ownership, hooks, firmware and boot effects. Source reconstruction and an
actual controlled rebuild remain separate from image authentication, release
trust and physical-machine boot/recovery acceptance.
