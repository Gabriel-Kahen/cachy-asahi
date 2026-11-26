# Qtbase packaging and installed 16 KiB handoff

This handoff starts after independent full-build readback and host retirement.
The source preflight can stage an unissued packaging plan and its guest
worker. A separate boot payload and offline reader define the package guest
boundary. The first attempt passed the dependency, source and recipe smoke
checks. The staging checker then refused the hard-linked tools `qmake` and
`qtpaths` and their versioned aliases in `usr/lib/qt6/bin`. The
retired workspace contained 5,109 entries and only those two repeated
non-directory inodes. The completed build and its input media remain
available for a fresh package-only attempt.

The refused guest retained its HOLD result and logs, then powered down.
Its launcher returned 1, and both post-scope observations confirmed that
the owned container and scope had retired. The failure trap ran while the
worker streams were redirected, hiding its UART marker. The corrected
launcher emits the HOLD marker after restoring those streams.

The package-only recipe projection checks the two known tool pairs, and
copies each versioned alias to its own inode when CMake created a hardlink.
The public `qmake6` symlink remains in the package. The staging checker reads
the regular installed notice policy copy and verifies the original policy
digest. The unchanged checker passed a copy of the retired payload with
those two corrections applied. Its original hardlink and notice checks
remain in force.

The second package guest completed on November 26. It passed the ordinary
recipe smoke check and assembled a 13,718,524-byte Qtbase 6.12.0-2 archive.
The guest powered down naturally, the filesystem check passed, and the
independent reader verified the original archive and packaging records.
Both retirement observations found the container and scope absent. A
disposable TEST key signed the recovered archive. Independent local GPG
verification accepted that signature and rejected the separate mismatched
signature. The exact TEST-signed archive later passed the Q3 installed
lifecycle and both signature-refusal cases.
[Installed trial](../qt612_installed_16k_preflight/README.md#corrected-installed-trial-november-26-2026)

| Retained package evidence | SHA-256 |
| --- | --- |
| Exact archive | `0c6ad9610086bfb7b2a88f9cb8794b88d2432dd53436fbc18eec808af01ea315` |
| Independent readback | `e9687edfeefd14607b770574b8267269ceffab48bc43f966eb4f29ffaf38f59a` |
| Post-scope observation | `d02e3780c8db2eff3f6c3bd7a6368f43bffde95f11a918e69bb8a66b7fac20e7` |
| Archive handoff | `fa3f6a0783d7d137ec15b3036d6c0f37145ac60753df8c3a4ec5fd857dfebafb` |
| TEST signing and verification | `f1822d6260a6b48aa46281ae006df12c2191a50cfda4cc55448f1bf329798a41` |

## Assemble from the completed build

1. Retain the full-build handoff, actor and independent receipts, post-scope
   observation, result disk, final overlay and the exact Gui, Core and scratch
   backings. Before proceeding, reopen their original hashes and verify the
   full-build and scope results.
2. Attach the original completed overlay and all lower layers read-only. Keep
   the embedded backing paths `/inputs/gui.qcow2`, `/inputs/core.qcow2` and
   `/inputs/scratch.raw` exact, then give a fresh writable child to a separately
   selected packaging guest. Keep the original media available for replay. In
   the disposable guest retain the `/qt-recipe/src/build` path used by CMake.
3. Pin the actual seven dependency additions, the initial 349-package
   baseline, and the resulting 356-entry lock
   `e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9`.
   The added versions were double-conversion 3.4.0-1, libb2 0.98.1-3,
   libice 1.1.2-1, libsm 1.2.6-1, md4c 0.5.3-1, xcb-util-cursor 0.1.6-1 and
   xdg-utils 1.2.1-2. The baseline includes wayland 1.26.0-1
   (`libwayland-server.so=0-64`) and libglvnd 1.7.0-3 (`libgl`).
   Use the retained Q3 archive and signature inventory for exact byte pins.
   [Q3 qualification](../../../docs/validation/qtbase612-emulated-arm16k-configure-20261118.md)
4. Supply the independently retained full-build readback and post-scope
   observation, with their externally recorded digests. The
   [source preflight](package_preflight.py) joins them to the original
   site, claim, actor and result disk, and replays the independent reader.
   It checks the Q3 input plan, source archive, recipe and inventory before
   preparing any output. Without `--output` it verifies inputs read-only and
   returns the proposed plan pin. With `--output`, pass a fresh absolute
   directory outside the capsule, Q3 media and repository. The output
   holds only the small recipe and plan files. The referenced carriers
   stay in their original locations.

   ```sh
   project=scripts/integration/qt612_full_16k_preflight
   python3 -I -B "$project/package_preflight.py" \
     --capsule "$CAPSULE" --site "$SITE" --site-sha256 "$SITE_SHA256" \
     --retirement "$RETIREMENT" --retirement-sha256 "$RETIREMENT_SHA256" \
     --readback "$READBACK" --readback-sha256 "$READBACK_SHA256" \
     --q3-media "$Q3_MEDIA" --nonce "$FRESH_NONCE" --output "$PRIVATE_STAGE"
   ```

   Use the same source bindings as the completed attempt to replay its site
   receipts. The new plan retains the original source evidence and has no
   execution authority. It specifies a separate packaging scope and a new
   writable child. A separately selected runner must prepare that child
   and its boot media, bind the staged inputs read-only and execute the
   recorded steps. The [metadata projection](package_metadata.py) changes
   the staged package release to `6.12.0-2` and makes it provide
   `qt6-base=6.12.0-2`. Omitting the release number allows libalpm to
   match an exact official `qt6-base=6.12.0-3` dependency. The revised
   provide still resolves generic consumers at Qt 6.12.0.
5. Verify the pinned 51,220,268-byte upstream archive, the four forward
   patches in order and the recipe source pins. Run the existing source and
   configuration validators against the completed Q3 build. Require normal
   `pacman -T` dependency resolution and execute the recipe's real `check()`
   as the ordinary user. Its CMake imports, scanner and offscreen plugins
   require the complete build tree. Require the actual
   `PASS_QT612_GUI_SERVER_OFFSCREEN_AND_LOCAL_DISPLAY_API_ONLY` output.
6. Assemble the archive through the normal recipe `package()` under makepkg
   and fakeroot. A controlled `makepkg --repackage --nosign` invocation can
   consume the preserved build after the separate dependency, source and smoke
   checks. This makepkg mode skips source preparation, build and check. In the
   fresh child, place the successor at `/qt-recipe/PKGBUILD.package` and use
   `makepkg -p PKGBUILD.package` from `/qt-recipe`. The original recipe and
   build paths then remain available for verification.
   Capture the exact configure and check outputs, staged ELF and notices
   receipt, normal archive validation, `.PKGINFO`, `.BUILDINFO`, `.MTREE`
   and whole archive pin. Inspect the finalized payload after normal
   install-time ELF transformations and makepkg cleanup. Reopen the immutable
   build evidence after packaging.
   [GUI-server recipe](../../../packages/port/qt612-gui-server-source-reference/PKGBUILD)

## Select and own the package guest

The [guest worker](package_guest.py) requires isolated Python, ordinary
UID/GID 1000, 16,384-byte pages, offline networking, read-only packaging
media and an empty private output directory. The package-only selection
must contain the following fields. Its SHA-256 and the plan SHA-256
remain independent runner inputs.

| Selection field | Required value |
| --- | --- |
| `kind`, `issuer`, `approved` | `ROOT_QTBASE16K_PACKAGING_WORKER_V1`, `Root`, `true` |
| `scope`, `nonce`, `plan_sha256` | `cachy-asahi-qtbase16k-package.scope`, the fresh plan nonce and the exact plan SHA-256 |
| `created_utc`, `expires_utc` | Current entry window, with a maximum length of one hour |
| `makepkg_configuration` | Original Q3 `/etc/makepkg.conf` whole pin in `main`, exact private map of `*.conf` drop-in pins in `dropins` |

The [execution adapter](package_execution.py) checks a current external
selection and derives the exact QEMU arguments, resource limits, boot
payload pins and separate `QT16K_PKG` result carrier. Its `boot_bundle()`
returns the actual payload bytes to an owned provisioner. The
[package PID 1](package-guest-init.sh) validates the sealed boot and
virtio media, reuses the full-build storage helpers, and exposes the
package plan at `/qtmedia/packaging` read-only. It caps each retained
command stream, the stage contract, and the single unsigned archive.

The [media provisioner](package_media.py) seals the pinned actor source,
the boot payload with its fresh PARTUUID and the clean 1 GiB result
template. Its output retains an unissued media record. The
[package actor](package_actor.py) verifies the five-node backing chain,
allocations, original QEMU exit and result filesystem. The
[package site](package_site.py) reuses the full-build owner's container
inspection, attach, CID recovery and retirement logic in a separate
scope. It accepts a completed full-build overlay of up to 8 GiB as a
read-only backing. The fresh writable packaging child retains its 4 GiB
file limit. The original source and full-build scope keep their pins.

```sh
python3 -I -B "$lane/package_media.py" --output "$MEDIA" --stage "$STAGE" \
  --plan-sha256 "$PLAN_SHA" --selection "$SELECTION" --selection-sha256 "$SELECTION_SHA" \
  --format-tools "$TOOLS" --format-tools-sha256 "$TOOLS_SHA"
python3 -I -B -Werror "$lane/package_site.py" preflight \
  --stage "$STAGE" --plan-sha256 "$PLAN_SHA" --media "$MEDIA" --media-sha256 "$MEDIA_SHA" \
  --selection "$SELECTION" --selection-sha256 "$SELECTION_SHA"
```

Run mode requires the selected package scope, control-group stop signals,
and effective 360-second systemd stop grace. After that scope exits, use
observe mode with the same inputs to verify the original container and
scope retirement. The package runtime has fixture coverage. Its first
live invocation depends on completed full-build evidence and separate
packaging admission.

The [offline reader](package_result.py) takes the staged plan and exact
external SHA-256s for the original selection, QEMU serial and result image.
It checks one scoped terminal, the bounded ext4 namespace, the command
receipts and the unsigned archive pin. It reads the archive hash without
extracting the archive. A host retirement receipt and clean fsck remain
separate requirements for subsequent signing.

The worker checks the exact completed build's 18 library bodies and
aliases, final Ninja log, configuration and local recipe inputs before
and after the sequence. It reuses the original Q3 signature and build
evidence by pin, checks the complete installed dependency inventory,
and performs the normal source checksum verification. The result binds
the new archive hash, exact 6.12.0-2 provider and recipe metadata,
BUILDINFO dependency inventory, stage receipt, and final aliases and
server feature files. It retains a HOLD phase on failure. Signing and
package database changes have no place in this worker.

## Sign and run the installed trial

- Use a dedicated, current TEST-only signing selection for the exact archive
  and detached signature. Record both lengths and SHA-256s, the full signing
  fingerprint, the pinned public certificate, expiry, and isolated signature
  verification receipts. Keep secret material out of the guest and retire the
  owned signing environment. An already installed, independently verified Q3
  snapshot carries its original md4c bytes. A fresh md4c install requires a
  current scoped signature on the exact qualified archive
  `19149e51f05a7d93426dda7a66fd80d67bd235cab7ac4505130f7de6d40b5b95`.
- Clone the verified Q3 base into a separate offline AArch64 guest, confirm
  16,384-byte pages, and use a disposable keyring and pacman configuration
  with both signature policies `Required TrustedOnly`. Verify signer identity
  independently before normal ALPM resolution. Test tampered and unknown-key
  signatures in sibling trials and require an unchanged inventory.
- For the clean target, record the exact 356 → 357 → 356 inventory across
  install, reinstall, removal, reinstallation and final removal. Check
  `pacman -Dk`, package payload and alias ownership, normal dependency
  resolution, defaults and configuration preservation. Load all 18 installed
  SONAMEs, verify the selected loader and transitive signed providers,
  build a separate installed CMake consumer and exercise the packaged
  offscreen plugin and Wayland server API. Verify dependencies, loader paths
  and installed runtime bytes after rollback.
- Scope an official-provider replacement to a separate reviewed image. It
  requires the exact official archive and signature for restoration, checks
  of all retained consumer constraints and a normal conflict transaction
  followed by normal reverse replacement. An official `qt6-base=6.12.0-3`
  dependent must keep that requirement and cause the replacement to refuse.
  Any matched Declarative, SVG, ShaderTools or Wayland packages require their
  own version and private-ABI qualification.
