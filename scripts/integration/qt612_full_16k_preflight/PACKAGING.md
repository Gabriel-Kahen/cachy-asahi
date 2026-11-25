# Qtbase packaging and installed 16 KiB handoff

This handoff starts after independent full-build readback and host retirement.
Metadata preparation is implemented. Packaging, signing, installation and
rollback remain `NOT_RUN`.

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
4. Use the pinned [metadata projection](package_metadata.py) to stage the
   packaging-only recipe and its matching SRCINFO in the new guest. It advances
   the package release to `6.12.0-2` and advertises `qt6-base=6.12.0-2`.
   The original `qt6-base=6.12.0` provide omits the release number. libalpm
   can match it against an exact official `qt6-base=6.12.0-3` dependency. The revised provide still
   resolves generic consumers at the matching upstream version. It leaves
   the original recipe, frozen Q3 metadata and live successor source unchanged.
   Keep the input and output receipt with the selected package producer. Set
   `PRIVATE_STAGE` to a fresh directory separate from `ORIGINAL_RECIPE`.

   ```sh
   project=scripts/integration/qt612_full_16k_preflight
   python3 -I -B "$project/package_metadata.py" --recipe-dir "$ORIGINAL_RECIPE"
   python3 -I -B "$project/package_metadata.py" --recipe-dir "$ORIGINAL_RECIPE" --emit PKGBUILD > "$PRIVATE_STAGE/PKGBUILD"
   python3 -I -B "$project/package_metadata.py" --recipe-dir "$ORIGINAL_RECIPE" --emit .SRCINFO > "$PRIVATE_STAGE/.SRCINFO"
   ```

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
   checks. This makepkg mode skips source preparation, build and check.
   Capture the exact configure and check outputs, staged ELF and notices
   receipt, normal archive validation, `.PKGINFO`, `.BUILDINFO`, `.MTREE`
   and whole archive pin. Inspect the finalized payload after normal
   install-time ELF transformations and makepkg cleanup. Reopen the immutable
   build evidence after packaging.
   [GUI-server recipe](../../../packages/port/qt612-gui-server-source-reference/PKGBUILD)

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
