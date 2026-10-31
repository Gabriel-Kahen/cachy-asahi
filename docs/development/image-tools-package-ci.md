# Image tools: finite CI proposal

This is a coordinator adoption proposal, not an active workflow or a native dispatch. Candidate version 0.1.0-1 is unselected. No changes to recovery/release packages, shared manifests, existing source profiles or active workflows are required.

## Source job

Use the exact adopted Git commit and an externally reviewed SHA256 of scripts/release/image-tools-source-profile-v1.json. Run:

```
python3 -I -B scripts/release/test_export_image_tools_source.py
python3 -I -B packages/tools/cachy-asahi-image-tools/check_package.py --recipe-root packages/tools/cachy-asahi-image-tools
python3 -I -B scripts/release/export_image_tools_source.py --root "$PWD" --profile scripts/release/image-tools-source-profile-v1.json --profile-sha256 "$PROFILE_SHA256" --output "$RUNNER_TEMP/image-tools-source.tar.gz"
```

Keep source export as DATA until an independent runner has verified the exact finite archive membership, every body hash, license provenance and recipe against the reviewed commit. Never auto-execute code from an arbitrary transported source receipt. No signing credentials or network inputs are needed. Export is deterministic, ordinary-file-only, bounded, no-follow, no-clobber; failures before complete source collection create no output. Preserve exporter failures. The profile records original Git custody plus new candidate bytes; it does not substitute for coordinator Git admission.

## Native package pair

Root should add this opt-in recipe to the reviewed native constructor through a versioned profile, without extending any old byte-pinned allowlist. Use two distinct disposable, clean, native aarch64 Arch builder environments with recorded immutable image/source/package inputs. Pre-provision python>=3.14, libarchive, e2fsprogs, gnupg, glibc and base-devel; do not install dependencies on the runner host. Run makepkg --nodeps --cleanbuild in each builder as an ordinary user. Retain full check() logs, .PKGINFO, .BUILDINFO, .MTREE, package archive digest and exact payload map. Compare archive and payload bytes separately; compare full build dependencies, not just package names.

The build's check() runs 29 original release-image, 4 signed recipe, 35 signed intake and 13 packaging controls on the current pinned source. These actor-free controls retain the original signature/selection/cap/process boundaries. Count changes require source/profile review, not loose greater-than checks.

## Built payload journey

Safely stage only the exact 66 mapped ordinary payload files from each package to an ordinary-user prefix. Preserve metadata separately. Rename the complete prefix and remove the first path before running the harness with the launcher's exact absolute Python interpreter:

```
/usr/bin/python3 -I -B scripts/platform/test_image_tools_installed_synthetic.py --prefix /absolute/moved/usr --work /absolute/fresh-synthetic-work --deny-checkout /absolute/original-checkout
```

Only owned tiny synthetic USTAR/xz archives are allowed. The harness generates ephemeral TEST RSA/OpenPGP signatures without a signing daemon or secret key file. It records actual host native tool and dynamic-library bytes, genuine GPG verification and exclusive-child receipts. It exercises plan/assemble/verify/resume, hardlink/symlink readback, existing-output refusal, wrong receipt, unsigned-kind refusal, input pin failure, genuine signature failure and incomplete resume refusal. Denial is explicitly Python open/listdir/scandir auditing, not namespace isolation. Native commands receive only standard system tools and owned synthetic operands. Verify/resume must retain every positive artifact unchanged and run no actors.

## Package manager lifecycle and target gates

Separately qualify a signed disposable native ALPM install/remove/reinstall lifecycle using an independent ordinary user. Check all package files/modes, preservation of external recipes/results and unchanged pre-existing package DB; no runtime image assembly should be treated as a package transaction. Do not add mounts, loop devices, live host images, firmware/partition/boot actors or physical M2 testing to this focused CI job. Native16K, integrated Asahi composition, both M2 Air sizes, production signing trust, bootability, performance and release acceptance remain independent gates.
