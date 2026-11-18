# Offline Qt6-base configure rehearsal on AArch64 with 16 KiB pages

This lane uses the shared Overlay583 virtual machine controller and its retained
boot references. In the disposable guest, the launcher verifies the signed
Arch Linux ARM seed and stages it in scratch. The guest dearmors the pinned
official public key into a temporary keyring before detached verification of
the original seed and signature. ALPM verifies the original 165
packages, builds the exact 349-package baseline, and installs the seven Qt
dependencies to reach 356. The scoped md4c TEST trust lives only in the guest's
private keyring. Both transactions require `Required TrustedOnly`. The guest
then runs normal Qt preparation and configure as an ordinary user, checking
md4c's pkg-config selection, ALPM ownership, loader and CMake integration. It
stops before the Qt build.

## Prepare input media

Use an external request object with these fields.

- `kind` is `QTBASE_16K_PREPARATION_REQUEST_V1`.
- `proposal` points to the reviewed Qt ALPM trust proposal. It selects the seven
  pairs, dependency inventory, qualified md4c, detached-signature readback and
  scoped TEST certificate.
- `provider` points to the complete 517-input baseline provider document.
- `source_map` points to the prepared Qt family source map.
- `original` points to the retained public evidence archive containing the
  original package and rootfs hook audit.

Each of the four operands is an object with canonical absolute `path`,
integer `bytes`, and full lowercase `sha256`. The caller supplies the request
digest from a separately reviewed selection. The planner reopens the selected
bytes and emits an unissued media plan. With no output argument it performs
the same read-only merge and reports the prospective plan pin. The planner
joins the exact md4c archive and its detached signature to two independently
retained native builds and the scoped TEST verification receipt.

```bash
lane=scripts/integration/qt612_base_16k_rehearsal
python3 -I -B "$lane/prepare.py" --request "$request" \
  --request-sha256 "$request_sha256" --output "$fresh_media"
```

## Bind the guest inputs

The tool profile is a canonical JSON object with `kind` set to
`QTBASE_16K_QEMU_TOOL_PROFILE_V1`, the exact shared `actor_image` ID, and a
`tools` map with both `bytes` and a full `sha256` for every shared tool path.
Use measurements from the retained tool image. The binder checks the four
fixed shared tool pins and requires a complete measured pin for `mke2fs`.
The launched controller must observe the entire approved map in its own
container before it can open the VM.

```bash
python3 -I -B "$lane/controller.py" bind --media "$fresh_media" \
  --kernel "$kernel" --config "$kernel_config" --baseline "$boot_disk" \
  --tool-profile "$tool_profile" --tool-profile-sha256 "$tool_profile_sha256" \
  --nonce "$nonce"
```

The binding selects the exact media, reviewed source, kernel, baseline, tools
and output purpose. It has no authority to execute. A separate Root-owned
handoff issues a canonical, fresh approval for those exact bytes and owns its
one-shot claim, predecessor closures, disposable container and terminal
evidence.

The controller's `run --authority ABSOLUTE_PATH --authority-sha256 SHA256`
entry is for that owner inside the offline actor. Use zero capabilities,
no-new-privileges, a read-only container root, no network or host devices, and
read-only mounts for source, authority and all inputs. The inherited actor
boundary checks read-only mounts, no KVM device and loopback-only networking.
The Root host owner owns the full container device, identity and retirement
checks. The guest image layout uses read-only boot and media with separate raw
scratch and result disks. The 24 GiB free-space gate is checked on the actual
output filesystem before it creates the attempt directory.

The controller retains pinned serial, result disk, ALPM and configure evidence
only after checking the guest's terminal state and owned-QEMU retirement.
Formatting-time and terminal result-disk checks have separate receipts. A
successful rehearsal covers emulated ALPM and configure at 16,384-byte pages.
It makes no full Qt build, native 16 KiB hardware, Asahi installation, M2 or
release claim.

## Static CI

Run the tests directly so each script installs its actor fence. These controls
use inert inputs and need no media, QEMU, Docker, key material or root.

```bash
for worker in guest-init.sh alpm.sh configure.sh; do
  bash -n "$lane/$worker"
done
python3 -I -B -Werror "$lane/test_prepare.py"
python3 -I -B -Werror "$lane/test_rehearsal.py"
```
