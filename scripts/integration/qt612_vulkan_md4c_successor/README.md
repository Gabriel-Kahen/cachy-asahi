# Qtbase Vulkan and md4c 0.6 recipe

This unissued source recipe targets both failures in the
[R132 official-provider comparison](../qt612_installed_16k_preflight/README.md#official-provider-replacement-on-r132).
It derives a separate makepkg directory from the pinned GUI-server recipe
and the existing packaging projection for the retired 6.12.0-2 archive.
The stage includes matching package metadata and a receipt with recipe,
source and signed dependency pins.

The recipe applies the four inherited patches followed by Qt's
032643f99e090e0304ef935c2ee11c109d55c8a1 md4c patch. Both changed bundled
notice records receive new pins. The configured build uses system
md4c 0.6.0-2 and enables Vulkan. It explicitly disables the standalone
VK_KHR_display platform plugin to retain the existing plugin scope.
Vulkan headers 1:1.4.363.0-1 are an exact build dependency. Package
staging checks the six versioned QtGui Vulkan exports required by the
retained Qt Quick consumers and the dynamic md_parse relocation.

The staged package has project version 6.12.0-3 and provides the bare
qt6-base name required by the five R132 dependents. An exact dependency
on the official qt6-base 6.12.0-3 still refuses this replacement.

Run the projection from this directory and inspect its receipt.

    python3 -I -B prepare.py --output "$NEW_RECIPE"
    cd "$NEW_RECIPE"
    makepkg --printsrcinfo | cmp - .SRCINFO

For offline source preparation, place the pinned Qt source archive in
an owned SRCDEST and select a private BUILDDIR. The following runs the
checksums and recipe prepare phase on a development host.

    makepkg --nobuild --nodeps --ignorearch --holdver

The November 26 source preparation verified all five patches and 173 notice
records. `makepkg --printsrcinfo` matched the generated `.SRCINFO` byte for
byte. On the retained R132 metadata with this replacement, `pacman -T`
accepted all 811 runtime dependency expressions. Adding an exact dependency
on the official Qt version failed as intended. The metadata-only check
receipt has SHA-256
`0cc007ca96d59dd9b0d32c187a0f7ee6b99991a161fea9e2cbe959aca809e536`.

Normal CMake and Ninja linked an x86_64 QtGui that passed the six-export and
external md4c readback. Its SHA-256 is
`afacaf47b181d16d967a55f0a9f1bdf878d771060a3cef78ac21d49469124c1f`.
Five cross-compiled AArch64 objects verified the matching source definitions
and import. The prepared recipe receipt SHA-256 is
`b3b46a27d6bb5e93bf411de9a23bf238c36230f268206af09637c9d66f0ce41a`.

A normal ARM64 makepkg build needs a fresh isolated 16 KiB environment
with the exact dependencies in the receipt, including the original signed
ALARM inputs. The prior Q3 graph and package receipts bind its md4c
0.5.3-1 input and configured QtGui bytes. The successor needs its own
configure and full-build evidence, staged package readback, scoped TEST
signing and a separate R132-equivalent installation and restoration.

## Offline ARM64 setup and build

`arm16k.py prepare` authenticates the 264 retained Arch Linux ARM package
pairs and signed seed, regenerates the exact recipe, and derives a new boot
payload from a read-only partitioned Q3 boot image. It verifies the kernel
configuration selects 16 KiB pages and checks the retained scratch, kernel,
boot, recipe and archive against their recorded digests. The 356-package Q3
scratch is used as the read-only backing of a new QCOW2 child. Within the
child, the setup installs the two original signed md4c and Vulkan header
archives with a fresh ALARM-only keyring and compares the actual 357-package
inventory with the pinned lock. The build uses a new source and build path.

```sh
python3 -I -B -Werror arm16k.py prepare \
  --evidence "$CLOSURE" --q3 "$Q3_INPUTS" --boot "$Q3_BOOT" \
  --kernel "$KERNEL_IMAGE" --config "$KERNEL_CONFIG" --backing "$Q3_SCRATCH" \
  --docker "$PINNED_ROOTLESS_DOCKER" --output "$NEW_CAPSULE" --mode full

python3 -I -B -Werror arm16k.py start \
  --capsule "$NEW_CAPSULE" --plan-sha256 "$PLAN_SHA"

python3 -I -B -Werror arm16k_readback.py \
  --capsule "$NEW_CAPSULE" --plan-sha256 "$PLAN_SHA" --launch-sha256 "$LAUNCH_SHA"
```

Run from this directory with absolute paths. The closure directory holds
`closure.UNISSUED.json`, `expected357.lock`, the public certificate and the
archive pairs. The original package pairs and signed seed resolve through
the pinned private closure. Prepare prints the plan digest. Start claims a
fresh run directory and prints the launch digest after retiring its own
container and rehashing the input media. Keep those digests for independent
readback. The start command can run in a dedicated user service for the
duration. `run/serial.log` records setup, configure, compilation and the
guest terminal, with a 16 MiB limit. `container.log` captures Docker attach
output outside the VM output mount, with a 2 MiB limit.

The `run/` directory claims the capsule for one attempt. If creation or
attach fails after the claim, the launcher checks the owned container identity
before retiring it and records the result in `launch.json`. An uncertain
retirement is marked `UNVERIFIED`. If the terminal receipt cannot be written,
the launcher tries `launch.hold.json` and reports to stderr if both writes
fail.

The rootless container and QEMU have networking disabled and use only
file-backed virtual storage. The container has an 8 GiB no-swap limit and
a four-CPU quota. QEMU runs with four vCPUs, 6 GiB RAM, a 10 GiB child-file
limit, a 2 GiB result disk and a 16-hour guest window. The recipe builds with
one compile job. The host needs 10 GiB available RAM and at least 14.125 GiB
free on the Btrfs filesystem used for the reflinks. Choose `--mode configure`
for a dedicated setup and graph check with a shorter deadline.

Full mode invokes the staged recipe with
`makepkg --noconfirm --nocolor --nosign`. Its result can include an unsigned
archive, package-stage and QtGui ABI reports, the actual CMake and Ninja
graph, and the original build transcript. Independent readback opens the
result filesystem without mounting it and inspects the archive and QtGui.
The archive remains a local test artifact.

The source projection, authenticated-input guards, launcher and independent
reader have separate local tests.

```sh
python3 -I -B -Werror test_successor.py
python3 -I -B -Werror test_arm16k_inputs.py
python3 -I -B -Werror test_arm16k_launch.py
python3 -I -B -Werror test_arm16k_readback.py
bash -n arm16k-guest-init.sh
bash -n arm16k-build.sh
```
