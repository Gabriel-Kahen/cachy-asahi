# Opt-in generic ARM64 16 KiB fixture

`fixture.py` prepares a diskless initramfs. It never extracts the rootfs to the
host or executes guest files on the host. It copies only `bash`, `uname`,
`getconf`, their ELF interpreter and recursively needed libraries from the pinned
rootfs. Guest symlinks are resolved as archive data and flattened to regular
files; path escapes, cycles, special files and excessive closure sizes refuse.
The original rootfs remains untouched. No package actors, bootloader, host
installation, disks, network or default lane changes are involved.

Required inputs: a successful build-helper receipt with nested `image.sha256`,
`config.sha256`, `kernel_release`, `status=BUILT_ONLY`, `kernel_build=PASS`; its
matching Image and config; pinned aarch64 rootfs tar; host Python3, clang and lld.
The receipt must declare a 16384-byte Image header and modules disabled; the
matching config must have modules disabled. The kernel must support built-in
initramfs, ELF/scripts, PL011 console and PSCI poweroff.

Prepare only (output directory must not already exist):

```sh
python3 artifacts/development/generic-arm64-16k-20261016/fixture.py \
  --kernel /absolute/build/Image --kernel-config /absolute/build/.config \
  --kernel-receipt /absolute/build/build-result.json \
  --kernel-release EXACT_RELEASE_FROM_RECEIPT \
  --rootfs-tar artifacts/development/maintained-desktop-auth-next-20261015/context/rootfs.tar.gz \
  --rootfs-sha256 42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319 \
  --out artifacts/development/generic-arm64-16k-20261016/prepared
```

Use a new output directory and add `--execute-in-owned-fixture` to prepare and
boot explicitly. This additionally requires `qemu-system-aarch64`; the fixture
uses `virt`, TCG, `-cpu max`, no NIC, no disks and an owned subprocess group,
with 180-second/1-MiB UART bounds and bounded cleanup on every return. It does
not reuse another VM or control another process group. `uart.log` retains the
bounded guest output; `fixture-result.json` records the nonce, input/content
hashes, selected ELF source closure, compile command, exact compiler/linker/QEMU
executable digests and runtime result. Compiler output uses the same bounded
supervisor (60 seconds/1 MiB, `compile.log`). Catchable SIGTERM becomes an
interrupt and retires the active owned subprocess group before returning.

Guest PID1 runs `/usr/bin/uname -r`, `uname -m`, and `getconf PAGESIZE`, requires
the exact selected release, aarch64 and 16384, then executes the static smoke.
The smoke requires auxv `AT_PAGESZ=16384`; it checks anonymous mmap, mprotect,
munmap, a 16384-aligned file mapping and EINVAL for a 4096-only offset. Its
freestanding AArch64 ELF has 16384-aligned PT_LOADs. The guest emits a unique
nonce-bound result and powers off via the reboot syscall. Host PASS requires
all exact markers once, in order, UART EOF and natural QEMU exit0. Killing a
timed-out VM or merely compiling the binary cannot pass.

Portable controls:

```sh
python3 -B -Werror::ResourceWarning artifacts/development/generic-arm64-16k-20261016/test_fixture.py -q
```

These controls compile the actual AArch64 smoke and check its ELF structure,
archive refusals, cpio device metadata, result binding and real owned-child
timeout/output cleanup. They do not run AArch64 code or prove a 16 KiB boot.
This candidate provides generic software page/ELF evidence only. It does not
run the signed installer transaction suite, measure performance or establish
Asahi/M2, platform, release or hardware acceptance. Fixture source license:
MIT (SPDX headers); selected rootfs binaries retain their upstream licenses and
are local development inputs, not a newly published distribution.
