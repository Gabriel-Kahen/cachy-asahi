# Generic ARM16K RTC reference build, 2026-11-15

Root's separately admitted compile r2 produced
`7.1.13-generic16k-managed-gui-rtc1`, status
**BUILT_ONLY_RTC_BOOT_NOT_RUN**. This is a successful x86_64→ARM64 cross-build
using LLVM22.1.8, not native16K, RTC boot, M2/Asahi hardware, performance or
release acceptance. The historical native LLVM18 receipt remains separate;
`same_toolchain=false` makes no reproduction or toolchain-parity claim.

The build ran from06:43:14 to06:48:20 UTC. Configure r3 had already produced
Root-reviewed config71589 bytes and exactly15 approved compiler/auxiliary facts.
Compile r2 reran configure in a fresh workspace, matched those exact config
bytes/facts, then completed these literal commands:

```sh
/usr/bin/make -C /work/rtc-kernel/linux-asahi-7.1.13-3 O=/work/rtc-kernel/build ARCH=arm64 LLVM=1 olddefconfig
/usr/bin/make -C /work/rtc-kernel/linux-asahi-7.1.13-3 O=/work/rtc-kernel/build ARCH=arm64 LLVM=1 -j2 Image
```

Both commands exited0, were naturally reaped and proved `EMPTY_TWICE` group
census, complete output, no timeout, no signals and no supervision error.
Root's terminal result confirms container exit0, no OOM, owned-container
absence, unchanged host inputs and CLOSE_ONLY lease release.

## Source, configuration and build domain

The unchanged262965559-byte source archive has SHA256
`874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`,
AsahiLinux revision `94fb23346d522edf53722357c426a3e58030beea`
(tag `asahi-7.1.13-3`). Original source provenance is
`4056e2505ed7081674e949e0460258672cce14ff`, run39156901928.
No source patch or PC bootloader change was introduced.

Against the original config, eight semantic changes set RTC_CLASS, RTC_LIB,
RTC_HCTOSYS, RTC_INTF_SYSFS, RTC_DRV_PL031 and RTC_I2C_AND_SPI to `y`, select
HCTOSYS device `rtc0`, and add the distinct `-rtc1` LOCALVERSION. The eleven-key
RTC contract also keeps SYSTOHC, NVMEM, PROC and DEV disabled. Held I2C=y derives
the hidden RTC_I2C_AND_SPI helper; SPI remains disabled and no additional RTC
driver is selected. ARM64_LSUI and WARN_CONTEXT_ANALYSIS remain off.

The fifteen separately reviewed facts have exact original→configured values,
not a prefix exemption. They cover compiler/assembler/linker probes and the
actual OpenSSL/pahole results. Their complete table and upstream evidence are
[retained source DATA](../../scripts/integration/arm16k_rtc_kernel/data/configure-r2-facts.json).
All unrelated semantic settings, including16K/MMIO/ext4 prerequisites, remain
held. The final config matches configure r3 byte-for-byte.

The explicit `HOST_CROSS_ARM64` domain used read-only host `/usr`, an exact
loader cache and separately verified bc, with pre/post guards over116 ALPM
records,18 tools and72 runtime files. The container had no network or
capabilities, NNP/read-only root,2CPU/8GiB/256PIDs and a fresh bounded tmpfs.
No host package installation occurred. The actual tool profile SHA256 is
`c2216dedb15b572fe38ef33a66dc827126597a18ea2567ce20a4da51e455fe7d`.

## Exact retained output

The three-file bundle uses `ARM16K_RTC_REFERENCE_KERNEL_BUNDLE_V1`.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| Image | 9019400 | `505ff41b342647828c399241d51b0cbd9527c6191607a6a3abdeec40a55c3266` |
| config | 71589 | `020243b2d55a0c093280581a70f337baa01d9822ab4075588ad74fca8857f1c9` |
| bundle.json | 8988 | `68f3ff68c78fa3aa8b3d66c3b301472c846a7eb8d2a830ba565d61547029492f` |

The actual64-byte header has SHA256
`621f2a525f58d3eeca54a8cd049939a0382e8bad48b07b7533850ff310162fcc`,
magic `41524d64`, flags12, text offset0 and little-endian16K page flags. Its
**9568256-byte effective memory span exceeds the9019400-byte file**, a valid
BSS/zero-init distinction established by the pinned upstream boot protocol and
linker source. File64MiB and nonzero memory-span128MiB bounds pass independently.
The raw header and decoded fields were retained before post-build validation.

Receipts remain under the local artifact namespace
`artifacts/development/orchestrator-resume-20261114/`:

| Receipt | Bytes | SHA256 |
| --- | ---: | --- |
| Root-RTC-kernel-configure-r3/actor-output/stage/configure-result.json | 5545 | `297d4c3d840d2f90a5000d8c11f8b13b3e9bdeec9c85ddf33555b50be13a3a5c` |
| Root-RTC-kernel-compile-r2/actor-output/stage/build-report.json | 4118 | `8950c832086f65d7649e774478707e25fb5008e36968e3afa8fa75d8e4238a92` |
| Root-RTC-kernel-compile-r2/Root-stage-result.json | 15503 | `cb8e6e407ddb17e3fd43c0d65bf8c37d5653a364c6d89b9b8f39f35e7f4a9747` |

Prior configure r1/r2 and compile r1 remain closed HOLD records. Compile r1
completed make but retained no actual header, so its rejected field remains
unmeasured; the r2 header does not retroactively supply that evidence. No old
trial was replayed or overwritten.

Next, separately admit a guest using this exact externally pinned bundle and
require advancing PL031 RTC/HCTOSYS/current-UTC proof before cryptographic
package journeys. No RTC guest boot or package-trust outcome is established by
this build. This documentation change ran no actor and copies no raw logs,
credentials or source payloads.
