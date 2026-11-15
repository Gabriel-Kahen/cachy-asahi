# Generic ARM16K UI-seat reference build, 2026-11-15

Root's separately admitted configure and compile produced
`7.1.13-generic16k-managed-gui-rtc-uiseat1`, status
**BUILT_ONLY_UI_SEAT_BOOT_NOT_RUN**. The successful `HOST_CROSS_ARM64` build
used LLVM 22.1.8 on x86_64. It establishes no guest boot, input/seat/UI behavior,
native 16K, Asahi/M2 hardware, performance or release acceptance, and makes no
same-toolchain claim against the historical native LLVM 18 build.

## Exact configuration and source

The starting point is the separately built
[RTC reference](arm16k-rtc-reference-kernel-build-20261115.md), bundle SHA256
`68f3ff68c78fa3aa8b3d66c3b301472c846a7eb8d2a830ba565d61547029492f`.
Exactly two semantic settings differ from its actual config:

| Setting | RTC reference | UI-seat successor |
| --- | --- | --- |
| CONFIG_VIRTIO_INPUT | n | y |
| CONFIG_LOCALVERSION | `-generic16k-managed-gui-rtc1` | `-generic16k-managed-gui-rtc-uiseat1` |

The same eleven-key RTC contract and fifteen exact compiler/auxiliary facts
remain held. No additional bus, RTC driver, PC keyboard/bootloader or unrelated
feature was admitted. Configure r1 produced the reviewed config; compile r1
reran configure in a fresh workspace and matched it exactly.

The unchanged source archive is 262965559 bytes, SHA256
`874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`,
AsahiLinux revision `94fb23346d522edf53722357c426a3e58030beea`
(`asahi-7.1.13-3`). Original provenance remains Source
`4056e2505ed7081674e949e0460258672cce14ff`, run `39156901928`.
No kernel source patch was introduced.

## Actual execution and resource policy

Configure ran from 09:16:30 to 09:16:47 UTC. Compile ran from 09:18:00 to
09:23:16 UTC and completed these commands:

```sh
/usr/bin/make -C /work/ui-seat-kernel/linux-asahi-7.1.13-3 O=/work/ui-seat-kernel/build ARCH=arm64 LLVM=1 olddefconfig
/usr/bin/make -C /work/ui-seat-kernel/linux-asahi-7.1.13-3 O=/work/ui-seat-kernel/build ARCH=arm64 LLVM=1 -j2 Image
```

Both compile-stage commands exited 0, were naturally reaped with `EMPTY_TWICE`
group census and complete output, and required no timeout or signals. The Image
command took 298.77 seconds. Root confirmed container exit 0, no OOM, final
owned-container absence, unchanged host inputs and `CLOSE_ONLY` lease release.

The read-only host `/usr` cross-build domain retained pre/post guards over
116 ALPM records, 18 tools and 72 runtime files. It used no network, capabilities
or host package installation, with NNP/read-only root, 2 CPUs, 8 GiB memory/swap
cap and 256 PIDs. The separately issued **v2 resource policy** required an
additional 3 GiB host reserve and no concurrent heavy actor. This was explicit
new authority, not a silent relaxation of the preserved, unentered 12 GiB
availability policy. The compile tool-profile SHA256 is
`39add9ed98a51e1b7ff3ea5d96b26226ada8b4d614bd2405a81ddfb5a72a7c14`.

## Retained output

The three-file bundle uses `ARM16K_UI_SEAT_REFERENCE_KERNEL_BUNDLE_V1`.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| Image | 9019400 | `36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494` |
| config | 71585 | `b8bc8c636ae7e58e8e338e7dba87d84a390d0555fa7307fc76217e0d56553d7f` |
| bundle.json | 9549 | `c8f03dff4f98dbf24e2273442c3008875cfb8a2d595d08e28b263c8c8b3308f1` |

The retained 64-byte ARM64 header has SHA256
`621f2a525f58d3eeca54a8cd049939a0382e8bad48b07b7533850ff310162fcc`,
magic `41524d64`, little-endian 16K flags 12 and text offset 0. Its effective
memory span is 9568256 bytes, independently bounded from the 9019400-byte file;
the 64 MiB file and 128 MiB memory-span caps both pass.

| Retained receipt | Bytes | SHA256 |
| --- | ---: | --- |
| Configure r1 result | 6086 | `c10eb8abac03302b20895eedb6f2f951d49caedbae0a13412359928104d8f7c7` |
| Compile r1 build report | 4143 | `927cb8bc3af6ebddcac2895556d6d127dd91f61617159ac5e93f0e4cd1d891b0` |
| Compile r1 Root terminal result | 18474 | `eadf4d2e463c2db2b09df8e16729862b3d53b32dba328ca47722a6c059cabd4c` |
| Compile r1 resource authority | 648 | `cc8afa1a990c2730e6e65570406b493d79e33a86316ffcb47991dd8e78a5914b` |

Next, a separately admitted consumer must bind this exact bundle and prove
current RTC time, actual virtio input enumeration, seat/PAM behavior and UI
operation in the guest. The existing RTC bundle and closed trials remain
unchanged. This documentation-only task ran no additional actor.
