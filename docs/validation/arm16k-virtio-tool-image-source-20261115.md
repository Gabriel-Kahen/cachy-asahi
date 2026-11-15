# Generic ARM virtio tool-image correction source, 2026-11-15

Root's retained device-help r2 establishes a concrete host-tool blocker in image
`sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207`:
`virtio-blk-device` and `virtio-keyboard-device` are present, while
`virtio-gpu-device` is absent. The probe container was retired; the old image
and its historical guest results remain unchanged.

The [new offline source](../../scripts/integration/arm16k_virtio_tool_image/README.md)
adds exactly Arch's matching non-GL split package. This task completed package
acquisition and static verification, **not an image build or device probe**.
Actual successor image ID, three-device qualification and guest behavior remain
pending Root admission and execution.

| Exact input | Bytes | SHA256 |
| --- | ---: | --- |
| qemu-hw-display-virtio-gpu 11.1.3-1 x86_64 archive | 38829 | `e6fff868047ec766fe2d1e065db96c31bcc5ca8b15f7cc570b2e1c83e444e7ee` |
| Detached official catalog signature | 119 | `acaa797c7d026778d0951509ed428ad1440f9aeefb2cc0f4c00fbba20e381200` |
| hw-display-virtio-gpu.so | 71632 | `389cbb38a545bacce11c4665e875bb37826acee1cd5205fe5ef99b804ca95db4` |
| Exact parent qemu-system-aarch64 executable | 34622584 | `6f16cea44da813a65a1076886f63687350a0173e188873ba227dcc06f5c16b27` |

The archive came from the [official 2026-11-09 snapshot](https://archive.archlinux.org/repos/2026/11/09/extra/os/x86_64/qemu-hw-display-virtio-gpu-11.1.3-1-x86_64.pkg.tar.zst),
using one HTTPS request without redirects or retries. Its checksum and detached
PGPSIG match the previously retained snapshot catalog, SHA256
`1b4caf18e4a57ba10f201c7b19892bb55a37283c2b0369b39cc6c4f6b654151d`.
Mathematical gpgv verification succeeded under the retained official public
keyring after dearmoring its ASCII input; the initial armored-input failures
remain separate diagnostic records. No private key, backdating, host keyring
mutation or signature-policy relaxation was involved.

The actual package has 17 ordinary members, no install scriptlet or hook, and
121232 installed bytes. Its PKGINFO requires only glibc, pixman,
`libpixman-1.so=0-64` and `qemu-common=11.1.3-1`. Retrieved ee1 ALPM metadata
confirms all providers already installed. The ELF needs only `libc.so.6` and
`libpixman-1.so.0`; exact parent provider bytes were retrieved and pinned. Its
exported `qemu_stamp_913ef03f58f097081461725293209a4ad4cab60a` matches the
parent QEMU binary, whose whole pin also matches Root's actual probe.
No GL, virglrenderer, rutabaga, PCI GPU or PC-bus fallback is needed.

Three uniquely owned containers were created, copied from and removed **without
starting them**. A second copy in the first container encountered a Docker
overlay mount error; no module-directory observation is inferred from it.
All three containers' absence was checked. No package payload was executed.

The runnable successor preserves the existing owned-container, cancellation,
command-runner and process-retirement primitives. Root must separately issue
fresh source/material/resource/output authority and retain the canonical lease.
The offline normal signature-required, dependency-checked pacman transaction
must add exactly one package to the unchanged 178-package parent. A distinct
read-only probe must then verify actual QEMU/module/provider bytes and all three
literal device names. It retains complete help bytes, actual UTC, bounded logs,
natural retirement and owned-container absence. A successful output includes
the exact ARM155 `ROOT_OBSERVED_ARM_QEMU_DEVICE_HELP_V1` metadata schema;
Root must pin the actual new image and whole receipt before updating a consumer.

Proposed bounds are one CPU, 512 MiB memory/combined-swap cap, 64 PIDs,
360 seconds, 8 MiB output, at most 32 MiB image delta and 256 MiB additional disk,
with 1 GiB disk and RAM reserves. No raw guest disk is prepared. The task ran
14 actor-fenced controls, three modeled producer-to-ARM155 metadata controls and
actual passive archive/ELF/signature checks. Models establish no GPU availability.
Image installation/build/probe, guest MMIO/seat/PAM/UI, native ARM/M2,
performance and release qualification remain unrun by this task.
