# Generic ARM guest feasibility for software desktop exercise

Source audit: October 11, 2026. **Guest tooling provision, guest boot, EGL/GBM
probe, compositor session, frame capture and all hardware checks: NOT RUN.**
This report specifies a finite software experiment. The subsequent
[source implementation handoff](../workstreams/virtual-desktop-guest.md) records
the guarded proof scripts, authenticated separate tooling closure, checks and
remaining native execution. No target platform or shared builder lock was changed.

## Decision

A full generic aarch64 Linux guest under QEMU TCG is a **source-supported,
conditionally viable next proof**. A physical Mac is not established as necessary
for exercising the compositor's software rendering path. The current container's
missing DRM interface remains a real blocker for that container; a guest kernel
can supply virtual DRM without passing host DRM devices or loading host modules.
The exact pinned Hyprland/Aquamarine/Mesa combination still requires a runtime
GBM allocation/import/render/scanout proof before a compositor success claim.

Use QEMU's ordinary 2D `virtio-gpu-pci`, software Mesa inside the guest, direct
Linux `Image` boot, serial diagnostics and QMP screen capture. TCG needs no
`/dev/kvm`; 2D virtio needs no host GPU. QEMU is an ordinary non-root process in
a network-disabled disposable container. No privileged Docker, host package
installation, loop mounts, host modules, host display/audio/input sockets,
virglrenderer, rutabaga, Vulkan passthrough or Apple emulation is needed for this
proposed route. Guest-root operations are confined to guest state.

This can test generic boot/userspace integration, rendering, the opt-in Lua
configuration, a Wayland client and session IPC. It cannot establish M2 boot,
Apple DRM/AGX, 16K-page compatibility, graphics acceleration, peripherals,
battery/suspend/thermals, installation/removal on Asahi or performance gains.
The guest kernel audited below uses **4K pages**.

## Audited pins and causal evidence

| Component | Audited revision / artifact | License / finding |
| --- | --- | --- |
| QEMU candidate | `v11.1.2`, commit `4fc49f46dc95d4a27de2509e7fceb2931e91faeb`; ALARM `qemu-system-aarch64` and `qemu-common` `11.1.2-1` | Emulator GPL-2.0; component licenses vary. Tooling is absent from the current builder. |
| Hyprland | `v0.56.2`, `efb50993780079460b0cbed1363e2166a2de1d9f`; `0.56.2-4` in current lock | BSD-3-Clause; software renderer detection exists; successful EGL/GBM remains required. |
| Aquamarine | `v0.15.1`, `f31c47a1b9d300847d8fc3108ad959448103dfc1`; `0.15.1-1` in current lock | BSD-3-Clause; DRM renderer falls back to the KMS fd; PRIME import and working GBM buffers are required. |
| Mesa | `mesa-26.2.4`, `96cb43121031992b85767f9c1be8f3f48e22b1d2`; signed `1:26.2.4-1` archive SHA-256 `b03b498ba04ef5217299a81a1ef4c1c3582a250fab74848a443b85ba4a352fbd` | MIT AND BSD-3-Clause AND SGI-B-2.0 per package. GBM has `kms_swrast` fallback; KMS software winsys creates dumb buffers and imports/exports PRIME fds. |
| Generic Linux | signed `linux-aarch64-7.2.10-1` archive SHA-256 `9172d7677d3c1c4b4b72b50b7931b5ccc19a4552d68e4a029ca7e9663e1ebcb7`; upstream `v7.2.10` source | GPL-2.0-only per package. Existing package contains `boot/Image` and guest modules; no custom kernel required by the audited config. |

QEMU's [pinned virtio GPU documentation](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/docs/system/devices/virtio/virtio-gpu.rst)
describes the 2D backend with guest software rendering. Its
[pinned ARM virt documentation](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/docs/system/arm/virt.rst)
describes the generic platform, PCI virtio GPU, required kernel options and direct
kernel boot with QEMU-generated DTB. `virt` does not model a Mac.

Mesa's [pinned GBM backend](https://gitlab.freedesktop.org/mesa/mesa/-/blob/96cb43121031992b85767f9c1be8f3f48e22b1d2/src/gbm/backends/dri/gbm_dri.c)
uses `kms_swrast` when hardware driver creation fails or `GBM_ALWAYS_SOFTWARE` is
set. Its [KMS software winsys](https://gitlab.freedesktop.org/mesa/mesa/-/blob/96cb43121031992b85767f9c1be8f3f48e22b1d2/src/gallium/winsys/sw/kms-dri/kms_dri_sw_winsys.c)
implements dumb-buffer allocation, mapping, PRIME import and export with linear
modifiers. [LLVMpipe screen capabilities](https://gitlab.freedesktop.org/mesa/mesa/-/blob/96cb43121031992b85767f9c1be8f3f48e22b1d2/src/gallium/drivers/llvmpipe/lp_screen.c)
include DMA-BUF import/export when its winsys supplies a DRM fd. The
[EGL DRM platform](https://gitlab.freedesktop.org/mesa/mesa/-/blob/96cb43121031992b85767f9c1be8f3f48e22b1d2/src/egl/drivers/dri2/platform_drm.c)
handles software GBM without requiring a compatible hardware render GPU.
These are causal software paths, not proof that the signed ARM build enabled or
successfully executes every feature. The signed Mesa archive inspected locally
contains `kms_swrast_dri.so`, `swrast_dri.so` and `virtio_gpu_dri.so` symlinks to
`libgallium-26.2.4-arch1.1.so`.

Aquamarine's [DRM renderer attachment](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/drm/DRM.cpp)
can use the KMS fd if no render-node fd exists. Its
[GBM allocator](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/allocator/GBM.cpp)
exports each buffer plane fd. Hyprland's
[renderer](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/render/Renderer.cpp)
recognizes llvmpipe/softpipe, while its
[OpenGL initialization](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/render/OpenGL.cpp)
requires usable EGL and GL extensions. This removes the categorical claim that
software rendering itself needs Apple hardware; it does not certify this VM.

## Exact guest boot inputs already inspected

The signed Linux archive contains `boot/Image` (50,485,760 bytes; SHA-256
`92445dac35421e6cba8ccf7b3e7de8fe8ca8914b69db26fce4a5162352f5dc0a`).
Local read-only extraction of its embedded IKCONFIG produced config SHA-256
`4748eb86a0f27b34de1e62435da15287d763637205d0ba44c249991b04bc7238`:

```text
CONFIG_ARM64_4K_PAGES=y
# CONFIG_ARM64_16K_PAGES is not set
CONFIG_BLK_DEV_INITRD=y
CONFIG_PCI=y
CONFIG_PCI_HOST_GENERIC=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_DRM=y
CONFIG_DRM_VIRTIO_GPU=m
CONFIG_VIRTIO_INPUT=m
CONFIG_DEVTMPFS=y
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_INPUT_EVDEV=y
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
CONFIG_EXT4_FS=y
```

The exact module is
`usr/lib/modules/7.2.10-1-aarch64-ARCH/kernel/drivers/gpu/drm/virtio/virtio-gpu.ko`
(122,336 bytes). Keep the entire matching modules tree and run guest-image
`depmod` during offline preparation: `modules.dep` is not shipped in the inspected
archive. Generate dependency metadata with
`depmod -b STAGED_GUEST_ROOT 7.2.10-1-aarch64-ARCH` inside the disposable fixture builder, never against
host `/lib/modules`. The [upstream virtio DRM driver](https://github.com/gregkh/linux/blob/v7.2.10/drivers/gpu/drm/virtio/virtgpu_drv.c)
declares modeset/GEM/render/atomic capabilities. Host kernels never load these
modules.

With PCI, virtio block and ext4 built in, direct `Image` boot of a raw ext4 root
disk is the smallest proposal; an initramfs is not inherently needed for root
discovery here. Validate this once. If the packaged boot path needs an initramfs,
use existing `mkinitcpio 42.2-1` and `mkinitcpio-busybox 1.36.1-1` inside the
fixture build, with explicit guest modules and no host-derived autodetect hook.
Never execute the rootfs's PC bootloader hooks or substitute the host kernel.
No UEFI/GRUB package is required for direct Linux boot.

## Separate tooling extension: missing inputs

The original audit identified the following **metadata candidate**, derived from the already captured
core/extra databases and the 341-package builder inventory. It is not a completed
pacman transaction or authenticated download closure. Normalized named
requirements yield 19 absent packages, 13,662,132 compressed bytes. The
subsequent handoff now records an actual isolated print-only pacman solve and
local authenticated download/metadata audit for all 19. A separately constructed
immutable fixture image and actual native execution remain required. Do not modify the original builder lock to hide this
extension. Source/build records must map each package to its upstream recipe and
source revision; that mapping has not been completed for the dependency closure.

| Missing package | Exact candidate version | Archive SHA-256 |
| --- | --- | --- |
| `capstone` | `5.0.9-1` | `f96ad05de152308112c6f895e42d52669942d5698d5a7491caeb853128fda3a9` |
| `dtc` | `1:1.8.1-1` | `c60faaee0f149ef74fc9feb9aba5cc564d971e021c5bff523568ae0fb257a319` |
| `fuse-common` | `3.18.3-1` | `f8a67e6a893e09ece9d9611112b46259df1d947b8d57ac9f118a00eb955780b9` |
| `fuse3` | `3.18.3-1` | `ea1a152ebe20cecf157378c8917e04b976e89287e2471dd20117b3923b3f0ebb` |
| `libaio` | `0.3.113-5` | `18af1ae9233952a6a505f09cc632b09b2eff5898ebff7e1e931829146169de47` |
| `libslirp` | `4.9.5-1` | `ca402058ef0080a83dd386fe550ef4659f3caad96c8017531df3535e578a4e94` |
| `libtraceevent` | `1:1.9.0-1` | `413357116a57a128084aa28513951ad2ebd5b18215d3b9de2eb5fb01856acd20` |
| `libtracefs` | `1.8.3-1` | `b41dc9bb609f2f72ab6078f111fedf7c4b559f3a2ab8b42c5dac65c0f1fe12ac` |
| `liburing` | `2.15-1` | `efb67ef7eed7b30bebebbe9420fbf67bbfd0676c2b731f30e47e544cdb73feaf` |
| `libxdp` | `1.6.3-2` | `536cca5cad699995dcc464d842e923acb8b18dff0aa665e1a17fc11e322ea45c` |
| `libyaml` | `0.2.5-3` | `f96d25c8898b27d3364034336630363bcf48eb968c90d5d5c240e4b237ae153b` |
| `ndctl` | `85-1` | `5090e80deb3566e2530d6115b036215216b2e0fd7c1a2205161203d59a34aae9` |
| `numactl` | `2.0.19-1` | `b28ebc082254c63fbbd9aac1e2ec9bae8e78fe7243682e875df537906ecb5971` |
| `qemu-common` | `11.1.2-1` | `f71da9d341459b24a0bf608d566421cad8788a3e8b3d0a93aa82f28066173be3` |
| `qemu-system-aarch64` | `11.1.2-1` | `989a142989ab9c6696593af4561d6d7cb40c408d6a5eb2a4eaee0fdacbdb127d` |
| `rdma-core` | `65.0-1` | `5031f9cbf8e98963c2b1b3e1a221e02e4f6962160cf8042afbe962577b236295` |
| `snappy` | `1.2.2-3` | `19e057413b812c31b2e540261480a7c1088c80c7d2999e3754953f3710cadaf0` |
| `vde2` | `2.3.3-10` | `3448c3a49d23407ac32f3dbd7fed4fefce406a4acc4cc150af3faaccc51cf77c` |
| `wolfssl` | `5.9.4-1` | `4a332bc1b879e3ef5619b012334a18393355297107dcba00e1c6daea8bee2704` |

Candidate URLs use the existing reviewed mirror and database filenames:
`https://ca.us.mirror.archlinuxarm.org/aarch64/{core|extra}/{filename}` plus
`.sig`; repository selection and signature byte pins must be frozen before use.
The QEMU packages' exact dependency metadata includes pixman, libpng, JPEG,
libseccomp, libslirp, storage/network libraries and `qemu-common=11.1.2-1`.
These installed library dependencies do not authorize enabling their host
interfaces. No `qemu-base`, `qemu-img`, EDK2, GUI display backend or virgl package
is necessary for the proposed raw-disk, QMP/serial-only run.

QEMU's [pinned LICENSE](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/LICENSE)
requires component-specific accounting. Dependency package metadata identifies
BSD-3-Clause (capstone, snappy), GPL-2.0-or-later (dtc), GPL-2.0/LGPL-2.1 (FUSE,
trace libraries, numactl), LGPL-2.0-or-later (libaio), BSD/MIT (libslirp), MIT
(libyaml), GPL/LGPL/BSD (libxdp), mixed LGPL/GPL/CC0/MIT (ndctl), mixed syscall
exception/LGPL/MIT (liburing), mixed GPL/BSD/MIT/CPL (rdma-core), GPL/LGPL (vde2)
and GPL-3.0-or-later (wolfssl). Preserve full license expressions and upstream
source obligations in the eventual fixture receipt; these abbreviated labels
are not a redistribution clearance.

Existing e2fsprogs `1.47.4-1` can be the candidate offline raw-image builder.
Use staged fixture contents and `mke2fs -d` in a disposable image-preparation
container; no host loop device, mount or FUSE device. Preserve numeric owners,
modes, symlinks and guest account ownership and verify them inside the guest.
A conventional root user within an unprivileged Docker container can stage
metadata without giving QEMU privileged host access. Review the fixture-only
`/etc/fstab`, init/systemd services and guest account/VT setup for `/dev/vda`;
do not inherit board-specific mount targets or unattended login behavior from
the generic rootfs without inspection. These edits affect only the disposable
guest disk, never the target Asahi stack. The final QEMU container
runs non-root with dropped capabilities. The guest image must contain the
reviewed overlay archive installation and evidence runner, not a host HOME.

## Smallest bounded proof and stop rules

1. **Tooling/boot gate:** Authenticate the separate extension, bind its image
   digest/lock to evidence, and require `qemu-system-aarch64 --version`,
   `-accel help`, `-machine help`, `-device help` and QMP commands to show the
   pinned binary, TCG, `virt-11.1`, `virtio-gpu-pci` and `screendump`. Prepare
   one disposable raw ext4 guest with the existing userspace/kernel/modules.
   Record all preparation commands, root image/Image hashes and package list.
2. **One boot attempt:** Use `-machine virt-11.1 -accel tcg -cpu max -smp 2
   -m 4096 -kernel Image -append "console=ttyAMA0 root=/dev/vda rw"
   -drive if=none,id=root,file=guest.raw,format=raw
   -device virtio-blk-pci,drive=root -device virtio-gpu-pci,id=gpu
   -nic none -display none`. Bind serial and QMP only to private Unix sockets
   or retained log files. Specify no KVM/host display/audio devices and no TCP
   listener. This is a proposed invocation, **not a tested command**. Supply
   guest-only serial boot service/input and automation explicitly.
3. **DRM/EGL gate:** In the guest, load `virtio_gpu`, settle udev and retain
   dmesg, module versions, `/dev/dri` inventory, connectors/modes and page size.
   Probe GBM/EGL against the guest DRM fd, software renderer identity, required
   GL BGRA extension, PRIME import/export, linear GBM allocation, exported plane
   fd, EGL DMA-BUF import and a cleared/rendered buffer. A small reviewed probe
   can be compiled with existing GCC and Mesa/libdrm headers; its source/hash,
   compiler command and actual return codes belong in evidence. If this fails,
   retain the precise error and stop; do not start a custom kernel/GPU project.
4. **Session gate:** Use guest logind with a real guest VT/PAM session, or a
   documented guest-only seatd session (`seatd 0.9.3-1` is already frozen).
   Configure seat/VT access within the guest; the outer container needs none.
   `GBM_ALWAYS_SOFTWARE=1`, `LIBGL_ALWAYS_SOFTWARE=1` and `GALLIUM_DRIVER=llvmpipe`
   are diagnostic forcing candidates, not proof of renderer identity. Capture
   actual Mesa renderer strings. Launch pinned Hyprland as an ordinary guest
   fixture user with a fresh runtime/home/config and no optional shell startup.
   First use minimal config; only after success launch the installed opt-in Lua
   overlay and an existing Wayland application such as Wofi. Log session IPC,
   monitor output, application lifecycle and clean shutdown. Do not assert
   Waybar/Mako execution: neither binary is present in the current frozen set.
5. **Frame gate:** QEMU `-display none` suppresses host presentation while the
   emulated GPU remains. Use the [pinned QMP screendump command](https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/qapi/ui.json)
   (requires QEMU pixman; PPM always avoids a PNG-only assumption). Capture a
   frame after the application appears, inspect it and bind its hash to the
   matching compositor/client/IPC logs. A boot console or blank frame does not
   pass compositor software exercise. VNC over a private Unix socket is an
   optional diagnostic, not needed for this proof. `egl-headless` is not the
   chosen backend because it introduces host EGL/render-node assumptions.

Budget one VM attempt with a 10-minute boot deadline, 5-minute EGL/session
subphase deadlines and 20-minute overall deadline; collect failure before
termination. Initial allocation is 2 guest vCPUs/4 GiB guest RAM, not a measured
minimum. Cap llvmpipe threads at 2 (`LP_NUM_THREADS=2`) to avoid oversubscribing
4 host CPUs. Set an outer container memory ceiling of 6 GiB (4 GiB guest plus
QEMU/software overhead; unmeasured sufficiency) and CPU ceiling of 4. Keep
serial/IPC logs bounded at 64 MiB with explicit failure on overflow.
Use an 8 GiB **sparse** root disk only after checking fixture size;
preflight real free disk space for rootfs extraction, container layers, disk
allocated blocks and logs against the runner's 14 GB allowance. The existing
341-package userspace and duplicated layers make this a genuine resource gate.
Measure `df` before preparation and `du`/allocated blocks for staged userspace,
container storage and guest disk throughout preparation; account for temporary
package extraction, existing builder layers and simultaneous fixture copies.
Do not call a trimmed package subset the complete 341-package base: record its
exact inventory and narrower scope if a separate minimal fixture is proposed.
If free space/allocated blocks exceed budget, stop with sizes rather than assume
sparsity guarantees capacity. Retain compact public evidence; do not export the
rootfs/dependency disk through current text-only integration exporters.

No runtime duration, memory sufficiency, pixel correctness or native ARM LLVM
JIT success is claimed. Failure of the bounded experiment establishes a blocker
for these exact inputs and limits; it does not establish physical Mac necessity.
The coordinator owns implementation, lock changes, CI dispatch and integration
with the existing desktop parser-only workstream.

## Subsequent implementation boundary

See [the executable handoff](../workstreams/virtual-desktop-guest.md). Twenty-nine
local guard/data/process/controller tests pass, and the guest GBM probe compiles with
existing x86 headers without execution. All 19 extra original ARM packages and
signatures were authenticated locally; the public lock/audit preserve their
resolved metadata. No native guest disk preparation, QEMU boot, compositor or
frame execution has run. Automated frame capture will stop pending actual
visual review; no colorful-frame heuristic grants acceptance. This is R1/R4
software integration infrastructure only. R1–R5/M5–M9 and both M2 Air hardware
acceptance remain mandatory under the revised goal and acceptance matrix.

The tooling closure was explicitly re-solved against revised native input lock
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`
(Perl `5.42.3-1`), with all 341 local package versions compared. It still adds
exactly the same 19 archives with no base replacements. All archive signatures
and signed metadata were reauthenticated from the private cache; this refresh
does not reuse the superseded baseline receipt as evidence for the new baseline.
