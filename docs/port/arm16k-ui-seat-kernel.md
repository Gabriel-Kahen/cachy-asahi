# ARM16K UI-seat kernel diagnostic

The source-only constructor at
[`scripts/integration/arm16k_ui_seat_kernel/`](../../scripts/integration/arm16k_ui_seat_kernel/README.md)
provides a distinct generic virt/TCG reference kernel recipe. It changes only
VIRTIO_INPUT=n→y and LOCALVERSION from the actual built RTC reference. Existing
16K/RTC/VT/EVDEV/virtio-MMIO/DRM/framebuffer declarations and the fifteen reviewed
compiler facts are held exactly. Unexpected configure results refuse.

This addresses an actual source/config gap for a future virtio keyboard and
stock tty1 UI-seat trial. It does not change the Asahi target kernel, the passed
RTC KSM/C01 bundle, its consumers, or any selected recipe/manifest. No configure,
compile, preparation, container or guest was run by this source task.

The [pinned Linux VIRTIO_INPUT stanza](https://github.com/AsahiLinux/linux/blob/94fb23346d522edf53722357c426a3e58030beea/drivers/virtio/Kconfig#L131)
depends on already-built VIRTIO/INPUT, without selecting an additional driver.
The [QEMU11.1.3 keyboard type](https://github.com/qemu/qemu/blob/v11.1.3/include/hw/virtio/virtio-input.h#L30)
is virtio-keyboard-device. The finite source plan pairs it with virtio-gpu-device
over virt's MMIO transport, without PC i8042, host input passthrough or KVM.
All read operands are retained and SHA-256-pinned as DATA in the new directory.

The inspected x86 reference actually passed tty1/seat0 with an i8042 input parent
and PCI DRM card: local report
`/tmp/cachy-asahi-real-seat-live-tty-first-boot-root-20261114/report.json`,11299bytes,
SHA-256 `3384ce35565e5dea49cd7ad9889ac413e917a6386d8754057e62939323d7717b`.
That input-parent predicate is x86-specific and cannot be copied as ARM proof.
A future ARM actor must establish actual QEMU device availability, virtio-MMIO
keyboard/evdev and DRM enumeration, standard udev seat tagging, active tty1 PAM/
logind seat0 and UI execution. These are pending, not implied by configuration.
The installation worker separately owns the145-addition package closure and its
reported six missing tiny archives; this kernel source claims no completed256-
package composition or package acquisition.

Root owns new host-tool profile/resource admission, configure review, compile
and any separately pinned consumer/VM actor. The constructor reuses the frozen
RTC two-stage build/supervision/tool guard, with a distinct operation/release/
output schema. Current native heavy work must retire before a new heavy stage.
See the source README for exact commands and resource/mount proposal. The38
actor-fenced controls and DATA inspector passed; no runtime stage was attempted.
No native16K, Apple/M2, performance or release acceptance follows from this work.
