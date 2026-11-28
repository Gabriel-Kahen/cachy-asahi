# Asahi629 Wayland and Lavapipe guest plan

Weston 15.0.1-3 in headless Pixman mode is a viable compositor fixture for the
existing offline ARM64/16 KiB Asahi629 guest. Run it and the Qt clients as UID
and GID 65534, with no supplementary groups. The retained QEMU command, the
installed Asahi stack and the 629-package lock can all be used as-is. The
Weston archive signature, required ELF members and relevant upstream paths
were checked. The corrected scoped guest subsequently passed as recorded in
the [Qt replacement result](../../scripts/integration/qt612_r132_replacement/README.md#corrected-scoped-guest-trial-november-27).

## Exact inputs

- Use the successful Asahi629 `rollback.lock` from the [Qt provider handoff](../../scripts/integration/qt612_r132_replacement/README.md).
  It is 12,346 bytes with SHA-256
  `f335e8430a1d6f8463e95e16524cf78fc224c24fb31cf8717723370490bae9fa`.
  The installed inputs include Qt Base 6.12.0-3, Qt Declarative 6.12.0-1,
  Wayland 1.26.0-1, Mesa and `vulkan-swrast` 1:26.2.4-1, and the Vulkan
  loader and tools 1.4.363.0-1. Both Qt Base archives carry the Wayland QPA
  plugin. Neither carries Qt Wayland Compositor, and the lock has no Weston,
  Sway or wlroots package. The issued trial used a distinct project TEST
  signature as required by the replacement handoff.
- Use the retained [Asahi629 launcher](../../scripts/install/asahi629_trial/README.md)
  with QEMU `virt`, TCG, `-display none -nodefaults -nic none` and the original
  four virtio block drives. The R132 transaction `Image` is 9,019,400 bytes with
  SHA-256 `36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494`.
  The 71,585-byte config is
  `b8bc8c636ae7e58e8e338e7dba87d84a390d0555fa7307fc76217e0d56553d7f`.
  It enables 16 KiB pages, UNIX sockets, memfd and tmpfs. Keep the actor's
  private `/run` and minimal `/dev` mounts. The compositor needs neither a
  DRM node nor a display backend on the host.
- Stage the [ALARM Weston 15.0.1-3 archive](https://ca.us.mirror.archlinuxarm.org/aarch64/extra/weston-15.0.1-3-aarch64.pkg.tar.xz)
  and [original signature](https://ca.us.mirror.archlinuxarm.org/aarch64/extra/weston-15.0.1-3-aarch64.pkg.tar.xz.sig)
  on the reviewed read-only input media. The 1,404,596-byte archive is
  `2da79ea9f1059b5e068debbf6c5b4f650c59c9b6725d98479c5c99753d878f36`.
  The 566-byte signature is
  `8c9ebba381aa0bee1b59aaff78e982401ede6f0d6c44c0864659db835661152a`.
  `gpgv` verified signer `68B3537F39A313B3E574D06777193F152BDBE6A6` using
  the Qt handoff's pinned ALARM public key. The package declares AArch64 and
  MIT. Its full package metadata depends on `colord`, which is absent from
  the lock. The selected headless executable and modules have no colord ELF
  dependency. The lock includes `libcolord`, while `libglvnd` supplies the
  declared `libegl` and `libgles` interfaces. [ALARM package metadata](https://archlinuxarm.org/packages/aarch64/weston)

The Qt client's Lavapipe ICD is the installed
`/usr/share/vulkan/icd.d/lvp_icd.json`, from the retained `vulkan-swrast`
archive with SHA-256
`7a7f91740277b249e7ffde741ce0775ce54cf288e2f27e14e84451b9a26439e8`.
Mesa 26.2.4 initializes Lavapipe WSI as a software device with DRM fd `-1`.
Its Wayland WSI binds `wl_shm` for software devices and creates Wayland
buffers from shared memory. This lets a real Vulkan swapchain present to
Weston Pixman without KMS or DMA-BUF. [Mesa 26.2.4 source archive](https://archive.mesa3d.org/mesa-26.2.4.tar.xz)

The installed Hyprland 0.56.2 selects Aquamarine's headless, DRM and Wayland
backends. Aquamarine 0.15.1 still requests a DRM-backed GBM allocator in this
configuration. Creating a headless Hyprland output cannot supply the missing
DRM descriptor. The retained kernel does have built-in virtio GPU/KMS and
virtio input, and an [earlier ARM16K seat trial](../validation/arm16k-virtio-seat-actual-20261115.md)
enumerated them with `-device virtio-gpu-device -device virtio-keyboard-device`
under `-display none`. A Hyprland trial would also need to admit those exact
devices, provide the DRM and input nodes to the chroot and establish an active
seat. [Hyprland 0.56.2 backend selection](https://github.com/hyprwm/Hyprland/blob/v0.56.2/src/Compositor.cpp),
[Aquamarine 0.15.1 allocator](https://github.com/hyprwm/aquamarine/blob/v0.15.1/src/backend/Backend.cpp),
[QEMU virtio GPU documentation](https://www.qemu.org/docs/master/system/devices/virtio/virtio-gpu.html)

## Stage and run the compositor

1. The owning guest worker verifies the archive and detached signature, then
   copies only the following members into a fresh, root-owned tree at
   `/trial-scratch/tmp/qt629-weston`. Preserve relative paths. Validate the
   two SONAME links and reject unexpected member types, ownership or modes.
   Five regular ELFs were inspected as AArch64 with 64 KiB load segment
   alignment. All 20 direct external SONAMEs match file entries in 16 exact
   locked packages. Check actual loader resolution in the disposable chroot
   before the timed probes, including dependencies of the two modules.

   ```text
   usr/bin/weston
   usr/lib/libweston-15.so.0 -> libweston-15.so.0.0.1
   usr/lib/libweston-15.so.0.0.1
   usr/lib/libweston-15/headless-backend.so
   usr/lib/weston/libexec_weston.so.0 -> libexec_weston.so.0.0.0
   usr/lib/weston/libexec_weston.so.0.0.0
   usr/lib/weston/kiosk-shell.so
   ```

   This is a private test fixture on executable scratch space. Pacman's
   inventory, installed package paths and `/etc` configuration stay as they
   were. Remove the fixture after supervision completes. [Weston 15.0.1 module lookup](https://github.com/wayland-mirror/weston/blob/15.0.1/libweston/compositor.c#L10350)

2. Create `/trial-scratch/run/qt629-wl` and its `home` and `tmp` directories
   with mode `0700` and owner `65534:65534`. Start Weston in its own process
   group with stdin closed and bounded log capture. The following command
   runs inside the actor while the target API mounts are live.

   ```sh
   rt=/run/qt629-wl
   fx=/tmp/qt629-weston
   /usr/bin/chroot /trial-scratch /usr/bin/setpriv \
     --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
     --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
     /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
     HOME="$rt/home" TMPDIR="$rt/tmp" XDG_RUNTIME_DIR="$rt" \
     LD_LIBRARY_PATH="$fx/usr/lib:$fx/usr/lib/weston" \
     "WESTON_MODULE_MAP=headless-backend.so=$fx/usr/lib/libweston-15/headless-backend.so;kiosk-shell.so=$fx/usr/lib/weston/kiosk-shell.so" \
     WAYLAND_DEBUG=server \
     "$fx/usr/bin/weston" -B headless --renderer=pixman --shell=kiosk \
     --socket=wayland-0 --width=256 --height=256 --idle-time=0 --no-config
   ```

   The headless backend creates a memory-backed output and repaints it with
   Pixman. Kiosk shell maps XDG toplevels without a seat. The `--no-config`
   default leaves the color-management module unloaded. [Weston 15.0.1 frontend](https://github.com/wayland-mirror/weston/blob/15.0.1/frontend/main.c),
   [headless repaint](https://github.com/wayland-mirror/weston/blob/15.0.1/libweston/backend-headless/headless.c),
   [kiosk surface mapping](https://github.com/wayland-mirror/weston/blob/15.0.1/kiosk-shell/kiosk-shell.c#L978)

3. Require a live owned Weston process, an enabled headless output and a
   fresh, nonsymlink UID-65534 socket at `/trial-scratch/run/qt629-wl/wayland-0`.
   Connect with a bounded readiness check and verify `SO_PEERCRED` names the
   supervised guest PID and UID/GID. Close the readiness connection before
   recording probe traffic. Select `/run/qt629-wl/wayland-0` in the Qt input
   review and pass it as `wayland_socket` to the existing runtime callback.
   Wayland 1.26 accepts an absolute `WAYLAND_DISPLAY`, so the clients can
   retain their separate private `XDG_RUNTIME_DIR`. Keep Weston's library
   and module overrides out of both Qt client and Vulkan tool environments.
   [Wayland 1.26 socket handling](https://github.com/wayland-mirror/wayland/blob/1.26.0/src/wayland-client.c#L1150)

## Evidence and refusal criteria

- At the vendor Qt rollback checkpoint, use the same UID, capability and
  environment controls for a bounded software WSI smoke check. Set
  `WAYLAND_DISPLAY=/run/qt629-wl/wayland-0`,
  `VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json` and
  `LP_NUM_THREADS=2`. Require `vulkaninfo --summary` to identify the CPU
  device and `/usr/bin/vkcube --wsi wayland --c 8 --width 64 --height 64`
  to exit successfully with real Wayland buffer traffic. The retained
  `vkcube` binary exposes these arguments and Wayland WSI. Use the vendor Qt
  raster and QRhi probes as positive controls with this same compositor.
- During the scoped Qt replacement, require the five existing runtime phases
  to pass. In the compositor trace correlate each Qt Wayland connection to its
  XDG toplevel, configure and ack, non-null SHM buffer attachment and surface
  commit. Keep each client alive through an output frame callback. Make the
  QRhi fixture produce at least two painted updates so the observer can match
  successive Vulkan WSI buffer commits and a callback from the same surface.
  Qt's Wayland Vulkan integration requests the surface callback before
  queuing presentation. Keep the event loop alive after `frameSwapped` so the
  buffer and callback have time to reach the compositor.
  Capture bounded, non-interleaved evidence correlated to the probe step.
  Qt's current `frameSwapped` marker alone is insufficient. In the Qt 6.12.0
  basic render loop the signal can still fire after a failed `endFrame`.
  Weston sends callbacks for visible surfaces on the enabled output during
  repaint. Collect its evidence independently of the client markers.
  [Qt Wayland present hook](https://github.com/qt/qtbase/blob/v6.12.0/src/plugins/platforms/wayland/qwaylandvulkaninstance.cpp#L85),
  [Qt basic render loop](https://github.com/qt/qtdeclarative/blob/v6.12.0/src/quick/scenegraph/qsgrenderloop.cpp#L708),
  [Weston repaint callbacks](https://github.com/wayland-mirror/weston/blob/15.0.1/libweston/compositor.c#L3810)
- Refuse a complete PASS for a package or ELF pin mismatch, unresolved
  dependency, stale socket or wrong peer, missing output or protocol
  evidence, fallback QPA or graphics backend, a non-CPU Vulkan device,
  failed presentation, timeout or truncated evidence. A loader enumeration
  or a working `vkcube` only establishes prerequisites for the Qt application
  check. The guest worker should retire Weston with SIGTERM and a bounded
  wait, verify socket and process-group removal, and flag forced termination
  or cleanup failure. The existing Qt transaction must still restore the
  exact vendor provider and match the original inventory and platform
  snapshot before target mounts and trust homes retire.

The completed PASS covers ordinary-user Qt Wayland raster and Qt Quick Vulkan
presentation to a memory-backed compositor in offline AArch64/16 KiB QEMU.
Hyprland, accelerated graphics, the installed Asahi boot path and physical M2
Air validation require their own evidence.
