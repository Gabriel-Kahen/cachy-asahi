# ARM16K virtio seat foundation

The source-only [ARM virtio seat adapter](../../scripts/integration/arm16k_virtio_seat/README.md)
provides the next real-seat input/observer/protocol boundary after the separate
UI-seat kernel is built. Actual kernel bundle, enumeration, Source/ref, actor
selectors and authority are null. No constructor, VM or UI ran in this task.

It preserves the real tty1 PAM/logind active seat0 proof, UID1000 system-bus
identity, original Polkit/udev policy and actual foreground VT checks. Its
unchanged passive evdev counter and live ECHO-off password readiness reuse the
passed x86 reference. ARM adaptation replaces the PC i8042/ATkbd/VGA identity
with strict actual virtio_input/virtio_gpu device IDs, platform virtio-MMIO
ancestry, QEMU virtual keyboard IDs and capabilities, and stock input-parent/DRM
seat tags. These are checked before LOGIN_READY, then recollected after login;
name-only or synthetic device evidence refuses.

The [pinned QEMU keyboard declaration](https://github.com/qemu/qemu/blob/v11.1.3/hw/input/virtio-input-hid.c#L255)
and [exact Linux virtio input driver](https://github.com/AsahiLinux/linux/blob/94fb23346d522edf53722357c426a3e58030beea/drivers/virtio/virtio_input.c)
provide expected identities and advertised capabilities. They are source facts,
not proof that a future guest enumerates them. The new observer requires real
kernel/sysfs/udev observations. No event grab, autologin, session fabrication,
policy grant or host input passthrough is added.

The finite host API sends one QMP make/break pair per character and requires an
ordered nonce-bound real-release ACK before continuing. It requires a genuine
password prompt with ECHO disabled, rejects failed authentication without retry,
and waits for normal logout/session removal. Raw credentials and typed keycodes
are not exported. Future Root custody code must redact serial output and must
separately prove natural QEMU retirement and owned-container absence; this
adapter cannot manufacture those claims.

69 actor-fenced source/model controls and pinned DATA verification pass. No
host input collector, process/socket actor, guest, preparation, compiler or daemon
was invoked. Root owns the later actual kernel/tool/package/policy/resource and
new actor/expectedCmd admission. The installation worker owns ARM UI package
closure; this source does not close missing archives or claim full ARM UI, native
16K, Apple/M2 hardware, performance or release acceptance.

The ARM111 baseline has no NetworkManager, and the initial145-addition UI plan
does not establish its provider. The genuine own-profile Polkit action remains
mandatory: a distinct externally audited signed official `networkmanager`
archive/dependency closure must own the exact installed policy XML. The delivery
map/verifier explicitly names this prerequisite and Python/GIR/pkaction namespace.
Missing provider holds before preparation; copying/injecting XML, inventing an
action or weakening the authorization check is forbidden. No NM daemon or
connection modification is requested by this policy reference.
