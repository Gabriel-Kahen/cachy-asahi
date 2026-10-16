# Managed virtual keyboard candidate

Source implementation only. No native VM, compiler, package, Docker, Git, CI
or host desktop actor was run here. Native runtime and every image review are
NOT_RUN. The focused tests use modeled actors and synthetic pixels; the inherited
runtime controls can spawn inert shell/logger lifecycle probes.

This separately selected manual lane keeps the exact574 base, existing591
runtime, real systemd user@23001 manager/bus, compositor, original root/guest
ownership guards, finite logs/deadlines and all14 consumer cleanup records plus
original owned-base retirement. It adds only QEMU's virtual keyboard:
`-device virtio-keyboard-pci,id=keyboard`. No extra binary package or privileged
Docker flag is introduced. It does not access a host input node or host desktop.

The unchanged installed overlay supplies SUPER+RETURN -> alacritty and SUPER+Q
-> close. Its installed Lua SHA must equal the pinned recipe's Lua bytes.
The minimal comparison fixture has those two bindings and explicit US layout
added to its own minimal.lua; that is a declared test policy, not upstream's
minimal default. A fresh private fixture Alacritty configuration specifies an
opaque readable terminal and interactive Bash with no profile/rc, HISTFILE
/dev/null. It contains no command payload. A user sentinel and this complete
XDG configuration tree must remain byte/mode/owner identical in both phases.

Each phase requires one kernel QEMU Virtio Keyboard, virtio_input driver and
matching character node, plus exactly one Hyprland qemu-virtio-keyboard with US
layout and Caps Lock off. One separate gpio-keys board power-button device is
allowed only with bounded passive sysfs proof: exact platform/driver/DT identity,
BUS_HOST, joined event character node and KEY_POWER-only bitmap. Its DT poweroff
code must be116; unknown, duplicate or alphabet-capable companions fail. The
compositor may report that power button as main; actual nonce-bound input
delivery remains required through the QEMU virtual keyboard. The host uses supported QMP input-send-event qcodes
through the existing owned QMP socket. Press/release pairs are paced40ms each;
modifiers release in reverse order even after an uncertain command reply.
No PTY write, clipboard paste, accessibility action or exec callback supplies
workflow results. The guest observer only launches Hyprland and read-only
hyprctl/busctl probes; its final explicit compositor exit is cleanup.

Fixed eight-step route per phase:

1. SUPER+RETURN creates the actual default Alacritty; UID/executable/starttime/
   pidfd and focused native window join it to an actual Bash child and PTY.
2. Type cd, a prompt setting and printf/tee command. The shell creates shell.txt
   containing shell-<nonce>; only exact bounded bytes/UID/single-link qualify.
3. Type vim -u NONE -i NONE -n edit.txt; join the interactive Vim child to Bash.
4. Type i and editor-<nonce> into the real modal editor.
5. Escape, :w and Enter save exact expected edit.txt bytes while Vim stays live.
6. Type :q and Enter; require Vim pidfd retirement and no remaining Vim child.
7. Type cat shell.txt edit.txt | tee result.txt; require exact two-line result.
8. SUPER+Q closes the actual window; require Alacritty and Bash pidfd exits and
   mapped-window absence. Their nonchild exit codes are UNOBSERVED_NONCHILD.

Shell output, saved live editor and final shell readback each get one unchanged
1024x768 QMP capture per phase: six images total. Capture gates include5s settle,
focused visible native terminal, a fresh real managed bus UID/PID/GetUnit join
and8s subsequent healthy hold. Root must inspect all six images for readable
matching text; metadata never supplies visual acceptance. The bounded public
export excludes disks, private homes, packages and arbitrary workspace files.

prerequisites.json pins exact held package/archive and ELF/module/Image bytes,
including QEMU11.1.2/source4fc49f46dc95d4a27de2509e7fceb2931e91faeb and
kernel7.2.10-1-aarch64-ARCH. Read-only archive inspection found both virtual
keyboard device strings and input-send-event in the held ARM QEMU ELF. The
held Image's embedded config (retained as upstream-kernel.config) has INPUT=y,
INPUT_EVDEV=y,VIRTIO_PCI=y,VIRTIO_INPUT=m; the exact virtio_input.ko is present.
The gpio_keys.ko bytes and CONFIG_KEYBOARD_GPIO=m are pinned as well.
The fixture verifies installed prerequisite bytes before staging, modprobes
virtio_input in the guarded guest and waits for udev. Device discovery and
successful key delivery still need the native actual.

The QMP API shape follows the official QEMU reference:
https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-input-send-event
The actual held package/version and runtime QMP greeting, not that changing web
page, supply the revision gate. Package records include upstream source/license/
dependency metadata; original helper source is MIT with existing notices kept.

Finite unexercised gates: native ARM fixture/VM execution, libinput/seatd event
route, shipped shortcut behavior, typed Bash/Vim commands and cleanup, and six
actual image reviews. Generic software input can pass without establishing
physical M2 keyboard/touchpad support,16KiB behavior, accelerated graphics,
latency, performance or hardware acceptance. Those remain NOT_RUN.
