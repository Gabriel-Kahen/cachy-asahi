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
through the existing owned QMP socket. The explicit VM policy sends each complete press/release chord in one QMP
events batch, followed by a500ms gap;
modifiers release in reverse order even after an uncertain command reply.
No PTY write, clipboard paste, accessibility action or exec callback supplies
workflow results. The guest observer only launches Hyprland and read-only
hyprctl/busctl probes; its final explicit compositor exit is cleanup.

Fixed nine-step route per phase:

1. SUPER+RETURN creates the actual default Alacritty; UID/executable/starttime/
   pidfd and focused native window join it to an actual Bash child and PTY.
   A10s initial settle holds both actors alive and rechecks terminal focus.
2. Type only cd <nonce-workspace> and Enter. Independently observe the stable
   Bash PID's /proc/PID/cwd at exactly that path before sending further input.
   No cd retry, injected command or observer chdir is available.
3. Type the prompt setting and printf/tee command. The shell creates shell.txt
   containing shell-<nonce>; only exact bounded bytes/UID/single-link qualify.
4. Type vim -u NONE -i NONE -n edit.txt; join the interactive Vim child to Bash.
5. Type i and editor-<nonce> into the real modal editor.
6. Escape, :w and Enter save exact expected edit.txt bytes while Vim stays live.
7. Type :q and Enter; require Vim pidfd retirement and no remaining Vim child.
8. Type cat shell.txt edit.txt | tee result.txt; require exact two-line result.
9. SUPER+Q closes the actual window; require Alacritty and Bash pidfd exits and
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


Failure diagnostics preserve the original failure. Before retiring an owned
terminal, the guest can emit one failure-only observation with last requested
step and only shell.txt/edit.txt/result.txt from the known nonce workspace.
Absent/unsafe/oversized leaves are labeled; safe single-link UID23001 regular
files up to1024B get a full SHA256 and at most256B of base64 content. No directory
listing, arbitrary path, PTY read/write or alternate command execution occurs.
An8s grace permits an optional original QMP failure capture. Two fixed public
leaves minimal-failure.ppm/overlay-failure.ppm are separately labeled diagnostic;
they never count toward the six success images or permit metadata acceptance.
Capture/diagnostic errors cannot replace the original workflow failure.
Actual38896363801 proved launch and acknowledged shell input, then failed the
exact output deadline. Its retained data lacks terminal text/workspace contents;
character fidelity and the cause remain unproven. This change adds evidence,
without a speculative timing/mapping change or weaker result criterion.


Startup client snapshots may contain at most two quiescent anonymous XWayland
setup surfaces: both unmapped/invisible, zero geometry, no workspace/monitor,
empty current/initial class/title and no focus/fullscreen/floating/pinning.
Addresses must differ and their one PID must join to the exact owned Hyprland
process or its direct UID23001 Xwayland child by executable/parent/starttime.
Any preexisting application, named/visible/mapped surface, foreign process,
third record or changed shape fails before input. A complete initial snapshot
is required; the existing narrow IPC readiness retry remains bounded90s.
The accepted startup records and process proof are emitted in keyboard_ready
and replayed by the public contract. Subsequent sole focused native terminal,
nonce bytes and all diagnostic/capture/cleanup gates remain unchanged.


Delivery policy vm-chord-batch-workspace-v1 is an explicit conservative generic
VM test condition, not a latency or throughput claim. Each QMP receipt records
that exact policy; keyboard_terminal records actual initial settle elapsed time.
keyboard_workspace independently records the owned Bash cwd before the outcome
command, and public replay requires its nonce/shell/path/method/order. Failed
cd stops before printf/tee; it cannot be bypassed by permission changes or a
blind input retry. Failure diagnostics also include a bounded identity-checked
shell cwd observation; fixed file diagnostics and optional QMP image remain.

Actual38901031090 shows repeated c characters replacing the initial cd/path
prefix, followed by correct later command text and exact printed nonce. That
failed cd left the expected workspace files absent. Its screenshot does not
establish which layer corrupted delivery. Pinned QEMU source has a64-descriptor
virtio event queue and discards a report when descriptors are unavailable;
there is no runtime queue-full trace establishing that condition in this run.
Single-report chords, slower pacing and initial settle are a testable mitigation, not a claimed
proven root cause. No product, package, kernel, access mode or default workdir
changes. The next native actual must establish received character fidelity.

The pinned qmp_input_send_event handler sends the supplied events in order and
synchronizes once afterwards. The virtio HID sync adds one SYN_REPORT; the
virtio input code reserves all descriptors before exposing that report. Each
chord therefore carries its own reverse-order key releases in the same report.
An uncertain QMP reply triggers one emergency release-only batch and remains
fatal; there is no replay of presses. Whole-chord delivery can still fail, so
QMP calls/key-event counts and policy acknowledgements never replace the cwd
barrier, exact result bytes or independent visible captures.

The longer typed workflow selects the same finite owned-compositor logger as
Welcome's seven-view exercise: stdout2MiB, stderr256KiB, no filtering, observed
byte counts and fatal overflow/drain errors. Only Hyprland gets this budget;
other actors retain their bounds. Replay requires the two exact stream bounds,
owned PID, normal exit0 and ordered complete-drain receipt for each profile.
Actual38904379501 passes separate key-only cd, exact shell output and its first
capture, then fails on compositor log overflow during editor-save. Its later
forced cleanup exit-9 is not normal shutdown. The adapter does not turn that
actual into PASS. All six successful captures and original keyboard gates remain
required; no physical-input or performance result is implied.
