# Generic x86 real-seat systemd/PAM/Polkit reference

This separate variant prepares a genuine virtual keyboard/VT/seat0 experiment.
It preserves all previous sources, raw inputs and once markers. The earlier real
serial login succeeded but measured `sd_session_get_seat=-61`; its genuine
own-action password challenge and subsequent successful NM journey remain valid
within that serial scope. The first three seat trials reached terminal HOLDs; the corrected fresh
variant is **prepared, not booted**. It supplies
no ARM/16K, Asahi/M2, physical input/display, networking, suspend or release credit.

## Existing kernel and inputs

The exact retained stock x86 kernel is unchanged (`7.2.14-arch1-1`, archive
`linux7.2.14.arch1-1`, existing verified official package custody). Bounded DATA
inspection decodes its embedded IKCONFIG without executing it. VT, VT console,
VGA/framebuffer console, input evdev, i8042 and AT keyboard are built in; Bochs DRM
is a retained module. QEMU11.1.3 metadata exposes `VGA` and the q35 `i8042` property;
the pinned image contains standard VGA firmware. These declarations/file checks
establish input availability only, not successful execution or a real seat.

The COPY-only tool image derives from exact retained
`cachy-nm-session-challenge:c4b31ba52acaa84e` /
`sha256:214e6381db6706d05c53ebe96f2eb9b43d9243c41fa8103c253a63412d57f483`.
Its already verified base/payload dependency export supplies original systemd,
logind, D-Bus, Polkit, Python/GIR and unchanged original NM policy XML. NM is not
started and no connection is changed: the existing own-profile action is simply
a shipped stock Polkit authorization reference. No new packages, source archives,
kernel/rootfs build, signatures or network acquisition is required. Official
[QEMU11.1.3 QMP schema](https://github.com/qemu/qemu/blob/v11.1.3/qapi/ui.json)
was read as DATA to pin explicit `input-send-event` key down/up and qcode values.
Provider-image custody remains separate from source completeness, signature
freshness, trust/legal approval or target acceptance.

```sh
python scripts/integration/systemd_tcg_seat_guest/prepare.py \
  --allow-prepare-seat-reference \
  --kernel work/systemd-tcg-reference-20261114/prepared3/final-assembly/vmlinuz \
  --output work/systemd-tcg-seat-reference-20261114/new-preparation
```

Preparation requires the ordinary host user, rootless Docker, the exact retained
image, and Python3.14+ for bounded stdlib zstd decoding. It never starts QEMU or
runs guest code. Offline fakeroot assembly verifies selected package files and
source pins, applies standard `systemd-sysusers --root` only inside the owned
tree, and creates one private builder UID/GID1000 TEST account outside admin,
wheel/root/sudo/empower. Password is32 random hex characters in an owned0600
credential file; plaintext is not baked into the image, arguments or environment.
Original PAM and Polkit bytes are pinned. No autologin, allow rule, seat/session
property override or alternate authorization helper exists.

The stock tty1 getty is enabled. Serial getty is masked solely to reserve the
emulated serial port for a read-only root observer. The virtual keyboard is
explicit q35 i8042/AT; virtual `VGA` supplies the genuine DRM seat device. The
existing stock Bochs module is loaded inside the guest normally; offline
`depmod -b <owned-root>` creates the missing module indexes without executing any
module or touching host state. Original direct kernel/initrd bytes are reused.
The fresh1.5GiB sparse raw receives local ALPM dependency, ownership and read-only
filesystem checks. NM/cloud/OVS services remain inert.

## Root-reviewed finite boot

Root receives exact new manifest/image pins and a fresh output invocation:

```sh
python scripts/integration/systemd_tcg_seat_guest/boot.py \
  --allow-first-real-seat-reference-boot \
  --prepared /absolute/new/prepared \
  --prepared-sha256 <exact-new-manifest-sha256> \
  --tool-image <exact-new-tool-tag> --tool-image-id sha256:<exact-new-image-id> \
  --output /absolute/new/first-boot-output
```

Do not replay any earlier once marker. No VM launches before Root reviews the
concrete invocation. This new boot driver and new actor explicitly change the
serial-only behavior: the actor adds VGA, explicit i8042 and VT console; the
controller types through explicit QMP down/up events rather than a serial login. The completed
x86 substrate's hash-pinned `Cancellation` and `OwnedContainer` identity/cleanup
helpers and existing owned-process reaper are reused read-only. No existing
controller, guest or native-family source is modified.

Host runtime remains rootless, capability ALL dropped/no added capability,
no-new-privileges, read-only container, network-none, no host services/bus/devices,
no KVM/privileged/seccomp fallback, explicit `--init=false`, two owned binds
(prepared RO/output RW),2CPU/3GiB/256PIDs and private32MiB tmpfs. QEMU remains q35
TCG,1536MiB guest RAM,2vCPU, no NIC/VNC/display window, no OS bootloader, direct
kernel/initrd and at most256MiB qcow2 overlay over immutable raw. The new actor
uses the same480s budget and normal reaper; controller420s, guest observer210s,
cleanup independent35s. VT/input devices exist only inside that VM. QMP key
values and credential are not logged; captured serial bytes are redacted.

The driver selects VT1 with genuine Ctrl+Alt+F1 keyboard input. A root observer
waits for actual DRM/seat0 VT capability and reads kernel `/dev/vcs1` text cells
for the stock getty and builder PAM password prompts. Password readiness also
requires actual read-only tty1 termios ECHO-off and all8 username key-release
acknowledgements. No termios change is made. Explicit QMP down/up events are sent
for each character, with the next character gated on a nonce-bound exact next
release count from the real AT keyboard event device. The passive reader does
not grab events or export keycodes/raw input; it exports cumulative counters
only. Original `login`/PAM performs authentication on `/dev/tty1`.

The ordinary login profile runs one fixed proof. It requires controlling tty1,
foreground VT1, active real logind user/login session assigned seat0, successful
actual `sd_session_get_seat` returning seat0, actual bus UID/PID, and unchanged
original action policy. It queries real Polkit with its actual system-bus subject,
flags0/no agent/no interaction, requiring authorized=true/challenge=false. It
keeps the real process/bus alive until root independently corroborates its PID,
UID, login1 session/seat, foreground VT, real AT keyboard event identity, its resolved inputN parent ancestry and
original parent seat tag/ID_FOR_SEAT, and DRM card. There is no NM daemon or system mutation in the user proof.

The root observer then exports a bounded nonce-framed report and acknowledges the
user proof. The driver waits for return to the genuine shell, types `exit`, and
requires observed login1 session removal plus the returning getty prompt. QMP
emulator quit and owned QEMU/container retirement follow; normal guest shutdown
is unqualified. Complete HOLD frames immediately enter cleanup. SIGINT/SIGTERM,
ambiguous container creation, bounded wait failure and report writing use the
retained scoped cleanup. No arbitrary process/container is killed or removed.

## Actual preparation and limits

Actual embedded configuration inspection, existing device/firmware metadata,
COPY-only image, selected payload checks, offline module indexing, guest ALPM
`-Dk`, ownership and read-only ext4 fsck passed. The new raw allocates about798MiB;
private extraction tmpfs is1280MiB under3GiB assembly memory. New global free-space
delta was880,340,992B (includes concurrent activity), not a process RAM peak.
The raw/kernel/initrd, image, source and evidence pins and exact Root invocation
are recorded in `validation.json`; private credentials/raw are uncommitted.
Real VT/keyboard login, seat0, Polkit no-challenge behavior and logout are **NOT
RUN** until Root's first actual launch. No existing hardware/target hold changes.

```sh
python -m unittest discover -s scripts/integration/systemd_tcg_seat_guest -p 'test_*.py' -v
```

Sixteen focused controls exercise acceptance refusal for seatless serial/inactive/
wrong-identity/policy/challenge data, nonce/size bounds, restricted keyboard codes,
immediate HOLD over a real Unix socket, retained timeout-safe cleanup, actual
event-leaf-only power-switch tags with a correct seat-tagged input parent, and
wrong-parent/unrelated-tag/ID_FOR_SEAT rejection, fragmented release counting,
ECHO/readiness ordering, exact ACK sequencing and PAM-HOLD interruption. They
pass on Python3.12/3.14 without launching a VM; preparation itself requires3.14.


## First actual seat result and input-parent correction

Root's first real seat trial is terminal HOLD; its once marker and artifacts are
immutable. The actual ordinary-user proof passed tty1 keyboard password PAM
login, active seat0, `sd_session_get_seat=0/seat0`, real bus UID/PID and unchanged
Polkit authorization without interaction. The root observer then rejected the
keyboard because it incorrectly expected `:seat:` on event1; the stock event
leaf correctly carried `ID_INPUT_KEYBOARD=1`, `ID_BUS=i8042` and only
`:power-switch:`. Cleanup and exact owned-container absence passed; normal VT
logout was not reached and is not credited for that attempt.

The exact retained `/usr/lib/udev/rules.d/71-seat.rules` (SHA256
`b57a64ab6c973d0b734dea808e6caf9a49b40739c7c7649784d09bd6d90c36d3`)
tags `SUBSYSTEM=input,KERNEL=input*`, selecting the inputN parent rather than the
eventN leaf. The correction reads both actual sysfs/udev records. It requires the
AT keyboard leaf's keyboard/i8042 identity and DEVPATH, its real resolved inputN
parent directly containing that leaf, matching parent DEVPATH/SUBSYSTEM, exact
parent `seat` tag, matching `ID_FOR_SEAT=input-<ID_PATH_TAG>`, and default/explicit
seat0. Wrong ancestry or unrelated tags do not satisfy the check. The independent
real session/UID/PID/bus/foreground VT/Polkit evidence remains required. No udev
rule, tag, seat, session, policy or PAM configuration is changed.

The new input-parent helper is pinned/copied into both the owned guest and host
parser; original71-seat.rules is pinned during assembly and checked at runtime.
Fresh preparation uses `/tmp` for its new raw/password/nonce/once state and
leaves the first raw/marker/reports intact. `validation.json` remains the initial
preparation record; `input-parent-validation.json` records the actual initial
HOLD and the corrected fresh pins/Root invocation. No dependent NM seat raw is
prepared before this correction's actual Root outcome.


## Second actual trial and acknowledged keyboard correction

The corrected input-parent trial is also terminal HOLD and remains closed. A
bounded passive conversion/debugfs/journal diagnosis preserved the original
overlay hash. It found exactly one builder PAM authentication failure and no
session open; no profile/report ran. Actual guest shadow matched the prepared
TEST credential in memory, and installed profile/helper ownership and bytes
matched their pins. This does not establish a QEMU/PAM defect or identify the
lost/mistimed character. No raw VT/input/journal/credential data was displayed.

The former driver relied on a visible password prompt plus timed QMP key taps
without guest input acknowledgement. The corrected driver requires kernel
ECHO-off, sends explicit down/up event pairs (no timed key-release helper), and
waits at most5s for each exact monotonic release acknowledgement. The root reader
exports only release counts, never event keycodes or values. Readiness/results
are ordered after releases8(username),41(password+return) and46(exit), so an ACK
wait cannot consume a later phase marker. Duplicate/skipped/foreign-nonce ACKs
and releases outside the admitted phase fail closed; there is one login attempt.

The private login profile now marks entry and captures private proof stderr/exit
status. The observer emits immediate sanitized HOLD for actual login/PAM denial,
interpreter startup failure or nonzero proof exit, without exposing stderr,
screens, keycodes or credentials. Normal warning text alone is not a failed
proof. No PAM/Polkit/udev/session/account policy is changed. Both prior source
records/reports/markers remain intact. `keyboard-validation.json` records the
passive diagnosis and fresh acknowledged-input fixture; older validation files
are historical preparation records, not overwritten runtime results.

Fresh preparation checks aggregate `MemAvailable>=6GiB` immediately before its
3GiB-capped assembly (3GiB additional reserve for Root's independent workload),
plus at least3GiB output filesystem free. The fresh raw and output stay under an
owned `/tmp` tree. Runtime remains2CPU/3GiB/256PIDs, guest1536MiB and max256MiB
overlay with the same actor/custody/signal/cleanup budgets. The new acknowledged
keyboard login, parent corroboration and complete normal logout are **NOT RUN**
until Root reviews and launches the exact new invocation.


## Third actual trial and live TTY descriptor correction

The acknowledged-keyboard trial is terminal HOLD with all8 real username release
ACKs observed. Before any password-ready marker or credential delivery, the
observer's retained tty descriptor returned termios EIO at the getty/login
transition. No profile/PAM-authentication outcome or input-parent acceptance is
claimed for that trial. QEMU retirement and exact container absence passed.
Its raw/credentials/once marker and sanitized evidence remain immutable.

The readiness observer now opens a fresh read-only `O_NOCTTY|O_NONBLOCK` tty1
file descriptor for each live check and always closes it. Only EIO/ENXIO may be
transient not-ready within the existing210s deadline; their counts are retained
in stage evidence. Other errors are refused. A successful actual ECHO-off read
is still required before the password marker, and there is no termios write,
authentication retry, policy/account or actor/profile change. A regression
exercises stale-EIO close followed by successful fresh reopen; another refuses
nontransient permission errors. `live-tty-validation.json` records this separate
source correction and one fresh `/tmp` preparation, not a replay or a VM result.
