# ARM16K virtio real-seat source substrate

**READY_SOURCE_ONLY.** This separate adapter provides guest input/observer/user
proof and a finite host protocol API. It creates no container, QEMU process,
socket, kernel, rootfs, prepared fixture, Source role or authority. Actual UI
kernel bundle, device enumeration, Source/ref, actor selectors/expectedCmd and
Root authority remain null. Existing x86, KSM/C01 and RTC sources are unchanged.
No ARM seat/UI/native16K/M2 acceptance is claimed.

## Runtime identity before credentials

`input_seat.py` must run inside Root's future aarch64/16384 guest. The actual
observer guards architecture, page size, PID1 systemd, nonce/cmdline and root.
Before publishing LOGIN_READY or accepting credentials, it requires:

- One unambiguous keyboard with real input/event parent chain under a platform
  `*.virtio_mmio/virtioN/input/inputN`, bound through virtio_input and
  virtio-mmio drivers/subsystems; actual virtio device ID0x0012.
- QEMU virtual input IDs bus0006/vendor0627/product0001/version0001 and
  `virtioN/input0` phys, keyboard name and advertised EV_SYN/KEY/LED/REP,
  fixed login/hex/exit/VT key capabilities and three LED capabilities.
- Stock udev keyboard identification on event and input parent; parent seat tag,
  default/explicit seat0 and consistent ID_PATH_TAG→ID_FOR_SEAT. Child tag alone
  is insufficient. No i8042 or guessed `ID_BUS` string is accepted.
- A genuine virtio_gpu card with virtio device ID0x0010, the same MMIO transport
  proof and stock DRM seat tag. Actual `/dev/dri/cardN` major/minor properties
  must match its sysfs device number.

The event descriptor opens readonly/nonblocking/cloexec/nofollow; actual record
is recollected before/after open and fstat must match the character-device
major/minor from sysfs. Keyboard/GPU records are recollected after authentication;
identity changes refuse. Wrong/missing/ambiguous/name-only identity holds rather
than picking a fallback keyboard or changing udev policy. No host evdev device is
opened by this source task or by verification/tests. Advertised capability masks
are static device metadata; typed event keycodes/values are never exported.

Pinned Linux94fb23346d522edf53722357c426a3e58030beea and QEMU11.1.3 operands in
`data/` derive device IDs, virtual input IDs, phys convention, MMIO types and key/
event capabilities. Linux input core adds EV_SYN; QEMU advertises KEY_ESC up to
but excluding KEY_REPLY, plus EV_REP and three LEDs. Actual sysfs path spelling,
capabilities and driver bindings remain runtime requirements, not observations.
An unfamiliar valid layout still holds for explicit review, never normalization.
`origin.json` pins every source operand and immutable neutral source snapshot.

## Preserved real login protocol

The original `keyboard.py` is byte-identical to the frozen x86 source. Its native
`@llHHi` evdev structure is24bytes on the guarded aarch64 LP64 guest, as on the
original x86_64 reference. It retains fragmented events only transiently in
memory and exports counts, never raw events or keycodes. No grab/ioctl is added.
Live tty attributes reopen after the known EIO/ENXIO getty hangup transition;
other errors fail. Password readiness requires eight username releases, the real
builder password prompt and ECHO disabled on a fresh `/dev/tty1` descriptor.

`observer.py` keeps the original read-only VCS/prompt/PAM journal observations,
stock login/session corroboration and210s observation budget. Only ARM/PL011/
nonce/status and input/GPU identity selection differ. It reports one nonce-bound
release ACK per real key release; username8, password33, authenticated phase41,
then normal `exit` logout46. Extra input outside the admitted phase or failed PAM
holds without authentication retry. Raw credentials/keycodes are not reported.

The ordinary UID/GID1000 `user_proof.py` still requires a real controlling tty1,
foreground VT1 and process session, no admin groups, genuine system-bus credentials
for its PID, logind GetSessionByPID active local login/tty/seat0 and libsystemd's
sd_session_get_seat=seat0. Root independently corroborates the bus owner/session
and active VT. The installed original NM own-profile Polkit action must authorize
this actual active seat without interaction; no NM daemon/connection action or
policy override occurs. Original policy XML SHA256 is
`6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446`,
stock71-seat.rules SHA256
`b57a64ab6c973d0b734dea808e6caf9a49b40739c7c7649784d09bd6d90c36d3`.
Future ARM package/fixture assembly must independently bind original PAM/policy
bytes; this directory does not invent missing ARM policy/package provenance.

`protocol.py` exposes Serial, parse, journey and redact_serial for Root's future
owned controller. It creates no connection. `journey(serial,rpc,password)` invokes
only fixed input-send-event QMP calls on the already-admitted connection; lowercase
builder and exactly32 hex password characters each use explicit down/up events
and wait for the matching nonce/count ACK before the next character. The bounded
parser requires the genuine guest/root corroboration schema; model fixtures are
unit DATA only. It requires normal shell return/logout and new getty prompt.
`redact_serial` must precede any persistent serial export; QMP credential events
must never be logged. It does not quit QEMU or claim retirement/cleanup: those
remain mandatory separate Root-controller responsibilities.

## Delivery and pending admission

`delivery.lock.json` pins every guest helper/service/profile and fixed installed
path. `observer.service` retains the bounded original service semantics, with the
new runtime directory `/run/arm16k-virtio-seat`. Only a fresh disposable builder
home may receive `profile.fragment`; no existing user profile may be overwritten.
The constructor must enable stock getty@tty1, mask serial-getty@ttyAMA0 solely for
the read-only observer and use fresh nonce/machine ID/credentials. It must not add
autologin, root/wheel membership, session properties, permissive policy or event
grabs. Source verification neither stages these files nor changes a service.

Root must supply the actually built separately named UI-seat kernel bundle,
read-only package closure with original signatures/policies, exact tool image,
new actor source/mount/argv and explicit OwnedContainer expectedCmd matching
that actor. Existing RTC or x86 actor selectors must not be reused implicitly.
The future guest device tuple is virt/TCG, virtio-keyboard-device and
virtio-gpu-device over MMIO, tty1 plus PL011 observer, no NIC/KVM/display/input
passthrough. Root retains all admission/resource/once-marker/ownership/retirement
and absence checks. No full UI constructor or new general process framework is
included; installation worker owns the package closure/acquisition work.

## Actual source verification

```sh
python3 -I -B -Werror scripts/integration/arm16k_virtio_seat/test_controls.py
python3 -I -B -Werror scripts/integration/arm16k_virtio_seat/verify_source.py
```

69 actor-fenced controls pass. They cover modeled identity/capabilities and
complete finite journey, source pins/neutral reuse, source syntax, name-only/
wrong driver/transport/IDs/device numbers/seat/keys, fd-close/no-follow behavior,
PAM/session/policy/bus/VT parser refusals, release fragments/overruns, ECHO state,
wrong/duplicate/skipped nonce ACKs, HOLD interruption and credential redaction.
Subprocess creation, socket creation, fork/exec are denied during tests; no
runtime sysfs/evdev collection is run. The source verifier reports actuals null.
This is runnable source for a separately admitted follow-up, not a synthetic
runtime PASS. Native16K, physical Apple hardware, UI rendering, networking,
performance and release acceptance remain unestablished.

Project adapters are MIT. Retained Linux/QEMU operands retain their original
SPDX/license notices; copied upstream bytes are pinned DATA, never executed here.

The ARM111 baseline has no NetworkManager, and the initial145-addition UI plan
does not establish its provider. The genuine own-profile Polkit action remains
mandatory: a distinct externally audited signed official `networkmanager`
archive/dependency closure must own the exact installed policy XML. The delivery
map/verifier explicitly names this prerequisite and Python/GIR/pkaction namespace.
Missing provider holds before preparation; copying/injecting XML, inventing an
action or weakening the authorization check is forbidden. No NM daemon or
connection modification is requested by this policy reference.
