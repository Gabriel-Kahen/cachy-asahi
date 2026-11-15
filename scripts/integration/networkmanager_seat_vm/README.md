# NetworkManager lifecycle in a genuine active seat0 login

This separate finite variant combines the independently passed real VT/seat/PAM
reference with actual NM own-profile writes, persistence, denied foreign/system
writes and restoration. **Prepared, not booted.** Root's generic seat report
actually passed real tty1 keyboard password PAM login, active seat0, successful
`sd_session_get_seat`, original Polkit own-action authorization without a
challenge, normal logout, QEMU retirement and exact container absence. That
substrate result alone cannot pass this new NM journey.

The earlier serial NM/password-challenge result and every closed generic seat
trial/source/input/once marker remain unchanged. This new scope is x86 software
only. Native ARM/16K, Asahi/M2, physical connectivity/input/display, suspend,
production trust/freshness/source-license completeness and release remain held.
No host account, PAM, policy, trust, service, interface or bus is changed.

## Reused inputs and preparation

`references.json` pins all reused source bytes. The successful generic
`systemd_tcg_seat_guest/boot.py`, its keyboard/input helpers, existing actor/reaper
and ordinary seat proof are read-only. The exact passed NM root snapshot observer
from `networkmanager_session_vm/fixture.py` is copied unchanged. The new root NM
unit orders its readiness before tty1 getty; the new derived seat observer adds
an NM-result join to its existing frame. Original generic sources are not edited.
The new assembler adds only the finite NM fixture and phase to the existing
base/payload assembly, keeping the genuine keyboard/login/seat path.

The COPY-only image provider is exact retained
`cachy-tcg-real-seat:196337a5c11df127`, image
`sha256:e34f4f1c8fa36c1bc7ffa03d707f8b9eeed933163a4b10800b8cd90103fac1e6`.
The real four unsigned `networkmanager/libnm/nm-cloud-setup/networkmanager-docs`
`1.58.1-2.1` archives are rechecked by the existing size/SHA intake. Their exact
previously installed/dependency-checked payload export, original PAM/Polkit/udev,
stock kernel/initrd and firmware are retained. No package installation/fetch,
`--nodeps`, new kernel build or source execution occurs in this preparation.
Provider custody remains distinct from production trust or hardware acceptance.

```sh
python scripts/integration/networkmanager_seat_vm/prepare.py \
  --allow-prepare-nm-seat-reference \
  --archives work/networkmanager-source-candidate-20261114/archives \
  --output /tmp/new-owned-nm-seat-preparation
```

Run as the ordinary host user with rootless Docker and exact retained images.
Output must be new. Source, payload and policy bytes are checked before offline
fakeroot assembly. Standard `systemd-sysusers --root`, module indexing, local
ALPM `-Dk`, ownership and ext4 read-only fsck operate only in owned temporary
state. A fresh nonce, raw and private0600 TEST credential are created, with no
once marker consumed. Aggregate admission requires6GiB available memory before
3GiB-capped assembly and3GiB output free. Private extraction tmpfs is1280MiB;
raw is1.5GiB logical, about766MiB allocated. No VM or guest program runs here.

Builder UID/GID1000 remains outside admin groups. A separate locked fixture
account owns the foreign-profile permission identity. Two root-owned offline
profiles have autoconnect=false, disabled IPv4/IPv6 and an absent fixture
interface. NM starts through its stock guest systemd unit; cloud/OVS examples
remain inert. No connection activation or interface operation is requested.
An unrelated user config file is pinned for preservation.

## Root-only real journey

```sh
python scripts/integration/networkmanager_seat_vm/boot.py \
  --allow-first-nm-seat-reference-boot \
  --prepared /absolute/new/prepared \
  --prepared-sha256 <exact-new-manifest-sha256> \
  --tool-image <exact-new-tool-tag> --tool-image-id sha256:<exact-new-image-id> \
  --output /tmp/new-owned-nm-seat-first-boot
```

Root reviews the exact supplied invocation before launch. No prior marker is
reset/replayed. The host adapter invokes the unchanged hash-pinned generic seat
controller and requires its full PASS, including normal logout and cleanup.
The actor, QMP keyboard down/up, real release ACKs, live ECHO-off, parent device
corroboration, signal/custody/cleanup are unchanged. Runtime remains rootless,
capability ALL dropped/NNP/read-only/network-none/no KVM/no host devices/bus,
exactly two owned binds, explicit init=false,2CPU/3GiB/256PIDs. Guest1536MiB,
TCG/VGA/i8042, no NIC/VNC, immutable raw plus256MiB-max qcow2. Observer210s,
controller420s, actor480s and independent cleanup35s still bound the run.

After genuine tty1 PAM login the private user profile invokes the new NM client,
then the unchanged generic seat proof. The NM client checks its own real bus
UID/PID and active login1 tty1/seat0 session, actual `sd_session_get_seat`, exact
NM/Polkit server UIDs, original policy digest and NM version. A genuine Polkit
check for its actual system-bus subject uses flags0 and must return authorized
without a challenge. No authentication agent or additional credential is used.
The normal keyboard PAM login is the only password exchange.

Actual GIR/D-Bus methods create a builder-restricted non-autoconnecting profile,
edit its ID and persist it. The root observer reads the actual root-owned0600
file and snapshots all original profiles/policy/rules/PAM/account/group pins,
complete package inventory and unrelated user config. Actual foreign/system
Delete requests must deny. The root observer requires the complete persisted
state to remain unchanged across those denied writes. Builder then deletes its
own profile; original inventory and all snapshots must match the starting state.
No administrative credential is supplied to authorize denied actions.

The derived seat observer independently reads both the ordinary NM report and
the root NM observer's result. It requires their complete matching successful
preservation result, embeds them in its single nonce frame, and still performs
all original live seat/bus/PID/UID checks. The host NM adapter separately accepts
that result after the generic controller's full logout/retirement PASS. It
rejects generic-seat-only success, missing NM evidence, extra credential/agent,
challenge results, false writes/persistence/denials or changed root snapshots.
`report.json` is the substrate report; `journey.json` is the distinct NM result.
A complete failure retains its observation and enters existing scoped cleanup.
Normal guest shutdown remains unqualified: PAM logout precedes QMP emulator quit.

## Actual preparation and remaining gates

The one fresh `/tmp` preparation passed source/payload pins, offline dependency,
module, ownership and filesystem checks with no OOM. The data-only assembly used
a staging variable that shadowed its intended unique container name; it completed
and removed that owned container. The caller was corrected before delivery; all
actual runtime-source/image/raw pins are unchanged and the exact executed caller
hash is retained separately in validation. No VM ran during that assembly.

Four focused controls pass on Python3.12/3.14 and check that actual NM evidence,
seat identity, no-challenge policy, persistence, denials, cleanup and independent
preservation are mandatory. They also verify every reused source pin. Existing
seat controls remain independent. Private raw/credentials and execution logs are
not committed. `validation.json` records exact prepared/runtime/source pins,
actual preceding seat report and Root's next invocation. This NM variant's real
start, own writes, denials, persistence and complete logout are **NOT RUN**.

```sh
python -m unittest discover -s scripts/integration/networkmanager_seat_vm -p test_nm_seat.py -v
```
