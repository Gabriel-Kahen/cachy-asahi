# Real-login NetworkManager reference VM experiment

This new experiment prepares the exact four unsigned x86 candidate packages for
a full-system session test. It leaves the completed TCG substrate, its first-boot
marker, and all earlier no-session container sources/results unchanged. Root's
separate initial boot actually established a builder UID1000 serial password PAM
login, systemd PID1, active logind tty session, D-Bus, normal logout and owned
QEMU/container retirement. That result is substrate evidence only. **This new NM
experiment is prepared, not booted.** ARM/16K, Asahi/M2, physical networking,
suspend, production trust and release acceptance remain NOT RUN/HOLD.

The unchanged upstream NM action policy allows `settings.modify.own` for active
and inactive sessions (`yes`), while system changes require `auth_admin_keep`.
The experiment follows those defaults: it expects an active ordinary builder to
create/edit/persist/remove its own non-autoconnecting profile without an extra
password challenge. Genuine password verification comes from the serial PAM
login. It registers real `pkttyagent` for the actual client PID/start time on the
real login tty, records any standard admin challenge and normally cancels a
pending admin request by retiring the agent. It never invents a challenge,
session, admin membership, authorization rule, policy change or alternate helper.

## Prepare without booting

Run as the ordinary host user with existing rootless Docker and retained exact
images/archives; no pull/download/dependency installation fallback exists:

```sh
python scripts/integration/networkmanager_session_vm/prepare.py \
  --allow-prepare-session-vm \
  --reference work/systemd-tcg-reference-20261114/prepared3/final-assembly \
  --archives work/networkmanager-source-candidate-20261114/archives \
  --output work/networkmanager-session-vm-20261114/new-preparation
```

The source provider is retained `cachy-asahi-nm-source-final:20261114`, image
`sha256:7052baf57a6eec068371ffdb2f9670ef69bd5ce11ee3ba67f705b724dc8a53d5`.
The fixed VM tool provider is `cachy-tcg-tools:reference-reviewed`, image
`sha256:c6bd2d0ed8c437a74b3e1713b7bfcb023b7446f1abe3c0d27a6a5b4fd734f925`.
Both descend from the earlier exact pinned official Arch inputs; these names are
never treated as sufficient identity. Candidate intake uses the unchanged real
archive size/SHA contract. A network-none image build runs actual dependency-
checked `pacman -U` for all four candidates, with scripts/hooks inert, no
`--nodeps`, and explicit unsigned-local scope. Installed public libalpm16.0.1
APIs join dependency/version/provides identities; exact named providers take
precedence and ambiguous alternative providers fail. This finite installed
payload export has no transaction/download API and does not replace the existing
project transaction planner.

Only dependency-selected additions to the exact137-package stock base are
exported. Package directories retain modes/ownership without recursive copying
of unrelated build-image files. Actual local ALPM descriptors, all selected
regular file hashes/link identities/directory metadata and dependency edges are
retained. The export imports no build-image account, password or machine identity.
The four candidates remain unsigned; provider-image custody and local file pins
are distinct from independently delivered upstream archive signatures, source
reproduction, freshness, legal or production acceptance.

Offline fakeroot assembly extracts stock base plus those additions, verifies
payload pins, runs standard `systemd-sysusers --root` inside the owned tree, and
creates only private TEST builder/foreign accounts. Builder is outside root,
wheel, admin, sudo and empower; other TEST login is locked. It enables the stock
NM unit and a finite root observer, retains stock system D-Bus/logind/Polkit/PAM,
and leaves cloud/OVS examples inert. The stock exact kernel/initrd are reused;
there is no target PC bootloader or host hardware autodetection. A fresh nonce,
password0600 and sparse1.5GiB raw disk receive filesystem/home-ownership and real
local ALPM dependency checks. No daemon, VM or guest program runs in preparation.

## Root-reviewed invocation

`boot.py` is a thin explicit adapter over the hash-pinned, unchanged completed
controller. It takes the new prepared manifest/image pins and fresh output:

```sh
python scripts/integration/networkmanager_session_vm/boot.py \
  --allow-first-nm-session-vm-boot \
  --prepared /absolute/new/prepared \
  --prepared-sha256 <exact-new-manifest-sha256> \
  --tool-image <exact-new-tool-tag> --tool-image-id sha256:<exact-new-image-id> \
  --output /absolute/new/first-boot-output
```

**Root reviews the supplied concrete invocation before launching.** The adapter
never resets/replays an old once marker. Rootless Docker has capabilities ALL
dropped, no-new-privileges, read-only root, network-none, no devices/KVM/host
services/bus, explicit `--init=false`, two owned binds (inputs RO/output RW),
32MiB private tmpfs,2CPU/3GiB/256PIDs. Unchanged QEMU q35/TCG has1536MiB RAM,
2vCPU, no NIC, exact direct kernel/initrd, raw RO backing and a256MiB-max qcow2
overlay. The serial deadline is420s, actor480s, independent cleanup35s. The fixed
controller retains INT/TERM handling, exact ambiguous-container identity recovery,
bounded serial bytes, original error reports and retirement/absence checks.

The guest uses its isolation boundary and standard system services, not the old
separate test bus. The ordinary process binds only `/run/dbus/system_bus_socket`,
compares actual own bus UID/PID, NM/root, Polkit/102 and logind/root credentials,
and queries the real PID's active `login1` session. The agent shares that actual
TTY/session. Root seeds only two offline non-autoconnecting profiles for an
absent fixture interface; no connection is activated and no interface or live
network is manipulated. The real GIR API creates/edits the builder-restricted
profile on disk, attempts foreign/system deletes, then removes its own profile.

A root-owned finite observer reads exact persisted profile bytes and snapshots
all profiles, policy/rules/PAM/account/group pins, complete package inventory and
unrelated user config before/after denied writes. It verifies unchanged denied
state and restored original profile inventory after own-profile cleanup. Its
root-owned report remains readable until the owned guest retires; the user cannot
supply the observer's result. Both observer and client have fixed phase deadlines.
The new adapter accepts only the exact nonce-framed report, real identity checks,
actual persistence, two denials, restoration, agent retirement and the original
controller's real session/logout/QEMU cleanup result. `report.json` retains the
substrate result; `journey.json` records the distinct NM result. A successful
substrate login cannot become a successful NM journey without those checks.
Normal guest shutdown is unqualified: the fixed controller observes PAM logout
then requests QMP emulator quit.

## Actual preparation and limits

The retained preparation selected164 actual installed packages:137 stock base
plus27 additions,717 dependency edges and5696 file/directory/link pins. The added
regular bytes total156,802,886. Actual unsigned image installation, local ALPM
checks, offline ext4 assembly and read-only fsck passed. Earlier BuildKit marker,
non-public libalpm symbol and vendor PAM-path refusals are retained. Superseded
unbooted assembly manifests/logs remain; only their owned raw scratch files were
removed for the disk budget. The final unit preserves its runtime report across
service exit. These are preparation corrections, not guest execution evidence.

The disk allocates about791MiB, with1280MiB private extraction tmpfs under3GiB
assembly RAM. Global observed new disk use remains below3GiB, including failed
image-build cache/concurrent activity; no per-process peak RAM claim is made.
Private raw disks/passwords are not committed. Validation/source/input pins and
actual final paths are recorded in `validation.json`. The new boot, stock daemon,
agent registration, own writes, admin denials and persistence runtime remain
**NOT RUN** pending Root's reviewed invocation. No prior HOLD is rewritten.

```sh
python -m unittest discover -s scripts/integration/networkmanager_session_vm -p test_session.py -v
```

Three focused host controls check nonce/size framing, refusal of false identity,
persistence/denial/preservation claims, and the exact frozen-controller pin.
They do not run QEMU or claim runtime authorization coverage.
