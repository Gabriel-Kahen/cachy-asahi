# NetworkManager real-seat lifecycle — 20261114

**PASS: finite x86 software profile lifecycle only.** Root executed this fresh
NM variant and independently rejoined the full generic seat and NM reports.
[The separate generic seat handoff](systemd-real-seat-20261114.md) preserves the
verified substrate and all three earlier closed generic seat HOLDs; this run
did not replay them or replace the earlier serial password-challenge evidence.

Builder UID/GID 1000 used a genuine keyboard/password PAM login on tty1, active
seat0, actual `sd_session_get_seat=0/seat0`, verified bus UID/PID and stock NM/root
and Polkit/102 server identities. Original own-action policy authorized the
actual client without a challenge, interaction flags 0. **No additional
credential or authentication agent was used.** No rule, session, PAM, admin-group
or kernel input override was added.

Actual GIR/D-Bus operations created the builder-restricted own profile, edited
its ID, persisted it, then removed it. Root read the persisted 261-byte,
root-owned 0600 file; SHA256
`8b1eb930655e2a5e389a96c91ebef63efa0f38072566d672ce4d9d3523aaf0cb`.
It was non-autoconnecting, with disabled IPv4/IPv6 and an absent fixture
interface. Actual foreign and system Delete requests both returned
`org.freedesktop.NetworkManager.Settings.PermissionDenied`. Their complete
profile/policy/package snapshot stayed unchanged. Root's final state equaled
initial state: both original profiles, user config, account/group, recorded original
policy/rules/PAM files and complete 164-package inventory were preserved.

The full seat proof also passed live ECHO-off and real keyboard ACKs 8/41/46,
input-parent seat corroboration, normal VT PAM logout and login1 session removal.
QEMU exited0, reaped `EMPTY_TWICE` without escalation/timeout/cancellation, and
exact owned-container absence passed. QMP emulator quit followed logout;
**normal guest OS shutdown was not qualified.**

## Exact successful inputs and source

Root source commit: `2900e90def51ab7427dbd8a6f4765310f23ec6df`
(worker equivalent `be47530c2c350942330d4b2c759aa0324f83b0b4`).
[Source scope](../../scripts/integration/networkmanager_seat_vm/README.md),
[read-only reference pins](../../scripts/integration/networkmanager_seat_vm/references.json)
and [preparation record](../../scripts/integration/networkmanager_seat_vm/validation.json)
record the unchanged generic controller/keyboard/actor and exact existing
four unsigned x86 `networkmanager/libnm/nm-cloud-setup/networkmanager-docs`
`1.58.1-2.1` archives. No new dependency fetch/build/install occurred in this
variant. Provider custody remains distinct from production trust/freshness.

Prepared directory: `/tmp/cachy-asahi-nm-seat-preparation-20261114/prepared`.
Image `cachy-nm-real-seat:ca3b06ea4aff9410`:
`sha256:1f4922c557070c90e9af8dbc2099ba9df61cce352b1f86f214d84d6eb19bbee3`.
Nonce `8b04d4e6f44d8a692da5e640ce94806a`; this successful once state is closed.
Private 0600 credentials are not published or included here.

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `prepared/prepared.json` | 2,808 | `f57c3b47632d2e75c9a1fa5b468886d11415c1bfb2a34a5b406b168d3b710cd2` |
| `prepared/guest.raw` | 1,610,612,736 | `e2f2b016921303789f7c67de689d459d86e842fc09f143e14d6db00f77166ad4` |
| `prepared/vmlinuz` | 17,248,768 | `b1e9eaf5700a53a31ed923edecd72b319a29da74be32c0885bff112d37ce325b` |
| `prepared/initramfs.img` | 9,685,879 | `9765fd579cee81a14092b10da1daa762e58c8e2112883a84f57a60550d1de8c9` |
| `prepared/package-export.json` | 1,138,986 | `3de0207063d5443d99855da2037af55ed93707137b4be162cfcca2d40793d445` |

| New exact source | SHA256 |
| --- | --- |
| [boot.py](../../scripts/integration/networkmanager_seat_vm/boot.py) | `39b5b0380e04b6b92f5779bdc398e748b1d87b2be3d215aa81eb7f06db2027fe` |
| [assemble.py](../../scripts/integration/networkmanager_seat_vm/assemble.py) | `9392f10caffcd052d21422e10e8709d174c971f4773ca544ea8e86554eacd454` |
| [client.py](../../scripts/integration/networkmanager_seat_vm/client.py) | `b222a3fd2d04047c43b7f7c13765eb0afea6ccaafb1a8ab8d08ebdf20333897c` |
| [observer.py](../../scripts/integration/networkmanager_seat_vm/observer.py) | `aeb379956571c2a17bb9ea4babd328a81d0554f8f3e76d352776c595e836df22` |
| [result.py](../../scripts/integration/networkmanager_seat_vm/result.py) | `73cab1e3c946e60cac213897ee70390c9daa0e706e5bc03fc66d2523ac2c39af` |

Reused exact root NM snapshot observer SHA256:
`2ec073ae9f239895219cc6800b0dd149f206c8b4d3bd9eccadefbcdbc77552e9`.
Unchanged generic controller, keyboard, input helper, user proof and actor hashes
are listed in the [generic handoff](systemd-real-seat-20261114.md) and joined by
the prepared manifest. The NM adapter requires both full seat/logout acceptance
and actual matching client/root NM preservation results; generic success alone
cannot pass. The data-only assembly caller naming correction is explicitly
retained in preparation validation; no second preparation/runtime result is
claimed for it. Executed caller SHA256
`3c28e98ff91cbb3e7d6c98f437d39be8927e5e5e78b207c75e8f65e713db1907`; delivered corrected caller SHA256
`321c16858202d0b3cddc34a0390f5f56957182b137dcf3fa72d6dece0c110f8c`.

## Exact retained result

Private local output directory: `/tmp/cachy-asahi-nm-seat-first-boot-root-20261114`.
Paths are local retention, not public export or release.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `journey.json` | 37,141 | `9a7781f86569094cee03b74d3ec11d24d3a8909f7d65105a0edfe0a21c93acdb` |
| `report.json` | 49,278 | `2a57f07e5563609fa3b15c06ee65a38e9efa741f4cb308fe002e2d2a8c595140` |
| `serial.redacted.log` | 53,236 | `0e30b42a061907fd8e1d8644db8ed0517534688998519aeee3339a71573a69c4` |
| `qemu-retirement.json` | 251 | `33a001b9dfc1c361d4a85f2cc2e4c817b61a7d32c02d9d6f038c54383b3bfbb7` |
| `qemu-argv.json` | 910 | `0642e3117d2e9dfd541e988f021d16210e6639a0e21fb4a42a1dbab661625fc3` |

`journey.json` reports `PASS_X86_REAL_SEAT_NM_PROFILE_LIFECYCLE_ONLY`;
`report.json` independently reports `PASS_X86_REAL_SEAT_REFERENCE_ONLY` with the
actual embedded NM client/root join. Complete root snapshots agree and neither
result is inferred from schema-only controls. The four focused acceptance/source
controls passed on Python3.12/3.14; Root separately ran the actual guest.

Runtime retained rootless all-capabilities-dropped/NNP/read-only/network-none, no KVM/host
bus/devices, init=false, two owned binds, 2 CPUs/3 GiB/256 PIDs. Guest 1536 MiB,
TCG/q35/VGA/i8042, no NIC/VNC;256 MiB maximum overlay,210s observer/420s serial/480s
actor/35s cleanup budgets. Actual admission before assembly had 17,810,911,232 B
MemAvailable; new `/tmp` space delta 831,651,840 B, with 3 GiB assembly cap and 3 GiB
additional reserve. No physical interface or connection was activated. Cloud/OVS
examples stayed inert; host services and global configuration were untouched.

This closes the real active-seat ordinary-user NM authorization/profile software
journey for these exact x86 candidates. It does not qualify ARM/16K, Asahi/M2,
physical connectivity/display/input, suspend/resume, target transaction, package
source/license completeness, production signing/freshness or release. Next:
first obtain and qualify the matching ARM candidate/transaction, then apply this
finite acceptance path on the supported Asahi stack under its own admission and
exact-machine gates.
Do not rerun this closed fixture to obtain a different result.
