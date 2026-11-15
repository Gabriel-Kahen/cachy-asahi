# Real-seat systemd/PAM/Polkit reference — 20261114

**PASS: finite x86 software reference only.** Root executed the opt-in guest and
independently checked its result. A real virtual keyboard drove stock tty1
getty/password PAM login as builder UID/GID 1000, outside administrative groups.
The live session was active, user-class, tty, `Service=login`, `Remote=no`,
`Seat=seat0`; actual `sd_session_get_seat` returned 0/seat0. Root independently
corroborated the live PID, bus UID/PID, foreground VT1, DRM card and real AT
keyboard event/input-parent ancestry with the original parent seat tag and
`ID_FOR_SEAT`. No session, seat, udev, PAM or authorization policy was fabricated.

The controller required actual read-only tty1 ECHO-off before password entry.
Explicit QMP key down/up delivery required nonce-bound monotonic real ATkbd
release ACKs: 8 username,41 cumulative through password/return,46 through exit.
No event grab, termios write, keycode/raw-input export or authentication retry
occurred. The actual system-bus subject's original NM own-action policy returned
`authorized=true, challenge=false` with interaction flags 0 and no agent or extra
credential. Original policy SHA256 is
`6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446`;
original71-seat.rules SHA256 is
`b57a64ab6c973d0b734dea808e6caf9a49b40739c7c7649784d09bd6d90c36d3`.

Normal VT PAM logout, login1 session removal and returning getty were observed.
QMP then quit the emulator. QEMU exited0, was reaped with `EMPTY_TWICE`, no
escalation/timeout/cancellation, and exact owned-container absence passed.
**Normal guest OS shutdown was not qualified.**

## Exact successful inputs and source

Root source commit: `c84ce6edcf6446b9a4a4b3de57fcf59a4820b536`
(worker equivalent `33da0d8f563b8372b2220bf333ab622b04c66d41`).
[Source/constructor scope](../../scripts/integration/systemd_tcg_seat_guest/README.md)
and [preparation record](../../scripts/integration/systemd_tcg_seat_guest/live-tty-validation.json)
retain earlier source and custody pins. Existing pinned official Arch userspace,
stock 7.2.14-arch1-1 kernel and QEMU 11.1.3 were reused; no new kernel was built.

Prepared directory: `/tmp/cachy-asahi-tcg-seat-live-tty-preparation-20261114/prepared`.
Image `cachy-tcg-real-seat:196337a5c11df127`:
`sha256:e34f4f1c8fa36c1bc7ffa03d707f8b9eeed933163a4b10800b8cd90103fac1e6`.
Nonce `58842e22afd852dbc59f0184b17b6e78`. The successful once marker is closed;
private 0600 credentials are not published or included here.

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `prepared/prepared.json` | 2,431 | `e5b0b1807c432cb098bd23b66d337e05b0f4c36c339329d1e72be3a891820561` |
| `prepared/guest.raw` | 1,610,612,736 | `a6056bebf1bb00edd218c3bee12fe166b3170f4ba131ed6d0cb1d484a779ced6` |
| `prepared/vmlinuz` | 17,248,768 | `b1e9eaf5700a53a31ed923edecd72b319a29da74be32c0885bff112d37ce325b` |
| `prepared/initramfs.img` | 9,685,879 | `9765fd579cee81a14092b10da1daa762e58c8e2112883a84f57a60550d1de8c9` |
| `prepared/package-export.json` | 1,138,986 | `3de0207063d5443d99855da2037af55ed93707137b4be162cfcca2d40793d445` |

| Exact source | SHA256 |
| --- | --- |
| [boot.py](../../scripts/integration/systemd_tcg_seat_guest/boot.py) | `5427fa4f6ae58734e8b9a37eac50fac6561a7593ffd318d1f92b6f13fb067d68` |
| [assemble.py](../../scripts/integration/systemd_tcg_seat_guest/assemble.py) | `54aebae8691c6f9f9307b92a1fe27663a6db13ea0c7da912f2379186860cb093` |
| [observer.py](../../scripts/integration/systemd_tcg_seat_guest/observer.py) | `5a5fa601ca8b8732c42628241966eed57925cf181f465ab38bf427318ed584f9` |
| [keyboard.py](../../scripts/integration/systemd_tcg_seat_guest/keyboard.py) | `040ca60ad6cdd4534a813072f133a7291d19898e89afe26c7a0c8477188ff279` |
| [input_seat.py](../../scripts/integration/systemd_tcg_seat_guest/input_seat.py) | `34559e846e14164ac7cb54d6879d106c1a911bf611c988252eebd46700e0c611` |
| [user_proof.py](../../scripts/integration/systemd_tcg_seat_guest/user_proof.py) | `01a6f6ba2e80ecd8c1b10520354fd1ad25809adcc1f5fff81cdc7a486bcae0a6` |
| [vm_actor.py](../../scripts/integration/systemd_tcg_seat_guest/vm_actor.py) | `38c649b56f95e62b31657ad4b773838726ef53517b13facf10bbc858791343d8` |
| [observer.service](../../scripts/integration/systemd_tcg_seat_guest/observer.service) | `f57847dfe57ea112fa484bb3bb8f67d1025275098a9eaf7949544aff63657f0c` |

## Exact retained result

Private local output directory: `/tmp/cachy-asahi-real-seat-live-tty-first-boot-root-20261114`.
These filesystem paths are local retention, not a public export or release.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `report.json` | 11,299 | `3384ce35565e5dea49cd7ad9889ac413e917a6386d8754057e62939323d7717b` |
| `serial.redacted.log` | 21,646 | `bf608029421340ac5bd8850b6df675fdeb98ea0960b439eb579e57eb0dfea857` |
| `qemu-retirement.json` | 251 | `1114afde0b2b809cb709d5e05fe3426048358ec8e7b7728304bdd0b29bfb8b98` |
| `qemu-argv.json` | 910 | `7e2976858dc0e8bbfc5d13ec12f6161eccf2681163fb309e54e39046969bb7a0` |

Runtime: rootless all-capabilities-dropped/NNP/read-only/network-none container, no KVM/host
bus/devices, init=false, two owned binds, 2 CPUs/3 GiB/256 PIDs. Guest 1536 MiB,
TCG/q35/i8042/VGA, no NIC/VNC; immutable raw with256 MiB maximum overlay. Observer 210s,
serial 420s, actor 480s and independent cleanup 35s. Aggregate admission and actual
preparation limits are pinned in the source validation record.

## Three earlier closed generic seat HOLDs

Each retained its own nonce/input/once state. None was replayed or relabeled
PASS; all three QEMU retirements and exact container-absence checks passed.

| Trial/output directory under `/tmp` | Terminal cause and credited limit | Report SHA256 |
| --- | --- | --- |
| `cachy-asahi-real-seat-first-boot-root-20261114` | Ordinary tty1/seat0/Polkit proof passed, but observer incorrectly required the seat tag on eventN rather than its stock inputN parent. Full logout was not reached. | `d76f89a85481c3c9e8f07970b00faf3a3c8c3950e8ec3225875daf1a573b935f` |
| `cachy-asahi-real-seat-parent-first-boot-root-20261114` | Timed keyboard attempt reached a builder PAM authentication failure before profile startup. Passive journal/shadow/source checks confirmed the prepared credential and installed bytes; the exact lost/mistimed character and a QEMU/PAM defect were not established. | `e41784db278ddadbe67022c04db03ced7820e83af5e9f300ef614b67bc05408d` |
| `cachy-asahi-real-seat-keyboard-first-boot-root-20261114` | Username ACKs1–8 passed; retained tty descriptor produced termios EIO at the getty/login transition, before password readiness/delivery. The observer lifetime was corrected with fresh read-only fd checks. No PAM authentication outcome is inferred. | `3e2d9168c36cebb4d6824205a373ac1599bf288d0421496246decd097d1ce91e` |

These are distinct observer/input failures, not evidence that original policy
failed. [Input-parent](../../scripts/integration/systemd_tcg_seat_guest/input-parent-validation.json),
[keyboard/passive diagnosis](../../scripts/integration/systemd_tcg_seat_guest/keyboard-validation.json)
and [live-TTY](../../scripts/integration/systemd_tcg_seat_guest/live-tty-validation.json)
records preserve the exact corrections and held evidence.

This PASS establishes a reusable x86 real-login/seat substrate. It supplies no
ARM/16K, Asahi/M2, physical display/input/networking, suspend, production trust,
source/license completeness or release acceptance. The independently executed
[next NM lifecycle handoff](networkmanager-real-seat-20261114.md) adds actual
application authorization/preservation; supported native/physical acceptance
still needs its own exact-machine evidence. Reuse source with fresh review and
once state; do not rerun these closed inputs.
