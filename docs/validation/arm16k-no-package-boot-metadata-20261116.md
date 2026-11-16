# ARM16K no-package boot metadata observation, 2026-11-16

Root completed one finite **emulated no-package observation and cleanup** on
2026-11-16. Original Perl case14 remains **HOLD**. The observation establishes
that the selected `/var` mtime can change without an ALPM transaction; it supplies
a boot/session confound for attributing that field's drift to a package operation.
It does not identify a creator, isolate a boot mechanism, prove package innocence
in case14, or grant a preservation waiver.

The guest ran aarch64 under QEMU TCG with 16,384-byte pages and PID1 systemd.
The ordinary-user PAM/login session was active, class `user`, type `tty`, with
active logind and D-Bus. After login, the reviewed idle target was 30 seconds;
the recorded interval was **30,000,063,521 ns**. Normal PAM logout was observed.
QMP quit led to natural QEMU retirement; this does not qualify guest poweroff.
The external controller exited 0 naturally, was reaped, and reached `EMPTY_TWICE`
with complete output, no timeout, signals or error. Ownership-checked Docker
cleanup and independent absence verification passed, the controller scope was
collected, and **148 HOME guard samples** were recorded. Custody remained
`SAME_FD_PIDFD_REAL_NB_CONFLICT_CLOSE_ONLY`.

The [curated JSON sidecar](arm16k-no-package-boot-metadata-20261116.json) retains
the exact public differences and whole evidence pins. It excludes private host
paths, process IDs, credentials, image configuration environments, raw images,
console contents and private guest file bodies. No ALPM transaction was run;
`ALPM` is NULL. The original raw-image identity remained unchanged.

| Comparison | Changed selected directories |
| --- | ---: |
| `offline_before` → `after_login` | 11 |
| `after_login` → `before_logout` | 0 |
| `before_logout` → `offline_after` | 0 |

The offline endpoint differences equal the first transition. In particular,
`/var.mtime` changed from **1785933444** to **1794860510**, and its separate
fractional `mtime_ns` field changed from **0** to **100993486**, by `after_login`.
That checkpoint combines boot and login; there is no early-boot checkpoint.
The result covers 15 fixed public directory selectors. It cannot attribute
unobserved changes, separate fixture-preparation effects in case14, or replace
a matched-duration or repeated control. The unchanged later checkpoints establish
only the recorded selected-metadata comparisons.

All 11 changed paths and raw values are below. `root` denotes the fixed `/root`
directory-metadata selector. Timestamp seconds and fractional `_ns` fields stay
separate; NULL means no prior node value. Decimal mode 448 is 0700. Access-time
changes are observations and were not restored or normalized.

| Public directory | Changed fields: raw before → after |
| --- | --- |
| `/root` | `links`: 2 → 3; `mtime`: 1785933495 → 1794860505; `mtime_ns`: 0 → 264000000 |
| `/etc` | `links`: 37 → 38; `mtime`: 1794708503 → 1794860510; `mtime_ns`: 0 → 99721648 |
| `/etc/audit` | `links`: 2 → 4; `mtime`: 1785933495 → 1794860505; `mtime_ns`: 0 → 255582721 |
| `/etc/udev` | `mtime`: 1785933457 → 1794860509; `mtime_ns`: 0 → 864000000 |
| `/usr` | `atime`: 1785933497 → 1794860501; `atime_ns`: 0 → 960000000 |
| `/usr/lib` | `atime`: 1785933490 → 1794860505; `atime_ns`: 0 → 588000000 |
| `/var` | `mtime`: 1785933444 → 1794860510; `mtime_ns`: 0 → 100993486 |
| `/var/cache` | `links`: 3 → 5; `mtime`: 1785933495 → 1794860506; `mtime_ns`: 0 → 188000000 |
| `/var/cache/ldconfig` | `atime`: null → 1794860506; `atime_ns`: null → 188000000; `gid`: null → 0; `inode`: null → 29323; `links`: null → 2; `mode`: null → 448; `mtime`: null → 1794860506; `mtime_ns`: null → 196000000; `present`: false → true; `size`: null → 4096; `type`: null → directory; `uid`: null → 0 |
| `/var/lib` | `links`: 6 → 13; `mtime`: 1785933495 → 1794860505; `mtime_ns`: 0 → 274600104 |
| `/var/log` | `links`: 4 → 6; `mtime`: 1785933514 → 1794860505; `mtime_ns`: 0 → 276111227 |

The preceding r2 entry ended
`CONSUMED_HOLD_PRE_PRODUCER_STALE_PHYSICAL_AVAILABLE_THRESHOLD`: the Source
controller was not started and the VM was not entered. Its stale selected floor
was **49,261,875,200 bytes**, above the observed **48,559,767,552 bytes**. Root
issued a fresh r3 entry with an explicit **10,737,418,240-byte (10 GiB) floor**.
The allocation caps stayed 1,342,177,280 bytes for the clone,
536,870,912 for the overlay, 1,342,177,280 for readback and 67,108,864 for logs:
**3,288,334,336 bytes (3.0625 GiB)**. Adding the unchanged **2,147,483,648-byte
(2 GiB) storage reserve** gives the reviewed **5,435,817,984-byte (5.0625 GiB)**
minimum. That total is approximately 5.4 decimal GB; it already includes the
reserve. The new floor remained above it. No allocation cap or reserve was waived.

The outer controller scope was 512 MiB. The separate actor limit was 4 GiB and
its guest memory was 2 GiB; these describe separate constraints. The complete
external runtime was **56.40118361002533 seconds** (about 56.401 s), including the
bounded work and retirement. It is not a performance comparison or measured gain.

The trial used the frozen Source23/65-file dependency pair below. Root's complete
source observation records 88 files/999,943 bytes at source revision
`08e08e99dfaa464049107fdb6b8887d810aa88b1`. Historical Main
`a5fe267721feb85f2f4079ef3b0f1588b57d09bd` provides the matching byte witness.
Current Main `b078d833bc6e0ccf15f84997d214bcef72790fb3` has a later readiness-test
reseal and dependent pin joins; it is a separate source identity.

| Family and identity | Files | Whole family bytes | Lock bytes / SHA256 |
| --- | ---: | ---: | --- |
| Source23 control — Frozen trial | 23 | 258225 | 3732 / `63ca909ef5828c43668fe3c56586a5fffa92badd1abcd670118802acd13213df` |
| Source23 control — Current Main reseal | 23 | 259910 | 3732 / `f680f5a8cc5f0f4f3eb055205b419ebd826595a6c2b579c5c3919455a0dd4a9a` |
| 65-file dependency — Frozen trial | 65 | 741718 | 10598 / `da1c8749a281b767f50ca696cf7818d1925aa852057d7de011b4c3ddd8eca75d` |
| 65-file dependency — Current Main reseal | 65 | 742532 | 10598 / `f787650b1dcd78c4081b544719cd4f1d8d7c67c46da09c495e6c185917c542ac` |

The legacy difference from that historical Main witness is
`test_probe_readiness.py` and its lock. Source23 updates its dependency pins in
`plan.py`, `support.py` and the public input template, with README/test proof and
a regenerated lock. Its actor, controller and metadata implementation descriptors
are unchanged. These current-Main changes do not relabel the consumed frozen
trial or establish another runtime result. The
[current source README](../../scripts/integration/arm16k_no_package_control/README.md)
explains the maintained reseal; its current pins must not replace the trial pins.

The original 111-package boot baseline and the control kernel are input provenance:

| Input identity | Bytes | SHA256 |
| --- | ---: | --- |
| Original 111-package baseline certificate | 3870 | `569d9373d0af561def524d8a573f67c50e7556886b59047ceac4804dfb239d61` |
| Original prepared descriptor | 58179 | `f7b3073f58acce8ab5e21ff61f2182779d24046e1582cda6adb0a3db66b7036e` |
| Original baseline raw-image identity | 1610612736 | `f69d74fbb0043793c96424d0f91ad2f6fb2d8cf3a72fb94024ea9cc40dae4cd3` |
| Control kernel Image | 9019400 | `36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494` |
| Control kernel config | 71585 | `b8bc8c636ae7e58e8e338e7dba87d84a390d0555fa7307fc76217e0d56553d7f` |

These pins do not establish full-system acceptance. The earlier
[systemd reference](arm16k-systemd-reference-20261114.md) documents the 111-package
baseline; its earlier kernel identity is distinct from this control's kernel
pins. The sidecar also binds Root's curated input, terminal closure, public
resource input, report and observations by whole byte count/SHA256. Those retained
private evidence files are not republished here.

Root accepted finite observation and cleanup only. Full VM, restoration, warm
baseline and release acceptance remain unissued; next-boot stability is
`NOT_RUN`. Case14 stays consumed HOLD. No timestamp normalization, absence
cleanup or waiver follows from this result. M2/native hardware, performance and
release qualification remain unestablished. This document adds no actor run,
policy change or implementation change.
