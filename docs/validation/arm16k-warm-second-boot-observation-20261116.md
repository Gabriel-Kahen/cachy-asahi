# ARM16K initialized-baseline second-boot observation, 2026-11-16

Root completed control 69 and accepted **one bounded initialized-baseline,
no-package second-boot observation and cleanup**. All 15 watched public directory
rows were unchanged across `offline_before`, `after_login`, `before_logout` and
`offline_after`. The three transitions and the offline endpoint each report
zero changes. Original Perl case14 remains **HOLD**, with no package preservation
or restoration waiver.

The QEMU guest reported aarch64, 16,384-byte pages and PID1 systemd. Its ordinary
UID1000 PAM/login session was active, class `user`, type `tty`, with active D-Bus
and logind. The fixed idle target was 30 seconds; the observed interval was
**30,000,034,599 ns**. Normal PAM logout and natural QEMU quit through the original
QMP peer were observed. The external controller exited 0 naturally, was reaped,
and reached `EMPTY_TWICE`. The scope was collected, owned-container absence was
independently verified, and **143 HOME guard samples** were recorded. Custody
remained `SAME_FD_PIDFD_REAL_NB_CLOSE_ONLY` and cleanup errors were empty.

The complete bounded external runtime was **52.81841781799449 seconds**
(about 52.818 s). This is execution/retirement evidence, not a performance comparison
or gain. The selected backing raw-image identity remained unchanged. That does
not describe every guest file or writable-overlay byte.

The [curated JSON sidecar](arm16k-warm-second-boot-observation-20261116.json)
retains the exact comparison, public selector list, timing, input pins and whole
receipt references. All four recorded selected-metadata dictionaries are equal;
access times are included, with `OBSERVED_ONLY_NO_RESTORATION`. No timestamp
normalization or metadata restoration was performed. The selectors cover
`/root`, `/etc`, `/etc/audit`, `/etc/udev`, `/usr`, `/usr/bin`, `/usr/lib`,
`/usr/share`, `/var`, `/var/cache`, `/var/cache/ldconfig`, `/var/lib`,
`/var/lib/pacman`, `/var/lib/pacman/local` and `/var/log`. Directory metadata
alone is reported; private guest file bodies, credentials, key homes, host
paths, process IDs, console data and image configuration environments are not
republished.

| Selected-metadata comparison | Original cold control | Initialized-baseline second boot |
| --- | ---: | ---: |
| `offline_before` → `after_login` | 11 changed paths | 0 |
| `after_login` → `before_logout` | 0 | 0 |
| `before_logout` → `offline_after` | 0 | 0 |
| `offline_before` → `offline_after` | 11 changed paths | 0 |

The [cold-control observation](arm16k-no-package-boot-metadata-20261116.md)
records `/var` mtime drift by `after_login` without an ALPM transaction. This
second boot also performed no package operation (`ALPM` is NULL). Both controls
used the same whole-pinned kernel and Root-bound complete 111-package identity;
the warmed image, prepared descriptor and selected certificate have distinct
identities below. The contrast supports a finite cold-versus-initialized
boot/session comparison. It does not identify the creator of the cold changes,
prove warming is their sole explanation, establish repeatability, or prove
package innocence in case14. No early-boot checkpoint separates boot from login.

| Exact input provenance | Bytes | SHA256 |
| --- | ---: | --- |
| Warmed backing raw | 1610612736 | `f30fa96283042b12229b455fe33918facb83a0650a8e7849fcaab493dda366cb` |
| Warmed prepared descriptor | 20564 | `04923eecb2548142f22498f306c2145bcdc35e60b27e3d1ffbd73d7d27ae7f26` |
| Root-selected control certificate | 1969 | `681d26b0be12f7992e261c53e54b6d663df94dbce0ee1e7e63de8cdd141572b9` |
| Run-specific control Source lock | 4153 | `99670bb69d3bf900a76a43c342559144eacfc5bf74535c81cc15b9bc825163b1` |
| Shared kernel Image | 9019400 | `36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494` |
| Shared kernel config | 71585 | `b8bc8c636ae7e58e8e338e7dba87d84a390d0555fa7307fc76217e0d56553d7f` |
| Complete original 111-package identity | 18370 | `ae69ebe75e2b17011ac6bd063f825f9993242e63b7a293799a5bcd1fa6fb4d79` |

The run-specific Source lock identifies Root's materialized control source.
It is distinct from the cold Source23 lock 3732 B/`63ca909ef5828c43668fe3c56586a5fffa92badd1abcd670118802acd13213df`.
The [maintained warm-control family](../../scripts/integration/arm16k_warm_control/README.md)
and its unissued templates remain unchanged. This observation does not fill a
future grant or convert a generic template into an accepted execution request.
The source/identity pins describe provenance, not full-system acceptance.

The terminal closure is **2,116 bytes / SHA256
`0447c7558154432cf5597acc2412a181b422b43b7f0f229bdd3dad909aca0cec`**,
observed at `2026-11-16T23:23:18.324529+00:00`. The report is 11,375 bytes /
`b8834d4039f7c66ba518d79a2c178a5ea6900969b0f487bb146712e9f3fda38c`;
observations are 10,496 bytes /
`a1abab9a410a0673180bbcbd32640e517d8888ab874197cb4bc1da0110416437`.
The sidecar strips private paths from these retained receipt references.

Root's scope is `ONE_BOUNDED_INITIALIZED_BASELINE_NO_PACKAGE_SECOND_BOOT_ONLY`.
The result grants no timestamp normalization, absence cleanup, restoration or
package-preservation waiver, general baseline refresh, future-boot stability,
or full VM/system acceptance. QMP quit does not qualify guest poweroff. Perl
case14 remains consumed HOLD. Native/M2 hardware is `NOT_RUN`, performance is
not measured, and release acceptance is false. No new actor or CI round is
performed by this documentation; Root retains later publication and admission.
