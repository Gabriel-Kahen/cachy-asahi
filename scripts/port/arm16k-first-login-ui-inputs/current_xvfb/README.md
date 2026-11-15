# Separate current official ARM Xvfb candidate — 2026-11-15

The live official package page declared **21.1.26-1**, acquired and verified as a
new proposed disposable-VM input. It does not recover or satisfy the unavailable
21.1.25-1 archive, change the old 145-package result, or upgrade the baseline.

| Object | Bytes | SHA256 |
| --- | ---: | --- |
| xorg-server-xvfb-21.1.26-1-aarch64.pkg.tar.xz | 705,736 | `c4729aaf327fae3f19795f4fbcad8035798316d4c812c56953c32796f1cf916c` |
| Detached signature | 566 | `b897acfedc03067a68f1c28bf7ad2d62ee78365fe83a4d48a081910dc57a90e7` |

The official discovery URL was
`https://archlinuxarm.org/packages/aarch64/xorg-server-xvfb`; its exact download
path was fetched over HTTPS from the documented California official mirror.
There were three GETs, zero redirects and 722,583 response-body bytes in one
29.347-second discovery/acquisition window (including time between stages).
Real host gpgv selected primary `68B3537F39A313B3E574D06777193F152BDBE6A6`;
actual PKGINFO name/version/aarch64 identity matched discovery. Full hashes,
public-key pins and mathematical signature verification are distinct from
current revocation/freshness or source acceptance.

## Protected metadata proposal

Only the Xvfb root changed, from the unavailable catalog archive to this actual
signed candidate's PKGINFO metadata. All other roots and 111 baseline versions
remain unchanged. The current-row adapter rechecks the real archive/signature,
not just the saved receipt's claim. Genuine libalpm 16.0.1 prepared 145 additions
and 256 final packages: zero errors/removals/questions/conflicts, 1,196 final
satisfier relations. Retained `xorg-server-common 21.1.25-1` remains unchanged;
its unversioned dependency satisfier is not proof of runtime interoperability.
There are no missing archive observations in this new profile, but the other
139 original observations have not been authenticated by this candidate intake.

## Static DATA audit and its limit

The existing ELF parser observed AArch64 Xvfb, interpreter
`/lib/ld-linux-aarch64.so.1`, and two PT_LOAD segments with 65,536-byte alignment
and 16K offset/address congruence. The existing bounded readelf helper inspected
641 dynamic imports against all 12 actual direct NEEDED providers. Every strong
symbol name/exact version matched an export; unversioned imports require a plain
or default-version export, not a hidden legacy version. Six NEEDED version
namespaces matched the respective provider's exports. Required GLIBC versions
range from 2.17 through 2.38, and were actually compared to the frozen libc/libm/
loader from glibc 2.43+r22+g8362e8ce10b2-2. Three unresolved optional weak symbols
are retained, not recast as strong imports.

Baseline providers were read with **read-only debugfs** from the already prepared
ARM111 raw file, without mounts/devices or guest execution. Its identity/size/
mtime/ctime stayed stable; a new full 1.6 GiB raw hash was not performed. The
original prepared descriptor's custody and each observed file's exact hash are
reported. Other direct libraries came from the exact selected cached archive
versions after full archive SHA checks. All 12 provider ELF shapes also met the
static 16K observations. No package ELF was loaded, mapped as a program or run.

Status remains **HOLD_DIRECT_STATIC_SCOPE_ONLY**: direct symbols/version names
and geometry do not establish the complete transitive namespace/version ABI,
relocation semantics, normal hook effects, source/license closure, actual loader,
Xvfb/GTK runtime or ARM seat0. No source-built alternative was started. That
proposal remains available if complete compatibility cannot be established.
ARM native build, physical M2/display/networking and release remain NOT RUN.

## Reproduce the separate DATA paths

No additional acquisition is authorized by this README. For a separately admitted
new live lookup, `acquire.py --discover-current --discovered-root NEW_PATH` bounds
discovery plus two small object GETs to the same 180-second window, 8 MiB total
response-body cap, TLS verification and a private public-only gpgv home. It never
silently reuses the old version's identity. To prepare the already retained input:

```sh
python -I -B scripts/port/arm16k-first-login-ui-inputs/seat_proposals/propose.py \
  --proposal current-Xvfb \
  --current-acquisition /tmp/cachy-asahi-arm16k-current-xvfb-20261115/acquisition.json \
  --output /tmp/new-current-Xvfb-proposal
python -I -B -m unittest discover \
  -s scripts/port/arm16k-first-login-ui-inputs/current_xvfb -p 'test_*.py' -v
```

Four controls pass. Exact private evidence pins, static provider hashes and holds
are in [actual-result.json](actual-result.json). Key reports:

- `/tmp/cachy-asahi-arm16k-current-xvfb-20261115/acquisition.json`
- `/tmp/cachy-asahi-arm16k-current-xvfb-proposal-20261115-v2/proposal.json`
- `/tmp/cachy-asahi-arm16k-current-xvfb-20261115/provider-static-audit-v2.json`

The last report is 34,053 bytes, SHA256
`487ee2042a1f8e6a8a3c8706560dd9b9f1a89eef057430b457f13275d8f2e030`.
