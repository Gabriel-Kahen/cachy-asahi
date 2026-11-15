# UI172 retained input successor

This separate DATA audit covers the proposed 172 additions to the protected
111-package baseline (283 total). It does not reopen the prior UI145/seat44
audit roles or their budgets. The original missing Xvfb 21.1.25-1 remains held;
this proposal explicitly selects current Xvfb 21.1.26-1. No actor, guest,
installation, daemon, network request, rootfs payload read or package execution
is authorized or performed by the reader.

The new proposal is 449,748 bytes, SHA256
`acc8eeae38de61fb0db844b621884a0d66b76f129e5a076c533d870f6e0856e6`.
The [successor reader](../../scripts/port/arm16k-first-login-ui-inputs/retained_archive_audit/ui172_successor/)
pins the original reports in both stored and decoded form, the actual proposal,
the current Xvfb acquisition receipt, public keyrings, inherited reader sources
and observed constructor sources. All 171 unchanged archive/signature identities
must match the prior actual reports. Every current archive and signature file
is freshly hashed; metadata and signature mathematics are reused only for the
exact same bytes. The one changed package is separately parsed and checked
with actual host gpgv.

Only packages needed for new namespace records and the two formerly oversized
ELFs are decoded. Hashing and decompression share a single compressed stream,
with source-descriptor identity checked before/after. The full original
NetworkManager policy hash and three already observed namespace records come
from the pinned seat44 ledger. Constructor payloads retain exactly the seven
fields `type,mode,uid,gid,bytes,sha256,link`; richer ELF facts remain separate.
The twelve addition namespace leaves are distinct from the two unread baseline
GLib/Gio typelib records Root must independently supply.

Official and project signing roles remain separate, including official
architecture-independent packages. The three named project TEST packages have
`signer_role=project`, their actual expected TEST fingerprint, and
`official_repository=false`. Their signatures are freshly checked against the
current clock without changing keys, timestamps or system trust. Expiry or
other rejection is retained as an actual hold. `trust.valid_until_utc` is left
null for Root; this ledger never fabricates an admission horizon or Root
approval.

The new role has limits of 256MiB additional compressed reads, 1GiB decoded tar,
150,000 headers, 192MiB per ELF, 600s wall and 768MiB combined address-space caps
(64MiB supervisor plus 704MiB worker; the signature phase divides the latter
into 672MiB worker plus 32MiB gpgv). The reader records `/proc/self/status`
high-water data as well as historical rusage, so the earlier projection's RSS
measurement discrepancy is not silently reused. A full read reservation is
written before package reads; a failed attempt must not restart with reset
counters.

The ledger's own DATA kind is
`ARM16K_FIRST_LOGIN_UI_AUTHENTICATED_LEDGER_V1`; the intended consumer kind is
`ARM16K_FIRST_LOGIN_UI_ADDITIONS_V1`. Remaining Root-owned fields are listed
explicitly: final kind/status/issuer, baseline prepared/metadata/provenance,
original file pins and baseline typelibs, plus currently admitted trust.
Actual fish/zsh template archive pins are supplied separately from the 172
installation additions.

Static ELF geometry, NEEDED and GNU version names do not establish full dynamic
symbol ABI, runtime compatibility, native builds, an actual seat, M2 hardware,
legal acceptance or release readiness. Any observed incompatibility must remain
visible. The separately owned GUI constructor performs its own complete
namespace/ownership checks before any Root-admitted experimental guest.

Actual result: 172 archive/signature identities, full PKGINFO for all 172,
1,319 metadata dependency joins, twelve exact addition namespace records and
1,101 observed static ELF passes (1,100 loadable ELF objects and one relocatable DATA object). Current Xvfb's 2,003,512-byte ELF has SHA256
`bd60e8aa75f7693cc7beadb07006226ec68e8d22609493c6dc883c4dd45af35d`.
The original ARM NetworkManager policy remains 188,810 bytes, SHA256
`6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446`.

The two former allocation holds were actually parsed using a streamed
`ELFBuffer` whose slices remain views. No check was waived:

| Object | Bytes | Full SHA256 | Actual geometry |
| --- | ---: | --- | --- |
| LLVM `libLLVM.so.23.1` | 171,229,352 | `a62802282e6e32e38d8415c287f053671962acc0f4917c99ff6c9f8bdf69d3f5` | Two LOADs, alignment 65,536, congruent 16K, no structural errors |
| Mesa `libgallium-26.2.4-arch1.1.so` | 53,602,840 | `9bf3bb56edf2c953c6dc620bae7e0f2c0e87cc6df6c4510e9de42c8e7dd0db82` | Two LOADs, alignment 65,536, congruent 16K, no structural errors |

The complete NEEDED lists and GNU version needs/definitions are retained in
`results/rescanned-ELF-metadata.json.gz`. LLVM declares `LLVM_23.1`, which Mesa
requires. Mesa also requires `GLIBC_2.43` from `libm.so.6`; baseline package
version declarations do not prove that export, and no baseline payload was
read here. This remains part of the explicit full ABI/runtime uncertainty.

Fresh host gpgv returned exit 0/direct-primary mathematical passes for current
Xvfb and all three exact UI TEST packages, with no expiry status. The exact TEST
certificate declares creation 1794701211 and lifetime 86,400s: expiry
**2026-11-16 00:06:51 UTC**, after the actual observation. The separate bounded
public-packet reader reports declarations only, without importing keys or
claiming self-certification/current-trust approval. Root's admitted trust
horizon remains absent; no expired-certificate exception was introduced.

The first attempt completed all 172 current archive/signature hash reads, then
failed during metadata joins because the adapter omitted provider `repo`.
Its exact source/config, failure, all-172 completion checkpoint and full read
reservation are retained. A second attempt refused before archive reads when
the concurrently edited GUI constructor source changed; immutable observed
source snapshots now avoid that race. Recovery carried the first budget,
repeated only ten selected decodes and four gpgv checks, and completed naturally.
The 162 carried hash-only rows refer to the pinned first-attempt checkpoint and
producer rather than inventing per-file descriptor-stat records lost when the
process exited. The final constructor must independently revalidate materials.

Combined actual accounting, including failure/recovery, is 226,141,431 compressed
bytes, 661,524,480 decoded bytes and 5,470 headers, with 8.261s aggregate parent
execution time. Successful recovery observed `VmPeak=239964kB` and
`VmHWM=226124kB`; both active scan workers enforced the 704MiB address-space
limit. The first failed worker did not retain a separate process high-water
measurement. Prior UI145/seat44 reports and budgets remain unchanged.
The final ledger labels the actual signature-phase cap from executed code;
the raw reports retain an unused inherited 160MiB limit-field value.

Validation: 26 synthetic controls passed (twelve stream/signature controls,
ten large-ELF controls and four certificate-declaration controls). Stored and
decoded output pins, exact PKGINFO/namespace shapes, separate 169 official/three
project roles and unchanged actual ALPM preparation were checked without
additional archive reads. `results/authenticated-ledger.json` is the final
DATA handoff; Root's missing fields remain explicit.
