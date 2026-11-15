# Retained ARM UI archive audit

This is an offline DATA audit, not an installed or hardware result. The
[reader and evidence](../../scripts/port/arm16k-first-login-ui-inputs/retained_archive_audit/)
cover the original 145-material proposal and the separate minimal-seat proposal
of 44 additions to the unchanged 111-package baseline. No old planner/intake
observations, package selection, manifests, or baseline payloads were changed.

The planner is pinned to `15220d620f9305558a45dbbec98d5ca616fd33e2`; the
six-pair intake is pinned to `9751c334c8c386135a68612556c848525530e548`.
`inputs.json`, `seat-inputs.json` and `ledger-inputs.json` bind the private
plans, reports, retained archive routes, public keyrings and inherited reader
sources. The roadmap and package inventory remain authoritative for project
acceptance.

| Actual observation | Original UI145 | Minimal seat44 |
| --- | ---: | ---: |
| Full archive/signature size and SHA256, host gpgv, actual PKGINFO | 144 | 44 |
| Official direct-primary signatures | 141 | 44 |
| Separate project TEST signatures | 3 | 0 |
| BUILDINFO identity matches | 144 | 44 |
| Observed ELF objects | 777 | 428 |
| Static aarch64/16K structural passes | 775 | 428 |
| ELF object-cap holds | 2 | 0 |
| Missing exact archive/signature pairs | 1 | 0 |
| Actual metadata dependency joins | 724 | 190 |

The UI145 hold is the frozen `xorg-server-xvfb` 21.1.25-1 pair. This audit
does not adopt another version. Its oversized ELF holds are LLVM's
171,229,352-byte `libLLVM.so.23.1` and Mesa's 53,602,840-byte
`libgallium-26.2.4-arch1.1.so`. They were fully hashed/drained, not allocated
for ELF parsing. These three holds do not belong to the separate seat44 set.

Official signatures require signing and primary fingerprint
`68B3537F39A313B3E574D06777193F152BDBE6A6`, exactly one valid status, exit 0,
and no rejected GnuPG status. The three named project packages instead use
`18E721CE9D7928221AD3163BA91B1AFC7142F94E`. TEST mathematics does not establish
a native build or production release. Actual host `/usr/bin/gpgv` used an
empty private home and the exact public binary keyring; no system trust or
private key was accessed.

The seat ledger contains the constructor-compatible `archives` rows with
full actual PKGINFO multimaps, the original public keyring pin, unchanged
actual proposal `metadata_prepare`, and four actual addition payload records.
The required constructor contract is pinned to SHA256
`94f3f323544ec754d1fb15c920ff07e2d1ec268e78b2e28fbd38a4db30535ced`.
The ledger has its own DATA kind and no Root authority. Root must independently
join baseline provenance, original file pins, the two baseline typelib records,
and its final approval to issue `ARM16K_VIRTIO_SEAT_ADDITIONS_V1`.

The actual ARM NetworkManager policy is 188,810 bytes, SHA256
`6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446`.
It contains `org.freedesktop.NetworkManager.settings.modify.own`, with
`allow_active=yes`, `allow_any=auth_self_keep`, and `allow_inactive=yes`.
This proves the original ARM XML matches the supplied comparison hash.
It does not exercise a policy action. The actual policy DATA and public
binary keyring remain in `/tmp/cachy-arm-seat44-authenticated-ledger-20261115-01/`.

Across both scans and the four required-path projection reads, compressed
accounting is 536,269,152/536,870,912 bytes; logical tar accounting is
1,109,657,600/2,147,483,648 bytes; raw headers 38,097/250,000; wall time 14.402s.
Initial scanning reserves three compressed reads per archive for snapshot
hash, gpgv and decode. Projection hashes and decodes a single stream once,
binding the same full bytes to the earlier signature result. No further
archive reads are authorized by these counters beyond the remaining 601,760B.

The original scan workers recorded peak RSS 72,859,648B and 50,995,200B.
The projection enforced 192MiB `RLIMIT_AS`, but recorded an anomalous
950,988,800B historical `ru_maxrss`; its process `VmHWM` was not captured.
Measured projection RSS below 256MiB is **not established**. The retained
ledger preserves this discrepancy rather than treating it as a memory pass.
Future runs also capture `/proc/self/status` process high-water data.

NEEDED and GNU version-name joins preserve explicit holds for unread baseline
payloads and unobserved providers. Version-name matches do not establish full
dynamic-symbol ABI. Namespace collisions were not reported by the actual
scans, but their original detector did not compare link targets; this is not
complete namespace acceptance. Final source now compares those targets.
The constructor must independently check the complete joined namespace.

The raw reports are immutable, losslessly stored as deterministic gzip DATA
with encoded and decoded pins in `results/evidence-pins.json`. Reconciled
reports label holds using metadata only. They correct the original seat44
report's generic Xvfb hold without changing the original report. Final source
also tightens failed-read accounting, unsupported-search version holds,
duplicate pkgbase checks and XML refusal handling after the initial scan.
The actual reports contain no hash refusals or unsupported-search rows;
offline metadata checks found no newly rejected pkgbase identities.

Validation: 20 synthetic controls passed with
`python -I -B scripts/port/arm16k-first-login-ui-inputs/retained_archive_audit/test_audit.py`.
They exercise tampering, finite routes, signer roles, metadata ambiguity,
traversal, link DATA, caps/deadlines, 4K/16K differences and baseline-symbol
holds. No package/ELF code, compiler, daemon, native actor, VM, installation,
network request or rootfs payload read occurred. Source build, actual seat,
runtime, M2, legal and release acceptance remain unestablished by this audit.
