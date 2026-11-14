# Observed clean host builds — November 14, 2026

Two fresh disposable source actors completed the unchanged Perl **5.42.3-1.2**
recipe with ordinary dependency-checked makepkg, its full upstream harness and
staged runtime checks. The original candidate namespace and retained source
archive remained byte-for-byte unchanged. No newly built archive was installed.

Private results: `work/perl-host-build-20261114-r1/` in the prepared Perl checkout.

| Result | Build 1 | Build 2 |
| --- | ---: | ---: |
| Upstream test files | 2,920 | 2,920 |
| Harness-reported tests | 1,351,560 | 1,351,736 |
| Upstream whole-file skips | 158 | 158 |
| Harness result | PASS | PASS |
| Archive bytes | 26,913,927 | 26,913,919 |
| Archive SHA256 | `6ddb6a4a0bd2daae44702202892634bf342ae5e4cd81fed5ccb9f811a31a4868` | `21c90d8254296f098e1093f5467f0739431941a4bd4a2191f39ed00e67f9053d` |

Both runs pass the recipe's 113 source-provider checks and five required core
C-extension loads. A separate staged interpreter readback loads eight real
objects from its own staged tree. Both archives pass final bounded inspection:
3,262 entries, 29 relative command aliases, two hardlinks and 54 x86_64 ELF
files, with exact root notices, runtime POD and root-owned safe payload metadata.
Twelve driver controls pass under Python 3.12.13 and 3.14.7. Each genuine archive
passes its positive inspection and nine corruption/DATA refusal controls.

**Byte reproducibility is HOLD.** There are no added/removed entries; 3,257
entries match exactly. All 54 ELF files, `.PKGINFO`, `.BUILDINFO` and all 29
aliases match byte-for-byte. The three changed regular payload files are
`usr/bin/core_perl/perlbug`, `CORE/config.h`, and `Config_heavy.pl`. Their only
textual differences are upstream configure times: `23:26:15` versus `23:36:31`
UTC on November 14. `perlthanks` is the corresponding hardlink, and only the
four corresponding `.MTREE` records differ. Comparing copies with just those
time strings replaced proves the remaining text equal; neither actual archive,
source nor recipe is normalized. Upstream Configure reads wall-clock `date`
for `cf_time`; fixed source epoch does not remove this input. No timestamp shim
or candidate change is introduced.

The source actors use the same exact provisioned image with 170 installed
packages, but independent fresh work volumes, fixed paths/hostname, UID/GID1000,
zero capabilities, no-new-privileges, network-none, read-only roots, 2 CPU,
4 GiB memory, zero swap allowance and 256 PIDs. The generated source metadata
contains `cf_by=root`; actual kernel UID/GID and capability observations remain
1000/1000 and zero. This is a same-host pair, not independent-machine or native
ARM reproducibility evidence.

Default upstream skips are retained verbatim with grouped reasons. Compared
with historical r3, the additional whole-file skip is upstream autodie
`t/kill.t`: “Can unexpectedly signal process 1. Won't run as root.” No recipe
test exclusion was added. Both logs also retain **1,547** `libfakeroot.so`
preload warnings during upstream installation and makepkg's `$srcdir` reference
warning. Full makepkg exits are zero, all archive ownership/layout checks pass,
and actual core C extensions load; the warnings are not suppressed or promoted
into target/installed acceptance.

Actual SIGTERM cancellation was exercised twice in separate runs. The first
stopped during compilation and retained a 39,483-byte partial log. The final
controller stopped during source preparation, returned130/`CANCELLED`, retained
its available partial output, accepted no build, and verified its registered
containers/volume/image absent. Cancellation paths are not counted as successful
source builds. Across the pair and both probes, all 11 owned containers, four
work volumes and three derived images are independently observed absent; the
original official Arch image remains.

The successful pair's executed controller source is retained as
`executed-run.py` beside its report. Later controller changes strengthen export
DATA bounds, input-recheck reporting, optional harvest/deletion budget separation
and absence checks. The full build/provision/provenance/staged-smoke scripts,
frozen inputs, actor options and actor validator are identical to the producing
run. Final `check_export` was separately exercised against both genuine exports;
the final controller's exact bytes were exercised by the final cancellation
probe. Exact producing/final source identities remain in `validation.json` and
private reports rather than being conflated.

These results are separate from r3's old1.1 archive, the earlier1.2 packaging
repack, and its TEST-signed ALPM lifecycle. The newly compiled archives have not
inherited installed behavior or ABI acceptance. Native ARM/16K, both M2 sizes,
external XS/actual target ABI, performance, legal/policy, production trust and
release acceptance remain unqualified.
