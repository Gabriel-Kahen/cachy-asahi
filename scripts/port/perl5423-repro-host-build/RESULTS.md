# Actual Perl 1.3 sequential host pair

**PASS_HOST_PAIR_BYTE_IDENTICAL.** Two actual clean source builds produced the
same untouched, unsigned `perl-5.42.3-1.3-x86_64.pkg.tar.zst`:

- Bytes: **26,913,892** each.
- SHA-256: `d0bbbc273dc9f60becc936536a0f2f6544cecc1d72379c76ddcea0e6375e2829`.
- Direct whole-file `cmp`: exit 0.
- All **3,262** decoded entry records match; no additions, removals or changes.
  This includes metadata files, contents, modes, owners, mtimes and link targets.
- Each archive has 2,870 regular files, two hardlinks, 29 command aliases and
  54 x86-64 ELF files. Root ownership and expected layout checks passed.

## Exact source and execution

The executed driver was commit
`ba220c029a799f3fd311860ad59429951eed4643`; no controller or actor code changed
while the pair ran. Candidate commit
`c8e9baea97f83f652763e701143d6dec5b679f31` remained unchanged. PKGBUILD SHA-256:
`cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068`.

The pinned upstream source is Perl commit
`bc3dab4d4f66de5ea67dda34e5feb5230a54c603`, 22,610,875 bytes, SHA-256
`16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725`.
The source epoch is 1785628800. Both full Configure runs, generated config.over,
staged Config and archived Config_heavy.pl/CORE/config.h use
`Sun Aug  2 00:00:00 UTC 2026`. No clock shim, post-build normalization or
archive rewriting occurred.

Both actors used ordinary dependency-checked
`makepkg --cleanbuild --nosign --noconfirm --log` and the unchanged default full
upstream test target. The official base digest, frozen signed dependency inputs,
all recipe/helper pins and actual operation arguments are retained. The derived
image was `sha256:97c6ee79122b1a25863e009546ae52f73ba82ef8d416ece9c77cd0b09a2268a0`.

| Actual result | Build 1 | Build 2 |
| --- | ---: | ---: |
| Upstream harness | PASS | PASS |
| Test files | 2,920 | 2,920 |
| Reported tests | 1,351,634 | 1,351,734 |
| Whole-file skip lines in default harness | 157 | 157 |
| Harness wall-clock seconds | 410 | 409 |
| Checked core providers | 113 | 113 |
| Required C extensions | 5 | 5 |
| Actually loaded staged XS objects | 8 | 8 |

Reported test counts differ; no test filters or recipe changes were introduced.
These elapsed times are build diagnostics, not performance measurements.
UID/GID 1000, x86-64/4K pages and actual cgroups were recorded for both actors:
2 CPUs, 4 GiB RAM, zero swap, 256 PIDs. Both had a read-only root, offline build
network, dropped capabilities and the exact private inputs/work mounts.

## Capacity, ordering and cleanup

Root's owner-confirmed cleanup made the fixed budget fit. All nine fresh
admissions passed. With output under `/tmp`, home retained the full 5 GiB peak
budget; tmpfs retained its separate source/export/scratch allowance and 1 GiB
reserve. No resource waiver was used. Btrfs kept actual zero inode counters as
UNREPORTED_DYNAMIC and passed identity-bound measured metadata admission.
Minimum measured metadata headroom after subtracting the global reserve was
2,925,494,272 bytes against the 1,073,741,824-byte requirement. Minimum
MemAvailable at a gate was 17,318,649,856 bytes against 8,589,934,592 required.

Build 1 was exported, inspected and pinned before its actor, initializer and
work volume were removed and absence verified. Only then was volume 2 created.
Both retirements completed before comparison. Cleanup removed all five owned
containers, both volumes and the derived image and verified absence. The cached
official base and Root's protected images remain. Original inputs were rechecked.
No host package installation, service/trust/boot/kernel changes or native jobs
were performed by this workstream.

## Retained warnings and limits

Both logs contain 1,547 libfakeroot.so preload warnings during DESTDIR packaging.
Archive ownership/layout and actual staged runtime checks pass; that does not
establish the warning's cause or complete fakeroot coverage. Retain the early
Pod::Simple/manpage warning (final POD manpages exist), six Configure probe
FORTIFY/optimization warnings, obsolete egrep warning, source-directory references
in 53 packaged ELF files and two unexpectedly successful TODO tests per run.
The 157 default upstream skips are included in the results above.

This proves one sequential pair on one x86-64/4K host using one provisioned image.
The archives are unsigned. Installed 1.3 command/lifecycle behavior, external XS
and target ABI, native ARM/16K, both M2 Air sizes, performance, legal-policy,
production trust and release acceptance remain unqualified. Earlier 1.2
lifecycle evidence does not qualify these new archives.

## Evidence

Original output: `/tmp/perl-repro-host-build-20261114-r1/`.
Retained copy: `work/perl-repro-host-pair-20261114-r1/`.

`report.json`, both complete makepkg/phase logs, source/build/payload maps,
actual environment/actor records, acquired tool/dependency pins and both archives
are retained. `first-run-pins.json` records the initial source/controller pins.
`pair-verification.json` records direct comparisons and actual results.
`retention-capacity.json` records the separate capacity check before the durable
copy; `retention-file-identities.json` verifies all 198 copied files. The small
comparison receipt added afterwards is separately pinned in validation.json.
An independent read-only review reconstructed every decoded entry and confirmed
the archived timestamp, complete pair comparison, retirement and cleanup.
