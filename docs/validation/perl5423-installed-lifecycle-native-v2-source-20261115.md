# Installed Perl capability serialization successor, 2026-11-15

The new `scripts/ci/perl5423-installed-lifecycle-native/successor_v2` fixes one
Source predicate before the first installed lifecycle attempt. The published
232-file Source `71246ca38e58f9f410d1f3eea15f5ddf174bb1bf` remains unused and frozen,
as do its core, capsule, prerequisite review and sealed once proposal.

Root's XS v4 run 43723410450/job132840063834 retained a real Docker inspect record
whose `CapAdd` was `['CAP_CHOWN']` after `--cap-add=CHOWN`. The 8,584-byte raw record
has SHA256 `39eb911a102ce8969f32bece90c13d8c98cf49b20b752f35fdbf4991fbc63cab`.
This is single-capability evidence. The seven-capability lifecycle fixtures are
explicit modeled DATA, not an installed result.

The revised producer accepts one optional literal `CAP_` prefix for each of exactly
CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, SETFCAP and SYS_CHROOT. Both raw and
semantic names must be unique. Every other inspect check and raw record remains
unchanged, including root/image/name/labels, CapDrop ALL, false Privileged, NNP,
cgroups, mounts and namespaces. Actor bytes remain identical: direct checks cover
CapEff/CapPrm `0x800400cb`, Inh/Amb zero and NNP1. CapBnd was not a direct assertion;
this successor neither adds it nor claims it was proved.

Actual retained-parent DATA rendering and complete inverse checks passed on
Python 3.12.13 and 3.14.7, with identical facts:

| Proposed field | Exact value |
| --- | --- |
| Files / bytes | 241 / 81,151,225 |
| Source map | 47,304 bytes / `34d0b92316fd3c3aac69fb947b3b31ef14474d0128d10f7a0b1684495cc14175` |
| Git tree | `2267627b5dd03ac09e71ce8819e76bce160faf65` |
| Producer | 14,879 bytes / `4c6db02555123c1878da8610fdf807e4f82ad6b8a3cf20257dc11aec73a01c24` |
| Capsule | 40,366,080 bytes / `a0527ea4cd1b84944c92ec1fe3849218a1c826100d3437c5276bbf0fa913b494` |

No Source export was written. The constructor changes both producer bodies and
associated pins; eleven old core files, eighteen capsule members and all original200
remain byte-identical. The contract names adapter revision v2 and treats core7bf0 as
historical, rather than claiming twelve unchanged core files. The full232 inverse
reconstructs the old capsule exactly using archived small metadata/producer instead
of retaining another 40 MiB capsule. Three tampered inverse cases refuse.

Ten fenced predicate controls pass on both Python versions, covering raw/semantic
duplicates, malformed/unknown names and all other inspect/mount refusal gates. The
real-parent checks also prove exact original200 inverse, package/trust and issued
input review `31aeecaa5ef5bdae8c001940587641cd2a32acb7ed5c5c93ed0609e8eb0acc1e`,
resource/domain/actor preservation and all ten null actual selectors. The reviewed
38→37→38 packaged-hook effect and four old interface removals/normal rollback stay
unchanged; no new hook or restoration result is asserted.

Root must construct/publish a fresh Source/ref, update once/Reader bindings for the
241-file map/tree, revised producer/capsule and full232 inverse, and issue separate
fresh bootstrap/image/RW-domain/trust/resource/runtime admission. Outer and inner
operation names remain v1. No actors, lease, network, ALPM, GPG, compiler, actual
Reader or publication ran. Native installation, 16K, M2 and release remain open.
