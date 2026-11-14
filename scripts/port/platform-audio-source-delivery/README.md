# Portable audio source delivery

This finite DATA adapter combines the unchanged five-package
[native-bound source handoff](../platform-audio-sources/README.md) with all 117
official `.crate` archives and 108 captured index snapshots from the
[registry join](../platform-audio-registry-sources/README.md). It reuses the pinned
intake, vendor-auditor and registry-join APIs. It adds export/recipient verification
and two explicit metadata projections; it does not create another build or fetch
framework, modify recipes, select packages or admit a release.

Every original handoff file, native package archive, source bundle, vendor archive,
notice archive, raw crate and index snapshot is copied byte for byte. Original
source archives remain inert archive bytes; no source tree is extracted to disk.
The original private acquisition packet is neither edited nor copied wholesale.

## Export

Supply the exact already acquired materials described in the registry README:

```sh
python3 -I -B scripts/port/platform-audio-source-delivery/delivery.py export \
  --handoff /private/verified-five-package-handoff \
  --materials /private/registry-packet/acquired \
  --wmidi /private/exact-wmidi-upstream \
  --output /private/new-source-delivery
```

The new output must have an existing parent and must be outside every input root.
Existing outputs refuse without modification. Outputs have mode0700 directories
and mode0600 files. A failed partial output may remain for inspection and is not
accepted, even if an index exists. Require exit0 and recipient verification.

The handoff index is fixed at
`70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c`,
the native profile at
`e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8`,
and the original registry descriptor at
`fc8d9e9bb5c2696dce29bdddfc58e39d8cb568a5434dac47eb8ace3afc9adc94`.
The join implementation is pinned at
`5eb6279bf5ad495d53e46771471aba0d345c7839f4354e0d2366a145ec0812eb`;
it independently pins the auditor/intake/source APIs. The adapter's own
`delivery-profile.json` pins the precise public metadata projection and two exact
wmidi materials. Use a trusted checkout including this adapter and profile.

Before export, the original registry receipt and full metadata report must match
their independent original pins and pass the original join. Public derivations:

| Original | Exported derivation |
| --- | --- |
| Private acquisition receipt | Only selected public object IDs, official URLs, HTTP200 observations, material pins, cache identities and byte total; rebuilt from the public descriptor after original associations verify |
| Full host metadata replay | Three lists of registry identities, with source-handoff/profile binding and an explicit new-host default-feature scope |
| Registry descriptor | Original descriptor preserved; separate derived descriptor changes only the two projected metadata references |
| Original full join | Recipient-recomputed join over the unchanged sources/indexes and public projections; original checker and original source/legal holds remain visible |

The public metadata projections contain no operator cache paths, credentials,
private operator receipt fields, environment variables or tool probes. Original receipt and metadata hashes
are retained as derivation references. A recipient cannot reconstruct those
private originals from the projections or independently replay the original
acquisition. The projection pin comes from the trusted checkout; it is not a
registry signature or an authenticated compiler attestation.

## wmidi 3.1.0: precise retained hold

Its actual published `Cargo.toml.orig` declares MIT and
`https://github.com/wmedrano/wmidi`; `.cargo_vcs_info.json` selects commit
`3bd91df0dc6af1d081b2ac6b43730a116bb2e198`. Exact lookups under the old repository
returned404 on November14,2026. The same commit is available under RustAudio:

| Required local file | Actual source | Bytes / SHA256 |
| --- | --- | --- |
| `source.tar.gz` | [Exact upstream tree archive](https://codeload.github.com/RustAudio/wmidi/tar.gz/3bd91df0dc6af1d081b2ac6b43730a116bb2e198) | 11153 / `87d9ef729f179445d2454c9fb3a48b02a6aeab146515372b6fa336a17b674c5d` |
| `commit.json` | [Exact commit API response](https://api.github.com/repos/RustAudio/wmidi/git/commits/3bd91df0dc6af1d081b2ac6b43730a116bb2e198) | 1102 / `e1689cf7bb26c453562997701c5f51300dfc0e1a8439e605dac99dc1b3de6241` |

Acquisition is separate from this offline adapter. Responses may change; do not
silently replace a pinned response. No request occurs during export or verify.
The original received source archive and commit response remain privately retained
and are copied unchanged into the review packet. GitHub marks this commit unsigned.

Verification reconstructs tree `350c51ae2311147baccb4c2ebda62320e24518d8` from
the eight regular upstream files. Every upstream file exactly matches the crate
after explicitly selecting published `Cargo.toml.orig` as the original manifest
and accounting for Cargo's generated normalized manifest/VCS file. Neither the
published crate nor that exact upstream tree contains a license-text candidate.
The result remains `HOLD_NO_LICENSE_TEXT_IN_PUBLISHED_CRATE_OR_EXACT_VCS_TREE`.
The existing later2023 MIT notice association stays unchanged and limited; no
license text or retrospective grant is fabricated. Supplying exact upstream
identity narrows the unresolved material question; it does not resolve it.

## Relocation and offline verification

Copy the complete packet preserving its private file/directory modes. Obtain
`delivery_sha256` through the coordinator's trusted channel, then run from a
trusted checkout, including from an unrelated working directory:

```sh
python3 -I -B /trusted/cachy-asahi/scripts/port/platform-audio-source-delivery/delivery.py \
  --trusted-checkout /trusted/cachy-asahi verify \
  --packet /relocated/source-delivery --sha256 TRUSTED_DELIVERY_SHA256
```

The recipient needs only the packet and the trusted API files/profile; original
package source directories and private acquisition caches are unnecessary. No
code is loaded from the packet. Verification recomputes the original five-package
handoff, vendor/lock audit, all117 official checksum/index joins and4292 member
comparisons, public projections, exact wmidi source association and both saved
reports. It enforces the full namespace, hashes, private modes, single-link regular
files, no symlinks/special files,512 nodes,32MiB/file and128MiB aggregate bounds.
It rejects extra/empty directories, changed/missing material, invented receipt
fields and acceptance promotion even when a caller supplies a new outer hash.
A hash shipped only beside an untrusted packet is not authentication.

## Actual local result and limits

On November 14, 2026, the actual packet contains276 regular files/41737653 bytes,
including the original42-file handoff. All117 crate archives and108 index snapshots
match the original bytes. All117 registry/vendor joins and4292 member comparisons
pass; the labeled new host-metadata subset has88 registry identities.

Fourteen actual-input controls pass, including export and relocated in-process
verification with socket/subprocess creation fenced; reads of the original
handoff, acquisition material and package sources also refuse during relocation.
A separate CLI replay runs from `/` using a minimal trusted runtime containing no
package source/cache directories. Missing/tampered inputs, forged reports/holds,
public receipt smuggling, changed projections, extra files, symlinks, modes and
output/input overlap all refuse. Tests require real inputs and fail if absent.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/port/platform-audio-source-delivery/test_delivery.py \
  --handoff /private/verified-five-package-handoff \
  --materials /private/registry-packet/acquired \
  --wmidi /private/exact-wmidi-upstream
```

This is source DATA delivery with holds. Original compiler/standard-library/linker/
runtime source closure, original build flags/features and binary correspondence,
relinking, wmidi/nalgebra text associations, grants/legal completeness, current
security/revocation and signature authentication remain held. Native compilation,
installation, service/audio/plugin execution, speaker safety, physical16K/M2,
performance, publication and release admission were not performed here. The
original protected-platform guard errors are preserved. The Asahi stack is unchanged.
Generated packets remain private for coordinator review; this work publishes none.
