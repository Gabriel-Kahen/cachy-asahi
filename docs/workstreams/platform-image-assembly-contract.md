# Private image assembly contract — 2026-10-13

The private proposal at `artifacts/reviews/platform-image-assembly-contract-proposal-20261013/` defines an exact-package, new-empty-staging approach. Its executable validates a plan; it does not assemble or authorize an image. The actual result is `PLAN_VALID_BLOCKED_MISSING_INPUTS`: 261 canonical package tuples, 259 retained archive metadata associations and 20 missing input identifiers. All nine acceptance flags remain false. No image, compressed archive, Tool/debugfs, package, GPG, native, installer or system actor ran in this task.

The roadmap's M8/R5 fresh installation and recovery gates remain open. `manifests/packages.toml` is development planning. This contract uses the retained Minimal inventory SHA256 `5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941`; neither the historical 211 acquisition count nor the separate 624-package proposed release defines this baseline. The retained JSON references do not prove current archive availability, payload authenticity, accepted key ownership, licensing or installation.

## Recovered assembler provenance

The official community [builder source](https://github.com/asahi-alarm/asahi-alarm-builder/tree/58cc158c7fda3ef6aeae36606f84a63b4b0867e7) is pinned to `58cc158c7fda3ef6aeae36606f84a63b4b0867e7`. The upstream packet retains all 32 ordinary source blobs and verifies their Git blob SHA1 and SHA256. In [build.sh](https://github.com/asahi-alarm/asahi-alarm-builder/blob/58cc158c7fda3ef6aeae36606f84a63b4b0867e7/build.sh#L159), base scripts run before the Minimal ZIP is produced; desktop scripts run afterward. Desktop account, skeleton, Bluetooth and Calamares changes cannot be attributed to that Minimal build stage.

The [October 5 successful workflow run](https://github.com/asahi-alarm/asahi-alarm-builder/actions/runs/37313500098) reports this commit and a build interval encompassing the retained ZIP's LastModified timestamp. This is temporal consistency only. The [upload workflow](https://github.com/asahi-alarm/asahi-alarm-builder/blob/58cc158c7fda3ef6aeae36606f84a63b4b0867e7/.github/workflows/manual.yml#L34) renames a mutable website ZIP without publishing a source-bound output checksum. The bounded release/artifact/attestation queries and site inspection recovered no immutable binding to ZIP `42df228b8bb7a3fc980a94d1eca01bc44a4e29efaf002bf77ffac2fbc08bbbd7` or root image `76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db`. These queries do not prove universal absence of an attestation. Historical image cause, intended configuration and reproduction remain unaccepted.

That builder also uses a rolling generic ARM rootfs, rolling repositories/keyrings, floating workflow inputs, runtime package hooks and non-normalized filesystem/ZIP state. Its privileged mount/chroot script was captured as data and never executed. A new project image must be generated from closed inputs; copying the opaque retained image is not a reproducible assembly strategy.

## Payload and configuration boundaries

The proposed sequence first compares pristine archive-owned payload in new empty staging, then applies individually source-bound configuration recipes with exact preconditions and outputs. Every changed path needs type, mode, ownership, content or link-target expectations, inputs and preservation behavior. Unexpected prior hashes must stop the operation. Existing user files are preserved; this plan authorizes no overwrite on an existing installation and adds no mismatch exemptions to the strict comparator.

| Path | Pristine package expectation | Proposed configured output or missing input | Preservation and attribution |
| --- | --- | --- | --- |
| `etc/fstab` | Regular, 126 bytes, 0644, UID/GID 0; SHA256 `e54626e74ed8fee4173b62a545ab1c3a3a069e4217a0ee8fc398d9933e9c1696` | Exact 220-byte `config/fstab.ext4.txt`, SHA256 `7e64abac2c07f61a3c4f420c381e5b1ed719dd72654dfb98ed5598eaab208675`; ext4 root and FAT EFI UUIDs from pinned source | Fresh staging only, after pristine check. Proposed output preserves pristine 0644/UID/GID 0. Upstream heredoc inherits inode metadata and does not prove those output attributes. Historical-image attribution is false. |
| `etc/resolv.conf` | Regular, 65 bytes, 0644, UID/GID 0; SHA256 `5557d8e601b17a80d1ea7de78a9869be69637cb6a02fbfe334e22fdf64e61d4c` | Source/revision, exact expected link target and service semantics remain null | No link followed; no cause accepted. Platform maintainer owns closure before admission. |
| Pacman configuration/mirror list, account database, mkinitcpio configuration, ARM64 GRUB output, first-boot drop-in and service state | Exact selected packages plus inherited/generated state require closure | `upstream/minimal-transforms.json` gives source lines, paths and known text; package/runtime-dependent output bytes remain missing | Each needs a finite recipe and prior-state checks. No wildcard generated-state exclusion. |

The pinned [20-fstab.sh lines 9–13](https://github.com/asahi-alarm/asahi-alarm-builder/blob/58cc158c7fda3ef6aeae36606f84a63b4b0867e7/scripts/base/20-fstab.sh#L9) explicitly emits the independently rendered 220-byte text, including its final newline and EFI field spacing. Its SHA256 is `3d0f0b6ffaee802b0cf41efe57ca96c9e85387e72773b2566eadc12693a1131f`. A source render matching an observed length does not establish the retained image's bytes or explain its mismatch.

The retained fstab diagnostic (`inputs/diagnostic-completion.json`, SHA256 `c9898056a7e649c609feee792ce2ccb05ee82557ba8a215a96ea88d8dc700e88`) observed 220 versus expected 126 bytes with matching 0644/UID/GID 0. Its before-CAT counters were 12 image calls, two prior CATs, two selected nodes and four frames. Cause remains unknown; final source hash/disposal were not attested by that failure.

The subsequent resolver diagnostic (`inputs/resolver-diagnostic.json`, SHA256 `a1fbd368449fa117d7721c695a5c476a79a355d80acf53a3b0a3e5fd15983951`) observed a symlink at inode 39, nlink 1, 32 bytes, 0777, UID/GID 0, against the regular-file expectation above. Its target was **not read** and cannot be inferred from length. Before-CAT counters were 51 image calls, 13 prior CATs, 16 selected nodes and three frames. The base builder source contains no explicit resolver replacement; package hooks and inherited/runtime behavior remain unresolved.

The original strict failure and subsequent observer CLI-1 structural failure (`inputs/observer-failure.json`, SHA256 `2e16a40ef8434e0a5d2f7039e4ab6fde8d872e31ce464bc7668c8b8cba3c7ab8`) remain preserved. There is no completed all-48 observation. This contract neither retries that observer nor relaxes its structural, single-link or regular-file guards.

## Asahi installation contract

The route packet pins [Asahi installer OSInstaller source](https://github.com/AsahiLinux/asahi-installer/blob/dffbb38ef0c00c0431c609ecd8a00f42deb5b24c/src/osinstall.py) to `dffbb38ef0c00c0431c609ecd8a00f42deb5b24c`. Its source raw-copies the root image, separately populates the internal ESP and creates the Apple stub stage-1 handoff. It does not mount/rewrite Linux fstab during that raw copy. Full served community-installer module/runtime correspondence remains missing; capturing upstream modules is not proof of that delivery closure.

Preserve `linux-asahi`, m1n1, matching device trees and Asahi U-Boot with the ARM64 EFI loader. Preserve Apple's macOS/RecoveryOS prerequisites and per-install boot policy. The stub's stage 1 identifies the new ESP GPT UUID and chainloads `m1n1/boot.bin`; it is distinct from the ESP's FAT UUID `2ABF-9F91` (installer volume ID `0x2abf9f91`) and ext4 root UUID `725346d2-f127-47bc-b464-9dd46155e8d6`. GPT identity, target model and firmware reference remain null. Mac14,2 and Mac14,15 require separate machine records. No PC NVRAM, fixed partition number or hardware-detection assumption is permitted.

The retained template's Root minimum is 2,209,614,225 bytes, while captured image metadata records 3,680,501,760 bytes. Expansion may provide capacity; no installation was run and this is not evidence of a runtime failure. Future **actual** image and selected partition sizes must be supplied, 4096-byte aligned, partition capacity at least image size, and image no greater than the proposal's 4 GiB cap. Neither historical length nor the template minimum fills those currently null fields. Stage-2/EFI bytes, target Apple firmware/stub inputs and stage-1 output must have explicit source/output bindings before execution.

## Finite missing inputs

The two unavailable exact tuples are `networkmanager 1.58.1-1 aarch64` and `perl 5.42.2-2 aarch64`; the package maintainer must recover these exact inputs with source/signature evidence. Twelve owned requirements are explicitly missing:

| Requirement | Owner | Required closure |
| --- | --- | --- |
| Build environment | build-maintainer | Pinned native aarch64 bootstrap, libalpm runtime and tool/library digests |
| Dependency/install order | package-maintainer | Closed exact-261 transaction and package database bootstrap |
| Hooks/sysusers | package-maintainer | Bounded scriptlet, hook and generated-path effects with deterministic outputs |
| Signature facts | signing-custodian | 26 unresolved signer joins, accepted key-owner and freshness policy |
| Source/license closure | package-maintainer | Exact sources, notices and distribution permissions for all selected inputs |
| Remaining config transforms | platform-maintainer | Exact pacman, mkinitcpio, service, GRUB, account and first-boot recipes |
| Resolver link/service | platform-maintainer | Pinned transform source, expected link target and service semantics |
| Filesystem determinism | build-maintainer | Tool versions, size algorithm, timestamps/seeds/allocation and two clean output comparisons |
| ESP/platform artifacts | platform-maintainer | Source-bound m1n1 stage 2, matching DTBs, Asahi U-Boot and ARM64 EFI bytes |
| Installer source closure | installer-maintainer | Complete chosen installer source/runtime/data and delivery authenticity |
| Target firmware/stage 1 | physical-operator | Target Apple firmware, macOS owner/RecoveryOS, stub and signed handoff records |
| Release output bindings | release-maintainer | Final package/config/image manifests, publication authenticity and recovery artifacts |

The 20 result identifiers comprise those twelve requirements, two package gaps, two layout sizes, three target references and resolver source/target/service details. These are finite evidence obligations; a supplied reference is still subject to independent review and does not become accepted merely because it fits the schema.

## Executable and verification

Run from the repository root using the pinned private manifest:

```sh
python -I -B -S -Werror::ResourceWarning artifacts/reviews/platform-image-assembly-contract-proposal-20261013/validate_plan.py \
  --manifest artifacts/reviews/platform-image-assembly-contract-proposal-20261013/assembly-plan.json \
  --manifest-sha256 9bc1011c9e7c0bd1e54c967e74a04aa7d7e48d2746f59e017e2f2b5f459b0cb6
```

Validator SHA256 is `c2ba2c6bd183ce4f300aec16757707017d273a7119b45072b1d2667d07ae0776`; independently pinned package-reference index SHA256 is `874b7406955baf36c455f8b0a9eeaddbfc0636506e757d3e98ff5ca6b97569a2`. CLI reads only its bounded manifest, canonical inventory, independent metadata index and fstab template. It checks closed tuples, metadata associations, recipe/preservation, UUID/capacity and false acceptance invariants. Other evidence references are declarations, not fresh content authentication. The preparation helper copies plain source/JSON evidence; it is not an assembler.

Independent review found that the first validator could count altered archive references as retained metadata under a newly selected manifest hash. The preserved `baseline/attempt01/` and `independent-peer/red-2eca/` show that failure; assembly authorization still stayed false. The corrected CLI loads the separately constant-pinned index and checks exact tuple-to-reference equality before counting. This proves association with retained JSON, not current archive hashes or trusted packages.

The corrected author run passed 12 methods; independent controls passed nine methods/nine summary rows, including 46 explicit refusal variants and a separate source/index audit. Both runs had exit 0 and zero skips. They cover exact tuples and metadata references, missing-input closure, schema/scalar/cap refusals, boot UUID/capacity, pristine/config preservation, fstab source bytes, resolver unknowns, false authority and bounded owned JSON. The author's first corrected-candidate run had one fixture error and one fixture failure: it patched an unimported `sys` module and classified regex compilation as code execution. Those outputs and the initial capture rejection remain preserved; only fixtures changed before the passing rerun. These are source/model controls, with no image, archive, assembler or hardware execution.

The pure API can classify a fully populated synthetic plan as `PLAN_VALID_FOR_REVIEW_NOT_AUTHORIZED`. It has no builder, subprocess, network, grant or target interface; no schema result grants execution or accepts physical, installation, recovery, reproducibility, performance, issuer, key-owner or licensing evidence. The final receipt seals the actual source/data artifacts and check results, with every earlier failed stage preserved.
