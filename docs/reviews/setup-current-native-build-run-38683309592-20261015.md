# Current setup native build run38683309592: retained actual review

The exact terminal run **38683309592**, attempt1, Source `465bf53545e1d83053bf3c412e210493961b74ae`, workflow **381664314** (`.github/workflows/native-arm-build.yml`), branch `codex/setup-current-native-build-v1`, and native job **116253082542** completed successfully. **The finite native-build evidence review passes:** all eight expected originals, inspections and provenance are present, and all four archive pairs are byte-identical. Root admission remains a separate step.

The selected and runtime-reported mode is `build`, with input lock `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f` and recipe lock `a5fb287b4dda2a90bf61d4fa8cbbc5d666dad8bb450a70544d00545b091f36e3`; integration is unselected. The immutable actual-Source admission is `d6773beb3c342a5f610b58ad0a61226b5a33082891197ccabd76c4d42721f110`. Recipe and actor snapshots are read as data; none is imported or executed by this review.

## Retention and transport

The collector ran exactly once. Completion `7509901f4bbf54d7b82b9046577496e20af598a7cf559b67319bcfd124324adc` authenticates13 indexed leaves,14 physical leaves including completion, with no retention issues and zero API artifacts. The original logs ZIP is2928073 bytes, SHA256 `a3f984999b36caf6c746b218dbaeccd3a7e7340bc616db81cdf8bf2ba9113185`. Preparation's pending/zero-job/collector-not-executed fields remain an unchanged historical snapshot; `execution-record.json` records the later terminal retention.

Independent bounded ZIP/header/CRC/closure checks authenticate10 members. Aggregate and step logs each contain the same two exports. The probe frame is1771 bytes, SHA256 `36034972c1ad52e2dc0bbf43111b480dcee1989b137ef704873c4ee44f9415c4`; the build evidence frame is1276963 bytes, SHA256 `1995534f7546929d2a7780deb24f13c973c1d0cb84bdd7d050853fcfa5129d69`. Their expanded tar sizes are10240 and9574400 bytes; regular payload totals4353 and9100207 bytes. They contain264 regular evidence members, including76 strict JSON files. The canonical decoded manifest is208431 bytes/0600, SHA256 `4204e4ed3878881150475dcf2f19b2e9d079a9a1542b8bce24414aea9e220a2c`, indexing277 files.

The first parent decoder skipped a Base64 record because a UTF8 BOM preceded its timestamp and stopped at the compressed frame hash assertion. That script, failure record and partial output remain under `history/decode-attempt-1`. A narrow adapter now permits one optional BOM immediately before an otherwise valid timestamp. Base64 data is unchanged; both log copies must satisfy the original published size and SHA256. The independent custody reader separately encountered and preserved the same transport detail. No collector retry or additional API acquisition was used.

## Actual package outputs

All four declared recipes exported two original archives, build logs, validation/inspection records, recipe snapshots and provenance. Eight distinct recorded container names and successful exit codes bind native `aarch64` builds to image `sha256:204eadc4d28a92fd727b4338aef7722546b677e8e66be636acd0c53d723b13c3`, epoch1791748800, non-root1001:1001 and network none. Commands also record read-only roots, dropped capabilities and no-new-privileges. These are retained command/provenance observations; independent machine execution and full Docker IDs are not attested.

| Package | Version | Bytes per archive | SHA256 shared by both attempts |
| --- | --- | ---: | --- |
| cachy-asahi-fish-config | 0.1.0-1 | 5396 | `38e766158d13a0e13b8f811766119d10c018ccc256f5d99c3561b74c99d12705` |
| cachy-asahi-hyprland-settings | 0.1.0-2 | 12740 | `0b22b778ec83d8b98d98d06fa4f016bd4e3f581b69efa83d6526c5265c2adf5e` |
| cachy-asahi-setup | 0.1.0-3 | 14496 | `85ab7b964cd628ef21f5df6133aa9d046d32ea35cd6af3de0e5b888341550f0c` |
| cachy-asahi-zsh-config | 0.1.0-1 | 6244 | `be2ef8ed4f0263720ed6290bff9992d5df53c7bf689a40478f2be329ba2d50e7` |

The parent directly compares each original archive pair byte for byte and checks every provenance file hash and validation error list. The package peer independently inspects the bounded xz/tar originals, package metadata, MTREE and installed payloads, joining them to immutable Source recipes:144 recipe-snapshot file joins,54 MTREE regular-file digest checks and19 exact installed payloads across the four packages. All archive headers carry epoch1791748800 and owner0:0; no links, hooks or ELF payloads are present. Four retained strict comparison reports have empty error lists and report byte, installed-content, PKGINFO and BUILDINFO equality. The source snapshot's older host evidence is historical recipe input, not an additional current native run.

## Inputs, signatures and bootstrap

The actual acquisition export contains501 unique PASS rows and no failed or pending rows, joined to the selected input lock and501 cache checksum records. Its `signature_authentication: NOT RUN` describes the acquisition stage. The separate `signatures.json` contains249 detached-signature GPG records (rootfs plus248 packages), each returning0 and reporting the pinned primary fingerprint `68B3537F39A313B3E574D06777193F152BDBE6A6` through a single accepted VALIDSIG without forbidden status. This review authenticates and checks those retained records; it does not rerun GPG or independently reverify the supplier bodies. The GPG diagnostic's undefined user-ID trust does not attest target trust configuration.

The rootfs inventory contains165 rows matching the frozen input lock;248 selected package audit records join to the same lock. The merged builder inventory is341 packages, SHA256 `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`, and matches bootstrap and all eight build inventories. Bootstrap records a network-disabled native ARM64 image build, masked ALPM hooks, disabled package scriptlets and explicit in-container ldconfig. These exported observations establish the reviewed bootstrap/build environment within this CI run. Raw image-inspect output and the generated Dockerfile body are not exported; their identities/policies are reported through the retained bootstrap/provenance records and logs.

## Scope

The observed runner is an ARM Neoverse-N2 Azure host, Ubuntu ARM64, kernel6.17.0-1022-azure and4096-byte pages, with Docker client/server Linux arm64. It is not Apple hardware. No setup installation/removal/upgrade/recovery, target dependency/trust transaction, M2/Asahi/16K/boot/hardware, performance, M1 or full-port acceptance follows from these package builds. General final host/image/daemon absence is not established by `--rm` or a successful job; cleanup must stay within explicit exported observations. Retained-cache finish is a handoff rather than disposal.

The review executes no GPG, package/module/script payload, native compiler, Docker/provider or Source actor. It performs no dispatch/retry/cancellation, Git/ref/API/secret/variable mutation, integration execution or unrelated kernel/KSM collection. Local review scripts only parse, compare and hash evidence. The final receipt/index and child receipts authenticate the exact file graph; standalone seal readback is the review-completion check.

The independent custody review passed55350 assertions, the package review passed2870 actual-data assertions plus109 Source-preparation assertions, and the input/bootstrap audit passed3001 checks. Their sealed receipts are incorporated into the parent graph; review completion does not authorize a broader hardware or lifecycle claim.
