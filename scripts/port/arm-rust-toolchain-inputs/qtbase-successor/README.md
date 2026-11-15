# Optional Qt-base 6.12.0-3 toolchain-input candidate

This is the explicitly authorized successor to the separate, still-held frozen
Qt-base **6.12.0-2** input set. It does not substitute an archive into that set,
change the parent catalog, or establish equivalence with the missing `-2` payload.

The exact signed `qt6-base-6.12.0-3-aarch64.pkg.tar.xz` is 15,177,820 bytes,
SHA256 `2777135b375ba82250896fa9a993926bf3c05b59dd22217f63d6a1391c1b4c31`.
Its 566-byte signature SHA256 is
`8db1bcda35923c7e719b2b82162521e59edc4aeb0ec45a270e94f0327a2673f5`.
Signature mathematics passes under the unchanged ALARM primary
`68B3537F39A313B3E574D06777193F152BDBE6A6`; freshness remains unestablished.

All original 271 and four subsequent Qt package descriptors remain exact. The
candidate adds 58 genuinely new packages, including Qt-base `-3`, to those 275
available protected inputs. Existing providers are used before selecting any
new provider; replacements of protected packages are refused. The original
271 descriptor/1,154-join guard and original 84 guard are reused unchanged.
`parent-binding.json` checks every tracked parent file before loading its parser
from the exact checked bytes. No parent file or bytecode cache is written.

## Commands

The executable command uses fixed, reviewable `candidate.lock.json` versions,
sizes and SHA256 pins. It does not consult moving repository metadata. New
dependencies were selected from the already-frozen repository entries; exact
archive/signature descriptors precede copy/download and are recorded in
`input-provenance.json`. Metadata, every payload file, namespace collision and
whole-payload ELF dependency are checked using the parent parser read-only.

```sh
mkdir -m 700 /tmp/owned-qt3
python3 -I -B scripts/port/arm-rust-toolchain-inputs/qtbase-successor/candidate.py acquire \
  --cache /private/exact-retained-cache --destination /tmp/owned-qt3/cache \
  --output /tmp/owned-qt3/acquisition
python3 -I -B scripts/port/arm-rust-toolchain-inputs/qtbase-successor/candidate.py verify \
  --cache /private/preserved-271/cache --cache /private/preserved-four-Qt/cache \
  --cache /tmp/owned-qt3/cache --output /tmp/owned-qt3/prepared --prepare
python3 -I -B scripts/port/arm-rust-toolchain-inputs/qtbase-successor/candidate.py verify \
  --cache /tmp/owned-qt3/prepared/cache --output /tmp/owned-qt3/recheck
python3 -I -B -Werror::ResourceWarning \
  scripts/port/arm-rust-toolchain-inputs/qtbase-successor/test_candidate.py
```

Output/cache paths must be under `/tmp`; output must be new. The command refuses
more than 100 new packages, more than 512 MiB of new archive cache or complete
bundle, changed/corrupt inputs, unsafe namespace nodes, and unresolved package,
ELF-provider or GNU version-name contracts. Each download is exact-name,
byte/hash/time bounded; redirects and version fallback are refused. A 429 blocks
further requests to that host during that invocation. Fresh space/RAM is checked.
No archive payload tree is extracted; preparation copies only archives/signatures.

The acquisition operation authenticates the selected supplemental archives.
The verification operation is required for the complete set and optional bundle.
GNU version-name checks additionally join each `DT_VERNEED` request to the actual
provider's `DT_VERDEF` names. They are not full symbol/interposition/loader or
native runtime qualification. No accepted Bankstown native tools profile is
produced, and the purpose/schema remain distinct from its required profile.

## Actual result, 2026-11-14

The first bounded attempt stopped before acquiring package 51 (`json-glib`),
retaining seven declared, nine ELF and three GNU-version failures. Root explicitly
raised the limit to 100. Resolving against the protected 275 inputs first then
closed the actual package and whole-payload graph at **58 new packages**.

- All 333 archive/signature pairs authenticate under the pinned primary.
- All 1,466 package-expression joins, 10,411 direct ELF joins and 14,899 GNU
  version-name joins pass; no missing inputs or unresolved records remain in
  these checks. All 223 previously unresolved Qt edges resolve in this candidate.
- Ten focused controls pass. Six independent read-only host `readelf` comparisons
  exactly match the version parser for Qt Core, glibc, libstdc++, tinysparql,
  JSON-GLib and libstemmer. Data is supplied through non-executable memory files.
- Complete preparation retains 666 mode-0600 files: 427,915,904 archive bytes plus
  188,477 signature bytes, totaling **428,104,381 bytes**. The directory is private.
- Rechecking from only that prepared cache produces a byte-identical 27,829,517-byte
  catalog, SHA256 `aa612232f6bf711b9d1137ec8e10c8aaca99d026f26fce2b1954f64c9973b673`.
- The new input archive cache is 50,566,388 bytes. Its aggregate with the prepared
  archive bundle is 478,482,292 bytes, below 512 MiB. No acquisition exceeds the
  58-package selection. Parent hashes and its original `-2` hold remain unchanged.

The data contains 2,510 AArch64 ELF records and nine separately pinned BPF objects,
81,851 archive members and 2,204,652,786 expanded file bytes. These are structural
observations; no package/ELF/BPF output is executed or installed. No Docker,
native/Source/Reader role, service/trust/boot/device mutation, push or merge occurs.

## Source and acceptance limits

`source-facts.json` pins the recovered ALARM `-3` recipe revision
`b32d838db0daea604a2f8080b9e17cc24d4c8b6f` and upstream Qt commit
`025bdad181de241e81bf853c8a2d7bf3d19261a9`. All 38 archived Qt license notice
files exactly match that upstream revision. The recovered raw recipe hash
`1adc61918ba3ac15746e4895872c5a0017d68fc349924bec9bc403ed15b445dd`
differs from `.BUILDINFO`'s
`0bd04f4db92ed8b0992e851a4ddd68f39ac7b6b079af4e354dba466946ca2272`.
Exact recipe/source correspondence remains unresolved. The recovered recipe
also documents the `-3` mouse-wheel tab-scrolling patch; frozen `-2` metadata
cannot establish payload equivalence.

Other supplemental inputs retain signed package metadata, BUILDINFO and notice
hashes; their complete corresponding sources are not accepted by this work.
Compiler/Cargo/LLVM/runtime corresponding source, source/legal/relinking
acceptance, key freshness and revocation/current policy remain held. Native
building, full ABI/runtime/profile admission, 16K/M2 hardware, performance and
release acceptance remain unrun. Root owns all further integration/publication
and native-role decisions. A closed input catalog is not a qualified release.
