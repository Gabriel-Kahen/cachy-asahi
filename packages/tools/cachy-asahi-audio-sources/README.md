# cachy-asahi-audio-sources 0.1.0

Original MIT, opt-in developer tool for finite offline audio source DATA delivery.
This unselected candidate packages the unchanged export/verify CLI and its ten-file
frozen project runtime from commit `08a99f95e72e3fb57e193525e3d125d377e76e5d`.
It works without a repository checkout and locates its runtime relative to its own
prefix. Python >=3.12 and xz supply the standard-library TOML/gzip/xz functionality;
no pip library or external runtime command is required for these exact inputs.

```sh
cachy-asahi-audio-sources check
cachy-asahi-audio-sources export \
  --handoff /private/original-five-package-handoff \
  --materials /private/original-registry-packet/acquired \
  --wmidi /private/exact-wmidi-source --output /private/new-source-delivery
cachy-asahi-audio-sources verify \
  --packet /relocated/source-delivery --sha256 TRUSTED_DELIVERY_SHA256
```

`check` verifies the installed runtime's exact namespace, modes, lengths and SHA256
pins before source modules load. Every export/verify performs that same check.
Only full, unique option names are accepted. Repository/runtime overrides refuse.
The launcher pins `runtime-map.json`; the map pins every frozen module/data file.
This is an integrity check relative to the trusted package, not package-signature
authentication. Obtain the package and packet hashes through a trusted channel.

The fixed source handoff/native profile/original registry descriptor are pinned by
the unchanged runtime. It verifies all five retained native-bound packages, 117
original registry archives, 108 index snapshots and 4,292 exact raw/vendor files.
It imports only its original private project code, never code from the packet.
Export requires all original inputs, including the private receipt/metadata for
their independently pinned acquisition association checks. Verification needs
only the portable packet. Both operations stay offline, run no source/build/
package/plugin code, and install or enable nothing.

The public packet preserves all original handoff/source/archive bytes. Its two
metadata projections contain only the selected public object references and
registry identity lists. Original private operator receipts/cache paths and full
host environment/tool probes stay outside the export. The recipient cannot
reconstruct the private originals from those projections. The package itself
contains only original project code, public profiles/descriptors, documentation,
license and NOTICE; no generated packet, audio binary, third-party crate/source
archive, cache or private acquisition receipt is included.

The exact published wmidi 3.1.0 manifest selects `wmedrano/wmidi` and VCS commit
`3bd91df0dc6af1d081b2ac6b43730a116bb2e198`. Its eight-file exact tree available
under RustAudio also lacks license text. The original limited later2023 MIT notice
association remains unchanged; no grant or text is fabricated. Compiler/standard-
library/linker/runtime source closure, original flags/features and binary
correspondence, nalgebra text association, relinking, terms/grants/legal completeness,
signatures and current security/revocation acceptance remain held. Native ARM
builds, installation/ALPM lifecycle, audio/speaker safety, physical16K/M2,
performance, publication and release require separate qualification. `arch=(any)`
describes the original Python package, not demonstrated ARM or M2 acceptance.

## Build and check

With existing base-devel, Python, xz and bubblewrap dependencies:

```sh
makepkg --verifysource
makepkg --cleanbuild --force
```

The ordinary dependency checks remain enabled. Do not use dependency bypasses or
install host packages as part of these checks. Recipe checks inspect every source
pin and frozen archive, stage the exact payload, move the prefix, hide the recipe
and source checkout in bubblewrap, disable networking, and test pre-import runtime
tamper/missing/map/extra/symlink and ambiguous-option refusals. Set
`AUDIO_SOURCES_HIDE_CHECKOUT` to the original checkout when building a disposable
recipe copy; by default the recipe root is hidden. No real audio input is required
by ordinary package checks.

The separate actual-archive check requires real private inputs and refuses their
absence. It verifies the actual `.PKGINFO`/`.BUILDINFO`, recipe digest and exact
17-file archive payload, exact parent directories, root ownership and modes before
extracting it as data, moves that extracted prefix,
then performs real export, packet relocation and verification with the checkout
hidden and networking disabled. It also tests packet corruption, runtime tampering
before import and a file-level removal inverse preserving caller data:

The developer archive checker needs Python3.14 for `.pkg.tar.zst`; `.pkg.tar.xz`
uses standard-library support available at the declared runtime minimum. The
installed tool's fixed audio inputs use `.xz`, not `.zst`.

```sh
python3 -I -B -Werror::ResourceWarning test_archive.py \
  --recipe-root /complete/recipe --archive /built/package.pkg.tar.zst \
  --packet /private/real-source-packet --sha256 TRUSTED_DELIVERY_SHA256 \
  --materials /private/original-registry-packet/acquired \
  --wmidi /private/exact-wmidi-source --hide-checkout /original/checkout
```

Payload: one mode0755 launcher; ten unchanged mode0644 project runtime files;
mode0644 runtime map, README, provenance, payload map, MIT license and NOTICE.
`source-provenance.json` records exact source revision, licenses, sizes, modes,
digests and deterministic source-archive construction. `payload-map.json` describes
every installed file except its own self-reference; the checker adds that file's
actual digest. There are no hooks, services, configuration, backup entries, trust
changes or platform replacements. Removal owns only these declared files; caller
packets, original inputs and reports remain caller-owned. Staging/archive tests
and the file-level removal inverse are not ALPM installation/removal evidence.
