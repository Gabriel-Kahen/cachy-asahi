# FDK 3.0.0 source and notice audit

The authenticated upstream binary is missing a required notice for a library it
ships. `libfdk-aac 3.0.0-1` contains both `libfdk-aac.so.2` and
`libfdk-xhe-aac.so.0`, but installs only the classic FDK NOTICE. Upstream's
separate [xHE NOTICE](https://github.com/mstorsjo/fdk-aac/blob/a68a51aa45d86a43c7b228e3d45624af09dcdd8d/xhe-aac/NOTICE)
requires its complete grant in binary documentation/materials and free complete
source copies. The source's [classic NOTICE](https://github.com/mstorsjo/fdk-aac/blob/a68a51aa45d86a43c7b228e3d45624af09dcdd8d/NOTICE)
exactly matches the notice in the signed package. Both complete grants and
copyrights are preserved here; package authentication remains unchanged.

The concrete proposed fix is a **source-built**
`packages/libraries/cachy-asahi-fdk-aac` recipe. Its
[source inputs and packaging plan](source-built-package-proposal.json) pin
upstream tag object `a53bfb8e62714f74612e4b85e679dbeb6b971606`, commit
`a68a51aa45d86a43c7b228e3d45624af09dcdd8d`, complete source hashes,
configure/build commands and all required notice destinations. It keeps codec
source unmodified, builds the classic and xHE shared libraries, disables static
libraries/examples, and retains both complete grants plus all nine observed
Fraunhofer license/copyright header variants. The prepared source-code distribution also
retains the upstream Rust NOTICE, Apache-licensed example headers with the full
Apache 2.0 grant, BSD-style SHA1 notices and Windows public-domain/MIT notices.
Rust/example/Windows code is not built by this Linux Autotools recipe.

The exact upstream Git archive BLAKE2 checksum matches the checksum in Arch's
[immutable 3.0.0 recipe](https://gitlab.archlinux.org/archlinux/packaging/packages/libfdk-aac/-/blob/b0c45e29a1bac452ece793799738e066d0c3f2cb/PKGBUILD).
That recipe declares no codec patches. Its own SHA256 differs from the signed
ARM `.BUILDINFO` recipe hash; the current immutable ALARM override tree has no
FDK entry. Therefore **exact retained-binary recipe/source equivalence is not
claimed**. A reviewed native rebuild from the pinned sources removes that
specific provenance uncertainty and allows packaging both grants correctly.
The upstream source archives are retained privately, not published by this audit.
Two bundled PDF manuals explicitly require publisher permission for reproduction;
an unrelated Rust test-vector blob has no established redistribution grant.
The prepared 3,861,432-byte codec source packet excludes exactly those three
non-source assets, preserves all 1,190 remaining upstream file bytes unchanged,
and adds the full Apache 2.0 grant. Its SHA256 is
`1244e51941011bb63433b022f8bc247a28cf374749a2c3fb30f73fae42c88c49`.
No codec or selected Autotools build source is removed or modified. The proposed
native recipe should build from that same recipient source packet; native
build verification is still required. The precise input/exclusion manifest is
[`prepared-source-manifest.json`](prepared-source-manifest.json).

The [exact 574-package reverse graph](reverse-dependencies.json) has one direct
consumer, `pipewire-audio`; its reverse closure is `pipewire-audio`,
`pipewire-jack`, `pipewire-pulse`, `portaudio`, `libopenmpt`, `ffmpeg`, `firefox`
and `waybar`. These are package dependency relationships, not automatically
linked copyright works. Static `readelf` on exact signed archive objects finds
the direct FDK dependency at the PipeWire BlueZ AAC codec plugin. Its
[immutable source](https://github.com/PipeWire/pipewire/blob/8fa27cabdc6c0c1350c69c026af5850ef0af1e26/spa/plugins/bluez5/a2dp-codec-aac.c)
declares MIT. The examined FFmpeg, libopenmpt, PortAudio and PipeWire JACK/Pulse
ELF objects have no direct FDK `DT_NEEDED`. No direct GPL/FDK linked incompatibility
was identified at this MIT plugin. Do not infer that installing a GPL client
beside the audio service changes either license. Adding FDK to a GPL-enabled
FFmpeg build would need its own compatibility review; FFmpeg's
[official compliance guidance](https://ffmpeg.org/legal.html) distinguishes
GPL/nonfree build choices and corresponding source requirements.

The proposed FDK package provides `libfdk-aac=3.0.0`,
`libfdk-aac.so=2-64` and `libfdk-xhe-aac.so=0-64`, conflicts with the upstream
`libfdk-aac`, and has no automatic replaces action. Expected runtime dependency
is glibc; build inputs are the baseline GCC/make/autoconf/automake/libtool/pkgconf
stack. One explicit upstream-to-project provider substitution keeps the proposed
574 package count; every actual provider, file ownership and dependency must be
checked after native builds and in a fresh transaction. It changes no 341 builder
or Apple platform package. No recipe was implemented in the package tree here.

A notice/source sidecar could supply missing grants as accompanying binary
materials and offer complete sources free of charge. It would add one package
(575); the unresolved retained-binary recipe identity makes the native rebuild
preferable. If FDK cannot be selected, a separately rebuilt PipeWire audio provider
with [`-Dbluez5-codec-aac=disabled`](https://github.com/PipeWire/pipewire/blob/8fa27cabdc6c0c1350c69c026af5850ef0af1e26/meson_options.txt)
can remove the AAC module/FDK dependencies. Its source still builds SBC A2DP and
HFP/mSBC codecs. That alternative explicitly defers Bluetooth AAC, preserves the
required core audio/Pulse/JACK workflows, and requires fresh resolution and
actual target tests; it would not simply remove PipeWire audio. Neither choice
establishes Asahi DSP/protection behavior.

The grants' copyright conditions can be met by this prepared package/source
plan: retain the complete notices and copyrights, supply complete source and
all modifications free of charge to binary recipients, charge no codec
copyright license fee, make no Fraunhofer endorsement claim, and add prominent
change/date/required modified-version wording if codec source is changed.
Neither grant conveys patent rights; appropriate patent authorization for the
intended use is a distinct requirement. **No legal approval, patent clearance,
publication, build, installation, performance or hardware acceptance is claimed.**
This is a concrete reviewable correction, not an indefinite unspecified license
blocker. Assign implementation/source-distribution ownership, then build and
validate the new provider before any candidate lock changes.

## Pending commit source-reference publication check

The [publication check](publication-check.json) establishes the copied Arch
recipe's **packaging-code grant separately from the codec license**. Immutable
Arch `LICENSE` grants use/copy/modification/distribution, and `REUSE.toml`
explicitly assigns PKGBUILD to **0BSD**. Both originals and their copyright/grant
records are retained here as `Arch-packaging-LICENSE` and
`Arch-packaging-REUSE.toml`; both exact recipe copies may remain in the audit.

Immutable PipeWire `LICENSE` explicitly assigns all source files to MIT except
two named libraries. Our AAC source and Meson reference files are not those
exceptions. The MIT grant, copyright and policy are retained in
`pipewire-COPYING` and `pipewire-LICENSE`. SHA1 source/header and Windows helper
copies retain their own inline BSD-style/public-domain/MIT grants.

No explicit file or repository-wide grant for the remaining standalone FDK
references was established. `Makefile.am`, `configure.ac`, `ChangeLog`,
`source-rust-build.rs` and `source-rust-Cargo.toml` were removed from this public
reference set, with originals privately retained. Their hashes, immutable
provenance and observations remain in the report/manifests. The codec's grant
and Cargo's license metadata are not treated as proof that every copied
standalone build/config/reference file has a publication grant.

The private prepared source packet is unchanged and **not published**. Before
publishing it as corresponding source, establish those standalone-source grants
or supply independently licensed replacement build glue/reference material;
a native rebuild alone does not establish a missing source grant. The existing
codec grant/copyright evidence and missing-xHE-notice finding are unchanged.

The coordinator's unpublished `d3ce7e1` already contained the withheld source
bodies. A new deletion-only commit would still expose them through history;
the coordinator must replace/amend that unpublished audit commit before pushing
this corrected reference set. This owner performed no Git operations. No
blanket legal approval or binary-authentication change is claimed.
