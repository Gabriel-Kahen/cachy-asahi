# cachy-asahi-fdk-aac

Development candidate for two source-built AAC libraries, upstream 3.0.0 commit
`a68a51aa45d86a43c7b228e3d45624af09dcdd8d`. Native compilation, installation,
consumer ABI, hardware, performance and publication remain NOT RUN. Independent
project packaging/build system dated 2026-10-12; codec source bytes are unchanged.
No Fraunhofer endorsement, patent clearance or legal approval is asserted.

The selected source packet contains exactly 898 implementation/header files
with their recorded explicit Fraunhofer grants plus original classic and xHE
NOTICES. Its SHA256 is
`1c4ade00f624c1e6f9e988cd17868a5e3faa78fea2522e9c302a89866d04cdd7`.
It omits all upstream scaffolding, Rust wrappers, scripts, examples, fuzzers and
docs. The earlier broad private packet remains private and is not cleared for
redistribution. The clean selection is complete source for the two selected
library implementations; it is not an archive of all upstream software.

`build-layout.json` pins all 898 source/header bytes and factual inventories:
170 classic and 225 xHE translation units, seven installed headers, 81 public
exports and preserved include order. Independent source review resolved all
Linux aarch64 project includes inside that selection. C-runtime headers come
from the builder; Windows/MIPS/Android SDK branches are inactive by default.
No needed default Linux aarch64 source with an unestablished grant was found.
Actual native compilation must still prove build completeness.

Original full codec notices, all nine observed source-header grant variants
(including original Latin-1 PPC bytes), and project MIT licensing accompany the
recipe/binaries. Source files retain their original complete copyright notices.
The independent build/stage/check/test/reconstruction logic is original MIT work;
it executes none of the five ungranted upstream scaffolds or other upstream
scripts. This does not relicense either codec. Preserve the full notices and
make complete corresponding source plus modifications available free of charge
with each binary release; charge no codec copyright license fee. Modified codec
source in a later version requires the grants' dated modified-version notices.

See `PUBLICATION.md` for concrete source selection, recipient reconstruction and
native build interfaces. The complete source bundle carries the clean codec
archive, all project build/packaging/tests/checks, both complete grants and a
hash-bound input map. It reconstructs a recipe without the private full archive
and invokes no compiler or installer. Actual public hosting/delivery is pending;
a local source packet or provenance JSON alone is not recipient source delivery.

The template intentionally omits the selected archive. `materialize.py` binds an
independently reviewed full template map and approved SHA256, verifies the exact
900-file archive/manifest, and creates a new external source-only recipe.
`publication.py` packs that complete reviewed recipe and reconstructs it using
trusted packet/map digests. Both refuse unsafe/special inputs, changed maps and
existing/repository-contained outputs. Neither extracts into arbitrary paths,
uses network, invokes a compiler or changes host system configuration.

Native build dependencies are GCC/Python/binutils from the existing 341-package
base. Build logic records inherited C/C++/link flags, adds PIC and the original
implementation's exception/RTTI restrictions, and links two shared libraries
with explicit SONAMEs/export scripts. It authors pkg-config files and preserves
full compiler/linker commands in the container's `/out`. It applies no codec
patch, x86 flag or platform/default change. `arch=aarch64` is a declaration.

Container checks run source/planner/publication tests against immutable `/inputs`,
check actual ELF64 AArch64, SONAMEs, exports, glibc dependencies and 16 KiB load
geometry, then classic AAC-LC encode/decode of original deterministic PCM plus
xHE version/configuration lifecycle. The historical comparison to the private
producer packet may be skipped for recipients; clean source reconstruction and
native library checks remain required. xHE encoding, conformance/quality tests,
PipeWire ABI behavior and physical 16 KiB/M2 runtime are not established by this
software suite or by ELF geometry.

Payload: two shared libraries and local SONAME/linker symlinks, seven public
headers, two pkg-config files, both full notices/header bundle, MIT grant and
README/provenance. No static archive, .la, examples, hooks, scriptlets, services,
platform configuration or automatic replaces. Proposed provides are
`libfdk-aac=3.0.0`, `libfdk-aac.so=2-64`, `libfdk-xhe-aac.so=0-64`; actual metadata
and exports must pass native checks. Conflicts with upstream `libfdk-aac` require
an explicit reviewed provider transaction; one substitution proposes retaining
574 packages. Removal must preserve dependency consistency and requires an
approved replacement for the PipeWire AAC plugin. Fresh resolution, signed
lifecycle/recovery, source delivery and both Air hardware checks remain open.
