# Corrected minimal206 native-source DATA CI

This separate lane runs all 14 unchanged controls from corrected author
`1f0a2a18600b5aea4c837974f91e3ba2451f18a9`, plus two fixture controls. Its
934-byte source lock is pinned by SHA256
`3a0adc63aa1ae9cbe17d4e0c2f45394f688b569484d27bdba688240220020096`.
The old `6651ad8` suite, its 160-command operational entry and its workflow are
never registered here.

The only new transported source fixture is the complete original Source95:
95 ordinary 0644 single-link files, 1,318,237 bytes, exact Git tree
`b73f92b1ed4e6f6ab8c4210fdaa19617b1a5721f`, and source map
20,200 bytes / SHA256 `ab743415f602ba8c5f81a063fc7cc5d25587be0d535601396f2ee617fb4149ce`.
`Source95.DATA.json` records its provenance. The parentless public CID
`c23c2874c82a3e83b76be09fe98ee6e134c8ff81` is attributed to the committed source
author's provenance; this lane performs no Git fetch or publication. Every
fixture body, mode, namespace and the independently calculated Git tree are
checked before importing author code. All actual selectors remain NULL.

The fixture has no `.git`, links, package/rootfs payloads or large cache. Its
only archive-named leaf is the original public 39,211-byte llhttp recipe source.
There is no 540 MB or 1.47 GB acquisition. The unchanged committed e947 source
family and the two author's committed retrieval/PKGINFO DATA proofs supply the
other inputs; those historical proofs confer no signature authentication.

The additional 197,700-byte public Source96 projection fixture (SHA256
`313c0a4b205b84c8fe8b8c1ddf7d98750c6e3da86d31b7bc915be55c18814862`)
contains only its 30 original compressed source preimages. The new author
validates and replays those exact bytes through `original_call()`, so host zlib
versions cannot change the frozen historical marker. Combined fixture bodies
total 1,515,937 bytes; no whole second Source96 is transported.

Inside the no-actor fence, that authored replay calls its exact original
constructor to regenerate Source96 as closed DATA in a temporary directory. Its suite, command runner
and operational entry are not invoked. That intermediate is supplied explicitly
to the corrected author's unchanged controls. The corrected source must retain
the full predecessor and Source95 inverse while changing the finite command and
matching receipt bounds. Two additional fixture controls cover complete public
source closure, the exact corrected 96-file/1,629,237-byte tree
`8a8f0baa349399a5546883acd67f43d4fe0f15f1`, and missing/extra/body/mode/alias
refusals. The corrected 512-command limit and 1582-leaf receipt catalog retain
the 16 MiB export bound. The original 96-file predecessor and full Source95
byte/mode/membership inverses remain mandatory.

The driver pins both constructor families and all e947 input leaves before
imports. It refuses every process, socket, ctypes, custody-lock or signal attempt,
including attempts caught by an author test. It requires the complete fixed
authored count, two fixture controls, zero skips/expected failures/unexpected
successes and zero actor attempts. Python runs isolated with no bytecode writes;
limits are 1 GiB AS, 180 CPU seconds, 16 MiB files and 128 FDs. These are DATA CI
bounds, not native builder fit or resource grants.

The workflow uses pinned setup actions, read-only contents and Python 3.12/3.14.
It contains no acquisition, package install, GPG, native workflow, Root adoption
or native selection step. Source/metadata PASS establishes no build success,
official trust, current baseline, old349 admission, native16K or M2 acceptance.

```sh
python -I -B -Werror::ResourceWarning scripts/ci/llhttp-minimal-native-source-data/ci.py
```
