# NEW Debian-orig GNU2.43 provider candidate

This private variant keeps pkgname `cachy-asahi-glibc-gnu-provider` and selects
version `2.43.caa2-1`. It is distinct from the GNU full-release tarball/tree and
all existing `2.43.caa1` native-pair, installed and private16K evidence.

Source is Debian's `glibc_2.43.orig.tar.xz`,21553420 bytes,
SHA256 `b8f0d50a7d4255658efe1f608cacdc4be82bb3c009875626df5968cc64c58880`,
payload tree `1fbcd978e2051d72273231f03b921b1503e0e424`. Debian sid signed Release
and Sources metadata reference2.43-7, but this candidate uses **orig only**:
no Debian packaging/patch series, Debian binary correspondence or maintained
security currency is claimed. Source version remains2.43. Security/release credit
is NONE. The existing GNU signature's expired-key failure remains unchanged.

All20628 common payload paths match the original GNU release. Debian omits112
regular files under `manual/`, including its Makefile and examples. Their exact
list is in `manual-omissions.json`. Nothing is copied back from unauthenticated
GNU manual files. Patch3 removes only `manual` from Makeconfig's subdirectories;
`make info` is omitted. Present-source upstream `check` and `check-abi` commands,
fatal returns, compiler flags, ABI/header/layout checks, licenses, C.utf8 and
runtime/normal probes stay as in the pinned provider harness. Missing manual
build/tests are explicitly NOT_RUN, not waived or claimed passed.

Original project patches1/2 and docs-only patch3 applied with fuzz0 and no offsets
to the real retained Debian source. Resulting tree:
`51979d25e61ba516e9fa73e147c75d021b4838e1`.
This establishes source preparation only, not compilation or runtime success.

The offline Debian Release→Sources→orig verifier checks both complete pinned key
fingerprint pairs, actual current key/signature expiry, strict statuses, signed
Date/Valid-Until, exact index/object hashes and the complete source tree. Its
independent key-bootstrap policy is bound by `root-debian-archive-authority.json`:
preexisting Arch pacman trust verifies a signed Debian keyring package containing
both exact archive certificates. Root replayed the complete chain independently.
This establishes source authority only; current metadata checks remain required
before every build bundle/native actor. Official HTTPS fingerprints alone did
not establish the trust anchor.

`adapter.py` emits a finite private harness from byte-pinned current provider
helpers. The original executor/build-entry/ABI/header/compiler/runtime/normal
probe/ownership/cleanup bodies are reused. Only package metadata version and the
explicit new source interface differ. The wrapper never calls the oldcaa1
admission or copies its acceptance bindings. Private16K, all new native builds,
installation/lifecycle, M2/hardware, security and release remain NOT_RUN or
NOT_ADMITTED until independently completed for this candidate.
