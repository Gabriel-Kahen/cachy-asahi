# Maintained Debian glibc source preparation — unselected caa3

This separate source-only lane prepares Debian glibc2.43-7 orig plus all84
ordered default quilt patches, then the existing project held-builder
expectation patch0002. It does not modify caa2, build glibc, install a provider,
claim security currency, or admit an ARM/M2 release. The proposed identity is
`cachy-asahi-glibc-gnu-provider2.43.caa3-1`; Root must explicitly select it.

`materialize.py --inspection-only --chain-inputs INPUTS --patch-tar PATCH_TAR
--output FRESH_OUTPUT` verifies the current signed Debian archive chain using
the unchanged byte-pinned sibling auth helper. It verifies exact Sources/DSC
orig and patch-tar hashes, validates every patch target, and applies actual
GNU patch commands with fuzz0, original bounds, exact recorded output and all40
Debian offset cases. Complete node/type/mode/hash manifests and source Git-style
trees are checked. No configure, make, compiler, Debian rules or glibc program
runs. Inspection grants no candidate authority. Inputs are caller-supplied local
files; this code neither fetches them nor bypasses freshness/key expiry.

The locked tree sequence is:

- orig:`1fbcd978e2051d72273231f03b921b1503e0e424`
- Debian84:`aa963b6ef1d55056efbab622411d2530a636422d`
- plus project0002:`08ea2aef96bd3144cf02cbc68cbbb003dc25ed9f`

Old project0001 is deliberately superseded. Authenticated git-updates already
contains upstream guarded OPEN_TREE_CLONE/CLOEXEC and the bits/cloexec refactor.
The source-policy check pins their complete bytes. Applying or forcing the old
hunk is prohibited. Project0002 remains a real required fuzz0 application;
its elf/Makefile hunk has the recorded offset−1. It changes the five formerly
XFAIL tests to ordinary required tests; their failure remains fatal.

Debian orig omits112 original manual files. Its authenticated
all/local-remove-manual.diff supplies only its own LGPL manual/Makefile; no
GNU manual files are restored. The source policy enforces that distinction.
The recipe uses MAKEINFO=: during configure and every build/check/check-abi/
install make command. Debian disables tst-errno-manual, removes the
list-diagnostics manual cross-check and changes a Hurd manual-linked dependency.
Full original-GNU test-body equivalence is not claimed. Present-source check,
check-abi, collection and exit failures remain fatal. No additional test skip,
ABI waiver, compiler/resource/deadline relaxation or performance claim is added.

`bundle.py --inputs INPUTS --patch-tar PATCH_TAR --output FRESH_BUNDLE` refuses
the shipped UNBOUND authority before helper imports, crypto or output creation.
A future explicit Root-bound caa3 decision must bind the exact candidate, two
archive key pairs and independent evidence. The old caa2 policy/decision cannot
satisfy this interface. `authority.py` documents the finite expected fields;
Root supplies the independently decided authority file and hash-referenced
ordinary decision file, rather than this code manufacturing them.

Once bound, the emitter replays fresh source authentication/preparation, then
copies a closed flat input set and generates exact PKGBUILD source checksums
and bundle.json. It includes the unchanged pinned auth, source-inspector and
provider-stage helpers, source lock, project patch, public chain objects and
new authority decision. No private checkout path is embedded. The recipe
uses ordinary `$startdir` inputs: makepkg's legitimate `$srcdir` source symlinks
never weaken the materializer's ordinary-path guards. All automatic extraction
is disabled; only the bounded source inspector/extractor handles archives.
The recipe retains native-aarch64/explicit-build guards, layout/configure
choices, fatal upstream/ABI checks and staging helper. Debian copyright plus
GNU/project license notices are installed with the provider.

The emitted recipe expects the existing disposable native harness's
`/work/evidence` and `/runner/collect_tests.py`; it is not a new native owner.
Root still needs a distinct source-pinned caa3 harness adapter/metadata and
expected generated SRCINFO, new native pair/normal probes and subsequent
lifecycle/runtime validation. No bundle or native acceptance exists while
this policy is UNBOUND. Prior caa1/caa2 evidence cannot satisfy these gates.

Portable source controls:

    python3 -I -B scripts/ci/glibc-debian-maintained-provider/test_materialize.py
    python3 -I -B scripts/ci/glibc-debian-maintained-provider/test_candidate.py

`dependency-pins.json` records the three unchanged repository helper inputs.
Explicit --auth-helper/--inspector-helper/--stage operands support detached
source preparation but accept only those exact existing helper bytes. Bundle
copies use the same pinned helpers locally. `source-provenance.json`, NOTICE,
LICENSE and authenticated Debian copyright/patch headers preserve origins and
licenses without asserting a blanket new license for upstream patches.
