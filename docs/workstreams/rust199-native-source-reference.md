# Prospective native Rust 1.99 Source reference

This is Source DATA and a future build path, not a native result. It owns only
`scripts/ci/rust199-source-reference-native/` and this document. Shared manifests,
the existing bubblewrap candidate, LLVM pipeline, and Original evidence remain
unchanged. No Source publication, dispatch, acquisition, stage0 execution,
compiler execution, container, installation, M2/16K test, performance result or
release admission is established here.

The constructor freezes the nine-file Rust candidate at
`dd6871d566661c4fe9eba055ae19e1e017e0b69d`, including its private LLVM23 dependency,
bootstrap configuration and rpath. It retains the complete original200 bootstrap
Source byte/mode map from the LLVM Source DATA checkpoint. Three literal phase
hook substitutions produce a separate native recipe; their inverse restores the
original PKGBUILD bytes. Dependencies and checksums are preserved. The old
bubblewrap preflight is not called or presented as a container qualification.

The input pins cover Rust source 1.99.0, LLVM source 23.1.1 and all three stage0
1.98.0 archives. The retained stage0 acquisition/audit/notices records are copied
unchanged as DATA, with no archive payload embedded. Their 108,298,076 archive
bytes and metadata model do not qualify native runtime use. They were recorded
against an older candidate: only the same three archive pins join this candidate.
Cargo's recorded metadata version 0.99.0 does not satisfy the candidate's runtime
probe for Cargo 1.98.0. The exact candidate probe remains unchanged; a genuine
runtime mismatch must fail, not be hidden by this adapter.

A future attempt needs external Root acceptance of the exact private LLVM23
package from published Source
`4ceaa1c6958349451197b19acdb084a2a5be216b`, actual Original/run/job/artifact pins,
its detached signature and public TEST key fingerprint, and a pinned verification
proof. Publication alone supplies none of these. A normal isolated image must
actually contain the ALPM-installed private package and retain the exact signed
349-package baseline. Its final inventory is recorded independently (at least
350 packages), not called 349. The LLVM self-build image's private-prefix symlink
is refused. Root must qualify the immutable image/full rootfs/private LLVM trees,
source audit, stage0 assembly and native compatibility, and both read-only
volume-subpath aliases before an actor may start.

`root-admission.TEMPLATE.json` leaves those actual gates NULL and refuses. Its
`source.approval` is an independent external Root approval pin; the CLI's
`--admission-sha256` pins the whole canonical admission JSON separately, avoiding
a self-hash cycle. Host gating checks all actual proof bodies and file hashes
before Actions metadata access or Docker. The actor repeats Source/contract,
original admission and external proof joins through the read-only input paths.

Only `LOCAL_READONLY` input files are implemented. HTTPS URLs are bounded pinned
declarations, with no downloader. External Actions artifact transport, material
preparation, exact current run/job admission delivery and image provisioning are
explicitly NULL prerequisites. The generated workflow cannot bootstrap those
prerequisites on a fresh hosted runner. It fails before acquisition or actors
until Root provides a reviewed finite transport/preparation seam. Large LLVM
Original/package or Rust/LLVM source archives must not be placed in Git or treated
as an unsigned opaque input. No artifact identifiers are invented.

After those gates, one CHOWN-only initialization container creates an owned work
volume. A cap0 nonroot preparation actor extracts the five verified archives and
assembles stage0 without running it. The second cap0 actor uses that volume with
`build/stage0` independently mounted read-only at both `/stage0` and
`/work/build/stage0`; unsupported daemon subpaths refuse without a fallback.
Actual create inspection and kernel mount/cgroup checks enforce this separation.
The candidate's nine probe calls execute under owned supervision. Its logical
Python sandbox probe is an explicitly recorded in-process phase, with no invented
PID or child receipt. The stage2 bootstrap remains `x.py ... install -j 2`.
Normal makepkg checks the installed dependencies and executes the derived build
and package hooks; no dependency bypass is used. Only the private Rust prefix is
staged. Packaging removes only the candidate's own installer ledgers and retains
Rust, compiler-rt, libunwind and packaging notices.

The proposal limits each workload actor to two CPUs, 8 GiB memory, zero swap,
512 PIDs, no network, a read-only image, no capabilities and no new privileges.
Preparation is capped at 900 seconds, the main actor at 16,200 seconds, the native
route at 19,800 seconds, cleanup at 300 seconds, package at 2 GiB and exported DATA
at 4 GiB. The workflow uses the distinct operation and its own alias on the shared
`native-arm-build` queue, with cancellation disabled and a 360-minute job cap.
Fresh host checks require 12 GiB available memory, 80 GiB available on each actual
storage device and one million free inodes; active reserves are 4 GiB memory and
8 GiB disk. This fits the previously observed 15 GiB/111 GiB host on paper only;
no completion time or successful fit has been measured. Actual observations are
mandatory for every attempt.

Owned command receipts require natural direct-child/group retirement. Export is
bounded and retained before resource removal. Forced actor cleanup fails the
attempt even if final absence is established. Only exact labeled resources from
this attempt are removed; the externally qualified image belongs to Root.
Successful build/export/retirement would still await an independent reader.
All original binary/recipe correspondence, license108/source-notice completeness,
Asahi/M2/16K, performance, production trust and release holds remain open.

The constructor profile and validation JSON record the exact DATA checkpoint and
controls. Run the constructor only with its externally reviewed profile SHA and a
fresh disjoint output. It imports no candidate/intake code and performs no network,
container, package, compiler or system mutation.

Checkpoint: 50 fenced DATA controls pass on Python 3.12.13 and 3.14.6. Both
constructors produced identical 277-file, 40,990,238-byte prospective Source DATA.
The whole Source map gate and original200 inverse pass. Prospective tree:
`dd2a89e0ca31ca19819b8d70019013fe283446ef`; map SHA-256:
`0ddf2db2abec15b5298ecce7f6b085f447152e3fb904f915e56738a3a8e53b1b`;
constructor profile SHA-256:
`aa83d68e268f9f3dae0980d4a67cea8c53a1c3b11adc24c204445edd9663aed0`.
See [validation](../../scripts/ci/rust199-source-reference-native/validation.json)
and [profile](../../scripts/ci/rust199-source-reference-native/constructor-profile.json).
These are development DATA identities; actual Rust Source/ref/run/job/artifact,
Root approval, accepted LLVM material and qualified image remain NULL.
