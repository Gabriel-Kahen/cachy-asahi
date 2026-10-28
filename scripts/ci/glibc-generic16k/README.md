# Private-loader GNU glibc generic16K slice

Source implementation only. No native compiler, runtime client, Docker, QEMU,
namespace, package-manager, kernel build, host installation or system mutation
was executed by this worker. Root owns integration and actual CI. The accepted pair and final Tools cache handoff are bound. The cache helpers are adopted canonically. Root must adopt this proposal, join
the final source/workflow manifest and freeze that real commit before dispatch. No null cache gate remains.

The input is the exact accepted GNU2.43.caa1-3 pair from38915137670, native source
d1055cf95f7d236fc55396db36b432df5191ff2a. Root's immutable checkout is
18569401aa28e2be86f4ada20489913f28739b92: index.json directly at checkout root,
2459 bytes/SHA256a356a22e211712c8e4e45cdde664239e81e763f03339498656f179a534dc222f.
All eleven declared original file references are checked before package parsing.
Both archives remain19400096 bytes/SHA256
04e481dc5b3ac711760ca42749044b0be85283b3aa9c9c631cb6738ac7d699fb.
No original89MB artifact or GNU source archive is downloaded again or duplicated.
The accepted6938 PASS/13 XFAIL/107 UNSUPPORTED GNU checks, eleven exact ABI
comparisons and C-header results are not rerun or relabelled as16K evidence.

Only a private runtime subset of /opt/caa/g243a1 is staged: usr/lib runtime/data
files, gconv/locales and l translation data. Development .a/.o files and private
CLI programs are omitted. Contained symlinks/hardlinks resolve to the exact
accepted regular bytes; no package script is sourced and no host path is
installed. Current immutable input gives343 selected files/54024868 bytes,
including287 loadable AArch64 ELF files. All selected ELF PT_LOAD alignment is
checked; this structural result alone gives no runtime credit.

One owned574 ordinary-user container compiles exactly the unchanged accepted
runtime driver's three programs. Its thirteen original commands, bootstrap
compiler/tools/headers and six source identities remain recorded. The candidate
is mounted read-only at its exact /opt/caa/g243a1 prefix. The capture never calls
the candidate loader or a produced test program. It separately compiles the
unchanged freestanding page probe in that same container, avoiding a host
compiler/client execution route. That probe is separately identified rather
than being counted among the driver's fourteen commands.

The capture includes ordinary bootstrap Python/bash/core tools, Python sources
and imported extensions, and their full interpreter/DT_NEEDED closure. Candidate
runtime DSOs, captured clients and bootstrap ELF must all be AArch64 and16K
aligned. Candidate/clients resolve dependencies only within the private runtime;
bootstrap Python uses the existing574 bootstrap closure. Missing dependencies,
foreign ELF, partial file sets, changed source/role hashes or archive substitution
fail. No new userspace/Rust/glibc build or replacement is introduced.

The marked diskless QEMU guest requires exact aarch64 kernel release and actual
16384-byte pages from uname/getconf, Python sysconf, the unchanged mmap/mprotect/
file-offset probe and the candidate's result. It drops supplementary groups and
UID/GID to23001. Compiled files and the candidate remain root-owned captured
bytes; only the private test workspace is writable to the fixture user.

The guest invokes the exact candidate loader with --inhibit-cache and explicit
private --library-path/GCONV_PATH/LOCPATH. It reuses the unchanged runner's command
supervision and validate_runtime functions, with actual guest inode/device/hash
identities rather than transplanting capture inode numbers. All eight parent
cases, the exec child, two complete identity groups, exact libc/libm symbol
providers, plugin/gconv/locale mappings and normal group retirement are required.
Full candidate and source inventories stay unchanged. The combined receipt joins
thirteen native capture commands and one guest command; it must contain all
fourteen and all twelve original runtime records. A reported version or aligned
ELF alone cannot satisfy PASS. Raw command stderr/stdout tails are retained on
failure so a guest syscall/loader failure is diagnosable without relaxing checks.

The original Tools supervisor/preflight/kernel checker, owned574 producer,
generic cpio/ELF/page probe and derived EVENTFD/PTYS kernel helper are reused.
The derived helper remains SHA256
3c8695685dcae7eded7406ccbf0f8152f6f5820f87ef47f4e791b577c2d3b55a.
No new kernel fragment, flags or limits are selected. The final Tools handoff is consumed directly: acquire_kernel.py8844B/SHA256
4a372e1f4bfbd1f8604579873fc6fbdec91ac2555bb36f028646017b44b8c23f and
retained_kernel.py5419B/SHA256
04a374fe025528a84249b318035d65b182c21d882402409053c0764d572373c6.
The exact Tools dependency JSON is also bound;22 reused files form the consumed
closure. This lane adds no cache implementation or alternate transport.

The workflow restores only the exact content-addressed archive key. cache_state
must establish a true miss before the unchanged retained helper can fetch fixed
asset647949735 with the read-only workflow token. Only a verified seed success
supplies retained_archive to acquire. A genuinely unavailable seed leaves the
existing bounded source-URL fallback available. Corrupt bytes, timeout or unknown
process cleanup fail; they do not become a cache miss or fallback permission.
A complete restore is hash-checked without a seed request. The verified archive
is saved before kernel compilation/cleanup; receipts remain attributable and
carry no signature/key-authority credit.

Held limits remain capture240s/2GiB/no capabilities/read-only/offline,4096 files,
256MiB selected bytes,64MiB/member,270MiB tar,1MiB capture receipt; original
client commands30s/256KiB and runtime60s/256KiB; QEMU900s/1CPU/1GiB/1MiB UART;
public report2MiB. The page probe compile has its existing separate60s bound.
No source/hash/page/deadline waiver or case skip is supported.

The capture name/token/image/CID is checked before exact removal. Producer
retirement is gated on verified consumer absence; uncertainty retains its
backing state. PASS is intermediate until the two consumer actors exit naturally,
all command/process groups are absent, the original producer probe/image are
retired, and the exact completed tools16k-kernel workspace is removed. Failed or
interrupted kernel preparation cannot acquire PASS. The shared archive cache
remains owned by the Tools cache route; it is not mistaken for a live runtime.

The proposed manual workflow accepts exact source_sha/manifest_sha256, validates
source/workflow equality, tracked source identity and pair/cache inputs before
secrets, reuses the same secret/public574 seed, and uploads one bounded
runtime.json for three days. Packages, compiled programs, initramfs, private
workspaces and kernel images are never uploaded by this lane.

Direct inert controls:

```sh
GLIBC16K_SOURCE_ROOT=/absolute/pinned-source \
GLIBC16K_PAIR_ROOT=/absolute/185694-input-checkout \
python3 -B -Werror::ResourceWarning -m unittest discover \
  -s scripts/ci/glibc-generic16k -p test_source.py -v
```

The controls use real accepted archive checksums/passive data plus explicit
synthetic receipt/ownership fixtures. They run no candidate/native actor and
cannot substitute for a real execution receipt. Actual generic16K runtime,
installation, security admission, old held-binary recipe recovery, independent
GNU key authority, M2/16K hardware, performance and release admission remain
separate and receive no credit from these source checks.
