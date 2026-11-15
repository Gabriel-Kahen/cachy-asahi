# LLVM23 private-prefix ARM16K runtime case

**Implementation of executable input gates and guest journey; no VM result.**
This separate case consumes a future Root-accepted native LLVM256 package. It
changes no existing VM/Reader/native family, package manifest or workflow. The
published native Source is365a763bc515a1b3550cc804536ddbf66353aac8, ref
`refs/heads/codex/llvm23-source-reference-native-v2-20261115-r2`. Package identity
is `cachy-asahi-llvm23-source-reference`23.1.1-1/aarch64; installed software is
confined to `/opt/cachy-asahi/llvm23-source-reference` plus ancestor directories.

`adapter.py` is an offline case-packet preparer, not a VM launcher. It checks an
external exact closed `source.lock.json` digest, Root-selected case bytes, every
retained material/certificate hash, actual readonly baseline raw/prepared/ownership
and original first-PAM report bytes, Reader4's actual package/Source/run/job tuple,
a separate explicit Root acceptance, public-only currently valid TEST signature
admission, and the complete baseline/candidate runtime/dependency certificate.
Missing/NULL evidence refuses before output creation. Certificates cannot be
created by filling labels from this code: Root must supply genuine observations
and independently accept their exact bytes.

`case.TEMPLATE.json` deliberately leaves all future package/signature/public
certificate/signing-receipt pins, native Run/Job/artifact, Reader/Root decisions,
guest certificate, trust and resources unissued. The native Source identity and
recipe name/version/prefix/five declared dependencies are known; they do not
establish an installed runtime closure. Source111 and155 lack a GCC compiler;
155's gcc-libs metapackage is not a development toolchain. Root must qualify the
exact **fixed probe command vectors**, Clang driver startfile/development search,
CRT/loader/linker paths, all ALPM owner versions, actual interpreter/DT_NEEDED and
GNU-version providers, and the complete package-owned namespace and ELF inventory.
Safe contained tool aliases and zero-byte files are supported. No runtime package
or tool is silently added to make qualification pass.

The resource certificate has no guessed defaults. It must cover actual archive
and fixture staging, expanded package, guest output, selected raw geometry and
filesystem free space, simultaneous clone/overlay/readonly-readback/log physical
allocations, host RAM reserve, finite CPU/PID/time/log/output limits and a Root
readonly own-UID quota guard covering the **entire** actor. `df` alone is not a
reservation. Guest scalar grammar and fixed command multiplicities are checked;
probe wait includes two compilations, six version/run operations and sync. This
VM resource certificate does not widen or alter the native LLVM policy.

The prepared packet contains only small code/metadata and references the four
retained materials; it does not copy a package or image. Its exact inventory and
Source selection are recorded. The caller's external Root resource review must
cover the actual generated fixture size. Stage it at `/var/lib/arm16k-llvm23-vm`
in a **new disposable guest** only. Public fixed material filenames are the LLVM
`.pkg.tar.zst` and `.sig`, `TEST-public.asc` and `signing-receipt.json`. No private
signing input is accepted. Retain original PAM files and credentials unchanged.

`guest/root.sh` is a case-only oneshot: exact baseline inventory and complete
owned payload/type/mode/UID/GID/xattr/local-database snapshots; user-owned
sentinels; advancing RTC before crypto; all material hashes; public-key-only
import and exact signer; `Required TrustedOnly` and `LocalFileSigLevel` equivalently
strict; normal `pacman -U` of the one LLVM package with ordinary hooks/scriptlets.
There are no repositories, trust bypasses or `-S` dependency downloads. It checks
installed inventory/payload/ownership, announces INSTALLED and waits for the user.

`protocol.py` uses the reviewed ordinary `builder` PAM serial login and original
baseline proof (aarch64/16384, systemd/logind/DBus), not runuser/su. It invokes the
cleared-environment `guest/probe.sh`, which checks UID/GID1000 and the certified
installed closure, exact clang/clang++/llvm-config versions and target, then
compiles/runs tiny C and exception C++ programs with LLD/compiler-rt, private
libunwind and the16K linker flag. All work is in the fresh case-owned user output
directory. It does not modify home configuration or set any clock.

After PROBED, root normally removes the one package, checks exact original
inventory and exclusive-path/prefix absence, restores only the known unowned
ldconfig cache state, compares full payload/metadata/xattr/database and user
snapshots, removes private TEST trust and syncs. Binary bytes and their hashes
plus the nonce-bound restoration summary are copied under durable `D/results`
**before** publishing RESTORED. `/run` alone cannot provide post-VM evidence.
The PAM session reads restoration and logs out normally. Failure yields HOLD;
there is no fallback success or fake LLVM result. Discarding only the owned
disposable clone is the outer failure cleanup, after evidence retention.

`proof.outputs()` is passive: it requires the complete durable four-file result
set, exact serial/disk restoration receipt and nonce, Root-bound baseline and
clock observations, binary hashes, output cap, and actual AArch64 linked ELF
PT_LOAD alignment/congruence≥16384. The LLVM Reader's reviewed ELF body is retained
with exact provenance. It reports DATA-only review and keeps VM/Root/native
acceptance null/false. It is not a substitute for actual PAM/QMP/owned-process and
whole-image preservation evidence.

Reviewed helpers are pinned in `helper-origin.json` and the closed Source lock;
the case-local runtime derivations retain their original byte/SHA provenance.
Unchanged copies include Rust-stage0 supervision/controller/RTC helpers and the RTC
lifecycle snapshot helpers. Rust's prefix assembler never performs ALPM, so it
is not retagged as this journey. Its hardcoded111 ownership functions are not
used to relabel a155 baseline. The new certificate uses the actual inventory
count and explicit file closure.

## Implemented preparation and host controller

`prepare.py --allow-prepare` and `boot.py --allow-boot` are separate explicit
operational entry points. Both require ordinary host UID, Python `-I -B`, the
external closed Source-lock/case/authority digests, real native evidence, actual
baseline/runtime/resource certificates, and the unissued authority template to
be replaced by Root. Every gate precedes daemon access or actor submission.
The immutable Source111 raw/prepared/first-PAM/consumed-marker and111 inventory
are pinned in `data/baseline111.json`; the accepted155 family is never selected
or relabeled. Independent baseline ownership evidence is a separate operand;
no ownership file or credential is written into the original assembly.

Complete-image ownership keys use a separate bounded passive validator. It
preserves literal printable UTF-8 names such as `usr/bin/[`, comma-containing
paths and systemd names containing the literal `\x2d` spelling; it does not
decode escapes or relax executable command paths. Absolute/traversing paths,
empty/dot components, controls and oversized names still refuse. An ALPM
`files` record with exactly zero bytes means no owned paths. Every nonempty
record must have a valid explicit `%FILES%` section, optional valid `%BACKUP%`,
and bounded unique normalized ownership keys. Whitespace-only, missing/duplicate
or unknown sections and malformed entries refuse. The captured record bodies
still join by byte length/SHA to the independent complete namespace, and all111
package names/versions must match. Portable synthetic controls cover these
classes; this change did not reread the retained222 ALPM dumps or scan a raw image.

The Root authority must also issue `docker_cli` with the canonical absolute
`path`, positive `bytes` and whole-file `sha256` of the host Docker ELF. These
fields are NULL in the template. There is no user-path default or PATH discovery.
Preflight, retained-input recheck and every Docker dispatch verify this operand:
ordinary single-link executable host ELF64, root/current-UID owner, no symlink
components, SUID/SGID or group/world writes, bounded size and stable whole pin.
The runtime translates its internal `docker` marker to this exact path, records
the canonical argv and executes a whole-pinned sealed executable `memfd` copy
via Linux `/proc/self/fd` with `pass_fds`. Write/grow/shrink/further-seal changes
are prohibited; pathname replacement and in-place changes to the original
cannot change the selected executable bytes. This requires Linux `MFD_EXEC`
and file seals; unavailable support refuses without fallback. The temporary
snapshot uses at most the reviewed CLI bytes (hard cap128MiB) in host memory.
Hash/copy loops check original deadlines, live resource guards and pending
cancellation before launch; copying cannot renew the work/cleanup envelope.
Recovery/list/inspect/wait/remove use this same boundary;
an unavailable or altered CLI holds cleanup rather than choosing a fallback.
The explicit Root-reviewed local rootless socket is checked again per dispatch.
Child PATH remains `/usr/bin:/bin`; endpoint, image, custody, cancellation,
quota and original cleanup deadlines still apply. This is host-only dispatch;
the guest actor receives no host CLI mount or inherited broad PATH.

The host preparation controller starts only the selected qualified rootless
cap0/NNP/read-only/network-none tool actor. `prepare_image.py` streams the actual
original ext4 namespace, verifies all111 ALPM records/owned bytes/modes and exact
PAM/boot pins, and reinspects every baseline-owned runtime certificate path
before cloning. Candidate-private paths are not yet installed and are not
falsely qualified as baseline files. The clone is sparse and owned; optional
nonshrinking growth uses only that clone, with readonly original checks, bounded
e2fsck/resize2fs, and the reviewed ext4 profile/4GiB logical ceiling. Signed
package bytes are staged as DATA only: no package extraction, installation or
compiler invocation occurs during preparation. Complete readback permits only
the fixed case directory and new service/wants link. A fresh case nonce retains
the original PAM nonce. Original raw and inputs are rehashed after retirement.

The prepared manifest and three whole image/kernel files, ownership model and
private original credentials require a new Root boot authority. Credentials
are host-only mode600 and never enter actor mounts: both controllers use
individual public image/manifest file binds. Boot consumes an exclusive attempt
marker and starts only fixed software-emulated TCG virt, no NIC/KVM, the selected
16K/RTC kernel, a bounded qcow2 overlay and fresh owned serial/QMP sockets. QMP
supports exactly capabilities then quit, bounded matching replies and no retry.
Ordinary PAM probes, normal logout, natural zero-exit/reaped/group-absent QEMU
retirement, verification-copy-only journal replay, readonly ext4 inspection,
all111/protected-PAM preservation, exact fixture/prefix cleanup, durable binary
hashes and ELF16K checks are required before a case PASS. A finite Root-reviewed
unowned-path policy accounts explicitly for permitted normal guest state; it
cannot waive package-owned files, PAM, user homes or the private package prefix.

`quota.py` implements only read-only `Q_GETQUOTA` for the current ordinary UID
using `quotactl_fd`. Unknown/unsupported/unlimited quota, wrong UID/device,
insufficient initial/live headroom, physical `st_blocks` cap/reserve, memory
reserve or original deadline exhaustion hold the run. The actual Root own UID
accounts for actor writes through the verified rootless UID0 mapping. A static
certificate does not substitute for these live kernel observations. Cooperative
checks run throughout child polling, serial/QMP waits and cleanup; there is no
background thread alongside `preexec_fn`. On resource/cancellation failure,
owned-container identity recovery/removal/absence checks still run inside the
**original** Root cleanup deadline. Bulk scratch-cap failure cannot block owned
cleanup, and no forced/ambiguous/cancelled run can become PASS.

`image.py` reuses the reviewed streaming ext4 reader without exporting a huge
filesystem tree. Large-file/read limits derive from actual candidate/baseline
facts and mandatory bounded `image_scan_passes`, never an invented LLVM size.
The immutable frozen parser's supported profile and4GiB geometry remain explicit
limits. Actual package/signature/trust, successful native/Reader4/Root acceptance,
guest ABI/development closure, finite image/resource/quota plan, kernel/tool and
prepared-image/authority values remain genuinely required and NULL until real.
The absence of those operands refuses execution; it does not stand in for code.

Future code/DATA-only packet preparation, once genuine operands exist (NOT RUN):

```text
python3 -I -B scripts/integration/arm16k_llvm23_vm/adapter.py --prepare-case-packet
  --source-lock-sha256 ROOT_REVIEWED_SOURCE_LOCK_SHA256
  --case /PRIVATE/Root-case.json --case-sha256 ROOT_CASE_SHA256
  --materials /EXACT/retained-inputs --baseline /EXACT/accepted-assembly
  --baseline-report /EXACT/accepted-first-PAM-report.json
  --baseline-ownership /EXACT/independent-readonly-ownership.json
  --nonce FRESH_32_HEX --output /PRIVATE/FRESH/case-packet
```

The source lock is an authoring identity, not a fabricated public Source/ref or
resource authority. No Source export, GET, GPG, ALPM, compiler, Docker, VM, lease,
actual Reader or publication ran during development. Generic emulated ARM16K
software runtime, native16K hardware, M2, performance and release remain unqualified.

Separate future operational command shapes (NOT RUN):

```text
python3 -I -B scripts/integration/arm16k_llvm23_vm/prepare.py --allow-prepare
  --case ROOT_CASE --case-sha256 CASE_SHA --source-lock-sha256 LOCK_SHA
  --materials RETAINED --packet VERIFIED_CASE_PACKET --base ORIGINAL111
  --baseline-report ORIGINAL111_PAM_REPORT --baseline-ownership READONLY_OWNERSHIP
  --kernel-bundle ROOT_KERNEL --tool-metadata ROOT_TOOLS
  --authority ROOT_PREPARE_AUTHORITY --authority-sha256 AUTH_SHA --output FRESH_PREPARE
python3 -I -B scripts/integration/arm16k_llvm23_vm/boot.py --allow-boot
  [same common exact case/baseline/material/packet/kernel/tool selections]
  --authority ROOT_BOOT_AUTHORITY --authority-sha256 BOOT_AUTH_SHA
  --prepared EXACT_PREPARED_ASSEMBLY --prepared-sha256 PREPARED_SHA --output FRESH_BOOT
```

The authority template also leaves phase seconds, rootless socket identity,
prepared/credential pins and finite postboot policy unissued. Its flags are false.
Only synthetic preparation/lifecycle/quota/QMP/resource/refusal tests ran. None
of the command shapes above, a real quota syscall, VM, Docker, GPG/ALPM, compiler,
Reader, lease, network operation or publication ran during this implementation.
