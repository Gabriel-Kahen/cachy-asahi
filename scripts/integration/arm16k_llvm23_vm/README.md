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

Reviewed helpers are copied unchanged and pinned in `helper-origin.json` and the
closed Source lock: Rust-stage0 supervision/controller/RTC helpers and the RTC
lifecycle snapshot helpers. Rust's prefix assembler never performs ALPM, so it
is not retagged as this journey. Its hardcoded111 ownership functions are not
used to relabel a155 baseline. The new certificate uses the actual inventory
count and explicit file closure.

## Remaining inputs and outer binding

No actual native package, signature/public TEST receipt, Reader4 runtime
result or Root native-package decision is supplied as an operand in this source task. No genuine
candidate-specific runtime/driver certificate or physical resource plan is
invented. The resulting packet deliberately has `host_VM_binding:null`.
Before an actual run Root must separately bind a new disposable prepared image
with readonly raw/runtime reinspection, exact case-service-only preparation delta,
accepted16K/RTC kernel and qualified tool image, current external authority and
private PAM credentials; then bind the reviewed host controller/actor and its
whole-lifetime resource/quota/cancellation/retirement owner to this packet.
Those image-preparation/controller bindings are **unfinished**, not an executable
VM success claim. They cannot be selected safely from the unknown future archive,
expanded size, baseline free space and linker closure. Root owns that next step.

Future code/DATA-only packet preparation, once genuine operands exist (NOT RUN):

```text
python3 -I -B scripts/integration/arm16k_llvm23_vm/adapter.py --prepare-case-packet
  --source-lock-sha256 ROOT_REVIEWED_SOURCE_LOCK_SHA256
  --case /PRIVATE/Root-case.json --case-sha256 ROOT_CASE_SHA256
  --materials /EXACT/retained-inputs --baseline /EXACT/accepted-assembly
  --baseline-report /EXACT/accepted-first-PAM-report.json
  --nonce FRESH_32_HEX --output /PRIVATE/FRESH/case-packet
```

The source lock is an authoring identity, not a fabricated public Source/ref or
resource authority. No Source export, GET, GPG, ALPM, compiler, Docker, VM, lease,
actual Reader or publication ran during development. Generic emulated ARM16K
software runtime, native16K hardware, M2, performance and release remain unqualified.
