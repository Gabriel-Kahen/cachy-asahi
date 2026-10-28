# Generic 16 KiB Welcome/Doctor CLI smoke proposal

Unselected source implementation. **No compiler, package, Docker, QEMU, GUI or
hardware execution has been performed by this worker.** This lane tests the
existing binaries in a diskless generic aarch64/16,384-byte-page VM. It adds no
product feature and claims no GUI, installed lifecycle, physical hardware,
performance, optimization or release-admission acceptance.

## Exact inputs and reuse

The native products come from immutable input Source
`8a38b3fd5963e61fc94707dd87e5dcd626a518a3`, index SHA-256
`3d200c4cd19bd7ca15426ae34617bb4fad6c83b194f1d25533ad9f462c9c0580`.
The existing verifier checks all four original archives, 68,152 total package
bytes, both identical build pairs, all 23 recipe-source joins, payload/metadata
bindings and Welcome's ARM64 ELF structure. Only the verified build-a payloads
are unpacked. The original unsigned/unselected producer provenance, including
its recorded `FAIL_USER_PRESERVATION_CHECK`, remains unchanged in the input
record; this trial does not rewrite it or duplicate the later full lifecycle.

The current `maintained_desktop574.py` owns the existing authenticated 574
base, image and probe. The workflow forwards only the existing 22 secret chunks
for its six retained input files, then uses the same fourteen-file public seed
from Source `04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd`, with unchanged helper/index
hash checks. No Rust/audio retrieval, product rebuild, new secret or derived
runtime image build is introduced.

The kernel is the accepted generic16k diagnostic profile: exact Asahi source
archive SHA-256 `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`,
revision `94fb23346d522edf53722357c426a3e58030beea`, unchanged build helper,
fragment and static page probe. Only that kernel input is fetched by the new
kernel step. VM userspace comes from the current 574 image, not a separately
booted August rootfs. The build helper retains its existing 16-GiB workspace,
3,600-second build and module-disabled policies and records kernel license,
source, tools, Image/config hashes and actual build results.

`dependencies.json` pins 61 existing source files, including the full verifier
prerequisites and kernel/producer helpers. `source-manifest.json` additionally
binds this lane and its manual workflow. Root must freeze an exact source and
workflow commit and supply its manifest SHA; no future commit is invented here.

## Concrete actor and installation boundary

`capture.py` runs once as an ordinary user in the original image with all
capabilities dropped, no-new-privileges, read-only root and source/input mounts,
network disabled, 2-GiB memory and finite process/time/output bounds. Its own
scoped guard checks those properties; no existing helper guard is weakened.
It verifies the unchanged 574 inventory before/after capture. Product tar
members are verified and unpacked into the private in-memory payload, never
installed on the host or registered with pacman.

The capture adds the image's Python stdlib sources, imported extension modules,
basic init tools and complete ELF interpreter/DT_NEEDED closure. Doctor and
the guest script are imported for definitions/stdlib discovery only; their
CLI entry points are not called in the capture container. Every captured ELF
must be AArch64 and structurally 16-KiB aligned. All member modes, sizes, hashes
and ELF dependencies join the receipt; missing dependencies or escaping aliases
fail. The payload is capped at 4,096 regular files / 256 MiB, 64 MiB per member;
its raw tar is private and receipt is capped at 1 MiB.

`run.py` creates one deterministic initramfs with those exact bytes and the
unchanged page probe. QEMU uses TCG, one CPU, 1-GiB memory, no network, display
or monitor, a 600-second limit and 1-MiB UART limit. Init mounts proc only
inside the private VM and verifies actual `uname`, `getconf PAGESIZE` and the
page probe. The guest requires its unique fixture marker, aarch64 and 16,384
pages before writing to `/tmp/welcome16k`.

The fixed 13-command guest set is Welcome help/version, text+JSON status,
three exact local guides and guide-path refusal; Doctor help, JSON stdout,
private JSON file publication and existing-file/symlink output refusals.
Welcome/Doctor platform fields must reflect the actual 16-KiB kernel. Input
payloads are hashed before and after. Existing HOME/XDG sentinels are compared
by bytes, ownership and modes. The report must be a regular 0600 file with
matching stdout; failed writes must preserve report/outside bytes and inode,
ownership, mode, link count and modification time. Each command has a 30-second
deadline, 128-KiB combined stdout/stderr bound and verified process-group exit.

There is deliberately no pacman database or package-manager binary in this
minimal VM. Welcome reports an unavailable package database and unknown
versions; Doctor package observations must be unavailable/unknown. The receipt
states `NOT_INSTALLED_EXACT_PAYLOADS_UNPACKED_ONLY`. That is an explicit unpacked
runtime smoke, not synthetic registration or installed-package acceptance.

## Success and cleanup

`trial` accepts exactly one nonce-bound report with all 13 ordered command
results, exact guide/product hashes, real platform fields, preservation and
scope limits. It requires normal QEMU exit 0 and rejects panic/guest-error text,
missing/duplicate/out-of-order markers, wrong pages, incomplete commands and
invented GUI/hardware credit. It records source/product/kernel/tool/payload
hashes and bounded command metadata. Capture, compile and UART tails are
preserved before private deletion; raw packages and reports are not exported.

The capture CID/name/image/job-label are joined before any cleanup signal.
Foreign ownership fails without removal. The consumer removes its private
capture/VM files under a 90-second cleanup deadline and proves the borrowed
producer image remains intact. Its intermediate success is only
`PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT`.

The next always-run workflow step invokes the unchanged owned574 cleanup.
Only `finalize` may report full lane PASS, after joining natural VM exit,
capture/private absence, the original owned producer's probe/image absence and
job identity. It then removes only the completed kernel workspace at
`$RUNNER_TEMP/welcome16k-kernel`; unknown/interrupted work cannot satisfy PASS.
An interrupted kernel build may retain its workspace for runner disposal; this
proposal makes no active-build cancellation improvement claim. Only bounded
`runtime.json` (maximum 2 MiB) is uploaded. No binary, report file, rootfs, key,
initramfs, package or sample becomes a public artifact.

## Manual adoption and checks

Adopt the new `scripts/ci/welcome-doctor-generic16k/` directory and
`.github/workflows/native-arm-welcome-doctor-generic16k.yml` from the proposal.
The manual workflow accepts `source_sha` and `manifest_sha256`, verifies source
and workflow equality before secrets, then executes: source controls, six-file
secret seed, fourteen-file public seed, owned574 build, pinned kernel fetch/
build, one capture+VM trial, original producer cleanup, final joins and bounded
metadata retention. It uses the existing checkout/upload action pins.

18 inert controls pass with ResourceWarning as an error and subprocess actors
forbidden (mocked pipes/signals only for guest command supervision). They cover
exact real input verification, source drift, isolated Python import entry,
host/unmarked-guest refusal, read-only override, structural 4K rejection,
closed payloads, DT_NEEDED absence, archive aliases, scope/identity/guide joins,
natural exit/panic refusal, preservation and foreign cleanup ownership.
All five Python modules and three embedded Python blocks parse; all twelve
workflow Bash blocks pass `bash -n`. A full YAML parser was unavailable locally;
GitHub workflow parsing/execution remains unrun. Root owns final integration,
source/manifest freeze, publication and the one actual run.
