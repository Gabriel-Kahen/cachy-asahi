# Generic 16 KiB script tools trial

Source proposal only. No compiler, Docker container, VM, native package build,
package installation or hardware actor was run by this worker. Root owns source
integration, exact commit/manifest freeze and the actual manual CI dispatch.

This separate diskless aarch64 lane exercises exactly four mapped products:
`cachy-asahi-mirrors` 0.2.0, Zsh syntax highlighting, Zsh history substring
search and Fish autopair. It copies 39 exact source payload files and four
unchanged project PTY drivers into private guest paths. It does not consume the
native package pairs or claim pacman installation. Every receipt labels this
`NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY`. Existing native package and
physical platform acceptance remain separate.

## Pinned inputs and capture

`payload-map.json` explicitly maps each source, destination, mode, byte count
and SHA256, including licenses/notices. `support.py` binds that map's hash.
`dependencies.json` pins 117 existing/derived source inputs, including each full
finite recipe directory, the unchanged drivers, owned574 producer and original
kernel helpers. `source-manifest.json` also binds this lane and its manual workflow;
it excludes only its own recursive hash. Recipe files are never sourced here.

The manual workflow reuses the existing six secret-seeded inputs and the same
fourteen-file public seed at `04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd` with
unchanged helper/index checks. It builds and borrows the existing owned574 image.
The exact inventory SHA256 is
`cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`.
It includes Fish 4.9.3-1 and Zsh 5.9.2-1. No new userspace, Rust, audio download,
secret, derived container image or product compilation is introduced.

A single ordinary-user capture runs with read-only mounts/root, dropped
capabilities, no-new-privileges, network disabled, 128 processes, 2 GiB memory,
240 seconds and 1 MiB output bounds. It verifies the 574 inventory before and
after capture. It imports only definitions to discover Python stdlib extensions;
no product/PTY CLI runs inside this capture container.

Capture includes Python sources/imported extensions; Zsh/Fish and init tools;
Zsh functions/modules; exact xterm terminfo; any installed Fish function/config
resources; and the full ELF interpreter/DT_NEEDED closure. The held Fish archive
contains no separate function tree; the actual captured Fish binary must provide
working autoload behavior when CI executes the unchanged tests. Every captured
ELF must be AArch64 and structurally 16-KiB aligned. Missing libraries or resources
fail; no page-check waiver or substitute interpreter is permitted. Limits remain
4,096 files, 256 MiB total, 64 MiB/member, 270 MiB raw private tar and 1 MiB capture
receipt. The receiver rechecks actual mapped product/fixture bytes against the
explicit map, independently of the capture's self-reported hashes.

## Separate kernel profile

The exact Asahi source archive is 262,965,559 bytes, SHA256
`874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`, revision
`94fb23346d522edf53722357c426a3e58030beea`. Its accepted fetch helper and static
page probe remain pinned and unchanged.

This directory's `build_kernel.py` derives from accepted helper SHA256
`e94adb4474183feea30ce1e2949b55c03e4969eeb1addb4c36892e8664ba9aaa`.
Its diagnostic fragment gains `CONFIG_UNIX98_PTYS=y`, `CONFIG_EVENTFD=y` and
`CONFIG_FILE_LOCKING=y`; the derivation receipt records all three. File locking
is required by the mirror product's unchanged `fcntl.flock(LOCK_EX|LOCK_NB)`
transaction locks. Actual Tools run38937106018 reached mirror activation with
`CONFIG_FILE_LOCKING` disabled and failed with errno38/ENOSYS. The source-audited
correction enables locking only in this separate diagnostic profile; a future
actual build/runtime must establish whether mirror lifecycle then passes. The EVENTFD addition follows the actual Fish eventfd ENOSYS failure in run38921035059. The derived `usage` and `run` functions now also apply the bounded compiler-output scan correction below; all other function bodies except `main` and the base `kernel.fragment` are unchanged.
The original `scripts/virtual/generic16k` helper/fragment and the accepted
Welcome/Doctor lane are untouched. The derived receipt uses profile
`TOOLS16K_PTY_DERIVED_DIAGNOSTIC`, binds base/derived fragment, helper, Image and
actual generated config hashes, and requires the PTY option plus 16-KiB pages.
The helper keeps the original source license, tool records, modules-disabled,
16 GiB workspace and 3,600-second build bounds. It never installs a kernel.

## Actual guest behavior required for PASS

QEMU uses TCG, one CPU, 1 GiB memory, no network, no display/monitor, 900 seconds
and 1 MiB UART. Init mounts proc, private devtmpfs/devpts and the private ptmx/fd
links. The initramfs contains fixed synthetic passwd/group/nsswitch entries;
these are fixture identity, not host data or package registration. Actual uname,
getconf, Python sysconf and the unchanged mmap/mprotect/file-offset page probe
must agree on aarch64, the exact kernel release and 16,384-byte pages.

After the marked-guest guard, root prepares one private directory and drops all
supplementary groups and UID/GID to 23001. All product/PTY commands run under that
ordinary fixture user. The eleven outer commands are:

1. Existing highlighting driver: noninteractive refusal, preexisting-module
   preservation, real ZLE unknown-token colour and custom binding, repeated
   opt-in and normal exit; two real editor snapshots.
2. Existing substring driver: all six cases, including real editing, literal/
   multiline search, preserved custom widgets/namespaces, repeat and coexistence
   with highlighting; ten editor snapshots in each editing/coexistence case.
3. Existing autopair driver: all fourteen cases, three keymaps and 57 real editor
   snapshots; existing keys/functions/autoload/variables/keymaps win, repeat
   preserves bindings, typed quoted data never executes, and exits are normal.
4. Mirror version 0.2.0 and local catalog check.
5. Private explicit activation, activation retry, restoration and restore retry.
6. Fresh explicit activation followed by a deliberate caller edit and failed
   restoration; edited bytes/inode and ACTIVE journal intent must remain intact.

The mirror catalog names `example.invalid`, aarch64/asahi-alarm and `core`.
Its candidate is created from exact controlled bytes; no rank/network request is
performed. The original bytes, mode/uid/gid, private journal, exact restoration,
retry and edit refusal are checked through actual CLI subprocesses. The parent's
report validator independently binds the known catalog/candidate/original hashes.
Mirror advisory locks retain their documented external-writer limitation.

Each outer command has 30 seconds (PTY drivers 180), 128 KiB combined output,
a natural expected exit and verified group absence. After every command, the
guest checks that no other UID-23001 process remains, including nested PTY groups.
Existing HOME/XDG sentinels and all root-owned captured source payloads are checked
before/after. The original test receipts keep their legacy host/installed labels;
only the outer marked guest supplies generic 16-KiB execution credit. No actual
package installation is inferred from those labels.

## Ownership, cleanup and workflow

The three host actors (capture, static probe compile, QEMU) have finite output/
time bounds and private sessions. Their leaders remain unreaped through cleanup
signals, then exact natural exit and complete group absence are recorded. The
nonce-bound ordered UART markers and all eleven guest commands must pass; panic,
duplicate markers, 4-KiB pages, missing cases, wrong hashes, leaked processes or
invented GUI/hardware credit fail.

Capture removal joins CID/name/image/job label; foreign ownership is never
signalled. Bounded capture/compile/UART tails are exported before private files
are removed, and the borrowed producer image must still exist unchanged. The
intermediate status is only `PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT`.

The next always-run workflow step invokes the original owned574 cleanup. Only
finalize can issue `PASS_GENERIC_16K_MAPPED_TOOLS_PTY_CLI_ONLY`, after natural VM
exit 0, all actor groups absent, consumer private/capture absence, original
producer probe/image absence, job identity and removal of the completed owned
`$RUNNER_TEMP/tools16k-kernel` workspace. Failed/interrupted kernel work cannot
receive PASS and may remain for disposable-runner removal, as in the accepted
helper. No stronger active-build cancellation claim is made.

The only uploaded artifact is bounded 2 MiB `runtime.json`, retained three days.
Packages, executables, keys, initramfs, rootfs and user report files stay private.
The workflow is manual and accepts exact `source_sha` / `manifest_sha256`; source
and workflow equality and every source hash are checked before secrets. Root must
freeze real identities, not predict a future commit. No scheduler is added.

Inert local controls block subprocess actors. They exercise source/map drift,
archive substitution, 4K ELF refusal, complete dependencies, derived config
provenance, host/guest guards, finite supervision, preservation/report replay and
foreign cleanup refusal. They establish source behavior only. Actual kernel
build/capture/VM execution, native package checks, Asahi integration, M2 hardware,
performance and release admission remain unrun by this worker.

The derived kernel helper records `workspace_scan=ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL`. During an active child only, an ENOENT below the exact private compiler output `build/` can be transient. Source, workspace and compiler-root absence, permission and other errors remain fatal. Completed-command and final allocation scans are strict. The periodic aggregate quota, per-file limits, log cap, build deadline and cleanup policy are unchanged. This follows the scanner failure on `.bitrev.o.d` during actual tools run38924169611; it is not evidence of a successful replacement build.

The source-acquisition successor shares acquire_kernel.py with the Done lane and
adds exact archive reuse through Root-verified official actions/cache restore/save
commit 0057852bfaa89a56745cba8c7296529d2fc39830 (Node20 metadata identities retained
in cache-action.json). Cache state grants no source-signature or runtime credit.
Only kernel.tar.gz is restored/saved, under a dedicated SHA-named directory outside
kernel build/cleanup roots. Both lanes use one exact content-addressed key, no
restore prefixes, no extracted source, packages, build trees or kernel images.

A true exact-key hit must have exactly that one ordinary owned archive. Every byte
is hashed while copying to a fresh private input; the exact 262965559-byte size and
874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad digest are required
before publication or extraction. Symlinks, hardlinks, special/writable files,
changed identities, extra restored members, partial/foreign matches, missing hits
and corruption fail. They never trigger an unreported fetch. Receipt statuses
separate RESTORED_HASH_VERIFIED from FETCHED_HASH_VERIFIED and retain cache identity,
byte/hash validation, attempts and partial-file absence. No fresh authentication
or signature claim is made for cache transport.

On an actual miss, the unchanged two direct codeload aliases, no redirects, one
capped transient pause and 300-second total acquisition policy apply. Actual fetched
bytes are rechecked while creating the separate archive-only cache copy. A copy or
hash failure cannot retry a URL or request save. Own partials are removed; existing
destinations and raced-in files are never overwritten. Explicit save runs only
following successful miss acquisition, before kernel build/final cleanup, with a
two-minute action bound. A save attempt is not evidence that persistence occurred.
Restore also has a two-minute bound. Cache failures cannot silently grant acceptance.

The exact source revision/input/provenance and all kernel/build/page/preservation/
cleanup and behavior gates are unchanged. Pure controls use tiny private byte
fixtures with network/actors forbidden; no live cache restore/save or new kernel
acquisition was performed by this worker. First verified future acquisition can
populate the cache; running/held actual work is not borrowed or changed.

Cache visibility follows GitHub's ref/default-branch rules. Identical content keys
do not guarantee reuse across the unique frozen dispatch refs used by these lanes.
This implementation avoids refetch only when that exact verified cache entry is
visible; it does not by itself solve cross-ref first-miss HTTP 429 failures. It
never borrows or edits an active run to seed cache storage.

On a true miss the workflow now uses Root's exact public CI-only prerelease source asset 647949735
from release 415175342 (ci-kernel-source-874ef68d04ac), through the fixed
https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/releases/assets/647949735
endpoint. retained-kernel-asset.json records its exact size/digest. A read-only
workflow GH_TOKEN is passed only to a fixed gh api application/octet-stream
command with a private empty GH configuration and stripped debug/proxy environment.
The helper accepts no authenticated URL argument. Root accepted gh's GitHub asset
redirect route; no helper constructs credentials for arbitrary origins.

The bounded 300s stream hashes every byte, caps stdout at the exact archive size
and stderr at 8KiB, and atomically publishes only verified bytes to a fresh cache
archive. Its owned process group is retired with an unreaped leader and absence
checks. Only stderr length/hash and exit metadata are retained, never token,
environment, response or stderr text. Corrupt bytes, unsafe paths, deadlines or failed cleanup are fatal. A naturally
completed nonzero gh transport is explicitly RETAINED_ASSET_UNAVAILABLE, publishes
no file and allows the original two URLs only after the workflow proved a true
cache miss. Its receipt remains retained; no continue-on-error or hidden retry
is used. Retained bytes cannot be mislabeled a cache hit.
The workflow then passes that explicit local retained archive to acquire(): a
second copy/hash gate publishes the actual kernel input and records distinct
RETAINED_ARCHIVE_HASH_VERIFIED provenance. The separate seed receipt joins exact
asset identity into existing runtime metadata. Early explicit save can seed later
eligible cache reuse. Without a selected retained input, a true miss still uses
the original two direct URLs and 300s policy.

This immutable checksum-bound asset route supplies the first miss independently
of dispatch-ref cache visibility; its public source bytes do not represent a
supported project release. No new cache/asset transfer or native acquisition was
run by this worker. Actual read-only workflow-token access, visible cache reuse,
first-miss source seeding and new kernel/guest behavior still need Root's actual.
