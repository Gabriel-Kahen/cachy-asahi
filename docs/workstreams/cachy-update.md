# Cachy-update native build candidate

Updated October 12, 2026 (America/New_York). This work owns
`packages/tools/cachy-asahi-update/**` and this report. Roadmap and package
inventory were read. Original four recipes/locks, shared manifests, Git and
workflows were not edited by this worker.

**The actual updater/tray recipe, Apple policy adaptation and a separate native
build adapter are implemented and source-tested. Native compilation has not run.**
There is no accepted target policy, target runtime transaction, installed package,
private-bus tray result, M2 validation or published release. Source checks and
mocked worker receipts are distinguished from actual native evidence below.

## Frozen upstream and source treatment

| Input | Identity |
| --- | --- |
| Upstream | CachyOS/cachy-update `e2b1b7144be71cf392809f48d1440f8da1d9c81a`, version 4.4.2 |
| Original archive | `b5e4ca8f2f779d1a877ab7a815cbb40a9a9cecf16ac59852eb7a3072fb3a261d` |
| Cargo.toml | `fcae83c668f4aa18800450ca165d87cd929cbf1141f33177628c32e451a2582a` |
| Cargo.lock | `0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753` |
| Sanitized source, portable transport | `86196b4d7be8336c321e3a033984a17e602a5e70ec5ea11126d1a249ddda8eab` |
| Full private vendor, portable transport | `e44dd795d5c392e37f44f63e041f25055924b75784b990788b24a80b442d5a9c` |
| Frozen original all-target audit | `01d8fdc321d58f0153019b576db5abfd3e4a66320d5c26507cb40df7e9ff7ff8` |
| Behavior patch | `08a781eeae66881359207ed93cbe808f3fdff884de646ec09c9bc640ad527db6` |
| Apple policy patch | `8201ed41b9790cbb004f3ce62d80ce1e9f25d314e7ef685ffea44d2f1594b783` |
| Supplementary notice evidence | `74a1dbfa75de13df5c82525af8d684e38b772c31bdf912d61f7fe74e7646c591` |
| Build-script source review | `11e687a1633cd09db2a24a9a6f7c32086a86e83dec615ec08a05143ed273ac49` |

Upstream README explicitly grants GPL-3.0-or-later; source headers and retained
license/author credits agree. Ten unresolved Cachy-branded SVGs are excluded.
Nine original MIT geometric icons replace the installed filenames; no omitted
logo geometry is reused or relicensed. The deterministic sanitized archive has
98 regular files: 87 retained upstream files, nine replacement icons, NOTICE and
ICON-LICENSE. The October 12 source refresh changes only NOTICE compared with the
previous source payload. The later portable gzip revision preserves every tar
byte; original Rust/shell source is patched later with zero fuzz. Dated per-file GPL modification notices are retained.

The original audit remains complete: 168 lock entries include the local tray and
167 registry packages. All 167 archive checksums and retained source ledgers
verify. The 323,117,153-byte portable vendor input is a **private audit/resolution input**,
not an accepted published source bundle. Historical full-vendor notice gaps
remain for block 0.1.6, malloc_buf 0.0.6, objc-foundation 0.1.1 and objc_id 0.1.1.
`historical-notice-followup.json` records 75 bounded primary-source reads without
finding the missing complete notices; later or unmerged grants were not applied
retroactively. Four other gaps are closed using pinned, matching upstream
notices for defmt-parser, r-efi and the two winapi GNU packages.

## Actual-input Linux compilation gate

`build-script-review.json` source-inspects all 38 declared entrypoints, included
inputs and six helper-source groups. It records commands, writes, conditional
branches and restrictions; it does not claim their execution. Dormant gettext
bundled source, Windows import libraries and system-deps download/test branches
remain separately identified. GNU Linux must use gettext-system; system-deps
binary/download features, DOCS_RS, bootstrap/wrapper/SDK overrides and unexpected
platform probe tools are refused by the reviewed execution path.

`linux-closure.py` validates actual worker metadata against frozen manifest/lock,
Rust target cfg, dependency kinds, normalized cfg predicates, optional/feature
edges and all vendored file checksums. Cargo may retain inactive dependency kinds
or optional source candidates on surviving edges; their platform/feature activity
is recorded separately. Supplemental complete MIT notice bytes are bound to
original package/source hashes, including defmt-parser in the conservative
metadata graph. Selecting any of the four unresolved historical macOS packages
still refuses compilation. No all-target distribution status is changed to PASS.

The independent review's existing **x86-host, ARM-filtered** resolver output was
replayed as data with an explicitly mocked native receipt: 123 registry sources
plus the local tray and 20 script candidates validate. Its normal/build tree has
116 registry packages plus the tray and 17 script candidates. Neither count is
actual native compilation evidence. Fresh native metadata/cfg is mandatory.
Metadata feature unions are not exact compilation-unit features.

`worker-metadata.py` verifies the nonroot native ARM worker, finite cgroups,
read-only root/inputs/entry, private tmpfs, capabilities/no-new-privileges,
loopback-only networking, absence of host sockets/hardware devices, controller
hash/nonce/image, authenticated tool aliases/content and all 167 source ledgers
**before Cargo/rustc/package-tool queries**. Its command runner bounds time/output, kills its
process group, retains partial stdout/stderr, and records original failure and
cleanup errors independently. JSON assertions alone cannot authenticate a
worker; the outer controller must bind the actual native daemon/image/launch.

`build-gate.py` validates fresh command logs and receipt hashes, the nine untouched
tray source inputs, reviewed script/helper bytes and the selected source graph.
It rechecks inputs for check/package, permits only canonical generated target
outputs, and requires repeated selected-source reports to match. The separate
`verify-updater.py` binds all 98 patched source files and modes before Makefile,
check and package operations, refuses extra library inputs, and reconstructs
1,113 notice files (11,735,034 bytes) from the immutable pinned vendor archive
before packaging instead of trusting writable extracted LICENSES copies. There are no
self-declared policy PASS booleans granting execution. A requested selected-source
projection is retained separately with the original lock/audit and supplemental
notices; it is labeled inert and distribution-unaccepted. The unchanged lock
still needs excluded all-target manifests for offline resolution: this projection
is not claimed to be independently buildable or complete corresponding source.

`worker-build.py`, loaded from read-only inputs, invokes the verified gate before
actual `cargo build --release --frozen --offline --locked --target
 aarch64-unknown-linux-gnu --jobs 2`. Its environment fixes compiler/linker paths,
private HOME/CARGO_HOME, epoch 1789753605, UTC and 16K maximum-page linker alignment.
It retains verbose compiler commands and JSON artifact/build-script records,
checks actual package IDs/features against the verified metadata graph, and
requires gettext-system and exclusion of system-deps binary in actual emitted
units. It verifies the actual tray artifact, static aarch64 ELF/16K LOAD layout,
and retains readelf headers/program headers/dynamic linkage. These paths remain
**NOT RUN**; static segment checks do not prove 16K loader or M2 compatibility.

## Authenticated separate builder and adapter

| Retained coordinator evidence | SHA-256 |
| --- | --- |
| Refreshed base inputs | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` |
| Extension lock | `988a74e39f5d3b74cee18dcd53e78733c38872fe2143ccf4e2f4e95d5a5f8776` |
| Extension receipt | `f48c3fa41de8df649260e3c16fa3361f0c4b65e28c70e431baee8d887bcf4490` |
| Exact 354-package inventory | `d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271` |

The extension authenticates 13 additions with no version changes to its current
341-package baseline: bats, compiler-rt, git, libgit2, lld, llhttp, parallel,
perl-error, perl-mailtools, perl-timedate, rust, scdoc and zlib-ng. All archives,
signatures and strict package metadata are authenticated in the coordinator's
receipt. Rust is 1:1.99.0-1. This refreshed baseline differs from the earlier first
successful historical 341-package builder, including its Perl version; the
adapter does not rewrite the original four-package lock. The original discovery
proposal is preserved as `builder-extension-discovery.json` with its historical
receipt hash binding.

`updater-native.py plan` is data-only. `freeze` snapshots the exact recipe and two
checksum-pinned archives. `build` requires an externally supplied candidate hash,
a nonroot native Linux ARM host and native local Docker daemon. It reauthenticates
all base/addition signatures, invokes the existing bootstrap with a private
merged input object and no original recipe jobs, derives tool hashes from signed
archives without execution, and verifies the actual immutable image/inventory.
Each build binds the approved recipe ledger before and after copying and uses a
pinned read-only entry plus controller. It creates two separate containers with
network disabled, all capabilities dropped, no-new-privileges, a read-only root,
4 CPUs, 4 GiB RAM, 512 PIDs and 4 GiB private tmpfs. Failed cleanup prevents PASS.
Artifact metadata, installed contents and exact package bytes are compared only
after both independently recorded clean builds pass.

The entry uses `makepkg --nodeps` for this **private compile-only trial**. The
354-package image includes build/check roots but not all target runtime packages
(e.g. htmlq, pacman-contrib, archlinux-contrib and xdg-utils). Runtime declarations
are retained; dependency skipping does not establish an installable supported
target transaction. Checks are not skipped. No compiler, package installation,
service operation or Cargo command was executed on this workstation by this work.

## Apple-aware updater behavior

The first four patches correct notification argument passing, activation failure
propagation, pre-operation Flatpak prompting and cooperative exclusive locking.
The lock refuses unsafe runtime paths/links and cannot be overridden with a yes
answer. No atomic guarantee against adversarial same-UID path races is claimed.

`apple-policy.patch` and the installed original MIT `asahi-policy` helper add:

- Mandatory preflight before the full upgrade or repository/AUR/Flatpak actions.
- Independently allowed cache/orphan/optional operations; unknown changes require
  coordination instead of implicitly accepting a platform transaction.
- Protected boot/kernel/firmware/graphics/audio version roles and observed,
  package-owned module-release files in place of a PC vmlinuz reboot heuristic.
- Strict service-unit arguments and separate scope allowlists; protected Asahi
  speaker-safety/audio units cannot enter the generic restart path.

No accepted policy or fabricated hardware observation is shipped. Policy and
separate pre/post observations require pinned bytes supplied by a trusted release
controller. Model strings (Apple j413/j415), package versions and hashes are not
hardware attestations. The helper does not implement the trusted live collector,
repository snapshot/transaction controller, AUR review or rolling-repository
TOCTOU prevention. Those remain required before supported Apple updates.

The package retains the real Bash updater, Rust tray, manuals/translations,
launchers and explicit units; it adds Python and installs the helper at
`/usr/lib/cachy-asahi-update/asahi-policy`. DESTDIR is honored, no global autostart
or install hook is added, and no unit is activated. An unconfigured policy
refuses update actions. Removal/reinstall and user-owned configuration handling
remain untested on the target. Source/mock checks cannot replace actual tray/menu
checks on a private session bus or coordinated protected-platform recovery.

## Verification and remaining execution

`validation.json` records exact file hashes and executed test counts;
`recipe-validation.json` records static fully staged recipe inspection. Source,
Cargo hostile-input, shell endpoint/lock, Apple policy, closure, worker,
compile-gate, adapter and synthetic emitted-unit fixtures pass. These are data,
mocked or private Python/shell fixture tests, not native builds or host updater
operations. Final portable source generations are byte-identical across both tested Python
runtimes. Bash metadata checks do not execute recipe build functions.

Next execution is the separately frozen native pair. **NOT RUN:** fresh native
metadata/cfg, actual compilation/unit traces, package comparison, private-bus
tray/menu behavior, target dependency transaction, installation/removal/reinstall,
16K loading, exact 13/15-inch M2 Air platform updates/boot/recovery, performance,
source/publication acceptance and release promotion. All five full-port
requirements and M5–M9 remain unfinished; this candidate is one tool workstream.

## Runner reconstruction and reviewed transport revision

`materialize-inputs.py` and the externally pinned `runner-inputs.lock.json`
reconstruct private sources directly from HTTPS. The only download hosts are
codeload.github.com and static.crates.io. It authenticates the original archive
and every locked crate before inspection, recomputes all source/notice/helper
records against the frozen audit, and generates both recipe archives. No Cargo,
compiler, build.rs, Docker, package installation or updater runs in this path.
The child has 900-second wall/600-second CPU limits, 2 GiB address space,
512 MiB per-file and 1 GiB retained-data bounds. Parent cancellation kills and
reaps its owned process group and durably invalidates success.

An actual earlier comparison identified different compressed bytes from stock
zlib versus zlib-ng, despite identical decoded source tar. That failed comparison
is retained under the historical entry in `materializer-generation.json`.
It was resolved by an explicit reviewed transport revision, not a relaxed hash:
`portable-gzip.py` writes fixed 65,535-byte stored DEFLATE blocks, zero-time/OS255
headers and CRC32/ISIZE without a compression engine. The two original auditor
files and all-target Cargo audit remain byte-for-byte unchanged. The writer is
used only around archive generation inside the bounded data child; the original
reader is restored even if generation fails.

`transport-revision.json` records an independent streaming comparison: exact
uncompressed tar bytes, all 98 source members, all 11,739 vendor members, and
all 1,113 notice files/11,735,034 bytes match their frozen predecessors, including
modes and metadata. Source-audit JSON changes only sanitized_sha256. Original
source grants, artwork exclusions, lock and notices are unchanged. Decoded tar
SHA-256 values are:

- Sanitized: `cb1a9d4d27a7105fedeee561704da7dee217bb994fe13e28d4df0991ce890c7f`
  (1,044,480 bytes).
- Vendor: `56c18f093e6d0fe5454b6998b9b4f647bdfa9442e3221250a140a479ccd10ab3`
  (323,092,480 bytes).

Actual fresh HTTPS reconstruction with installed Python 3.12.14/stock zlib 1.3.2
PASS: 168 inputs, 43,873,283 downloaded bytes, all 167 registry sources audited,
source archive 86196 and vendor archive e44dd reproduced exactly. An independent
second run with Python 3.14.7/zlib-ng 1.3.1 used checksum-matched offline inputs and
reproduced both compressed archives, both decoded tar streams and source-audit
JSON byte-for-byte. This closes the identified compression-runtime blocker.
Hosted workflow execution itself remains NOT RUN. Exact archive hashes are
mandatory for every runner, including future or untested runtimes.

A subsequent root review identified cancellation after fork/session creation
but before Popen returned its handle. The corrected materializer blocks signals
across spawn/registration, restores the child's prior mask before exec, and
installs non-raising deferred handlers before it owns any child. Bounded 0.1-second
waits check cancellation; those handlers remain installed throughout kill/reap
and durable finalization, avoiding a teardown handler-transition gap. Eighteen
focused fixtures pass. A real private process regression for TERM/INT/active ALRM
fails the old code and verifies absent/reaped groups plus restored parent/child
masks with the corrected code. Fresh HTTPS stock and second-runtime reconstruction
were executed again under the new code/lock pins with identical archive bytes.
The earlier 42f7785 checkpoint and f493 candidate are superseded explicitly;
source/artwork/notices and archive pins did not change in this correction.

The cost is larger private inputs: source 1,044,578 bytes and vendor 323,117,153
bytes, compared with the old 171,941/46,238,716-byte compressed archives.
Controller recipe reads, notice verification and public typed size fields now
support the reviewed 512 MiB bound. Four unresolved historical macOS notices
remain unresolved; full vendor and compiled package publication remain unaccepted.
Independent integration review passed 61 focused worker/gate/materializer/verifier
fixtures. All 289 bounded tests pass; static staged recipe inspection verifies
22 source/pin pairs with zero errors and matching .SRCINFO/PKGBUILD metadata.

## Reviewed helper, cancellation and public evidence

The adapter explicitly adopts the coordinated reviewed native helper SHA-256
`a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.
The exact reviewed test fixture is retained separately from the historical 2443
fixture; neither is imported/executed or used as a runtime fallback. A real
data-only production plan now PASS with the unchanged 3c16 base, 988 extension and
exact 354 inventory. Coordinated helper review covered its durable result write
before optional integration; acquisition/bootstrap/audit/build behavior is
unchanged. This work edited no shared helper, workflow, manifest, lock or Git state.

The native adapter requires positive matching real/effective UID and GID,
handles SIGTERM, verifies owned named-container absence after removal, and
fsyncs authoritative failure results for cancellation, cleanup or pair failure.
Cancellation during final PASS replacement supersedes it with FAIL. Twenty
adapter tests include actual private Python SIGTERM fixtures with Docker mocked;
actual Docker/native execution remains NOT RUN.

`public-evidence.py` selects only fixed receipts with bounded reads and
schema-specific value allowlists. Typed status/hash/controller/tool/inventory,
Cargo identity/feature, package/ELF and transport metadata are retained. Raw
argv/env/errors/logs and source/vendor/cache/binary trees are excluded. Eighteen
fixtures and both final portable success receipts pass projection, then the
unchanged generic credential guard. Historical success/failure receipts still
project unchanged. No encoding bypass, raw source upload or publication occurs.
Raw inputs are ephemeral, at most 7200 seconds; actual deletion is a controller
obligation and is NOT ATTESTED by this selector.

## Current native handoff

The immutable dispatch/source map is
`packages/tools/cachy-asahi-update/runner-ready-pins.json`, SHA-256
`ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2`.
It binds owned code/evidence plus the reviewed helper and unchanged root input
locks. Verify its hash externally before invoking the materializer/adapter.
Materializer SHA-256 is
`4e8a6111a70bdb93d2a5e75aa786c96ce099a54d0fcd5e4bba38177da4c2e964`;
its runner-input lock SHA-256 is
`ba869e80d9fa2bdeb9c5bf504dc9cbddff1b164f6276d3ab75516fc5985fa0ac`.
The earlier 87c/890f/f493 local candidates are superseded and must not be dispatched.
The newly frozen local candidate is
`/tmp/cachy-update-native-spawn-final-20261012/candidate.json`, SHA-256
`42e1901bc9ea5243b98e68e40fc362d0e7c5df77f68b856b1a3101a9cecce2cd`.
Its staged recipe passes static inspection; PKGBUILD is
`56b7d672a2bcc45f989159e7771d27777382c294217c5b0f7270005c342768c7`
and .SRCINFO is
`14a91c42f79884a49b490544fa59b4266852a7698c5465925daf6b0df6998050`.
The fixed local snapshot is private temporary input, not permanent publication.
A candidate recreated at a different coordinator path has a different candidate
hash; verify the new receipt externally before build invocation.

```sh
# Data-only fresh reconstruction, no workstation cache required.
python packages/tools/cachy-asahi-update/materialize-inputs.py \
  --output /tmp/cachy-update-runner-inputs \
  --pins-sha256 ba869e80d9fa2bdeb9c5bf504dc9cbddff1b164f6276d3ab75516fc5985fa0ac

# Freeze a new equivalent candidate on the native coordinator and rehash it.
python packages/tools/cachy-asahi-update/updater-native.py freeze \
  --source /tmp/cachy-update-runner-inputs/private-sanitized/cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a-sanitized.tar.gz \
  --vendor /tmp/cachy-update-runner-inputs/private-cache/cachy-update-vendor.tar.gz \
  --output /tmp/cachy-update-native-runner

# After the coordinator-owned native pair exits, project into NEW directories.
# Apply the unchanged guard only to the projected receipts.
python packages/tools/cachy-asahi-update/public-evidence.py \
  --raw /tmp/cachy-update-native-trial \
  --materialized /tmp/cachy-update-runner-inputs \
  --output /tmp/cachy-update-typed-public
python scripts/ci/integration_export.py \
  --raw /tmp/cachy-update-typed-public --output /tmp/cachy-update-guarded-public
```

Native metadata/compilation, actual unit/linkage records, native package pair,
private-bus behavior, licensed source/binary publication, target transaction and
M2 lifecycle remain NOT RUN/unaccepted. The local data reproduction proves
source transport compatibility; it does not establish a hosted build or hardware
acceptance. Native workflow/build dispatch remains owned by the coordinator.
