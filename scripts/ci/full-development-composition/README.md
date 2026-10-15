# Fixed development composition trial

This job installs ten current project packages and four missing signed upstream dependencies on a fresh instance of the proven 574-package generic ARM runtime base. It substitutes project FDK for upstream FDK and requires the exact 587-package inventory in `expected-installed.lock`. It is a development transaction, with package scriptlets disabled and hooks masked; target/platform/release acceptance is not claimed.

`run.py` consumes the original four and FDK build outputs in the same job, obtains the four small tool binaries on the unchanged 341 compiler, builds the updater pair with the unchanged 354 compiler, then constructs the unchanged 574 runtime base. Recipe Source, updater API Source and runtime builder Source are pinned in the runner. All ten actual package metadata and BUILDINFO records must match the selected recipes before temporary TEST signing. `dependencies/` reuses the existing updater helper/lock unchanged: all five are authenticated; exact already-installed xdg-utils is excluded from the four-package transaction selection.

The updater caller receives an explicit clean environment and private HOME with no `DOCKER_*` variables. The 574 helper pin includes Root's mode-0644 pacman configuration correction; the selected input/configuration bytes and 574 versions remain unchanged.

`container.py` requires a disposable native ARM root container with its explicit nonce, no network or host system mounts, and the fixed 14 incoming archives/signatures. It uses fresh private trust for the upstream and TEST public certificates, required signatures and one ordinary pacman transaction. Exact inventory, dependency consistency, package integrity, payload ownership/symlinks, pyalpm import and installed FDK loads must pass. All application sessions, target hardware/lifecycle and release publication remain NOT RUN.

The workflow invokes the runner with explicit product, updater, desktop-builder, original native output, FDK output, cache and fresh output paths. Public output contains bounded metadata/diagnostics only. Owned temporary signing state, trial containers and two new builder images are removed after use; the borrowed original builder remains available to its existing job owner. Cleanup uncertainty fails the trial. No binary publication or accepted signing-key setup occurs.

## Optional composed lifecycle

Append `--lifecycle` to that same runner command to exercise the fixed ten-package composition after its existing exact587 checks. Default invocation ends at the original composition boundary. This mode preserves the original recipes, versions and dependency locks; it does not select updater 4.4.2-2.

The mode reuses the existing core fixture generator to derive four explicitly marked **DEVELOPMENT ONLY 0.1.1-1** original-package upgrades, then builds those with the same 341 compiler and existing builder. Their changed template comments/helper identity test controlled configuration refresh, not a real upstream migration. They share the temporary TEST signing identity with the ten original packages. The original FDK archive and official signature are copied from the exact574 builder's authenticated inputs for restoration.

Fresh and existing private homes run the installed setup helper as UID/GID65534. Preview/repeat, user edits, signed four-package upgrade, removal, original-v1 reinstall, surgical deactivation and deterministic interrupted activate/remove recovery are checked. Interruption uses the existing installed-helper `os._exit(75)` fault after a configuration write; it is not power-loss or package-manager interruption testing. No accounts, login shells or services are changed. Shell PTY sessions, desktop sessions, real updater Check and target/boot recovery remain NOT RUN in this mode.

Each removal uses ordinary dependency-aware transactions: remove nine project packages, replace project FDK with its original signed upstream package, then remove the four additions. Both cycles require exact574 inventory and restoration of the two upstream FDK library identities. Installed payload hashes, modes, symlink targets and package owners are checked at v1, fixture-upgrade and reinstall stages. User-file snapshots must survive package removal. Only this mode adds CAP_KILL for the existing bounded demoted-child helper, and extends the transaction timeout to1200seconds.

The result keeps `package_count=587` and its digest for the initial composition stage. Lifecycle mode adds `composition_checks=PASS-exact587-before-lifecycle`, a separate lifecycle summary, and `final_package_count=574` with the original runtime inventory digest. Overall PASS is set only after the selected lifecycle completes and private container trust/home cleanup succeeds. The host retains only a bounded development-fixture summary plus the existing public composition diagnostics; raw updater output remains private.

## Optional updater v1-to-v2 successor

Use `--updater-v2-source /path/to/exact-480053-checkout` for a separate upgrade/Check/rollback exercise. This option is mutually exclusive with `--lifecycle`. Keep the three original product/updater/desktop selections unchanged; the additional checkout must be `480053c0866a922138d85af2b9880fb0e10d7b2c`. No workflow is registered by this code.

The original signed14 transaction and v1 exact587 checks run first. A second private native pair uses the same updater API and exact354 compiler selection, with Source480053's materializer lock. The v2 recipe and package must match their known native hashes, including package `88e6ebad51700499bc2f0c608409e06983b0146ebf555101b526c7a32d5ba4f6`. Its fresh archive is signed by the same temporary composition TEST identity. The v1 recipe map, input lock and historical result are retained.

One ordinary required-signature `pacman -U` upgrades only updater4.4.2-1 to4.4.2-2. `expected-updater-v2.lock` has587 entries and SHA256 `2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7`; every other entry equals the v1 lock. Dependency/provider metadata, exact inventory, database consistency, dependencies and all ten package payloads must agree.

`updater-v2-real-check.py` reuses Source480053's seven real Check/refusal cases. Its only behavioral adaptation is strict optional full-inventory equality for587 packages and dynamic result counts; the default standalone360 gate, clean user environment, signature policy, output limits, cases and cleanup stay held. The existing fixture pattern creates a second private TEST signing identity inside the container for its inert data package and local database. It temporarily installs one inert baseline, making588 packages. It advertises but never installs its newer data-package candidate. This is an actual installed Check command, with no network repository, optional backend or notification service.

After those cases, normal dependency-aware removal of the inert package must restore exact587v2. A required-signature local transaction then restores the retained updater4.4.2-1 archive, exact587v1, dependency consistency and all ten payloads. The nested `updater_v2` result records the v2 lock and seven cases; `final_package_count=587` and the final inventory digest refer to the restored v1 selection. These direct pacman transactions do not exercise an actual `arch-update` commit, platform changes, interruption or boot/session recovery.

V2 raw build data uses Source480053's existing public projector/exporter; raw updater output remains private. Cleanup includes the extra private builder/GPG home, deduplicating image IDs only after verified removal so identical compiler images do not cause a second removal failure. No borrowed core image is removed. This mode uses the1200second container timeout; defaultv1 behavior and its480second limit remain unchanged. Native combined v2 execution, real target lifecycle, hardware, release and performance remain NOT RUN until an actual result is reviewed.

## Optional retained setup4 trial

Add `--setup4-pair /path/to/retained-pair` to the same caller to exercise setup0.1.0-3→0.1.0-4→0.1.0-3 in a disposable generic ARM composition. It is incompatible with `--lifecycle`. The default initial587 checkpoint retains updater4.4.2-1. Only after review of the actual combined v2 result, the coordinator may also select the exact `--updater-v2-source` checkout: in this new mode that selects updater4.4.2-2 in the initial14 transaction, rather than running the historical updater successor exercise. Existing default/lifecycle/standalone-v2 paths and their locks are unchanged. No new workflow is registered.

The pair directory contains `build-1/` and `build-2/`, each with its retained `provenance.json`, `expected-packages.lock`, `inputs/` and one package under `artifacts/`. These are the already retained outputs of native run38782193131 at Source98fecf28a3cde63a9dd7531501c2187825349310. Both archives must equal `c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a` (22632bytes), with the exact recorded341 builder and all29 pinned input files in `setup4-source-inputs.json`. The adapter reuses the existing native handoff, metadata binding and package checks. It does not build setup4 again or require the historical builder image to remain installed. Only setup4's six known files are accepted; no hook, install script, service or package-owned `/etc` payload is added. The existing TEST signer signs the copied archive alongside the other inputs.

The initial checkpoint still installs setup3. A normal required-signature, scriptlet-disabled local transaction upgrades only setup to4, preserving the chosen updater. The new target locks each contain587 rows and differ from their respective checkpoint only at setup. Installed inventory, database consistency, dependencies, all ten package payload hashes/modes/owners, and both installed command help paths are checked. Existing core fixture methods exercise setup preview, repetition and preservation of edited user files in private demoted homes. Package installation must leave repository enrollment disabled.

The installed repository CLI then previews, explicitly enrolls, repeats enrollment and disables twice using an inert canonical TEST URL and the same TEST public fingerprint. Its public certificate is copied to a scoped root-owned directory beneath `/root`, satisfying the unmodified safe-parent policy. The container's initialized ALARM keyring is preserved; enrollment imports and locally signs the TEST public certificate through the installed CLI. Effective package/database signatures remain required and trusted-only. Disable restores original main configuration bytes and removes only the managed include/block; imported TEST public trust intentionally remains in this disposable keyring. No repository network request occurs, and no keyring is initialized or reset.

Normal setup4 removal must leave586 packages and preserve fixture user files; reinstall returns587. A final signed setup3 transaction restores the exact initial checkpoint, removes the setup4-only command/documentation, preserves user files and leaves enrollment disabled. Overall PASS is set only after this stage and existing cleanup succeed. This mode adds only the existing bounded-helper CAP_KILL and1200second timeout. Public diagnostics add one bounded retained-input summary; private source copies, certificates and signing state follow the existing cleanup. New combined native execution, target installation/recovery, production repository enrollment, hardware, performance and release acceptance remain NOT RUN.

## Optional actual filesystem footprint

With the retained setup4 pair and explicitly selected updater-v2 source, add
`--measure-footprint` to copy and measure bounded filesystem data after setup4
installation, before user/enrollment fixtures. A fresh nonce-owned local Docker
volume supplies disk-backed storage; the optional caller preserves setgid modes
with FSETID. It requires capacity for8GiB plus500000 nodes and reserves before
allocation. The helper has a900-second bound and the owned worker960 seconds.
Runtime/mounted paths, xattrs and timestamps are excluded or omitted explicitly.
The before/after source package database and exact587 inventory must agree.

The output is a scoped, non-atomic footprint with unsupported shape examples,
not a whole-root snapshot or update acceptance. A measurement failure remains
visible while setup removal/reinstall and setup3 rollback continue; the overall
job then fails. Cleanup removes the exact owned volume only after verifying the
composition container absent. No system mutation, copied executable or ldconfig
execution is added by this measurement path.

## Explicit retained-audio install/removal slice

Append `--audio-inputs /absolute/owned/audio-archives` to select the separate audio
trial. It is mutually exclusive with `--lifecycle`, `--updater-v2-source`,
`--setup4-pair` and footprint measurement. The default composition and every
existing lock remain unchanged. This mode starts from the original 587 v1
checkpoint, not a setup4/updater-v2 checkpoint.

Supply exactly six pinned archives in that directory and the retained official
LSP detached signature; `audio-inputs.json` lists their exact versions/hashes,
actual package metadata, complete payload maps and closed generic error sets.
The five project archives come from the successful audio native pairs; no audio
build is repeated. The existing temporary TEST signer signs only those five.
LSP keeps its exact official ALARM signature. No acquisition helper is added.

After ordinary 587 composition checks, the same offline ARM container installs
all six with required signatures, hooks masked and scriptlets disabled. It
requires exact 593, dependency consistency, all 22 runtime relationships, package
integrity and payload byte/mode/ownership checks. Existing files cannot be
replaced. It then removes asahi-audio first and the remaining five additions in
one normal dependency-aware removal; no dependency bypass or recursive removal
is used. Exact 587 inventory and original local package database bytes/modes/
ownership, pre-existing payload-directory attributes, absence of added files,
and original project payloads must be restored.

There is no service manager or `/dev/snd`, and no produced daemon, LV2 plugin,
audio command or helper is executed/loaded. Unit/udev/runtime configuration files
are installed only as package data. This is a disposable generic transaction
proposal, not target audio/speaker-safety validation, trust enrollment or release
acceptance. Existing source/recipe and complete license-closure gaps remain.
The actual native transaction has not run merely because these source checks pass.

The three additional ALPM mutations retain the existing libalpm auxiliary path:
when ld.so.conf and ldconfig are present, each invokes ldconfig despite disabled
hooks/scriptlets. ALPM ignores its return. These are three eligible additional
calls; no cache/link correctness or auxiliary-success result follows from a
successful transaction. ELF scanning is not plugin loading, but SONAME links,
ld.so.cache and aux-cache may change. No auxiliary waiver/stub/removal is added.
Preservation checks cover original package DB records, selected payloads and
ancestor attributes; they do not restore/validate all base files, caches or links.


## Proposed four audio ldconfig-state checkpoints

Artifact-only successor to actual audio run38797262875. That historical bounded
signed593 transaction/restoration PASS is unchanged. This proposal records B0
before audio U at587, B1 after U at593, B2 after first R at592 and B3 after final
R at587. No extra cache-generation call is introduced. The existing normal helper,
U/R/R commands, signature rules, package/dependency/payload/database checks,
hooks/scriptlets isolation, global guards and owned cleanup remain held.

Each checkpoint pins the normal helper's known bytes/size and root-owned0755
identity. The main configuration must match retained filesystem SHA256
785c6c3614a27ae6115a27c1ca55bbf333654780997c4ba7e181172b021d1bf3 (the exact two
include-glob file). Only those two fixed include directories are examined, with
at most32 entries each and at most4096 bytes per ordinary included conf file.
Included syntax is deliberately finite: blank/comment lines or literal /usr/lib
and /usr/lib64, with ASCII space/tab and trailing comments. No nested include,
glob, flag, other directory or symlinked configuration is interpreted. Config
nodes must be root-owned and not group/world writable. The held package audit
and exact fakeroot exception are described below. An unfamiliar include,
e.g. a separate vendor-library directory, produces a bounded UNACCEPTED result;
its exact source/data shape must be audited before adding explicit support.

Scan directories are the two fixed standard spellings, resolved only to those
same two paths, the exact fakeroot directory below, and ordinary glibc-hwcaps
children (at most32 per root). All
resolved roots/aliases and hwcaps metadata are recorded. Any audio ELF bundle
parent selected as a scan directory is refused. Direct regular files and symlinks
are snapshotted with bytes/hash/type/mode/UID/GID and stat identity; regular files
are capped at256MiB and aggregate scanned bytes at2GiB, with8192 entries total.
Enumeration/count and aggregate size checks precede sorting/hashing. Ordinary
non-hwcaps child data directories are not recursively observed or compared;
normal package-created LV2 directories are outside this library/link scope.
This is not a complete directory-tree or all-writes observer.

Both cache files have presence/type/root ownership/mode/size/hash recorded,
with a16MiB per-cache cap; the auxiliary directory metadata is recorded too.
Both temporary ~ leaves must be absent. Main-cache ordered mapping rows and
generator text come from the pinned read-only `ldconfig -p -C /etc/ld.so.cache`
branch under existing bounded c.run supervision and clean C locale. Every listed
target must resolve to a recorded ordinary scanned library under the existing
guard, or use the new observed-root-link exception for an exact audited target
below. Other nested targets remain refused. Duplicate priority/order is retained. Main bytes may
change only while mapping/generator and other metadata including size stay equal;
the new raw hash remains in the result. Auxiliary raw bytes/metadata must match
B0 exactly: ANY byte difference is AUDIO_LDCONFIG_UNACCEPTED. No auxiliary semantic
decoder is added until a real raw change demonstrates that it is needed.

Helper/config, selected root metadata and regular/link identities must remain
stable. Missing/stale baseline state, leftover temporaries, configuration drift,
changed unowned SONAME links, unexplained mappings or auxiliary byte changes
fail closed, with checkpoint and bounded changed-field/path/hash diagnostics.
Private complete state records remain in the existing temporary container work;
normal public audio results contain only hashes/counts/status, not cache bytes.
Unrelated exceptions expose their class rather than arbitrary text/private paths.
A post-commit check failure stops this branch; it is not a rollback. Existing
container cleanup still owns disposal. No cache is restored or normalized to
force a pass, and no ALPM helper exit status is fabricated from state equality.

Only audio.py, test_audio.py and this scope note change. Source pins/caller Source
selection need a new Root freeze if adopted; no shared lock or workflow is edited
here. Inert fixtures mock all commands and target ownership, using ordinary
private temp data. Actual native configuration acceptance, generic-native checkpoint
results, loader correctness, user homes, audio/plugin operation, M2/16KiB,
performance and release acceptance remain NOT RUN/unestablished by this proposal.


## B0 fixed fakeroot include correction after38808131262

Artifact-only correction against exact Source7c96efd7454d18a43f2ed4f0dc9f93c7bd0530b3.
That actual attempt stopped at B0 before cache inspection or audio U because
/usr/lib/ld.so.conf.d/fakeroot.conf was outside the original finite syntax.
All574 already-held package archives and signatures match their input-lock byte
pins (lock SHA256b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9;
no fresh GPG verification). Their bounded MTREE metadata identifies only the
main config and fakeroot include in the two included directories. Actual config
members confirm that finite closure. The retained fakeroot1:1.37.2-3 input
contains exactly21 bytes
`/usr/lib/libfakeroot\n` (SHA256564c4c4d369d005702d825d34edc5e5568cb1ab6ee1b19fa03d0d672fb8b3aee),
root-owned0644, with ordinary root-owned0755 /usr/lib/libfakeroot. Only that exact
file path/content/hash/size/mode/UID/GID now enables that exact additional scan
directory. It is required on this held base. Symlinked directory/alternate alias,
changed metadata/content, missing file, or the same path directive in another
include remains UNACCEPTED. Generic include syntax and standard-dir alias rules
are unchanged; no arbitrary vendor directories were added to their allowlist.
The referenced directory contains regular0755 root-owned libfakeroot-0.so
(69168 bytes, SHA256c76794dc4470a2f57aeae1db1cfe4d2332beccec2c61211bf13a66025740dd9b)
and symlink libfakeroot.so -> libfakeroot-0.so. These bytes were read as data,
without extracting or executing the library. Their installed state is observed
at B0 and compared at later checkpoints; this correction does not replace the
existing package ownership/signature checks with a new payload allowlist.

The fixed directory joins the existing direct library/link, hwcaps, cache-target
and four-checkpoint comparisons; its libraries are not loaded. Actual cache
presence/mappings/aux bytes and all later checkpoint outcomes remain unknown.
Aux raw byte differences still fail with bounded before/after hashes; no decoder,
extra regeneration, cache restore or ownership/payload/signature/lock relaxation
is added. Existing587/593 inputs and exact locks remain held (original587 runtime
checkpoint). Historical38797262875 remains a separate bounded older-input PASS;
this failed attempt does not establish current audio install/removal/cache PASS.

## Explicit target observation after38812382520

Artifact-only correction against Sourceb44baf215b14c45b26e7a5f242060579d20f100c.
That run passed the exact fakeroot config/directory gates, then refused the B0
printed cache target /usr/lib/libvsscript.so. No audio install/removal or completed
checkpoint occurred; no aux byte comparison was reached. The retained public
error does not export the actual link chain or resolved target.

The574 held archive/signature byte pins were rechecked; their bounded MTREE
inventory has1714 direct scan-root symlinks, six resolving outside those roots:
four vapoursynth library links, one NSS library link, and the terminfo directory
link. Actual held vapoursynth/NSS/libp11-kit members confirm three regular root0755
targets and their fixed ordinary root0755 parents. Two targets are in
/usr/lib/python3.14/site-packages/vapoursynth; the third is
/usr/lib/pkcs11/p11-kit-trust.so. Exact size/hash pins are in LD_TARGETS. This is
expected package data, not a recovered observation of the destroyed container.
The terminfo data directory is not admitted as a library target.

Observe only those three exact files, with type/mode/UID/GID/size/hash and
device/inode/ctime/mtime identity. Their size/count contribute to the existing
2GiB/8192-entry observation bounds, and exact sizes are checked before hashing.
Record the four fixed canonical ordinary parent nodes as metadata, without adding
them to ldconfig scan roots or traversing their other children. Printed cache
addresses must still have a configured scan-root parent. An off-scan resolution
is accepted only at an exact pinned file and through at most16 already observed
root symlinks; each link step must be another observed root link or the exact
file. Unobserved intermediate links, parent aliases, direct nested cache paths,
changed bytes/metadata, other files and unknown target directories remain refused.
This added chain restriction applies to the new explicit-target exception; the
pre-existing ordinary-scanned-file resolution guard is unchanged and does not
independently record every intermediate off-scan alias returning to a scanned file.
All root links remain in the original scan snapshot. New explicit target records
join all three comparisons against B0; existing configs, ordered mappings, main
cache hash policy and aux raw-byte refusal are unchanged. No decoder, recursive
scan, regeneration, cache copy/restore, lock/payload/signature or ownership
relaxation is added.

The known fourteen additions were audited separately from retained metadata and
pinned source. Four dependency archives/signatures match their lock, four current
project validation maps contain no direct-root symlinks, FDK source defines only
four links terminating within /usr/lib, and the data-package recipes install
outside the scan roots. No additional outside-root link was identified there.
Complete current project archive member maps are not all retained; notably the
updater projection omits its member map and the pinned upstream Makefile bytes
were unavailable locally. This gap is not reported as a complete fourteen-archive
inventory, and no frames were decoded to fill it. Unknown actual targets continue
to fail closed. Generic-native retry and all four checkpoint outcomes remain
unestablished until Root adopts and tests a fresh source selection.

## B0/B1 raw auxiliary diagnostic proposal after38816517554

Artifact-only against Source65d50336b8137e67f871fc1b45811724c7e57a23. That actual
completed B0, installed six additions with exact593 inventory, then failed B1
auxiliary raw hash equality. Same68552-byte/root0600 auxiliary nodes had different
hashes. General equality comparisons, postinstall payload/dependency/database
checks and both removals were not reached. The actual bytes were not retained;
their semantics/cause remain unknown. Raw equality and every existing acceptance
comparison remain unchanged in this proposal.

For B0-587 and B1-593 only, after state collection/private snapshot and before any
comparison or following package mutation, read the sole fixed
/var/cache/ldconfig/aux-cache path with NOFOLLOW/NONBLOCK/CLOEXEC. Require a singly
linked regular file, positive size at most256KiB, and stable dev/inode/mode/nlink/
UID/GID/size/ctime_ns/mtime_ns across descriptor reads and the pathname check.
Read at most size+1 bytes; require the complete raw size/hash/type/mode/UID/GID
node to equal the already-collected checkpoint node. This join does not claim an
identity that the earlier ld_node did not record. Refuse raced/unavailable/more
than256KiB diagnostic data explicitly; this smaller diagnostic bound does not
alter the existing16MiB acceptance cache bound.

Write only fresh /out/audio-aux-B0-587.bin and /out/audio-aux-B1-593.bin (each at
most256KiB) with corresponding fixed-name JSON metadata companions (each at
most4KiB), exclusive/nofollow0600 leaves. The existing public /out bind and bounded
public-evidence bundle carry these four files without a workflow/exporter change.
There is no user-supplied path, host/user-root read, package/key/source binary,
directory sweep or additional helper command. At most512KiB of raw data is added;
the existing16MiB total/8MiB compressed bundle limits remain intact. The raw data
can include runtime keys/strings and source-level unclassified padding; Root must
review this exact public diagnostic scope before adoption/dispatch. No current
raw cache is exported by preparing this artifact.

Capture/read failures produce bounded UNAVAILABLE metadata and a fixed diagnostic
log marker with controlled reason/class only; no raw bytes enter the log. Partial
owned output is removed where possible. Metadata-output failure is explicit in
that marker. Capture success is not auxiliary acceptance; capture failure cannot
waive or replace the existing raw hash mismatch. B0 occurs before six-audio -U,
B1 before its first comparison; no B2/B3 or extra capture is selected. No existing
cache is written, restored, normalized, regenerated or decoded. Repeated fixed
output names are refused rather than overwritten. Root owns source selection,
publication and any next actual run.
