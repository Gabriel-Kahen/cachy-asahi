# Generic emulated ARM16K Perl5.42.3 runtime journey

**Source implementation and fenced synthetic controls only. This family's actual
preparation, VM, ALPM, trust and generic16K Reader/Root acceptance: NOT RUN / unissued.**

This separately owned family targets the Root-retained **perl5.42.3-1.3/aarch64**
archive: 22,071,176 bytes,
`647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22`.
Native Source is `25dc3e65bdb6137c87a9409067fe9b2cf6e9763f`, ref
`refs/heads/codex/native-arm-perl5423-v2-20261115`, run43692477455,
job132745843566, Original14153417247. Actual recipe is
`perl/packet/recipe/PKGBUILD` in that Source; the integration checkout's top-level
`packages/port/perl5423-source-candidate/PKGBUILD` still declares older1.2 and does
not identify the accepted pair. Source25's command delivery/checks retain the
same `/usr` system layout, shared/threaded configuration and dependency literals.
Native pair acceptance is bounded ARM4K evidence, not runtime16K acceptance.

Installed Source445b37a9475a4e92804954f4f0e3d0ac84cd9511,
run43734696338/job132874611601/Original14170381597 now has actual Reader2 PASS
and finite Root ARM4K installed lifecycle acceptance. Decision6168B
SHA084794319bf849ed1cc2a2387f502acf8cc82dec3fad11b00e3dc8cfc4096535
accepts upgrade/reinstall/noop, limited recorded runtime, dependency-protected
removal refusal and normal old-package rollback with explicit normal timestamp
and log differences. It does not accept full uninstall, generic16K, external XS,
M2 or release. `known/` retains only the exact small Reader/decision DATA bytes
for matching this prerequisite; no artifact code is loaded or executed. Published external
XS v6 Source898554db64007b7b6071e7d94cfcbbb06d906145 has no successful XS
qualification. This family does not import artifact code or claim that either
producer success or publication supplies installed acceptance. Archive operands,
signatures, public TEST admission, future16K Root input decision and baseline,
runtime/resource certificates remain NULL in `case.TEMPLATE.json`.

## Executable stages and authority

1. `adapter.py --prepare-case-packet` validates a caller-selected exact closed
   Source lock, case SHA256, retained material/certificate bytes, exact native
   archive/Source/Run/Job tuple, the **actual completed installed Reader2 and finite Root component decision**,
   and a separate future explicit Root16K input decision. It pins the original raw image,
   ownership/prepared metadata and original accepted first-PAM report. It writes
   only small code/metadata, never a package or image copy.
2. `controller.py prepare --execute-root-bound-actor` requires a fresh external
   Root authority tied to that packet, Source lock, output directory, own UID,
   rootless local Docker endpoint, immutable tool image, binary pins, exact RTC
   16K kernel and readonly quota device. It creates one cap0/NNP/network-none,
   read-only-root, no-device container with finite memory=swap, CPU and PID caps.
   The actor streams a bounded ext4 scan, joins actual complete ALPM ownership and
   baseline runtime hashes, checks actual free/allocated bytes, sparse-clones the
   raw image, and adds only case storage, a oneshot and its enablement link using
   debugfs. It verifies exact added namespace and unchanged baseline file bytes,
   modes, ownership and xattrs, then readonly fsck. No preboot ALPM occurs; existing hooks, PAM, credentials and platform files stay.
3. `controller.py boot --execute-root-bound-actor` is a distinct, separately
   Root-authorized invocation selecting the exact `prepared.json` and private
   original builder credentials. One attempt marker prevents accidental repeats.
   The actor creates a disposable qcow2 overlay, boots fixed software TCG/QEMU
   with no network/KVM, actual qualified RTC kernel and fresh nonce. The controller
   uses the original ordinary builder PAM serial login, verifies the original
   systemd/logind/DBus16K proof, runs the fixed cleared-environment user probe,
   waits for durable restoration, logs out normally and requests QMP quit.
4. After a natural, signal-free zero-exit QEMU reap/group census, the actor
   converts only its overlay to a sparse readback copy, replays journals only on
   that copy, readonly fscks and independently scans all baseline ownership and
   user/platform/database state. It extracts only bounded selected result DATA.
   `proof.py` joins serial/disk nonce receipts and every installed Perl ELF hash,
   checks actual LE AArch64 ELF64 PT_LOAD alignment/congruence>=16384 and checks
   functional output. All resulting reports retain NULL Root/VM acceptance.

The scanner supports only its reviewed <=4GiB 4KiB-block ext4 profile with bounded
node/file/read budgets. There is no geometry-resizing fallback. Unknown profile,
insufficient capacity, unqualified tool/kernel, quota unavailability or missing
closure refuses. Source111/155 are never assumed to contain Perl, a compiler,
headers, db5.3, libxcrypt or the full Perl ABI closure.

## Certificate and probe contract

`contracts.py` is the exact schema authority. The baseline certificate carries
actual inventory/count and accepted ordinary PAM/retirement/raw/prepared/ownership
pins. Runtime certification covers the **complete candidate namespace**, actual
baseline Perl namespace or explicit absence, a complete baseline namespace hash,
baseline and candidate resolved file hashes/modes/ALPM owners/versions, all helper
vectors, complete actual `.PKGINFO` constraints including `gdbm>=1.17` and the makepkg-expanded
`libcrypt.so=N-64`, actual
provider versions, reverse dependencies, interpreter/libperl/all XS ELF inventory,
recursive DT_NEEDED and GNU-version providers and actual fixed probe paths. A
Root claim of complete ELF coverage must come from the genuine independent
package audit; this code does not manufacture that audit from the package name.

The command selections are evidenced by Source25's
`perl/packet/recipe/{stage_commands.py,test_staged_commands.py,check_stage.py}`:
`/usr/bin/{corelist,json_pp,perldoc,pod2text,podchecker,prove,shasum,splain}`,
relative links to `core_perl/`, `prove` invoking normal `/usr/bin/perl`,
`perldoc -T -t -f print` using packaged core POD and `splain` using perldiag.
`runtime.pl` additionally requires exact Config paths and shared/threaded5.42.3;
exact loaded module/XS paths and actual `/proc/self/maps` shared-libperl mapping;
DB_File and GDBM real create/close/reopen/read; real zlib/bzip2 compress/decompress;
thread join/shared state; JSON and known SHA. These new roundtrips are source
implemented, not yet executed on candidate Perl. Their exact paths/API behavior
must be genuinely qualified by Root; the future certificate cannot be issued by
copying this modeled test fixture. No CPAN/network or compiler probe runs.
All package-owned candidate ELFs selected by the certified full inventory and
all11 command/functional logs are durably retained before package recovery.

`guest/root.sh` uses normal `pacman -T`, `-U`, `-Dk`, ownership and complete payload
checks. Private public-only TEST trust uses a single exact primary fingerprint,
valid nonrevoked current signature and `Required TrustedOnly` for global/local
files. The sole optional addition is the separately admitted, exact cached official
`db5.3`5.3.28-7 pair from the materials DATA audit, installed normally with the
unchanged baseline public trust and then normally removed after Perl recovery.
Its full namespace/ELF/ALPM closure, actual libgcc/libstdc++/sh baseline providers,
current signature/public trust and simultaneous staging/expanded/output budgets
are required. Empty `dependency_transaction` means no additions; no other package
is allowed.
No repository, signature bypass, `--nodeps`, `--dbonly`, `--overwrite`,
`--noscriptlet`, fake pacman, suppressed hook or unadmitted runtime dependency install exists.
The runtime certificate also requires independently observed baseline/transaction
effective hook equivalence and the complete two-default-directory hook namespace.
A baseline with additional or disabled alternate HookDir policy is held until a
new reviewed case can preserve it; merely preserving pacman.conf bytes is insufficient.
The ALPM baseline payload, modes/UID/GID, xattrs, normalized local DB bytes/metadata, users,
protected platform state and known unowned ldconfig caches must restore exactly.
Private TEST trust is retired and removed on success and on handled guest failure.
A forced VM/container failure retains HOLD and permits disposal only of owned
scratch, never the selected baseline.

Recovery is selected from actual certified inventory:

- No baseline Perl: normal `pacman -R perl`, no reverse dependents, exact original
  inventory and exclusive-path absence.
- Baseline Perl: require the genuine exact old archive, detached signature and
  original install reason; normal Required/TrustedOnly `pacman -U --asexplicit`
  or `--asdeps`. Restore the complete old inventory/payload and users. The
  certificate permits **only** Source445b's observed normal variance: one integer
  `%INSTALLDATE%` value in that exact old Perl `desc`; timestamp changes in the
  database root and old Perl directory/desc/files; transaction payload directory
  timestamps; known unowned ldconfig cache-directory timestamps; and append-only
  `/var/log/pacman.log` (or normal first creation from certified absence). Everything else, including REASON and all other DB bytes,
  modes/UID/GID/xattrs, unrelated file/database timestamps, accounts and user state
  remains exact. `restoration.py` implements the same single-field normalization
  read in Source445b `lifecycle-code/{actor.py,read_result.py}` and Root's actual
  `rollback_comparison`. Raw original/final desc records and raw DB manifests
  remain durable alongside normalized hashes; the host reports actual differing
  timestamp paths and original/final install dates. The normalizer is DATA only;
  it never writes the ALPM database or changes package files to make a pass.

The known two candidate hardlinks are explicitly certified and checked by device/
inode identity after installation. Actual PKGINFO4,483B/SHA31461fa035ad9f3761775dc412f3966c1c451c817e51eb5a2412808027133edc
and all seven expanded dependency literals are fixed from the Root-provided
materials DATA packet, whose seal is
cf921ed04c387beda254af1d50492ce94e7813ccf7736f80d6779dcf4f4c0456.
No new package/provider/symbol or signature acceptance comes from that passive
geometry/ownership audit.

## Resource, cancellation and recovery contract

No numeric candidate resource defaults are issued. Root supplies compressed
candidate+old-package staging, expanded payload, actual raw geometry/allocated
blocks/filesystem free, fixture and durable receipt/output sizes; simultaneous
clone+overlay+readback+logs caps and reserve; host/guest memory and host reserve;
finite CPUs/PIDs/prepare/boot/cleanup/guest phase/log/output limits. Fixed phase
multiplicities and the frozen cleanup tail must fit the assigned envelope.

The host performs **readonly Linux Q_GETQUOTA for its own UID** before Docker and
throughout all commands and serial waits, alongside allocated-block, disk reserve
and host RAM checks. Missing/unlimited/unknown quota returns HOLD. It never writes
quota, signs, acquires leases or silently switches a Docker transport. A single
lifetime owner recovers ambiguous create using exact labels/CID/name, validates
all mounts and runtime limits, records natural retirement, then removes only that
verified container and proves absence. INT/TERM defer during owned cleanup.
Budget failure stops work; the reserved cleanup tail does not depend on a now
failing quota guard being able to launch cleanup. VM STOP and process group
retirement are fixed and finite. Failed partial images/logs are retained for Root
inspection; scripts do not recursively delete arbitrary outputs or input trees.

## Future invocation shape (not executed)

```text
python3 -I -B scripts/integration/arm16k_perl5423_vm/adapter.py --prepare-case-packet
  --source-lock-sha256 ROOT_SOURCE_LOCK_SHA256 --case /PRIVATE/Root-case.json
  --case-sha256 ROOT_CASE_SHA256 --materials /PRIVATE/material-paths.json
  --baseline /EXACT/accepted-base --baseline-report /EXACT/first-PAM.json
  --nonce FRESH_32_HEX --output /PRIVATE/FRESH/packet

python3 -I -B scripts/integration/arm16k_perl5423_vm/controller.py prepare
  --execute-root-bound-actor --packet /PRIVATE/FRESH/packet
  --baseline /EXACT/accepted-base --kernel /EXACT/qualified-RTC-kernel
  --authority /PRIVATE/Root-prepare-authority.json --authority-sha256 EXACT_SHA
  --source-lock-sha256 ROOT_SOURCE_LOCK_SHA256 --output /PRIVATE/FRESH/prepared

python3 -I -B scripts/integration/arm16k_perl5423_vm/controller.py boot
  --execute-root-bound-actor --packet /PRIVATE/FRESH/packet
  --baseline /EXACT/accepted-base --kernel /EXACT/qualified-RTC-kernel
  --prepared /PRIVATE/FRESH/prepared --credentials /PRIVATE/original-credentials.json
  --authority /PRIVATE/Root-boot-authority.json --authority-sha256 EXACT_SHA
  --source-lock-sha256 ROOT_SOURCE_LOCK_SHA256 --output /PRIVATE/FRESH/boot
```

`--materials` accepts a canonical JSON map of every `adapter.NAMES` role to an
existing absolute original path, or a legacy single directory. A sibling
`extra-materials.json` maps exactly the needed `dependency_archive`,
`dependency_signature`, `rollback_archive`, `rollback_signature` roles to their
existing original paths. No extra roles are allowed. Controller mounts each
original file read-only at its fixed guest name; candidate archive, signature,
public certificate and decisions can live in different retained directories.
This avoids making new host archive/signature copies to satisfy staging layout.

`authority()` defines exact closed authority fields; unissued
`authority.TEMPLATE.json` is only a field guide. Root must supply current genuine
facts and independently accept them. No actual Docker, VM, debugfs, ALPM, GPG,
compiler, Reader, lease, acquisition/publication, image/archive copy or signing
was performed in this source task. Generic emulated16K runtime remains NOT RUN;
native16K hardware, M2, performance and release remain NOT RUN/unaccepted.

## Source seal authoring and Git regression

Stage all ordinary source leaves first, with Git0644/0755 modes. Run
`python3 -I -B scripts/integration/arm16k_perl5423_vm/seal.py --seal-staged-source`,
then stage the regenerated source.lock.json and commit. The sealer reads the Git
index, requires exact staged/worktree bytes and Git modes, and refuses ignored,
untracked or special leaves. It never seals __pycache__ or private0600 modes.
Run `python3 -I -B scripts/integration/arm16k_perl5423_vm/test_git_roundtrip.py`
after commit. It exports only the committed source family to a fresh temporary
directory with actual Git modes and runs the strict Source predicate under an
operation fence. No package/image export or actor runs.

## Explicit expected-package-payload input path

`ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1` is a separate input kind,
never an installed-guest/runtime certificate. Root must explicitly select it in
`Root_decision.input_kind`; there is no fallback from the original actual-runtime
input kind. Native/installed Root decisions, accepted baseline16K ordinary-PAM/
raw/prepared/ownership proof, fresh public trust, explicit db5.3 admission,
resources and separate prepare/boot authorities are still mandatory. The new
kind retains NULL actual guest hash/owner/namespace and Root runtime-certificate
fields, and runtime_acceptance=false. Probe path evidence is named
`expected_paths_source_verified`; it makes no installed-path claim before ALPM.

`expected_payload.from_packet(directory)` reads only the exact final ABI DATA:
seal2621B/SHA bef60067b67633c64e9eab447b9de7bae0dc21c7d4f9b3265c592a15a7987e24,
expected-runtime-providers40826B/SHA
35de58576441fbd5857f21cbbafdeb72b98dd6b8daee86d42aa4ceeaf33da75d,
and pinned namespace/packages JSON. It imports none of that packet's Python code.
The small `known/expected-payload-inputs.json` projection retains all81 exact
rows, original pins, seven required symlink associations and all NULL/false
acceptance fields. It is expected input DATA. It does not attest actual guest
files, fresh signatures, runtime symbol scope, dlopen/NSS/PAM or static linking.
Root may embed it in the explicit expected-input certificate after independent
review; `expected-payload-certificate.TEMPLATE.json` leaves that issuance NULL.

The new input kind joins each expected byte/hash/package/version to the correct
baseline, db5.3 or Perl phase. Before cloning, the actor compares actual raw
baseline hashes, sizes, UID/GID and complete ALPM owners against those expectations,
including the exact filesystem `/lib -> usr/lib` chain. It retains a separate
`baseline-provider-observation.json` DATA report with Root/runtime acceptance NULL.
Inside the fresh VM, before the first **mutating** ALPM transaction, root checks
all baseline provider bytes/modes/UID/GID, package versions and ownership (including
all17 db5.3 ELFs if db5.3 is already in that baseline), and
checks exact alias targets and package ownership using readonly ALPM queries.
The raw observed receipt is retained in receipts and durable results and joined
by the passive output proof. A wrong byte, alias, owner or version refuses before
`pacman -U`; matching archive inputs alone cannot supply this observation.

All54 Perl and17 db5.3 roots plus10 reachable inherited provider ELFs remain
expected static ABI inputs until their actual phase runs. Current signatures,
ALPM dependencies and normal rollback remain independent gates. No actual raw
observer, VM, ALPM, GPG, compiler, Reader or quota actor ran in this increment.

## Exact host Docker CLI binding

Every prepare/boot authority must contain `docker_cli` with the absolute resolved
path, bytes/SHA256, UID/GID, mode, device, inode and nlink. There is no default
path. The caller must select an ordinary nonsymlink single-link executable owned
by root or the current UID, with no group/world write or set-id bits. The
controller checks its current identity and hash before output/actor entry;
runtime rechecks and rewrites every fixed `docker` vector to that exact absolute
operand, including CID recovery, wait and removal during cleanup. The same
binding remains active until cleanup ends. A missing, replaced, aliased or
hash-mismatching CLI refuses; no alternate executable or PATH fallback is used.

Child PATH remains `/usr/bin:/bin`. Only explicit own-UID rootless DOCKER_HOST,
HOME and XDG_RUNTIME_DIR are passed for Docker calls; DOCKER_CONTEXT is cleared.
A Root wrapper's broader PATH therefore cannot redirect the command or repair a
missing binding. The ordinary actor's finite PATH and all image/mount/capability,
resource/custody/cancellation/retirement checks remain in force.


## Literal ALPM ownership DATA and separate baseline observation

ALPM ownership keys have a separate bounded parser from command/runtime paths.
It accepts punctuation such as `usr/bin/[`, comma and literal backslash text
without unescaping or normalizing it. It rejects absolute paths, empty/dot/dotdot
components, controls, duplicates and missing exact namespace keys. Exact empty
`files` bytes mean no owned paths (observed retained ca-certificates/dbus-units
metadata packages); nonempty malformed records and empty descriptions refuse.
The portable retained-r8 regression contains selected exact keys plus provenance;
the namespace in that test is synthetic, not a new raw observation.

Original111 lacks `ownership.json`. Both adapter and controller now accept
`--baseline-ownership /PRIVATE/NEW/ownership.json` with the same exact baseline
certificate byte/hash requirement, leaving the original raw/prepared directory
unchanged. Omitting it retains the legacy colocated path and fails if absent.
No image/archive copy, hardlink or symlink is needed to satisfy a layout.

`baseline_observer.py` provides a separately Root-authorized **read-only** scan
using the frozen `Ext4Reader` and the actual `image.owners` parser. On import it
does nothing. Its template leaves every Root grant NULL; a fresh, exact,
accepted `ROOT_PERL5423_READONLY_BASELINE_AUTHORITY_V1` is required. Root must run
it under generic CUSL/S supervision and whole-process memory/CPU/PID/quota/output
controls; the program only enforces read, walltime, input identity/hash and
aggregate output bounds. It imports no artifact code, launches no subprocess,
and performs no mount, debugfs, ALPM, network, lock or quota operation.

A future Root invocation is:

```sh
/usr/bin/python3 -I -B /EXACT/SOURCE/baseline_observer.py \
  --observe-readonly-root-bound --authority /PRIVATE/ISSUED/observer.json \
  --authority-sha256 ROOT_AUTHORITY_SHA --source-lock-sha256 ROOT_SOURCE_SHA \
  --output /PRIVATE/FRESH/readonly-baseline-DATA
```

It opens the exact original raw read-only, joins its prepared package inventory,
retains `ownership.json`, complete `namespace.json`, raw `alpm-records.json`, and
`observation.json`, then rechecks original inputs. Its report and all Root/runtime
acceptance fields stay NULL. It neither issues a baseline certificate nor
supplies PAM or filesystem-integrity acceptance. Worker verification uses only
synthetic DATA and retained ALPM record bytes; no actual raw scanner ran here.


## Explicit HOME Btrfs trial mode

The original `READ_ONLY_Q_GETQUOTA` resource branch remains strict: finite
observed quota headroom is mandatory and every error holds. A separate
`READ_ONLY_HOME_BTRFS_ENOSYS_FSTATVFS` branch is available only through an exact
Root-issued resource certificate and matching phase/packet/controller authority.
It is restricted to `/home/gabe`, UID1000, device54, Btrfs `/@home` subvolid257.
`home-storage-guard.TEMPLATE.json` declares the shape; phase outputs, exact closed
Source lock and fresh finite validity are NULL until Root issues them. HOME
controller authority `quota_device` and resource quota headroom fields must be
NULL: this branch makes no quota headroom, other-quota or reservation claim.

The whole-actor guard walks directory FDs without following aliases and selects
the held FD's actual mount ID from bounded kernel metadata. Before and after the
allocation census it repeats readonly own-UID `quotactl_fd`, Linux x86_64 syscall
443 / Q_GETQUOTA, and fstatvfs. Only `result=-1, errno=ENOSYS38` is admitted and
reported as `UNSUPPORTED_NOT_UNLIMITED`. EPERM, other errors, success, an unknown
filesystem, changed mount or expired profile hold. Live f_bavail*f_frsize must
cover the initial complete physical plan and then the same finite live reserve.
All-zero files/ffree/favail means `UNREPORTED`; no inode headroom is invented.
Reported inode counters must be consistent and cover16384 initially/4096 live.
The existing150000-node allocation census and allocated-byte/component caps stay
in force. Memory, CPU/PID, time, cancellation, owned cleanup/recovery and all
Perl expected-provider/pre-ALPM checks are unchanged.

HOME reports use `storage_guard` / filesystem-capacity scope, never quota PASS.
They explicitly retain unsupported own-UID quota, other quota UNCLAIMED and
capacity_reservation=false. This opt-in mode is a guarded first-trial path, not a
global fallback for missing quotas or an observation that storage is unlimited.
No worker HOME filesystem/quota query or actor ran; controls use synthetic FD,
mount, syscall-return and fstatvfs DATA only. Root owns fresh admission and runs.


## Strict SHM quota backend compatibility

The strict `READ_ONLY_Q_GETQUOTA` branch now opens the selected `/dev/shm` mount
directory with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` (all components walked by
FD) and calls Linux x86_64 `quotactl_fd` syscall443, command0x80000700, own UID,
with the72-byte if_dqblk layout/valid offset64. It closes the directory FD on
success and failure. Legacy libc.quotactl expected a block device and returned
ENOTBLK for this actual mount-directory operand; it is no longer called.

Only the backend changes: the existing block-limit/used-space valid mask,
conservative minimum nonzero hard/soft byte limit, finite-limit requirement,
zero-clamped remaining headroom and live reserve checks remain. ENOSYS/EPERM/
ENOTBLK and every other unsuccessful strict query HOLD. There is no fallback to
HOME semantics. HOME already used its separate actual FD syscall443 query and
continues to admit only exact ENOSYS38 within its explicit Root profile.
Synthetic controls exercise the actual ctypes argument/layout construction with
CDLL/syscall mocked, verify FD flags/cleanup and errors, and perform no real quota
query. Frozen Root observer Source0acdb...4886 is untouched by this increment.


## Observed Tool529 e2fsck hardlinks

Root's actual six-binary Tool529 DATA records e2fsck nlink4. A dedicated image-tool
hasher now admits that exact four-link e2fsck layout (or its ordinary one-link
layout), while all five other fixed tools require one link. All six must be
regular root:root0755 files, within64MiB, with stable device/inode/mode/owner/link/
size/timestamp identity and exact Root-selected bytes/SHA after alias resolution.
Generic DATA/archive/authority/host-CLI single-link guards are unchanged. No tool
execution is used for qualification. The Perl controller already starts Docker
with `['docker','start',name]`; the unsupported start sig-proxy flag is absent.


## Separate HOME device identity domains

The HOME profile explicitly pins both userspace `fstat st_dev=54` and kernel
mountinfo `kernel_mount_device="0:33"`. They are independently reviewed values;
os.major/minor of54 must not be used to derive the kernel pair. The guard still
selects the actual held FD's mount ID, checks Btrfs/@home/subvolid257, and requires
stable before/after mount records. Unknown pairs/filesystems remain HOLD. Update
the closed profile's filesystem declaration and all Source bindings after this
fix; old draft packets are not silently rewritten or granted an exception.


## Absent global trust, isolated official db trust

Original111 has no `/etc/pacman.d/gnupg`. An admitted db5.3 transaction now requires
`dependency_transaction.official_trust` matching `official-trust.TEMPLATE.json`:
exact three baseline `/usr/share/pacman/keyrings/archlinuxarm.gpg`, `-trusted`,
`-revoked` rows, the sole signer68B3537F39A313B3E574D06777193F152BDBE6A6, Root
policy review, revoked-signer absence and explicit scratch/global-absence policy.
Each file row equals baseline_files/files with its actual bytes/SHA/mode644,
resolved path and archlinuxarm-keyring owner/version. Empty revoked DATA is valid.
`baseline_public_trust` is the canonical JSON pin of exactly those three **relative
path → image.stable(actual_node)** rows; it no longer means an assumed global
GPG directory. The actor compares actual raw hash/metadata/ALPM ownership and
absence before preparation. Root still admits signatures/current trust separately.

Guest checks the same three actual files, normal trusted/revoked text and ALPM
owners before import. It imports only the unchanged public ring into bounded
volatile scratch, exports the sole admitted primary, and imports just that key
into a separate `/run/arm16k-perl5423-vm/official-trust`. It rejects secret keys,
requires one exact primary, sets ownertrust only for that Root-admitted signer,
and verifies the exact db archive/signature with one matching VALIDSIG and
TRUST_ULTIMATE. No bulk ownertrust, signing key, global GNUPG directory or changed
Required/TrustedOnly policy is used. Normal db install/remove use explicit scratch
GPGDir. All import/export/list/trust/verify/retirement calls are time/log bounded;
public-only GPG calls disable autostart and key retrieval, writes are capped,
success and failure retire/remove scratch homes. Nine extra GPG/retirement slots
are charged when db is added: full envelope16*gpg_seconds + existing transaction,
probe, overhead and cleanup bounds. With prior15/60/240/90/120 timings that is
1010s;900s refuses, e.g. boot1200s needs a freshly reviewed corresponding outer cap.
No actual GPG/ALPM/guest operation ran in this increment.

## Original log absence and hash comparison prerequisites

When the certified baseline pacman.log is absent, normal ALPM still writes its
normal log. Guest retains that bounded complete log in durable receipts, then
removes only that newly created unowned log to restore absence. Readback requires
actual absence and exact safe retained receipt hash/size/ownership. Only `/var/log`
parent mtime from this normal create/remove is additionally allowed; unrelated log
residue refuses. An existing baseline log retains its original-prefix/append-only
policy. User/database/payload/global-trust preservation gates stay in force.

`cmp` is no longer a prerequisite or guest command. Both guest entry points use
the reviewed `same_bytes` API implemented as bounded regular-file lengths plus
SHA256, propagating stat/hash failures. This is cryptographic hash equality,
not a new literal-byte comparison claim; no Python/Perl is needed for recovery.
The local `test_guest_data.sh` regression covers literal binary/empty/equal/
different/missing/symlink operands and command failures, plus trusted/revoked
policy DATA, without GPG/ALPM/VM execution. Frozen helper bytes remain unchanged;
Root sources the reviewed comparison override after the frozen helpers.


## Exact alternate AArch64 PT_INTERP

An ELF's literal PT_INTERP may differ from the selected loader only for the actual
`/lib/ld-linux-aarch64.so.1` and `/usr/lib/ld-linux-aarch64.so.1` pair. Both strict
paths and the canonical path must join identical baseline/file bytes, size,
mode, glibc owner/version and canonical resolved target. The expected-input
certificate must retain the exact filesystem-owned `/lib -> usr/lib` alias with
its observed baseline version/root metadata; ordinary raw and guest alias checks
remain mandatory. Missing/wrong alias, differing target/hash/metadata or arbitrary
paths refuse. ELF interpreter facts are preserved; no double-slash normalization
or relaxed general guest-path grammar is introduced.


## Actual prepare-r1 cleanup name capture

Actual Root prepare-r1 produced prepared DATA and actor exit0, then the controller
held during cleanup because a later material loop rebound the closure variable
`name`. Scope.validate now captures the immutable original name as a definition-
time default. All image/label/mount/cap/resource checks remain unchanged; wrong
names still refuse. The actual retained report references and closed-HOLD scope
are in known/actual-prepare-cleanup-r1-reproducer.json. No r1 Source, packet, actor
output or Root cleanup was edited. A regression compiles the actual Scope class,
rebinds the material-loop name and requires original identity acceptance and
wrong-name/image refusals. No actor runs in that regression.

### Compression lifetime successor (2026-11-16)

Retained Source53/case8 installed Perl5.42.3-1.3 and passed its version probe,
then aborted during the functional probe with `free(): double free detected in
tcache 2` (exit134). That case and the qualified package archive are unchanged.
The actual Source leaf is `guest/runtime.pl`, copied by `adapter.contents`;
`image.py` does not generate this Perl program.

The pinned upstream snapshot `bc3dab4d4f66de5ea67dda34e5feb5230a54c603`
(22610875 bytes, SHA256
`16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725`)
contains Compress::Raw::Bzip2 2.218. Its `Bzip2.xs` constructor order is
appendOutput, blockSize100k, workfactor, verbosity. The old `(1,9,0,30)`
requested verbosity30; the successor uses explicit workfactor30/verbosity0.
`bzclose` finishes output; native allocation is released separately by DESTROY.
No Bzip2 CLONE/CLONE_SKIP implementation is present. Live native stream
references therefore must not cross this probe's interpreter-cloning boundary.
This is a probe lifetime correction, not a package thread-safety qualification.

A bounded host matrix on Perl5.42.2/Bzip2 2.213/Zlib2.222 reproduced SIGABRT
with original or quiet live streams, including either compression family alone.
Both lexical-scope variants passed roundtrip plus thread join. This supports
the lifetime diagnosis. At that time the exact candidate's corrected ARM16K
behavior was unexecuted; the later Source54/case9 observation is recorded below. The recipe still performs actual DT_NEEDED checks, then the full
`TEST_JOBS=2 make test_harness`, then check_config; no recipe/test exclusion changes.

`test_runtime_lifetimes.py` runs only installed HOST core-module APIs in fresh
temporary DATA with core0, CPU3s, wall6s, AS256MiB, and per-file64KiB limits.
It checks DB_File/GDBM/zlib/bzip2 roundtrips, observes all four stream objects
expire via weak references before thread creation, then checks join/shared state.
Its lifetime mutant refuses before creating a thread with live streams. The
full target Config/module/XS/libperl/path checks and success frame stay intact.
These checks provide HOST API/lifetime evidence only; no candidate ARM16K,
restoration, M2, performance or release acceptance follows. New Source and case
authorities require separate Root issuance; unissued selectors remain NULL.


### Postboot actor failure diagnostics (Source55 successor)

Retained Source54/case9 reached genuine INSTALLED, all12 PROBE checks and RESTORED
PASS frames on aarch64/16384, then observed normal PAM logout. Its final controller
and outer outcome is CLOSED HOLD, with no VM/runtime/Root qualification. Docker
wait's CLI exited0 but stdout was exactly `1\n`; inspect independently recorded
container ExitCode1/OOMKilled=false. QEMU and readback-convert, journal-copy-only,
and readback-readonly-fsck receipts each record natural exit0. The stopped actor
failed after those commands and before preservation/results export. The retained
fsck stdout includes free-block/inode count warnings despite that command's
recorded exit0; these words do not identify the later Python exception. The old
Source/case/output remains immutable and its exact post-fsck cause is UNKNOWN.

The prior actor allowed uncaught postboot exceptions to escape only to unattached
Docker logging, which was not retained before owned container removal. The new
actor writes only fixed `actor-failure.json` (at most4096 bytes, exclusive0600)
when an admitted phase raises, then rethrows the original exception. A finite
postboot stage identifies QEMU, conversion, journal replay, readonly fsck, either
scan, preservation, retention, trust absence, report write or scratch removal.
The reason is an allowlisted public category/code/message. Unknown exception
text, credentials, environment and arbitrary absolute/private paths are omitted;
only sanitized already-certified `/usr` runtime operands may accompany the three
known path-bearing preservation reasons. No raw image or Docker log is exported.

On failed actor completion, the controller accepts this diagnostic only after
same nonce/Source/phase joins and a whole bounded stable read of an ordinary own-
UID/GID, single-link0600 file. Canonical schema, fixed stages/reasons and NULL
acceptance are mandatory; malformed, truncated, changed, aliased or mismatched
DATA refuses. The report records CAPTURED/ABSENT/REFUSED diagnostic state. It
still applies the identical zero-exit/nonrunning/non-OOM actor gate and natural
QEMU/retirement checks. A diagnostic never changes HOLD to PASS. Guest-HOLD
priority, fixed command arguments, time/output/resource caps and all restoration,
preservation, trust and later Root qualification gates remain unchanged.

`test_natural_retirement.py` models the actual boot function through readonly
fsck, fails the next scan, verifies the bounded retained receipt and original
exception identity, and exercises unsafe/mismatched/changed DATA refusals. It
opens no actual image/credential/key home, executes no Docker/GPG/VM or lease,
and supplies no fresh Root evidence. Source55 still requires separate Root
publication, review and a new once-only case; it does not repair or qualify the
unknown Source54 postboot failure merely by retaining future diagnostics.


### Historical late-capture cache-parent restoration (Source56)

Source55 case10's independent preservation result remains HOLD. Root's public
readonly observation identified only unreviewed `/etc` directory timestamp
variance: before1794708503.000000000, after1794823231.184000000, with the reported
stable directory metadata equal. Its successful installation/functional and
restoration frames and natural QEMU exit do not override that final failure.
This source correction neither reruns nor accepts case10.

Before any ALPM transaction, `cache_etc_timestamp_capture` opens the ordinary
root-owned0755 `/etc` directory and records its device/inode/type/mode/UID/GID/
link count and exact nanosecond mtime. It exclusively creates a fresh ordinary
root-only0600, single-link, zero-byte `cache/etc-mtime.reference` under the
existing root-only0700 disposable case cache. Already-certified GNU `touch -m
--reference=/etc` captures the original mtime; no new tool, package or runtime
requirement is added. Symlink/noncanonical directories, occupied references,
wrong owner/mode and reference mutation refuse.

After normal package/dependency recovery and existing exact cache byte/metadata/
xattr comparison, `cache_etc_timestamp_restore` repeats the original directory
identity checks and verifies the unchanged reference. `touch -m --reference`
restores only mtime through the still-open original directory FD. The original
pathname must still name that same directory before and after the operation;
even a replacement between the last precheck and touch cannot redirect the
write onto the replacement inode. Directory aliases, replacement, mode/owner/
group/link-count changes or a missing/replaced/tampered reference fail. The
helper does not modify directory atime, contents, permissions or xattrs; ordinary
ctime changes caused by timestamp restoration are not presented as a baseline
ctime restoration. It removes the reference and closes the FD before the final
payload preservation snapshot and final sync. Errors propagate to the unchanged
HOLD path. No receipt allowlist entry is needed because the reference is gone.

`image.preserve`, every prior directory timestamp allowance, cache/file/payload/
configuration/xattr check, normal hook/scriptlet/dependency operation, package
archive, trust decision and execution/output budget remain byte-identical to
Source55. In particular `/etc` timestamp variance remains forbidden. Removing
the two new helpers and their two calls exactly restores Source55 `guest/root.sh`
SHA256 `9be11484131188df57b7f23fec3fe9e75b4fe9066833f752fed7353b7b513aa0`. The focused test pins this whole predecessor inverse;
the handoff also checks every unchanged predecessor leaf and CI's one-line
inverse. The new sealed family has56 total files (55 lock members plus the lock),
compared with Source55's55 total files. Its Source/ref/authority/case/image/VM/
ALPM/runtime/Root acceptance selectors remain NULL.

`test_etc_mtime.py` runs10 focused controls on ordinary, owned temporary HOST
files under CPython3.12.13 and3.14.6, with no skips in the observed runs. It executes
only the extracted two helpers in non-root Bash fixtures, projects `/etc` into
scratch with an exact inverse, and substitutes the test owner's UID/GID in the
Root-only assertions. These are HOST GNU touch/stat/proc-FD results, not ARM or
VM execution. The tests restore nonzero nanoseconds for initially absent and
present caches, preserve atime/configuration/user xattrs and inode identity,
reject unsafe directories/references and modeled owner/group changes, exercise
replacement during touch, propagate touch/removal failures, and confirm the
unchanged independent preservation function still refuses modeled `/etc` drift.
The unchanged broader `test_controls.py` has54 passes and one existing error
on each local uv interpreter: its pidfd mock requires `os.pidfd_open`, which
these builds do not expose. This is not a complete broader-suite PASS and is
not suppressed or changed here. The eight existing root-progress controls,
synthetic guest DATA checks and shell syntax pass.

The fixture permits only its fixed host Bash subprocess and denies Python-side
network/ctypes/exec/fork/lock actors; child limits are CPU3s, wall6s, AS128MiB,
file64KiB, FD64 and core0. The exact CI command, in both existing Python jobs, is:

```sh
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_perl5423_vm/test_etc_mtime.py
```

Publication/outer-capsule DRAFT only: Root can export the newly committed family
at its reported exact Git subtree and lock, keep all existing closed capsule
payloads/tools/authorities unchanged, and replace only the reviewed Source
binding and this finite family. Source/ref publication, exact capsule commit,
fresh nonce/authorities and a new once-only actual case remain Root work; no old
capsule or completed case is relabelled. Actual new VM/ALPM/runtime/Reader/Root
outcomes remain NULL; native16K hardware, M2, performance and release stay open.


### Historical unpublished preboot /etc-only attempt (58-file DRAFT)

Source56 case11 remains consumed HOLD and must never be retried or reentered.
Root's supplied public readonly observation reports prepared `/etc`
1794708503.000000000 versus final1794827034.205988225, with stable directory
metadata unchanged. Guest install/probe/recovery PASS frames and natural QEMU
exit0 do not override the preservation failure. Source56 captured the directory
only after boot. This successor uses the authenticated preboot scan; it does
not establish which boot operation changed the timestamp.

`adapter.contents` adds exactly one public packet file, `preboot-context.json`
(root0644). Its canonical DATA binds the Source lock, exact original case-file
pin, case nonce, complete baseline certificate pin, independently selected raw
and prepared baseline pins, and complete stable namespace pin. Directory times
are deliberately absent from `image.stable`, so that namespace pin alone is
not timestamp evidence. The original independent raw pin is indispensable.

After the prepare actor has scanned the independently pinned original raw,
validated the complete namespace, ownership, providers, hook policy and other
existing gates, `preboot.descriptor` checks the exact context and selects only
ordinary root0755 `/etc`'s actual inode, link count and exact mtime seconds/ns.
It never reads a running-guest clock or late `/etc` timestamp. A bounded,
canonical one-line `preboot-etc.tsv` (at most256 bytes, root0600 single-link)
is created exclusively and added at `/var/lib/arm16k-perl5423-vm/preboot-etc.tsv`.
This is the only prepare-generated image leaf beyond the adapter's declared
packet membership. Both public DATA leaves remain unchanged in the image;
neither is removed during recovery. The existing transient
`cache/etc-mtime.reference` is still guest-created and removed normally.
Prepare readback checks exact additions, descriptor SHA/size/link count, and
unchanged original `/etc` inode/type/mode/UID/GID/link count/xattrs/atime/mtime.
The host `prepared.json` joins descriptor/context pins and final prepared raw.
No image geometry, resource budget, package, hook, trust or root-service change
is made. Existing staging caps apply to both additional leaves.

The Root-selected prepared-manifest pin is already joined to boot authority.
`qemu_argv` adds one explicit kernel DATA token,
`arm16k_perl5423_vm_preboot_etc_sha256=SHA`, from that manifest's descriptor pin.
The guest requires exactly one token, matches the ordinary descriptor SHA,
checks its canonical fixed schema/length, nonce and context SHA, and compares
its certified inode/link count to both `/etc` and the actually opened FD.
Missing/duplicate tokens, aliases, changed context, malformed numeric fields,
wrong mode/owner/link count and identity substitutions refuse. The descriptor
identity is captured before its hash/read and checked afterward and before
restoration. No descriptor content is sourced or evaluated as shell.

The guest builds its private zero-byte reference using already-certified GNU
`touch -m --date=@SEC.NS`, then checks exact numeric seconds/nanoseconds using
already-certified `date`. After normal transactions and exact cache restoration,
the existing held-FD `touch -m --reference` restores the certified preboot mtime.
It does not set atime, permissions, UID/GID, xattrs or contents; ctime restoration
is not claimed. The reference is removed and FD closed normally. Only the two
timestamp helper bodies change in `guest/root.sh`; the15 focused controls pin
its complete Source56 inverse SHA256
`48b99a1d9173e38a71259acea52d7f6a0dc5aeea4cc095e4619e0aac1d6502b4`.

`image.py` and its strict preservation predicate remain byte-identical to
Source56. `/etc` timestamp drift is never allowed or normalized. A separate,
stricter readonly actor check now also requires original/final `/etc` inode,
links, type/mode/UID/GID/xattrs and exact atime/mtime sec/ns equality before the
unchanged predicate. There is no atime restoration or allowance. This closes
the earlier independent atime gap and may expose pre-existing boot atime drift;
no actual case has demonstrated this new guard passing. Every `/etc` child,
configuration byte, mode, ownership and xattr stays under the existing strict
namespace/preservation requirements.

`test_etc_mtime.py` runs15 HOST controls, including preboot timestamp, earlier
boot drift before capture, transaction/cache replacement and exact original
zero/nonzero-nanosecond restoration, unchanged atime/configuration/xattrs,
pre-open and post-open directory substitution, malformed DATA, metadata,
nonce/provenance/hash/token/reference tampering and error propagation.
`test_preboot.py` runs7 fenced DATA controls for every provenance join,
namespace/metadata bounds, kernel binding and stricter original-atime/identity
refusals. These are owned temporary host filesystem/GNU-tool and modeled scan
results, not ARM/VM or ALPM execution. The new family has58 total files
(57 lock members plus the lock), two more than Source56.

Run both controls with isolated Python3.12 and3.14, then existing source, guest
DATA and shell-syntax checks. On the observed local uv3.12.13/3.14.6 builds,
`test_controls.py` retains its existing `os.pidfd_open` mock API error; report
54 passes/one error rather than claiming the whole broader suite passed.
The system Python3.14.7 runs all55 broader controls successfully. All actual Source
publication, authority issuance, packet/image preparation, Docker/GPG/VM/ALPM,
Reader/runtime/Root acceptance fields remain NULL in this source increment.

Root's DRAFT handoff must carry exact commit/subtree/count/lock, the complete
binary Source56 inverse and outer-capsule inverse, original public
Source0ba807e67554549939644a7cc7f138c3efda8b2b and fixed baseline/raw/tree/certificate
pins. Only Root can publish, issue a fresh nonce and new actual case/authorities,
or execute actors. No historical capsule/case is relabelled. Case11 is terminal
HOLD. Native16K, supported Asahi/M2, performance and release remain unqualified.


### Certified nine-path absence and three-parent recovery (revised DRAFT)

The unpublished e14/Source58 attempt is superseded and must not be published or
entered as operationally ready. Root's case11 readonly metadata observation
shows `/etc` inode16 unchanged but links37 before versus38 after, `/etc/audit`
links2 versus4, and unchanged `/etc/udev` links4. Its exact nine paths below
are absent from the authenticated prepared baseline and present in the final
case11 image. Those timestamps suggest early boot activity; they do not establish
causality or prove the next guest's initial state. Case11 remains consumed HOLD.
This successor performs an actual initial guest snapshot before ALPM and fails
if the later recovered state cannot join it.

The fixed policy is exactly:

| Relative path | Initial allowed type/mode | Maximum body bytes |
| --- | --- | ---: |
| `etc/.pwd.lock` | regular0600 | 0 |
| `etc/.updated` | regular0644 | 4096 |
| `etc/audisp` | empty directory0755 | no children |
| `etc/audit/plugins.d` | empty directory0750 | no children |
| `etc/audit/rules.d` | empty directory0755 | no children |
| `etc/ld.so.cache` | regular0644 | 1048576 |
| `etc/os-release` | symlink0777 | 4096 |
| `etc/udev/hwdb.bin` | regular0444 | 16777216 |
| `etc/vconsole.conf` | regular0644 | 4096 |

All initial nodes must be root-owned. Regular files/symlinks must be single-link;
empty directories must have two links. No arbitrary additional path, recursive
cleanup, wildcard operand, root-home/trust inspection or timestamp allowance is
introduced. A baseline containing any selected path, alias or descendant is
refused by prepare rather than deleted by the guest. The exact original pinned
baseline certificate/raw/prepared/ownership/report inputs stay unchanged.

`preboot-context.json` now has schema-kind V2, adding the exact fixed ordered
policy and the three parents `etc`, `etc/audit`, `etc/udev` to the unchanged
Source/case/nonce/certificate/raw/prepared/namespace joins. Prepare derives the
V2 `preboot-etc.tsv` only from its original authenticated readonly scan: one
header, three `P path inode links seconds nanoseconds` records and nine ordered
`A path type mode cap` absence records. The descriptor is at most4096 bytes,
root0600, single-link; context is bounded4096 root0644. Both existing public
prepared leaves remain unchanged through recovery; no further image leaf is
added. Prepare independently verifies original parent identity, mode/UID/GID,
links, xattrs, atime and exact mtime through staging. The prepared-manifest and
kernel descriptor-SHA binding are unchanged. Raw geometry and all existing
resource/staging guards remain exact; exceeding a cap fails rather than changes it.

Guest capture validates the bound descriptor/context, canonical byte count,
strict13-line schema/EOF, nonce, path policy and SHA. It rejects NULs discarded
by Bash `read`, trailing blank lines, missing newlines, reordered policy and
unbounded integers. Each original parent is held open and must join its certified
inode/type/mode/UID/GID. Parent identity checks omit link count while the exact
selected new directories exist. Only their individually verified presence may
account for the initial link delta; an unselected child directory refuses.
This does not treat links37 as mandatory when the observed running state has38.

Before any ALPM write, the guest snapshots each selected initial node's actual
bytes or symlink target (length/SHA), type/mode/UID/GID/link count/size/nanosecond
mtime/xattr hash, and physical identity. A fixed-byte emptiness probe returns
only presence/absence, never directory names or file contents. A bounded literal
`pacman -Qlq` view refuses ownership of selected paths, including directory
entries with a trailing slash; it never follows `os-release` to classify its
target's ownership. Query failures propagate. Initially absent paths may remain
absent; a later appearance refuses. Snapshot state is private in-memory guest
DATA, never a fabricated baseline or durable runtime acceptance certificate.

After normal package/dependency recovery and the existing exact cache recovery,
all three reference identities, current parent identities/link counts, and the
complete nine-path initial snapshot must still join before any deletion. Every
node is rechecked immediately before its single anchored removal. All non-cache
nodes require their original inode/ctime identity; the existing normal ldconfig
and `cp -a` cache recovery may replace only `ld.so.cache`'s inode while its full
logical snapshot (including body, xattrs and mtime) remains exact. The currently
verified cache inode is newly held before removal. This bounded exception does
not change host preservation: its independently certified final state is absence.

Only the fixed file/symlink operands are unlinked with `rm --`; only the three
verified empty directory operands use `rmdir --`. Operands are anchored beneath
the original held parent FDs. Ordinary file/directory FDs must report zero links
after removal; no recursive deletion is used. Symlink and child-inode checks are
sequential shell checks, not a claim of atomic same-child-inode deletion against
concurrent privileged replacement. Parent pathname/FD joins remain required
throughout, and strict independent preservation still catches any residue or
protected baseline change. Later recreation is HOLD, not a cleanup loop or retry.

Only after all nine absences and all three exact original parent link counts are
restored does held-FD `touch -m --reference` restore each certified parent mtime.
Each current parent atime is checked immediately before/after touch and is never
restored or normalized. The unrelated wholeboot-atime requirement from the held
attempt is removed. A separate final readonly three-parent identity/link/type/
mode/UID/GID/xattr/mtime check remains; `image.py` and every strict original
preservation allowance remain byte-identical to public Source56. No parent or
child timestamp difference is waived. The guest-created references are exactly
`cache/preboot-parent-0.reference`, `-1.reference` and `-2.reference`; all are
zero-byte root0600 single-link private transient DATA and must be removed.

The revised family still has58 leaves (57 lock members plus the lock), with no
shared manifests or other package families changed. Existing normal ALPM hooks,
scriptlets, cache recovery, Root phases, package archives, trust and output
contracts remain enabled. Only the timestamp/absence helper block changes in
`guest/root.sh`; the focused control pins the complete unpublished e14 root
inverse. Handoff provides complete Source56 and unpublished Source58 inverses,
exact final subtree/count/lock, fixed baseline pins, all-six-leaf outer-capsule
inverse, concrete unissued case inputs and publication/helper APIs.

The23 owned scratch HOST controls model preboot absence, exact nine-path boot
creation, a13735371-byte MODEL hwdb, normal cache replacement/recovery, and exact
final absence plus original three-parent link counts/nonzero-nanosecond mtimes.
They test file/dir/symlink substitution, nonempty dirs, changed body/mode/mtime/
xattrs/link count, literal ownership/query errors, descriptor/context/reference/
nonce/token tampering, strict EOF/NUL handling and touch/error propagation.
Every restore-refusal fixture proves capture passed first. Ten fenced provenance
DATA controls cover all parents, policies, absence/alias/descendant refusal and
scope of atime. These pass on local uv3.12.13/3.14.6 and system3.14.7; no actual
ALPM/VM/ARM16K execution is performed by these controls. The uv broad-suite
`os.pidfd_open` mock API error remains explicit; it is not a skipped or passing
control. Fresh committed exports and all applicable existing source checks must
be recorded separately before Root review. No new Source publication, authority,
packet/image/VM/Reader/Root runtime acceptance is issued by this increment.
