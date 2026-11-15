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
