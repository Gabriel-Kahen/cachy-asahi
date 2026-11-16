# Rust kernel mount preentry proof successor v13

Source344 run43900684447/job133416142892 failed before the qualification probe
started. The actual API projection has exact configured `build/stage0` Subpath
operands and readonly aliases, but reports the owned volume root as Source for
all three volume mounts. It has no effective subpath field. Source344 kernel
mountinfo was NOT retained: actual effective kernel subpaths remain UNKNOWN.
The v12 CID correction worked in that run: all three containers and the volume
were absent, and both images reported PASS_RETIRED. That is retirement evidence,
not native qualification. The consumed Source344 and all old packets stay intact.

The API guard now permits only this exact owned-volume-root representation when
the fixed probe/makepkg caller explicitly requires the new actor kernel proof.
Configured Subpath/NoCopy, readonly flags, name/source/local driver, cardinality,
propagation, empty DriverConfig recognition and CID custody remain strict. It
permits starting the trusted actor to obtain proof; API acceptance alone proves
no effective subpath, toolchain, build or native acceptance.

New `actor/mount_proof.py` reads only fixed `/proc/self/mountinfo`, twice with
equal whole bytes, bounded to1MiB/4096 rows/8192 bytes per line and a2s cooperative
parse deadline. No command, workspace write, privilege or mount action occurs.
It requires unique IDs/targets, canonical paths and unambiguous escapes; exactly
one writable `/work`; no unexpected mounts below work or either alias; and both
readonly aliases on the same device/filesystem/source/backing rw superblock.
Their effective roots must equal the filesystem-relative work root plus
`/build/stage0`, with exact parent-ID joins. It does not compare filesystem roots
to a Docker host path. The [kernel mountinfo definition](https://docs.kernel.org/filesystems/proc.html#proc-pid-mountinfo-information-about-mounts)
defines that distinction. [Docker's subpath option](https://docs.docker.com/engine/storage/volumes/#mount-a-volume-subdirectory)
describes configured intent; the retained API projection supplies this failure's
actual representation. Only an actual new kernel observation can settle it.

Qualification data/probe and build prepare/makepkg/build/package entries must
obtain this proof before workspace mutation or tools. Existing authentication,
readonly/cap0/native/resource and initialized-volume guards still run. After a
successful proof, the actor retains whole raw bytes and a canonical receipt;
every subsequent command and phase joins its proof SHA. Chronology is enforced
by the pinned trusted source order, NOT claimed independently measured by a
kernel event trace. On proof refusal, bounded escaped whole proc DATA is emitted
only as HOLD diagnostic stderr; no workspace write or PASS proof occurs.

Receipt schema13 is `PASS_KERNEL_MOUNTINFO_PREENTRY_DATA_ONLY` with exact context
source/ref/map/approval/run/job, dispatch/input-admission SHA, image, volume token
and phase; helper SHA; whole raw descriptor; parsed selected rows; derived alias
root; fixed preentry order declaration; native_acceptance:false/holds_preserved:true.
Qualification raw/proof basenames are `kernel-mountinfo-qualification-{data,probe}.raw`
and `kernel-mount-proof-qualification-{data,probe}.json`. `qualification-plan.json`
binds both, and `data-commands.json` binds all five naturally retired data children.
The native result's `kernel_mount_proofs`, `qualification_plan`, `data_commands`
join the retained bodies. Hosted validation replays both proofs and all data/
probe command digests, also after the existing phase-transfer relocation.
The existing transfer copies every bounded qualifier file; its code is unchanged.

Build raw/proof names use `kernel-mountinfo-{action}-{pid}-{uuid32}.raw` and
`kernel-mount-proof-{action}-{pid}-{uuid32}.json`, with the existing phase token.
Each phase result contains a `kernel_mount_proof` envelope and every command
contains `kernel_mount_proof_sha256`. A matching independent Reader must replay
the raw rows and require these joins before any acceptance; v12 outputs cannot
substitute. No existing Reader is edited here.

The finite constructor replaces only hosted producer/qualification and actor
entry/qualify, adds the helper, archives all replaced leaves plus the old map
under `previous-v12/`, and verifies the complete344 byte/mode/namespace inverse.
Hosted entry, workflows, phase/HTTP programs, compiler flags, Root templates,
all108 historical holds and606-minute/8GiB resource policy stay byte-exact.
All new actual publication/runtime/grant/acceptance fields remain NULL.

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/rust199-source-reference-native/successor_v13/test_runtime.py
python3 -I -B -Werror::ResourceWarning scripts/ci/rust199-source-reference-native/successor_v13/test_data.py
python3 -I -B scripts/ci/rust199-source-reference-native/successor_v13/prepare.py \
  --parent /absolute/verified-files-only-Source344 \
  --output /absolute/fresh-private-successor \
  --profile-sha256 EXTERNALLY_SELECTED_WHOLE_PROFILE_SHA256
```

The API fixture is actual public6302-byte data; all kernel rows are explicit
MODEL data and have never been observed from Source344. Fenced controls exercise
both forms, filesystem-relative roots, access/parent/shadow/escape/mutation/bound
refusals, all six preentry refusal seams, complete raw replay/relocation and the
whole Source inverse. No Docker/GPG/actor/lease/Original GET, credentials/private
keys/homes, privilege, Root grant, package execution, push or publication occurs.
Root alone issues a fresh Source/operator/Reader/native trial. Native/M2/legal/
performance/release acceptance remains unproven.
