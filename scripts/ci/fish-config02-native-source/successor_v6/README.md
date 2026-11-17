# Fish payload diagnostics and failed-owner retirement v6

Source implementation only, based on frozen code
ac3cd1caf06720817be8479ae391044c7a1eea72 and exact Source53. No native actor,
Root role, grant, lease, signing, secret access, dispatch or push occurs here.
No existing failed evidence is reclassified. Native Fish pair/build, M2,
installation, performance and release remain unqualified.

## Narrow implementation

This integrates the controller/payload correction from immutable llhttp commit
8667d0a1912bc141416e1ab954cfe94adba835e4. UPSTREAM.json records its exact helper
pins, parent commit and literal Fish adaptations. The diagnostic helper is copied
byte-for-byte, including its historical LLHTTP diagnostic kind. The retirement
helper changes only the declaration kind and canonical Fish unit/Description
prefixes. Both helpers retain their MIT SPDX headers. No external build dependency
or package change is added.

Sixteen literal phases surround the existing payload steps. Every admission,
Source, signature, UID, namespace, filesystem, socket, kernel-domain and package
predicate stays exact. On exception, the existing bounded owner.log receives one
line at most512B: fixed phase, allowlisted exception class, message UTF8 length,
SHA256 of the first at most8192B, prefix length and truncation flag. No exception
text, private path, environment or arbitrary file is published. Exit2/HOLD remain.

The observed live service start records the original PIDFD descriptor and device/
inode identity after the original PID/start/executable/cgroup/domain checks. The
narrow failed-owner stop path requires the canonical nonce-derived Fish owner
unit and Description, submitted positive original PID/starttime/cgroup, retained
original PIDFD identity and exit, and the same already-failed loaded unit before
and after stop: MainPID0, empty ControlGroup, Result=exit-code, ExecMainCode1 and
unchanged canonical exit1..255. Two separate original cgroup censuses must show
populated0 and empty cgroup.procs; a genuinely absent cgroup is accepted only
after FileNotFoundError. Permission/unknown errors, duplicate event keys, changing
directory identity and ERR/NVAL PIDFD events refuse.

Only those joins permit STOPPED_EMPTY_FAILED_OWNER with the actual payload exit,
payload_success=false and unit_reset=false. No reset-failed, timeout/OOM waiver,
signal-style success or missing-custody fallback exists. Main success/HOLD logic,
storage cleanup, setup, command qualification/supervision, every numeric budget
and package gates remain exact. Dead failed payload retirement does not establish
payload success. Existing no-host-APT/XZ, Go Docker-only finite child allowance,
ordinary owner limits, base33 and native workflow/concurrency remain unchanged.

## Closed construction

```sh
python3 -I -B scripts/ci/fish-config02-native-source/successor_v6/prepare.py \
  --base /absolute/exact-Source53 --output /absolute/fresh-Source57
```

The constructor requires the complete53-file/967199B source, map11296B/SHA256
ef50c6185a228cefcc4b241863221eb3bf9d44959b4b312b422887bdf6dc3db5 and tree
4f10cc1cdb48d946b6a0af8bd4051b54308c34f5. It adds two pinned helper leaves,
their provenance/projection binding and a complete Source53 inverse:57 files.
Owner, payload, two explicit policy declarations, validator, README, program and
map are regenerated. Removing the two policy fields restores every old field.

The validator reconstructs all53 predecessor bodies/modes/map/tree before the
existing complete50-to48 inverses. Old sources and their control families remain
unchanged. All actual Source/run/authority/runtime/role selectors remain NULL.
Root must independently review/publish/read back and bind fresh exact Source,
program, policy and caller documents. Runtime54 same-FD/PIDFD/nonblocking/
CLOSE_ONLY, two full global EMPTY sweeps, Main CAS, proof freshness and retirement
remain Root-owned gates outside this constructor. Native workflow bytes and
shared Fish serialization are preserved.

## Focused checks

```sh
TMPDIR=/dev/shm python3 -I -B -W error::ResourceWarning \
  scripts/ci/fish-config02-native-source/successor_v6/test_data.py \
  --base /absolute/exact-Source53
```

Checks construct disposable source DATA and execute the actual projected stop
method and helpers with modeled systemd/PIDFD observations and synthetic cgroup
files. Real process/network/resource/cgroup actors are fenced. These checks give
no native service, physical memory, hardware or release credit. No local real
PIDFD-child test is included because this slice excludes real actors.
