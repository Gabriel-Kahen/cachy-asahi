# Fish fixed-path filesystem diagnostic v7

Diagnostic-only source successor to frozen Fish v6 code
fddcd756bfdee7a748dee4739acf8a9c114e6a9e and complete Source57. No existing code,
failed evidence, unit property, write path, guard or acceptance rule is changed.
All actual Source/run/runtime/authority/role selectors remain NULL.

## Source conclusion and concrete scope

Root reported llhttp Source76 run44048877765 failed at readonly-filesystem with
the unchanged64B guard message, SHA256
fb486df27f93098ca0869bbefefdfc5eebd0260b10abfcc4fb1b8c1dfb3286bb.
That is cross-controller evidence, not an actual Fish failure or qualification.
No Original/artifact or actual Root operand is fetched here. The underlying
cause is not established by this Fish source audit.

Fish's actual service_args already declares ProtectSystem=strict and
ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup. The owner has exactly one
ReadWritePaths exception: quota volume/work. Source and output are canonical and
separate; HOME, TMPDIR and payload output are within quota work. There is no
PrivateTmp or write-path fallback. The existing guard checks /tmp, /var/tmp and
source with real-ID W_OK. No deterministic source mismatch is proven, so these
properties and the exact guard stay unchanged. Systemd documents nested writable
exceptions separately from ordinary permission checks; actual namespace/permission
observations are still required. References:
[systemd.exec254](https://www.freedesktop.org/software/systemd/man/254/systemd.exec.html),
[access2](https://www.man7.org/linux/man-pages/man2/access.2.html).

The original MIT filesystem_diagnostic.py probes exactly four role targets:
tmp=/tmp, var_tmp=/var/tmp, source=the already-selected source root and
quota_work=the existing payload output's parent. It reports only literal labels,
entry class, mode bits, W_OK and statvfs ST_RDONLY mount class, plus allowlisted
error classes. There is no mount-table/directory enumeration, raw private path,
UID, environment, exception message or write probe. Permissions and mount class
are independent observations; neither authorizes anything.

A FILESYSTEM_DIAGNOSTIC line of at most2048B is written to the existing bounded
owner.log immediately before the unchanged guard. Missing/error observations
stay UNKNOWN/PARTIAL; emit failures use a fixed UNKNOWN fallback. Diagnostic
results never replace or suppress the guard. Existing readonly-filesystem phase,
hash-only exception record, exit2/HOLD and strict failed-owner retirement remain.

## Complete construction and controls

```sh
python3 -I -B scripts/ci/fish-config02-native-source/successor_v7/prepare.py \
  --base /absolute/exact-Source57 --output /absolute/fresh-Source60
TMPDIR=/dev/shm python3 -I -B -W error::ResourceWarning \
  scripts/ci/fish-config02-native-source/successor_v7/test_data.py \
  --base /absolute/exact-Source57
```

Constructor input is57files/1066965B, map12161B/SHA256
f98da639c80ae35423f7c33a66df12bd5f70ea9fc15ecbaabb93c6569f3a6150 and tree
4e06d52d001a504916fab131104b39014fd2338c. It adds one exact pinned helper,
provenance/projection binding and complete57 inverse: Source60. Payload import
and diagnostic call, validator, README, one policy declaration, program and map
are regenerated. Every original owner byte and service_args AST stays exact.
The new validator reconstructs every57 predecessor body/mode/map/tree before the
existing53-to50-to48 inverses. All numeric budgets, no-host-APT/XZ/package gates,
finite Go VA correction, strict failed-owner custody, base33 and native workflow/
shared serialization remain exact. Removing filesystem_diagnostics restores the
complete predecessor policy.

Focused controls use modeled permission/mount observations and execute the actual
unchanged guard AST. Constructor/inverse/readback checks use disposable DATA.
Process/network/resource/mount/native actors are excluded. No source or DATA
test establishes actual filesystem confinement, Fish ARM success, M2 compatibility,
installation, performance or release acceptance. No write paths are widened.

Root must separately integrate/review/publish/read back and bind fresh exact
Source/program/policy/caller documents. Existing runtime54 same-FD/PIDFD/
nonblocking/CLOSE_ONLY, two full global EMPTY sweeps, Main CAS, freshness, custody
and retirement gates remain Root-owned. No grant/lease/signing/key/secret access,
role reservation, real service/Go/Docker/cgroup actor, native dispatch, limit
mutation, Original GET, host repair or push occurs here.
