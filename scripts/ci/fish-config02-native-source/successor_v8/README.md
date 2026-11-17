# Fish explicit Source read-only binding v8

Source implementation only, after frozen v7 code
7a2aeac9fcc7b86e0d3246c54efe7ad54588adbd and complete Source60. Existing source
snapshots, failed evidence, Root roles and incoming integration waves are untouched.
Actual read-only mount effect requires a new native observation.

## Evidence and exact change

Root reports llhttp Source85 Native92 observed root/tmp/var_tmp read-only, quota
work writable, but Source writable with statvfs_readonly=false and covering mount
read-only=false/class=other, followed by the unchanged guard failure. Its Original
was60995B/SHA256 80cb6154035c5b1b5e4c7c6dc7f6411e59446c1c3b93fb9333ec93fc43fb3c54.
This is Root-provided cross-controller evidence; it was not fetched/read here,
and establishes neither an actual Fish failure nor Fish qualification.

Fish has the same structural omission: service_args accepts no declared Source
root and emits no exact Source binding. General ProtectSystem=strict and fixed
ReadOnlyPaths are present. Source and quota volume are lexically separate; their
actual Fish covering-mount behavior is unobserved. This successor makes the Source
contract explicit without changing the guard or any writable exception.

The sole controller caller now passes source_root=self.root as a required
keyword-only operand. service_args validates canonical existing absolute directory
paths, safe property-token syntax and bidirectional disjointness from the whole
quota volume. Relative/missing/symlink/.. aliases, whitespace/colon/percent/control
characters, root / and source/volume overlaps refuse before unit submission.
No fallback source inference, optional-missing prefix or destination remapping.

Both owner and daemon args gain exactly one property:
BindReadOnlyPaths=<the exact declared source_root>. Source and destination are
the same path. The daemon also resolves source-backed Docker inputs. Existing
ProtectSystem=strict, read-only temp/cgroup properties, owner quota-work and daemon
quota-volume/owned-cgroup writable paths stay exact. No chmod, timestamp/source
body repair, source move, raw mount command or filesystem enumeration is added.
Systemd documents this unit-local read-only bind syntax in
[systemd.exec254](https://www.freedesktop.org/software/systemd/man/254/systemd.exec.html).

The payload, its exact filesystem guard and both bounded diagnostic helpers remain
byte-exact. Main/HOLD logic, finite Go child VA, strict failed-owner PIDFD/two-empty
retirement, no-host-APT/XZ/signature/dependency/package/semantic checks, all numeric
limits, storage cleanup, base33 and native workflow/shared serialization remain.
Only one source_readonly_binding policy declaration is added; removing it restores
every predecessor policy field. Runtime success is never inferred from arguments.

## Closed construction and focused controls

```sh
python3 -I -B scripts/ci/fish-config02-native-source/successor_v8/prepare.py \
  --base /absolute/exact-Source60 --output /absolute/fresh-Source62
TMPDIR=/dev/shm python3 -I -B -W error::ResourceWarning \
  scripts/ci/fish-config02-native-source/successor_v8/test_data.py \
  --base /absolute/exact-Source60
```

Input is the complete60-file/1130628B source, map12826B/SHA256
c604399d2472fb5dd0a5e97a299b1017a697426ebd47454c5a43c72ce05892d5 and tree
8e7d42d9a25eeef1bd80389d198fedf84a5902ac. Constructor adds a projection/declaration
binding and full60 inverse: Source62. Data/unit args, owner caller, README, policy,
program and map are regenerated. The new validator reconstructs every predecessor
body/mode/map/tree before complete60-to57-to53-to50-to48 inverses. Templates retain
their existing v4 kinds but require fresh exact Source/program/policy joins.

Controls execute actual service_args on disposable canonical DATA paths and model
the caller boundary. They establish argument construction, refusal and source
preservation only. No systemd service/mount/cgroup, subprocess, network, limit
setter, actual Root grant/lease/signing/key/secret, native dispatch, Original GET,
host repair, push or publication is entered. Root must separately integrate,
review/publish/read back, bind fresh caller/admission/runtime and issue any role.
All actual Source/run/runtime/authority/role fields remain NULL. Runtime54
same-FD/PIDFD/nonblocking/CLOSE_ONLY, two complete global EMPTY sweeps, Main CAS,
freshness/custody/retirement and unchanged payload guards remain mandatory.

Hosted CI, actual Source read-only effect/Fish ARM startup, native Fish pair, M2,
installation, performance and release acceptance remain NOT RUN.
