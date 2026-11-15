# Proposed Perl native runtime namespace diagnostic

Source/DATA implementation only. No Docker, native actor, namespace probe,
operational Reader, compiler, publication, or intake ran. Actual Source/ref/run/
job/approval/artifact/image selectors remain NULL. This source grants no authority.
Only this new directory changes; Root owns integration and all actual roles.

The diagnostic is deliberately small: one in-container producer, one fixed
pre-exec/inner observer, and an independent passive DATA classifier. It has no
host orchestrator, image build, installer, daemon manipulation, or policy repair.
Dependencies are the Root-admitted native image's Python 3, bwrap, unshare, and
Linux proc/cgroup-v2 surfaces. New code and the retained helper use SPDX MIT.

## Exact changed domain

`domain.json` is byte-identical to adapter `91908c31`'s
`PERL_ARM_CAP0_NNP_RO_CONTAINER_V1`, SHA-256
`6c6bdc29acf59e8ea911167f08d4d66a993777c121b2399211cec030e2a5b804`.
It requires aarch64, UID/GID 1001, 2 CPUs, 4 GiB memory with zero added swap,
256 PIDs, init, no network, read-only root, cap-drop ALL, NNP, read-only inputs,
one private work volume, and exact safe 64 MiB `/tmp`/8 MiB `/run` tmpfs mounts.

Original Source3937 (`3937d8b9f3210f4e9868bf19f01dfa22de64ddfe`, tree
`f1757dbedeed1591cdb8538f6c91e493cd451966`) observes an ordinary image-build
`RUN USER alarm` domain. It cannot qualify this domain. The actual Git observer
is the corrected 1001 version; the local predecessor observer still uses 1000.
Neither observer was copied. Only the immutable `owned_child.py` is reused from
Source3937, with its exact hash and origin in `provenance.json`.

The entry uses the adapter's `/usr/bin/bash --noprofile --norc /inputs/entry.sh`
then `exec /usr/bin/python3 -I -B /inputs/entry.py` structure. It clears its
environment to the same fixed build environment and runs probe children from
`/work/recipe`. The Python entry must be a direct non-PID1 child of observed init
PID1. Init, entry, and each pre-exec wrapper must share the actual outer namespace
links, maps, groups, and cgroup. All outer capabilities must be zero with NNP1.
The collector retains executable/argv, PID/PPID/group/session/start time, complete
bounded groups/maps, selected security fields, cgroup limits, mountinfo, interface
names, architecture/page size, hostname, and cwd. Parent identity is checked
across observation; unavailable observations cannot qualify.

## Root-owned launch contract

Before any import, Root authenticates the complete finite Source, actual native
host and local daemon, fresh signed349 image, canonical admission, and host
receipt. Hashes bind bytes; they do not authenticate Root or grant approval.
The NULL admission template cannot launch a diagnostic.

Root supplies read-only `/inputs/admission.json` and `/inputs/host.json`, sets
`ADAPTER_ADMISSION_SHA256` to the canonical admission hash, and initializes the
fresh private work volume to 1001. Admission binds Source, run, job, immutable
image, approval, map, domain, nonce, and the exact container/volume/input names.
The compact canonical encoding is sorted JSON with separators `(',', ':')` and
one trailing newline. `host.json` contains exactly `binding_sha256`,
`image_inspect`, `container_inspect`, and `create_argv`. These must be actual
Root-authenticated observations, never caller assertions accepted as authority.

`reader.create_argv(admission)` is a pure finite launch definition for Root's
existing launcher. It returns the adapter's exact Docker create shape with the
separate `perl5423-native-namespace-v1` operation label. The Reader joins that argv
to actual native image and container inspections, including entry, resources,
NNP/capabilities, network, rootfs, tmpfs, and both mounts. Images with inherited
anonymous volumes refuse. The in-container collector checks this host envelope
before observations/children and retains its hash in the report.

Root owns the actual create/start/terminal natural retirement, log custody,
export, cleanup, native-host proof, and resource admission. The classifier cannot
infer those facts from in-container data or inspect JSON alone. Root must enforce
a finite 75-second outer actor deadline and retain actual outer lifetime evidence.
No such actor or receipt exists in this implementation.

## Finite observation and independent classification

The producer performs only two fixed owned commands, at most 25 seconds each,
with an aggregate command deadline below 60 seconds. The unchanged owned-child
primitive records WNOWAIT ownership, natural direct waitpid retirement, and group
absence. Each raw log is limited to 512 KiB and each framed observation to
256 KiB, with at most 128 KiB mountinfo. The log limit is observed by the owned
primitive; it is not a disk quota. SIGINT/SIGTERM set a scoped cancellation flag
observed after child ownership exists, allowing owned retirement before failure.
Repeated cancellation is deferred during retirement. A baseline mismatch is
retained as FAIL DATA before either probe; earlier operand/observation failures
remain nonzero outer failures for Root to retain.

The wrapper emits a canonical same-process pre-exec frame with actual tool hash,
mode, and owner, then execs the fixed tool. The inner Python emits a second frame.
All frames bind admission, Source map, nonce, case, and operation. The cases are:

* `bwrap-user-mount-net`: fixed `--die-with-parent --unshare-net --ro-bind / /`
  plus proc/dev and home/pacman tmpfs mounts. Success requires changed user/mount/
  network namespace IDs, preserved PID namespace, UID/GID1001 mapped to outer1001,
  `/tmp` cwd, and preserved supervised process group/session. A different process
  PID is allowed because bwrap may fork.
* `unshare-mapped-root`: `unshare --user --map-root-user --` with no fork. Success
  requires changed user namespace only, UID/GID0, exact `[[0,1001,1]]` maps,
  and the same leader PID/start time, group/session, and direct parent.

The independent API is `reader.classify(report, logs_by_name_bytes, host,
admission)`. It imports no producer or observation code. Root must parse report
bytes with `reader.decode` (finite timing floats are required); the producer's
`data.decode` is intentionally stricter for Source/admission operands. The
classifier checks the original raw frames/log pins, exact argv, runtime baseline,
host binding, actual effects, mappings, chronological lineage, finite bounds,
and natural retirement. Timeout, cancellation, malformed/partial observations,
forced retirement, wrong domains, and exec failures cannot establish support.
Some malformed failure receipts are refused rather than classified.

Natural positive tool exits with matching denial text may yield `DENIED`;
unrecognized results yield `UNKNOWN`. No kernel namespace errno or seccomp/LSM/
daemon policy cause is inferred. Collection success is separate from support.
Only both exact supported effects produce `PASS_NAMESPACE_EFFECTS`; native
acceptance remains false and Root authentication/lifetime admission is still
required. Root owns any authenticated bridge and canonical re-encoding into the
adapter's qualification format. There is no automatic permission or lane alias.

## Source closure and validation

`profile.json` and `source-map.json` describe the finite proposed runtime leaves.
Root materializes exactly those leaves plus the map and the two authenticated
external operands under `/inputs`; tests, README, and validation records are
authoring material outside that runtime closure. `data.verify_source` checks
every held byte and mode and rejects unrecorded directories, aliases, and extra
files before any diagnostic child. All proposed map selectors remain NULL.

Nine actor-fenced Source controls and 19 independent synthetic DATA controls
pass on Python 3.12.13 and 3.14.6. Fixtures model proc surfaces, AArch64 context,
mounts, host inspections, and namespace frames; no actual runtime observation or
namespace command was used. `validation.json` records profile/map hashes, bounded
closure, exact held helper/domain joins, test transcripts, and role counts.

Actual namespace support, native Perl builds, native16K/M2, installed ABI,
external XS, performance, and release acceptance remain unestablished. Source3937
is not a fallback for any of those gates.
