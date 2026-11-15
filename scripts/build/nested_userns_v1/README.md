# Explicit nested namespace policy for builder v3

Source implementation only. Docker, namespace probes, native builds and policy
qualification are **NOT RUN**. No actual run/output, Root resource grant, pinned
builder image or future server observation is supplied. Existing v2 builders,
comparators, container entries and frozen Sources are unchanged. The maintained
source-control workflow runs only the portable DATA checks below.

`../build_v3.py` is a finite reversible derivation of the public v2 builder at
`522e7cc8d2446416849dc5c1f84642cc46f82a06`. Without both opt-in arguments, its
Docker argv and default policy are unchanged. `derivation.json` records exact
before/after edits; portable controls invert both new scripts to the complete
unchanged v2 bodies. Default records explicitly bind `nested_namespaces=null`.
No old Source/package qualification or dispatch authority is inherited.

## Required integration base

This feature is explicitly stacked on [PR459](https://github.com/Gabriel-Kahen/cachy-asahi/pull/459),
public integration commit `522e7cc8d2446416849dc5c1f84642cc46f82a06` or its
integrated descendant. Main before that prerequisite lacks the V4 recipe and is
not a valid standalone base for this feature. The portable controls intentionally
require the exact eleven-file V4 join; absence or drift fails, never skips or
silently substitutes another candidate. Adopt the prerequisite package/CI change
first, or keep this feature stacked until PR459 merges.

The existing `Native adapter DATA controls` job runs these17 actor-fenced checks
on Python3.12 and3.14 in separate processes. It performs no Docker/Engine probe
and does not grant namespace or native execution authority.

## Why this distinct policy exists

The enrollment0.4.0-1 check executes bubblewrap with `--unshare-net`, mount/bind/
proc/dev/tmpfs setup and no PID/IPC/UTS/cgroup flags. It then executes util-linux
`unshare --user --map-root-user` inside that sandbox. The exact eleven recipe
files from public522e are pinned in provenance.json; raw v4 namespace argv is
checked as DATA, not inferred from a package name. Both clean builds must run
these unchanged checks. Missing kernel/LSM support still fails them; there is no
skip, fallback to host root, `--nocheck` or `--nodeps`.

The previous genuine Source3937 diagnostic observed DENIED for normal Docker
build-RUN bwrap and mapped-root operations. It did not establish the denial's
kernel/seccomp/LSM cause, and is not a v3 runtime-container observation. A new
preprovisioned image cannot by itself fix or qualify the daemon policy.

This profile retains the complete Moby28.0.4 default with exactly seven appended
rules. Primary source bodies and commit/URL/length/SHA pins are in provenance.json.
The original default.json is copied exactly with Apache2 LICENSE and NOTICE;
new Python/packaging material is MIT. Moby28 is selected because its default
and strict Engine consistency seam already exist in the maintained Core builder;
it is a versioned source baseline, not evidence that our future native runner
uses it. Local Docker29.8 is outside this profile. Client package/version or
an image's contents cannot stand in for a fresh **server** version observation.

| New rule | Required selected operation |
| --- | --- |
| `clone(arg0 == 0x50020011)` | Exact SIGCHLD + NEWUSER + NEWNS + NEWNET from ordinary bubblewrap with selected flags |
| `unshare(arg0 == 0x10000000)` | Util-linux's selected mapped-root call and bubblewrap's second user namespace after devpts setup |
| `mount` | Selected tmpfs/proc/devpts/bind/remount/propagation setup |
| `pivot_root` | Bubblewrap's two root pivots |
| `umount2(arg1 == 2)` | MNT_DETACH of the previous root |
| `mount_setattr(arg2 == 4096, arg4 == 32)` | Nonrecursive bound mount attributes |
| `mount_setattr(arg2 == 36864, arg4 == 32)` | Recursive bound mount attributes |

Upstream bubblewrap at719a4fd uses mount_setattr for those selected binds and
only falls back on ENOSYS, so omitting that syscall while returning default
EPERM would knowingly reject the check. Attribute-pointer contents/path strings
cannot be inspected by this seccomp JSON. The kernel must still enforce capability
and mount/user-namespace ownership. No general namespace clone mask, setns,
chroot, clone3, bpf, fsopen/fsmount/open_tree/move_mount or capability is newly
allowed; original ordinary-process clone and clone3 ENOSYS behavior remain exact.
Mount operations have no string-based seccomp scope. Admission therefore still
requires ordinary UID, cap-drop ALL, NNP, read-only outer root and reviewed bind
mounts; policy alone does not prove a caller entered the intended namespaces.

## Opt-in and exact retention

Use both `--nested-seccomp-profile /absolute/path/nested-seccomp.json` and
`--nested-seccomp-sha256 471a0bfd86586464226ac69cedf7104ab573d37c3be83771a3fb5f33e95f1e29`.
Only this exact whole profile is accepted, not arbitrary caller-supplied JSON,
ALLOW defaults or `unconfined`. Default profile bytes/hash and seven-rule inverse
are independently checked. The input must be a bounded, safe, nonaliased ordinary
single-link file. Missing half of the option pair refuses before daemon contact.
Custom mode requires `--mode native --network none` and an ordinary caller.

Before custom container creation, a bounded10s successful `docker version
--format '{{json .Server}}'` query must report Version28.0.4/OsLinux/Archarm64.
Unknown, other versions/architectures, stderr, failed query or timeout refuse.
The caller-selected profile is captured as bytes and retained exclusively as
`output/nested-seccomp.json`,0444, outside the container's writable artifacts
mount. Its bytes are checked again before argv construction and before a positive
build result. The comparator requires the exact retained profile in the evidence
closure and identical default/custom descriptors across both attempts. It cannot
mix v2 records, a default attempt and custom attempt, or different profiles.

The inherited builder keeps cap-drop ALL, NNP, read-only root, no Docker socket,
4CPU/4GiB/512PID and4GiB private tmpfs limits. Offline source checks, ordinary
makepkg, dependency checking, actual check(), fresh containers and all existing
archive/payload/metadata inspection remain unchanged. This is the old generic
runner's execution/timeout-cleanup contract, not the newer canonical once-role or
independently supervised native Source controller. Root must separately review
and supply appropriate outer resource custody/retirement before any actor.
No new Root authority/controller/dispatch framework is introduced here.

## Root-only future two-build path

First review exact522e recipe/source bytes, the public primary-source profile
basis and both script derivations. Separately qualify the real kernel/LSM/daemon
context and provide an immutable preprovisioned linux/arm64 image, sorted exact
package lock, matching ordinary UID/GID, normal checks-enabled makepkg config and
all signed dependency inputs. The held349 inventory contains Python, GnuPG,
pacman, coreutils, libarchive, bubblewrap and util-linux plus build tools; actual
image/lock correspondence and namespace availability remain external prerequisites.
No Setup8 dependency or first-login build is needed for this single recipe.

The reviewed recipe-input map is the exact `input_sha256` object returned by
`package_checks.recipe(PKGBUILD)`; that static helper reads files as DATA only.
No downloads, dependency installation or source code need run to prepare it.
After Root separately admits resources/execution, run two new output directories
with identical image/epoch/lock/input-map/profile, then compare:

```sh
python3 -I -B scripts/build/build_v3.py "$RECIPE_V4" \
  --image "$ROOT_PINNED_ARM64_IMAGE" --mode native --network none \
  --source-date-epoch "$REVIEWED_EPOCH" --timeout "$ROOT_BUILD_SECONDS" \
  --expected-packages "$APPROVED_PACKAGES_LOCK" --reviewed-inputs "$RECIPE_INPUTS_JSON" \
  --nested-seccomp-profile "$REVIEWED_NESTED_PROFILE" \
  --nested-seccomp-sha256 471a0bfd86586464226ac69cedf7104ab573d37c3be83771a3fb5f33e95f1e29 \
  --output "$FRESH_ATTEMPT_1"
# Repeat the identical command with a distinct FRESH_ATTEMPT_2.
python3 -I -B scripts/build/compare_v3.py "$FRESH_ATTEMPT_1" "$FRESH_ATTEMPT_2" --require-bytes
```

Actual namespace denial, failed check/dependency resolution, unequal archive or
payload remains failure DATA. No native ARM, ALPM lifecycle,16K/M2, performance,
production trust or release acceptance exists from source controls. No image,
server/runtime qualification, Source publication, lease or build was performed.

Portable controls: `python3 -I -B -Werror::ResourceWarning
scripts/build/nested_userns_v1/test_policy.py -v`. They validate exact defaults/
inverses, actual v4 selected commands, numeric rule/refusal boundaries, source
and policy pins, option pairing, Engine mismatch, safe retention, real main's
pre-launch Docker argv under mocked process boundaries and comparator policy
joins. A permanent audit fence denies all actor/network/ctypes/lease calls.
