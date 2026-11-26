# Full Qtbase continuation preflight

This local preflight binds the configured Q3 Ninja manifests to the exact
independent QtCore and QtGui readbacks. It uses the existing bounded Ninja
`-t commands` and `-t graph` reader. The output is an unissued DATA plan
for the serial Qtbase `all` target on the emulated AArch64 16 KiB route.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/qt612_full_16k_preflight/prepare.py \
  --manifests "$Q3_MANIFESTS" \
  --core-readback "$QTCORE_READBACK" \
  --gui-readback "$QTGUI_READBACK" > "$NEW_PREFLIGHT"

python3 -I -B -Werror::ResourceWarning \
  scripts/integration/qt612_full_16k_preflight/test_prepare.py
```

Use the directory holding the original `build.ninja` and
`CMakeFiles/rules.ninja`, with absolute paths for all three arguments.
The two report filenames may vary. The reader checks both reports' exact
original bytes. The output keeps the original result disk, overlay and
build-log pins with each historical measurement.

The configured `all` graph contains 1,855 commands. Removing the 639 QtGui
commands with their multiplicities leaves 1,216 commands, including 788
compiler edges. These counts describe static graph work. The current
timestamps, Ninja logs and dependency state in the guest determine what
will actually schedule.

The recorded serial Core build took 6,212.764 seconds and the 318-step
incremental Gui build took 8,343.745 seconds. Each host cgroup reached the
6 GiB cap. The peak watched allocation for the incremental Gui run was
782,979,072 bytes. These figures describe the completed link checkpoints.
Select independent memory, time and disk budgets for the remaining work.
The preflight leaves full-build timing, package checks and installation open.

For the next guest preflight, bind the original boot image and kernel,
the verified Q3 scratch/Core/Gui backing chain, the isolated runtime and
an owned new writable overlay. Verify the package inventory, inherited
Core/DBus/Gui files and exact command graph before issuing the proposed
guest commands. The guest must preserve the original absolute build path
and Ninja state. Capture `ninja -n -v` with `NINJA_STATUS='[%f/%t] '` first
for the QtGui target, then for `all`. Both dry runs need their own
deadlines, output caps and owned process receipts.

The optional `--gui-dry-run`, `--gui-dry-run-sha256`, `--all-dry-run` and
`--all-dry-run-sha256` inputs check a later caller capture. The Gui
transcript must record zero actions. Every reported `all` action must
belong to the pinned continuation, including repeated commands. The
check verifies the captured stdout against the graph. Producer custody
and completed execution still depend on the independently bound actor.

Keep signed package staging, installed 16 KiB loader and desktop checks,
and the separate Qt family repositories in the subsequent qualification
plan. A successful `all` build covers the configured Qtbase target.

## Runner and budget review, November 25

The historical local runner image still resolves by its exact ID
`sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a`.
The rootless Docker CLI and all six image tools can be reverified by their
retained pins. The reviewed runner selected four vCPUs, 4 GiB guest RAM,
6 GiB container RAM, a 14,400-second guest build cap, a 14,700-second
QEMU cap and a 4 GiB child overlay. Its entry was specific to the QtGui
link and expired on November 22 at 9:00:09 p.m. Eastern. The full build
needs a new scope and budget. QtCore and QtGui both reached the old
container memory ceiling.

The [local dry-run worker](guest-dry-run.sh) booted the exact retained
Q3/Core/Gui chain on this runner. The source and computed device identity
checks selected a disposable 64 MiB-capped child over the three
read-only backing nodes. The first read-only attempt reached Ninja and
refused when `-n` tried to create a missing autogen directory. With the
disposable child, the exact QtGui target reported zero actions and the
configured `all` target reported all 1,216 actions in the pinned
continuation. The 356-package inventory, inherited libraries, Ninja
manifests and Ninja log matched before and after the probe. The guest
unmounted the child and powered off. The five input image hashes matched
after exit, and the owned container was observed absent twice.

The child reached 3,014,656 bytes. Guest filesystem free space was
11,558,694,912 bytes after the dry run. These are observations of the
scheduling probe. Full-build memory, time and disk high-water marks
still need measurement.

The retained local probe, decoded logs and updated unissued preflight
are under `~/.cache/qtbase-full-dry-run-20261125.FK0DZ4UP/`.
The [committed evidence](evidence) includes the original receipts and
the losslessly compressed serial stream. Its uncompressed SHA-256 is
`55d50fe5f241caeb83950e43aca8d15f837eb2d1005f347254be30139670c04f`.

| File | SHA-256 |
| --- | --- |
| `dry-run.ACTUAL.json` | `9634688898152d17063d94bcfd2421e8048e07ceea5d969e6eec30aaec934f7d` |
| `full-base-with-dry-run.UNISSUED.json` | `9e9c98a210a58453661aed6622aff78dba8e27fca3c59a53551555d728d800b3` |
| `probe-outer.ACTUAL.json` | `1bf906fdaa600bec1d9bf3fd29b6269f11b7182f50cddfb3072d0b2e926a7b0b` |
| `all.log` | `48732e61acb20d36c37d253e3e42a63bcd1986ede207d0f843f7a8d9d1f39ec7` |
| `gui.log` | `8c35b1682f73592d30612d7b0fabdb384fcfff35cb5a076cb48b85b1368aa794` |

The registered native ARM64 GUI-server route has separate pair-only
authority and resource limits of 6,900 seconds, 4 GiB RAM and 4 GiB
tmpfs per build. Its latest retained run stopped during signed base
image assembly. The retained R12 TEST authority expired on November 20
at 1:15:21 a.m. Eastern and the exact historical contract refuses current
entry. Offline readback reopened all 250 mapped source files, all 517
baseline references and seven archive/signature pairs. A new native
runner binding, owned signed image preparation and separately bound
package lifecycle still need evidence.
[Native pair contract](../../ci/qt612-gui-server-pair-adapter/contract.py)

The passive `prepare.py` plan grants no full-build authority. Both routes
still need reviewed limits for compilation and package staging, a
qualified output package and an owned install, loader and rollback trial.

## Bounded build-only successor

Continue the tested Q3 chain on the local Ryzen 7 3700X using the pinned
rootless controller. Keep the original kernel, read-only configured scratch,
QtCore and QtGui backing layers, the 356-package lock, and the pinned
Qtbase graph. Discard the dry-run child and start the successor from a
fresh child of QtGui. Use the observed dry run to require zero QtGui
actions and the exact 1,216-action multiset before executing the serial
`cmake --build /qt-recipe/src/build --parallel 1 --target all`.

The completed Core and Gui builds used four QEMU vCPUs, a four-CPU
container quota and one Ninja job. Their respective wall times were 6,212.764 and
8,343.745 seconds, with 321 and 318 actions. Both containers reached
6 GiB of accounted memory. Scaling by their observed rates puts 1,216
actions at roughly 6.54–8.86 hours and the child EOF at roughly 0.94–2.67 GiB.
These are illustrations for budget selection. Compilation mix, link peaks
and filesystem growth for the remaining graph still need measurement.

| Resource | Default unissued full-build limits |
| --- | --- |
| CPU and RAM | Four vCPUs, one build job, 6 GiB guest, 8 GiB container with no additional container swap |
| Deadlines | 14 hours guest build, 14 hours 15 minutes QEMU, 14 hours 20 minutes outer attach |
| Writable media | 4 GiB child file cap, 2 GiB clean result disk, 2 GiB guest free-space floor at build boundaries |
| Retained output | 1 GiB artifact cap, 64 MiB build log cap, 128 MiB host report allocation |
| Host reserve | 2 GiB disk and 2 GiB available memory beyond the selected limits |

At 4:56 p.m. Eastern on November 25 the host exposed 16 logical CPUs,
14.75 GiB available RAM and 161.77 GiB free on the cache volume. This
fits the implemented 10 GiB available-memory check and the 8.125 GiB
disk admission check on the capsule volume. Preparation requires
same-filesystem reflinks. The inherited per-command QEMU limit is
4 GiB and remains the default. The prior disposable guest reported
11,558,694,912 free bytes after the dry run. The successor
samples guest free space before and after the build. The owned host runtime
watches host reserve and output allocation during QEMU. Admission reads
current resources and carries no reservation.

The original QtGui authority passed historical readback, failed the live
entry window and refused a changed scope under the frozen reader. The
successor needs an independently issued `Root` selection for a new
build-only scope. Bind the following fields in its sealed handoff and
independently supplied selection digest.

| Binding | Required values |
| --- | --- |
| Authority | Fresh nonce and scope, approving issuer, approved handoff and plan SHA-256s, creation and expiration for entry |
| Producer | Reviewed source revision and source-tree digest, exact guest worker, host actor and independent reader, controller image, tool pins and rootless endpoint |
| Input state | Q3 terminal, 356-package lock, two archived link readbacks, dry-run receipt and logs, configured graph and inherited ELF pins |
| Media | Exact kernel, reviewed derivative boot image and fresh result image pins, four-node block chain including the new child, separate owned output directory |
| Work and limits | Exact build argv and environment, selected deadlines, memory and disk bounds, artifact allowlist, partial-failure retention and owned process retirement |

The local build can reuse the verified installed md4c bytes on the
read-only Q3 base. Q3's original TEST signer is
`D02BE98DE9C0986C1120951315A8B1E319DBEE03` and that authority expired on
November 19. The hosted route's later TEST signer
`CE8ED75F205581BFF9C470173F6B1AA9DA3ABD8A` also expired. A fresh
transaction needs current trust for any archive it introduces. The
resulting Qt package needs a separately selected current TEST certificate,
its full signing fingerprint, exact archive and detached-signature pins,
and an independently authorized install and rollback scope.

The [capsule sealer](seal_full.py) uses the exact retained unissued QtGui
capsule, its archived source bytes, and the three independently pinned
scratch, Core and Gui backing files. It prepares a fresh boot carrier
and a clean ext4 result template inside a private output directory.
The tool file is a canonical JSON mapping of `debugfs`, `e2fsck` and
`mke2fs` to absolute `path`, `bytes` and `sha256` pins. Supply its digest
independently and use a fresh 32-hex nonce. The sealer produces an unissued
binding and reports the handoff digest.

```sh
python3 -I -B scripts/integration/qt612_full_16k_preflight/seal_full.py \
  --qtgui-capsule "$QTGUI_CAPSULE" --scratch "$Q3_RAW" \
  --core "$CORE_OVERLAY" --gui "$GUI_OVERLAY" \
  --tools "$PREPARATION_TOOLS" --tools-sha256 "$TOOLS_SHA256" \
  --nonce "$FRESH_NONCE" --output "$NEW_CAPSULE"

python3 -I -B scripts/integration/qt612_full_16k_preflight/full_capsule.py \
  --capsule "$NEW_CAPSULE" --handoff-sha256 "$HANDOFF_SHA256"
```

Passive admission reopens the exact source, plan, dry-run receipt,
derivative media and ext4 boot payload and checks current disk, memory
and CPU capacity. The [host actor](full_actor.py) additionally requires
an independently supplied Root selection for the fresh full-build scope
and the pinned offline runner. It uses the existing owned command and
allocation guards and rechecks the read-only backing chain after QEMU exits.
The [guest worker](full_guest.py) requires both dry-run transcripts to
match before running the serial build. Completion requires a retired
build process group, an idle `all` target and all 18 named AArch64 shared
libraries with matching ELF SONAMEs and 16 KiB load alignment. Only the
exact inherited QtCore may carry its pinned interpreter. The worker
retains the bounded Ninja log and reports appended output rows and
distinct timing and command tuples separately from the 1,216 scheduled
dry-run actions. Its RSS field is the cumulative child high-water mark.
Guest uptime reduces the worker window and preserves time for post-build
checks, result export and poweroff. The host's full allocation samples
run once per second, while the owned runtime checks disk limits twice per
second. The [independent reader](full_readback.py) reopens the process
receipts, serial terminal and bounded ext4 result against the same plan.

The [outer launcher](full_site.py) uses a separately pinned local site
descriptor. The descriptor selects the capsule path and directory
identity, launcher bytes, and the exact historical QtGui handoff and
retirement record. Passive admission verifies the retained Q3, R4, Core
and Gui closure copies and the local CLI and socket pins. The CLI
produces the descriptor and reads it back without launching a container.

```sh
python3 -I -B scripts/integration/qt612_full_16k_preflight/full_site.py \
  --capsule "$NEW_CAPSULE" describe --handoff-sha256 "$HANDOFF_SHA256" \
  --qtgui-handoff "$QTGUI_HANDOFF" --qtgui-retirement "$QTGUI_RETIREMENT" \
  > "$SITE_DATA"

python3 -I -B scripts/integration/qt612_full_16k_preflight/full_site.py \
  --capsule "$NEW_CAPSULE" preflight --site "$SITE_DATA" --site-sha256 "$SITE_SHA256"
```

The launcher requires the separately reviewed Root selection and its
independent digest for `run` inside the selected full-target user scope.
The scope must send SIGTERM to its control group, retain a 360-second
stop grace, and allow final SIGKILL. The launcher checks the effective
scope configuration before it can claim or launch. The grace lets the
launcher retire a container owned by the rootless daemon after scope
cancellation.
It checks the pinned rootless daemon and image and takes the permanent
`full-build.claim` atomically. It prepares a private result clone and
verifies the original container's isolation, memory, CPU, no-swap and PID
bounds before attaching. It retains the original exit and inspect
records, keeps stdout and stderr private, and removes only the owned
container. If Docker create is interrupted before the CID file is
complete, cleanup searches by the exact name and nonce label and
verifies the full owned identity before removing a still-unstarted
container. A pending create or ambiguous census yields an `UNKNOWN`
HOLD disposition. After the scope exits, `observe` reopens the original
receipts and checks twice for both the original CID and the scope.
The guest reader covers guest and actor evidence. The outer observation
separately establishes host retirement.

The first real unissued capsule, sealed at `8001859c`, passed passive
admission from the byte-exact Q3, Core and Gui files. Its handoff
SHA-256 was `326ac4d4e770c0e94e704ff50b65d90161df3d78eb14b94ac0d04c53058585be`
and its preflight receipt SHA-256 was
`ecce9f0278c96de8d7d0f1b9b241d80f3b9bb4ccb4bc16ec802023ad677f56c9`.
The revised capsule returned `PASS_FULL_TARGET_HOST_PREFLIGHT_ONLY`
on November 25. The launcher refused to use that site descriptor
with the earlier capsule, and both capsules remained unclaimed.

| Revised unissued record | SHA-256 |
| --- | --- |
| Handoff | `00781ee8dada031334e93d0f1263f7f697775b580a8429b56493c36ee42bf0f4` |
| Plan | `b70e038081212bf8fcc29f451c669d89cbdebfc259ac0646af5efe1086e760e4` |
| Host site descriptor with explicit stop grace | `383353a39b6a46afb37bb4399a25bf6252aeb81aea5f9c83a891e6dc37f9bb0f` |
| Host preflight receipt with explicit stop grace | `451f88c7c292f4854de30471388d94b7ded3160b0fd3d6c875e9c4bcbd902820` |

The launcher and revised worker have offline tests for root and
authority binding, retirement, completion, library identity, deadlines
and output limits.

The authorized first full-target attempt exhausted the 4 GiB child
ceiling after 15,272.820 seconds of QEMU time. QEMU reported file-size
errors and retired with its process group observed empty twice. The
guest emitted no terminal marker. The host actor exited 1 and the
independent outer observer confirmed scope and container retirement.
Readback verified the original backing pins and retained partial
evidence. The partial result supplied no completion count.

The recovery capsule may explicitly select
`seal_full.py --overlay-file-bytes 8589934592`. This sets an 8 GiB
ceiling for a fresh child, preserves the original backing chain and
raises the minimum host disk admission to 12.125 GiB. For a cap above
4 GiB the disposable actor sets an exact kernel limit and verifies
that the owned QEMU process inherited it. The original runtime retains
its process custody and allocation watches. This path is unissued
and requires a fresh selection scoped to the exact replacement capsule.

The [packaging and installed 16 KiB handoff](PACKAGING.md) selects the
completed overlay and pinned dependencies, projects the corrected Qtbase
provider metadata, and describes the separate signed installation and
rollback criteria. Package assembly, installed Qt family compatibility,
and physical Asahi graphics remain separate qualifications.

The route review and host snapshot are in
`~/.cache/qtbase-full-route-review-20261125.j5djy795/full-build-route.UNISSUED.json`,
SHA-256 `ee20cb360c411d1f4bd3bfcd0bba93ff29c363f848e0bb0aca9efb14ff54f8ff`.

[QtGui hardware and build scope](../../../docs/validation/qtbase612-emulated-arm16k-qtgui-link-20261122.md)
· [Separate native Qt family producer](../../ci/qt612-complete-family-native-source/README.md)
