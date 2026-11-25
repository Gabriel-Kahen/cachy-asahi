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

[QtGui hardware and build scope](../../../docs/validation/qtbase612-emulated-arm16k-qtgui-link-20261122.md)
· [Separate native Qt family producer](../../ci/qt612-complete-family-native-source/README.md)
