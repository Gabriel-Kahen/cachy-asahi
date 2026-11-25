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

[QtGui hardware and build scope](../../../docs/validation/qtbase612-emulated-arm16k-qtgui-link-20261122.md)
· [Separate native Qt family producer](../../ci/qt612-complete-family-native-source/README.md)
