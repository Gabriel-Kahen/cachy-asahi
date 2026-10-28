# Updater Docker default-mount correction

This is a bounded source correction and fixture validation. Native execution, package acceptance, installation, M2 hardware, 16K behavior and performance remain untested by this correction. Root integration still owns recipe pins, `.SRCINFO`, registration, ready/stage/source maps, workflow and any future dispatch.

Actual updater run **38296615950**, source `4748a5d5f4d2d649c1b397baaa63b087d3658ed0`, remains **FAIL**. Its bound diagnostic identifies `entry-guard / unexpected-mount / ValueError` before controller validation or compiler launch. The offending raw mount path and actual hosted Docker/runtime revision remain **UNKNOWN**. This correction addresses independently reproduced standard-default refusals; it does not identify that run's offending row or promote its result. The [independent run review](../reviews/native-updater-execution-38296615950.md) is preserved.

## Source-backed admission

[Moby `6430e49a55babd9b8f4d08e70ecb2b68900770fe` defaults.go](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/oci/defaults.go) supplies exact `/dev/mqueue` with filesystem `mqueue` and `nosuid,noexec,nodev`, fixed masks `/proc/timer_stats` and `/proc/sched_debug`, and conditional `/sys/devices/system/cpu/cpuN/thermal_throttle` masks. Its CPU helper produces decimal CPU numbers and includes paths only when they exist. The new CPU admission accepts canonical `cpu0` or nonzero decimal forms through 8191; this is a bounded project policy, not an upstream maximum.

The same Moby revision pins runc v1.2.6 in its installer. The official annotated tag resolves to [`e89a29929c775025419ab0d218a43588b4c12b9a`](https://github.com/opencontainers/runc/blob/e89a29929c775025419ab0d218a43588b4c12b9a/libcontainer/rootfs_linux.go). Its `maskPath` binds `/dev/null` for file masks and mounts readonly tmpfs for directory masks. The latter operation supplies `MS_RDONLY` only. CPU directory masks therefore require tmpfs with readonly and no contradictory writable flag. New fixed file masks require readonly tmpfs, or an observed exact null character device on writable tmpfs with the inherited `nosuid` flag and no contradictory flags. No truthy surrogate is accepted as null proof.

Unrecognized paths, extra nesting, stacked mount rows, malformed CPU names, wrong filesystems, contradictory flags, writable directory masks and unsafe null facts remain refusals. Existing static masks and every original capability, identity, network, root/input/output custody, resource, controller, compiler and package gate retain their behavior. Mount facts use the existing table, flags, filesystem and observed-null fields; no new projected diagnostic fields are introduced.

## Private IPC binding

The launch now includes exactly one `--ipc=private`. `parse_worker_inspection` requires `HostConfig` to be a dictionary and `IpcMode` to be a string, then requires exactly `private`. Malformed observations use the existing `inspection-schema-invalid` predicate; valid nonprivate modes use `inspection-identity-mismatch`. Both existing independent captures apply this check under the existing shared 60-second deadline. The finite State projection, container identity anchoring, query count and every success gate are unchanged.

## Validation and custody

The four authorized files were preserved byte-for-byte before editing under `artifacts/reviews/updater-default-mount-correction-20261012/history/`. All new primary captures, controls, fresh test inputs, logs and receipts are confined to that correction namespace. Captured Moby and runc sources retain their Apache-2.0 license texts; no downloaded source was executed. Tests use finite synthetic mount facts, mocked Docker observations and existing private Python subprocess fixtures; they invoke no actual Docker, compiler, package, installer or device actor.

Final source hashes, fixture results and independent review are indexed in the correction handoff. Historical root diagnostic evidence and the actual run's committed 86-file source capture are rehashed separately and remain unchanged. Other updater Python source/test files are checked against their initial hashes.

The final fresh fixture suites pass: **56 worker tests**, **51 independent guard controls**, **75 native-adapter tests**, **4 focused IPC tests**, and **61 offline primary-source checks**. Root AST checks restrict production changes to `observe`/`guard` and `launch`/`parse_worker_inspection`; the inspection function and State return ASTs are identical to the preserved originals, and all 44 literal guard predicates belong to the unchanged diagnostic schema. Three bound recorder controls verify that new mount refusals preserve the finite first failure rather than falling back to UNKNOWN.

The first guard fresh-copy harness omitted the frozen diagnostic helper and set its file-size cap to 8 MiB, below an existing 16 MiB output-limit fixture. That harness attempt and its failures are retained. The corrected copy includes the helper and uses a 32 MiB cap; all 56 tests pass. This was a fixture-harness correction, not a waived source failure. The native suite's existing signal-test child generated one copied bytecode file; its hash and size were recorded before removing only that owned generated cache. No live source or historical evidence was removed.

Independent frozen review passes **61 static checks and 8 selected guard/Recorder fixtures**, with no unresolved findings, skips or native execution. Its `refs/review.json` is indexed by the final handoff.
