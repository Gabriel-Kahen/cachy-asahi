# Benchmark v2 validation boundaries

The source runners are `scripts/benchmarks/benchmark_v2.py` and
`paired_zlib_v2.py`. Read [the migration contract](owned-retirement-v2.md)
before declaring new plans. Historical plans and the measurement 0.1 package
retain their original source pins; this integration changes neither.

The exact twelve controlled lifecycle tests are published as
`scripts/benchmarks/benchmark_v2_retirement_controls.py`. Their bytes match the
qualified test source; the explicit controls filename prevents generic host
unittest discovery from launching namespace-only workloads. Nothing is skipped
inside the controls. Each test requires a distinct private PID namespace and
empty `/sys`, in addition to its fixture work and receipt directories.

Retained qualification passed all12 controls, plus both CLI help paths, on
Python3.12.13 and3.14.7. It used bubblewrap with a read-only host filesystem,
private PID/proc/network, private `/dev`, empty `/sys` and only fixture receipts
writable. Sensors were mocked; RSS/proc reads concerned fresh tiny owned
children inside that namespace. These results are software controls, not
hardware measurements or performance evidence.

The `benchmark-owned-v2-source` CI workflow checks exact finite file/mode pins,
Python syntax, adapter/owner connections, twelve declared controls and held
comparison source. It imports no benchmark code and runs no workload, sensor,
process census or lifecycle test. A source-check PASS grants no fresh twelve-test
execution credit. The pinned source profile lives beside the CI checker.

Fresh execution of the twelve controls requires a separately owned private
guest/namespace runner with the same PID/proc/dev/empty-sys/no-network boundary,
ordinary test UID and finite output ownership. The environment must provide
`OUTER_PID_NS` (the enclosing runner's own PID-namespace inode), `TEST_WRITABLE`
and `CASE_RECEIPTS`, then invoke the explicit controls file with Python3.12 or
3.14 using `-I -B`. Every control must run with zero skips. Ubuntu hosted namespace
availability is unestablished; provisioning a host binary alone does not prove
that boundary. A denied namespace requires a separately qualified owned guest,
not a skip, privileged/unconfined test or host security-policy change. This layer
adds no guest boot or hosted lifecycle claim.

Full performance blocks, actual paired artifacts, native ARM/M2, calibrated
sensor/energy data, package installation and release acceptance remain NOT RUN.
