# Apps inventory parser microbenchmark

Run with Python3.11+ and two explicitly reviewed `inventory.py` sources. This utility extracts and executes only their `need()` and `sections()` functions, avoiding module initialization and package/database operations. It is not a sandbox for hostile source code. Inputs are read through nofollow ordinary-file descriptors, checked for drift, and never written. JSON goes to stdout; choose a new output file when redirecting.

```sh
python3 -I -B scripts/benchmarks/apps_inventory_parser.py \
  --baseline packages/tools/cachy-asahi-apps/inventory.py \
  --candidate packages/tools/cachy-asahi-apps7/inventory.py \
  --repeats 4 --machine-label 'operator-defined-machine' \
  --execution-context physical > parser-measurement.json
```

The default deterministic record has16384 unique FILES entries. Use `--values 8192` for a smaller fixture, or `--record /readonly/package/files` for one explicit ALPM record. FILES/BACKUP are allowed by default; e.g. select `--sections NAME VERSION ARCH` for a corresponding desc record. Custom records are bounded to1MiB and16448 LF characters. No database is discovered or opened automatically.

Before timing, both parsers must produce exactly equal results or equal exception type/message on eight duplicate/malformed controls **and the selected workload**. Matching refusals may be timed and are explicitly labeled REFUSED. Each timed outcome must still equal the untimed result. A mismatch exits1 without a success report.

Even repeats2..20 alternate AB/BA, giving each variant equal first/second positions after untimed warmup. Bounded JSON retains raw nanoseconds in execution order, full source and workload hashes, outcome hash, Python/executable, uname/page size, UTC interval, load averages and operator context. Timing includes the parser call and identical outcome capture; comparison and hashing are outside the timed interval. It uses one process without CPU pinning, thermal/power controls or automatic inference of physical hardware.

This measures section parsing of a synthetic or explicitly supplied record. It does not measure the full two-scan inventory, repair lifecycle, TCG capacity or complete system performance. A run on ARM/M2 remains a parser measurement with its recorded conditions; hardware/release acceptance is never set by this utility. Retain raw reports and control power, background load and thermal conditions independently for any later performance study.

Tests join the existing `scripts/benchmarks/test_*.py` discovery; no workflow change is needed:

```sh
python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/benchmarks -p test_apps_inventory_parser.py -v
```
