# Read-only native ARM Apps parser experiment

This lane measures the reviewed `sections` function and identical outcome capture over every original574 disposable builder ALPM `files` record. It does not measure inventory scanning, applications, a full system or M2 hardware. It neither installs packages nor changes the database in its consumer. Original574 reconstruction remains the unchanged producer.

Baseline is Apps6 code at eac600bd4f256068a78eb793dd464277eed6ce23; candidate is Apps7 code at 134e02ba0c73dab4eb4a22cbfd562599b9e7a411. The exact two source operands and original standalone microbenchmark are held by whole hashes. Only reviewed `need` and `sections` function ASTs execute. No exported code is imported.

The original microbenchmark's eight exact equivalence/refusal controls stay unchanged. Native corpus scope is explicitly separate: the production MAX_RECORD=4 MiB, MAX_BYTES=64 MiB and FILES<=32768 constants are checked in both exact source ASTs. All574 records must fit; zero-byte fileless records are valid, and no package is skipped. Missing/extra database rows, locks, symlinks, malformed records, excess limits or any output/refusal disagreement fail the whole trial before timing. The candidate enforces the ownership-count cap before the quadratic baseline. Record/source bytes and namespace are rechecked after timing.

The consumer is one nonroot, cap0, no-new-privileges/seccomp, read-only root/inputs, network-none native aarch64 container, 1 CPU, 1 GiB,64 PIDs. Worker300s/owner330s; the unchanged process-group owner and exact consumer-before-producer retirement remain required. Two warmups each precede six complete-corpus repetitions each, alternating AB/BA. Raw perf_counter_ns wall and process_time_ns CPU durations are recorded; equality comparison/hashing is outside timed intervals. Timing covers parser plus identical outcome capture, not raw I/O.

Only bounded project statistics, exact source/dataset digests, Python numeric version, architecture/page size, UTC, guard labels, twelve raw sample pairs and retirement booleans are exported. No raw record/package names, full maps, hostnames, kernel release, uname payload, environment, argv, private logs or raw original574 report is exported. Physical hardware, thermal/power/background controls are unverified; speedup/gain is not accepted automatically. M2/release remain NOT_RUN/NOT_ADMITTED. A cap0 read refusal or a corpus that cannot finish within the fixed budget is an incomplete trial, not permission to skip records or change bounds.

## Source preparation

`prepare.py --workspace REPO --output NEW --authorization NEW.json` emits the closed NULL template. `job.py preflight --source NEW` is source-only and can run with process creation forbidden. `python3 -B -m unittest discover -s NEW/scripts/ci/apps7-parser-native -p test_lane.py` uses only private fixtures and the reviewed parsers.

The coordinator must independently join both exact public source files before explicitly selecting them. A separate JSON file has exactly `{ "status":"ROOT_SELECTED_PUBLIC_PARSER_CODE", "baseline":"eac600bd4f256068a78eb793dd464277eed6ce23", "candidate":"134e02ba0c73dab4eb4a22cbfd562599b9e7a411" }`. Pass it to `prepare.py --selection FILE`; the original NULL template remains separate. Only policy, source-manifest and workflow stamps may change on binding. No actual source/ref/run IDs are guessed. After publication, source proof requires actual workflow and checkout revision equality and native runner identity before accessing retained inputs.

No actual/native measurements have been performed by this source handoff. All control measurements use synthetic private fixtures on the development host and establish method/guards only.
