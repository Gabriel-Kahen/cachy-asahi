# Qt612 source controls successor

This is a new CI route. The entire `3305881fdba011be1d0cc28a9d4d4e834b074f85`
control family and its original workflow remain unchanged. The successor calls
that complete 140-control route once per selected Python, then runs the actual
frozen DATA adversarials from:

| Family | Original commit | Logical coverage | Additional executions |
| --- | --- | ---: | ---: |
| GUI evidence/lifecycle adapter | `85626d96a95abc0a29d7239c63b8d522150bcb50` | 117 | 117 |
| Producer/transport/GUI projection | `663927a694fcfddda56f32c1eff00701a6395a93` | 114 | 86 |
| Successor I/O boundary | authored here | 1 test / 10 subcases | 1 |

The producer's other 28 controls are an exact copy of the transport suite already
executed by the baseline. The successor verifies **all six copied files**, their
whole bodies, sizes, modes and complete namespace against that frozen baseline
before reusing its coverage. Different bytes/modes or a missing alias refuses;
no changed suite can silently inherit that result. This is explicit duplicate
coverage reuse, not skipped unittest cases. The route executes **344 tests with
zero skips** on each of Python **3.12.13** and **3.14.6**.

`inputs.lock.json` pins the complete authored families (baseline CI: 6 entries;
GUI adapter: 20; producer: 42), the unchanged legacy workflow, seven additional
public support files, the suite catalog and three new local execution/control
files. The reused baseline independently checks its 298 frozen recipe/transport
entries. All those inputs are rechecked after the suites; no C/E/F source family,
old CI code or shared manifest is modified. A shallow checkout is sufficient;
this gate compares current file bytes to original Git-derived pins and does not
fetch or assert historical Git ancestry.

Each new suite executes in a separate interpreter under a 512 MiB address-space
cap, 30-second CPU cap and 40-second parent timeout. A permanent audit policy
allows pinned public repository reads, interpreter libraries, `/proc/self/status`
and owned temporary MODEL data. It rejects unpinned/private reads and writes
outside the owned MODEL scratch. The `os.open` wrapper carries the actual
`dir_fd` target into the audit check while preserving the original descriptor-
relative syscall; relative names cannot masquerade as reads/writes in CWD.
Directory enumeration is bounded to the same selected public/owned trees.

Existing per-suite actor fences remain active with their original exception
semantics and self-tests. The two producer transport suites without their own
fence use the successor's wrapper actor fence before implementation imports.
The boundary test creates only inert temporary fixtures before installing a
nested policy and verifies absolute and descriptor-relative read/write refusal,
owned writes and a synthetic actor audit refusal. The parent cleans its MODEL
scratch after that child exits; the test cannot relax the installed guard.

The suite catalog's support-file list was obtained from real source-suite read
traces. The successor checks every actual repository read against the pinned
allowlist. No network, native process, Qt configure/compile/smoke, GPG, actual
source-material cache, input provider, Source construction requiring unavailable
private material, artifact upload/download, Root grant or package acceptance is
part of this route. Producer cache tests create and read small inert MODEL
objects in their own temporary directories. Public committed evidence documents
are inspected as source data; their previous real operations are not replayed.

```sh
/absolute/python3.12-or-3.14 -I -B -Werror::ResourceWarning \
  scripts/ci/qt612-source-controls-v2/ci.py \
  --workspace /absolute/composed/checkout \
  --report /absolute/fresh/report-outside-checkout.json
```

The fresh report is written only after all suites and final pin checks pass. It
records the once-executed baseline, all new suite receipts and their repository
read sets, plus the exact 28-test alias. Success is source-only, always with
native acceptance false and Root acceptance null. The new workflow uses the
existing pinned checkout/setup-python actions, read-only contents permission,
no credential persistence, a 180-second command timeout and an eight-minute job
limit. It uploads nothing and does not dispatch native work. Its PR/push path
filters include the actual public support inputs. The old workflow keeps its
original independent triggers; deduplication here describes this successor's
single invocation, not unrelated workflow runs.

Local execution of the exact workflow shell command verifies this authored route.
Hosted Actions availability/execution and actual native/provider/signing/runtime
acceptance remain separate and unrun until those actors and gates complete.
