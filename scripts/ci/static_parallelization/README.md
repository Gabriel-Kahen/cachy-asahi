# Static validation shards

Ordinary static validation now runs four independent `ubuntu-24.04` matrix
jobs. Commands remain inline in `static.yml` in their original order; explicit
step predicates assign each suite to exactly one shard. `fail-fast: false`
lets the other shards finish if one fails. This changes scheduling, not scope.

| Check display name | Scope |
| --- | --- |
| `Static foundation` | Setup/package/safety, KSM, repository/trust and release controls |
| `Static source-data` | The complete corresponding-source data tools block, including its port and integration controls |
| `Static desktop` | Audio/desktop fixtures, Doctor, boot-report, Welcome and current606 factories |
| `Static composition` | Copied-root, glibc, passive replay, repair, historical GUI, generic16K and final recipe controls |
| `checks` | Final aggregate; every static matrix job must succeed |

The matrix retains the job ID `checks` for existing source-contract readers,
but its display name is now `Static <shard>`. The final job ID is
`static-result`, with display name `checks`. Root's exact-head merge verifier
must expect the four new successful `Static ...` check runs and the successful
aggregate `checks`; the old long-running check run is replaced by this
aggregate. `cache-seed` remains an expected skip on ordinary runs. Existing
developer/release component and selector identities are unchanged.

The aggregate runs after both the matrix and cache seed reach a terminal
state. It requires matrix success and seed `skipped` normally, or seed
`success` when `workflow_dispatch` requests `measure-cache`. A failed, skipped
or cancelled matrix cannot produce a successful aggregate. Cancellation also
prevents the aggregate job from running through its job-level guard. Ordinary
step skips in each matrix job are
explicit routing: each suite runs on one other required shard, rather than
being removed from validation.

## Setup and source dependencies

Each runner performs the unchanged credential-free current-source checkout
and verified prerequisite action. APT authentication, archive-only cache
identity, receipt handling, package readback and action pins are unchanged.
Normal runners may share the same exact archive cache key; they still perform
their own verified setup. No native-build scheduling or permissions change.

Only these historical checkouts repeat across normal shards:

| Checkout path | Exact ref | Shards |
| --- | --- | --- |
| `.ci-inputs/historical604-runtime` | `3e71f2de1810d3eb94ab1621d23a087b27ea2568` | desktop, composition |
| `.ci-inputs/historical-inventory-input-basis` | `97f44c9e275b8d6446ae2d5aa99f1c413e884c64` | foundation, desktop, composition |

All other historical checkouts remain with their consumers. Doctor and
boot-report preparation/testing stay in desktop. Composition retains the
historical inventory preparation and its glibc/provider/Apps consumers, both
exact updater Git fetches, Setup5 checkout/archive/staging/replay, public-pair
profile construction/testing, repair/CI and cancellation preparation/testing,
and Welcome1 preparation/native/CLI/GUI tests. Generated paths and staged DATA
never cross runner boundaries. There are no cross-shard artifact transfers.

## Matched setup measurement

`measure-cache: true`, and reusable workflow calls with `setup-phase: warm`,
select one `Static all` matrix job. It executes all original steps on one
runner in original order, including the original report after the full suite.
This preserves `PASS_ONE_HOSTED_SETUP_PAIR_AND_FULL_STATIC_SUITE` without
claiming a full-suite result on a runner that ran only one shard. The aggregate
still waits for this job. `static-cache-trial.yml` and setup helpers are
unchanged. Normal runs do not emit a matched measurement report.

## Offline evidence and remaining validation

Hosted run `43865046798` rejected the initial workflow before creating jobs:
GitHub does not permit `cancelled()` in a step `env` expression. The correction
moves that condition to the aggregate job's supported `if` context. The
validator now rejects status functions in aggregate environment expressions;
the actual aggregate job condition and shell together cover cancellation.
Offline actionlint 1.7.12 reproduced that exact error on the original head and
passes the corrected workflow with external shellcheck/pyflakes disabled.

From the worktree root, run:

```sh
python3 -B scripts/ci/static_parallelization/validate.py
actionlint -shellcheck= -pyflakes= .github/workflows/static.yml
python3 -I -B -Werror::ResourceWarning scripts/ci/component_selection/test_select.py
python3 -I -B -Werror::ResourceWarning scripts/ci/component_selection/test_collect.py
python3 -I -B scripts/ci/test_static_apt_trial.py -v
```

The validator needs either PyYAML or `fy-tool`; it performs no suite commands,
APT, network, Docker, VM, GPG or privileged operations. Its baseline defaults
to the pre-change commit `fd374f605cc51381a8c787549b9e15c424c9f48e`.
It parses real YAML and compares all 181 original step objects, allowing only
new routing predicates. Thus exact shell commands, env, working directories,
timeouts, checkout action/ref/path/credentials and every other original field
remain equal. It proves that all 149 non-report suite shell blocks run exactly
once normally, checks 81 source/temporary-path dependency edges plus passive
replay ordering, and checks 155 real shell blocks with `bash -n`. It evaluates
the actual matrix/seed predicates and executes the actual aggregate shell for
all 64 success/failure/skipped/cancelled combinations. The existing selector
and prerequisite suites also remain required by the workflow.

Local results: preservation/routing/syntax checks PASS; selector 30 PASS,
collector 8 PASS and prerequisite receipt controls 12 PASS. Eight in-memory
negative mutations were refused: changed command, changed checkout pin,
omitted command, unrouted suite, missing historical prerequisite, premature
aggregate, permissive aggregate and fail-fast cancellation. These negative
checks changed no repository file and dispatched no suite actors.

Expected active step counts before composite-action expansion are foundation
40, source-data 3, desktop 56, composition 90; the source-data step contains a
large existing suite. Counts do not predict duration. Additional runner setup
and three repeated historical checkout operations have a cost. Real hosted
exact-head runs must validate all four shards and the aggregate, preserve the
expected cache skip, and measure elapsed time before claiming a throughput
gain. A dispatched matched warm run must separately validate the unchanged
measurement path. No hosted CI, native build, installation, M2 check or
performance measurement was performed for this change.
