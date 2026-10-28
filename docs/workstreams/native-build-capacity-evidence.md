# Retained native build capacity observations (COV5)

October 13, 2026. This finite proposal extracts five actual hosted ARM jobs from
already retained metadata. It supplies observed elapsed times and evidence sizes
for B15/M5 operational planning. COV5 remains incomplete: no sustainable compiled
build capacity, account quota, resource high-water marks or recurring human
maintenance capacity has been established. Root owns review and integration.

The captured roadmap, inventory and status keep full R1–R5/M5–M9 mandatory. All
ten project development candidates remain outside an accepted release set.
Template build success is intermediate evidence. Both M2 Air sizes, 16K compiled
compatibility, final-system performance/power, full target transactions, recovery,
signing custody and a subsequent maintained release remain separate gates.

## Observed wall times

All times below are seconds derived from job/step `startedAt` and `completedAt`
in the retained `run.json`, whose timestamps have one-second precision. A zero
means equal reported timestamps, not zero execution cost. Job elapsed time uses
the job endpoints, not run creation/update timestamps. It includes setup,
retention and scheduler overhead; it is not billed runner minutes or CPU time.

| Actual run / Source prefix | Whole job | Source proof | Official prefetch | Native/caller/composition step | Retention steps | Observed outcome |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Maintained `38354516537` / `0f6b202` | 348 | 1 | 35 | 305 | 1 | Eight baseline builds, four comparisons, 249 signature observations; checkpoint PASS |
| Topmem `38450105697` / `bf5ea66` | 371 | 4 | 45 | 311 | 0 + 0 | Fresh baseline 8/4/249 accepted; signing failure; addon counts zero |
| Topmem `38458434811` / `1014a19` | 356 | 3 | 44 | 302 | 1 + 0 | Fresh baseline 8/4/249 accepted; signer `io-failed/start`; addon counts zero |
| Topmem `38463181445` / `9710bcf` | 345 | 3 | 24 | 311 | 1 + 0 | Fresh baseline 8/4/249 accepted; signer `io-failed/start/PROC_EXE_READLINK/13`; addon counts zero |
| Composed `38462431231` / `4327634` | 13 | Not a separately timed step | Not entered | 12 | Included in composition step | `TYPE_ERROR/SERVICE_CANCEL_EXIT_SET_HANDLER`, native hook false, cleanup projection PASS |

The maintained step includes bootstrap, authentication, eight template/package
builds, comparison and cleanup. Each Topmem step includes a fresh baseline,
failed addon setup and recovery. None is an individual compiler or pure build
duration. The runs use different Source revisions and failure paths; these are
five observations, not repetitions of one controlled workload. The composed
12 seconds describes a pre-hook failure, not native build throughput.

`observations.json` includes every individual step and its exact endpoints,
including checkout and post-job steps, plus each job's conclusion. No selected
job metadata is missing. Per-package/per-phase compiler timestamps are missing;
there is no basis to divide these durations into unrecorded phases or estimate
jobs per hour, parallel capacity or emergency rebuild response time.

## Byte and command/record evidence

| Run | Held log bytes | Held plain evidence bytes in this proposal | Recorded unread packed export sizes |
| --- | ---: | ---: | --- |
| `38354516537` | 50,789 | 121,961 | Packed native metadata size not separately held |
| `38450105697` | 53,880 | 61,198 | Caller 681; prefetch 549 |
| `38458434811` | 54,077 | 61,994 | Caller 824; prefetch 553 |
| `38463181445` | 54,129 | 62,133 | Caller 864; prefetch 551 |
| `38462431231` | 37,669 | 46,084 | Handoff status 684; observed summary 1,169 |

The five logs total **250,544 bytes**. The 27 captured plain evidence files total
**353,370 bytes**, including completion indexes and decoded JSON; these are
retained evidence sizes, not private build storage or total workflow artifact
usage. Duplicate alias exports from Topmem01 are not counted twice. Compressed
exports and raw archives were not read, decoded or copied. Their sizes/hashes
are reported from the existing completion index; no fresh archive verification
is claimed. Evidence embedded in a log and its decoded JSON are distinct
retained files, not independent resource observations.

Each of the four baseline/caller jobs records a successful acquisition count
of **501** pinned files and the same acquisition-record digest. The downloaded
input payload byte total is **not exported**. Prefetch times therefore supply
elapsed step observations, not transfer throughput. Baseline metadata reports
19 private/public record sizes totaling **214,962 bytes**, with one additional
sanitized-signature JSON record lacking a recorded byte size. Those numbers are
Source-gated record-size projections, not measurements of input payloads,
package artifacts, extracted filesystem, image/cache or process disk usage.
The four baseline package artifacts have recorded hashes/comparisons but no
exported artifact byte sizes. Budget/deadline values and byte caps in Source or
metadata are limits, not consumed resources.

The extractor indexes actual timestamped metadata-marker lines and paired log
groups without decoding rendered payloads. Maintained markers occupy lines
241–245; each Topmem caller marker is line 303 and independent prefetch marker
line 321. The composed startup marker is line 195, bounded evidence exports
196–209 and 210–232, and launch-result marker line 234. Each record includes its
log step, endpoints and line numbers. A rendered `Run` command group indicates
the Actions command presentation boundary; its displayed Source is not proof
that every contained command ran. No raw per-command runtime journal or pure
build timing was exported by this selection.

## Small reusable extraction and validation

The owned artifact directory contains `extract.py`, 27 exact plain evidence
captures, six context captures, `input-index.json`, `observations.json` and
`controls.json`. The completion indexes bind each consumed non-completion leaf;
the proposal receipt pins the completion captures themselves. Run ID and Source
commit are checked against completion. This consumer authenticates retained
data consistency; it does not repeat prior Source/actor/native reviews.

From the repository root:

```sh
python3 artifacts/reviews/native-build-capacity-evidence-proposal-20261013/extract.py
python3 artifacts/reviews/native-build-capacity-evidence-proposal-20261013/extract.py --controls
```

All five positive inputs pass. Ten bounded in-memory corruptions are rejected:
duplicate JSON key, duplicate job ID, duplicate step number, reversed step time,
nonterminal job, duplicate/unclosed evidence begin, unmatched evidence end,
duplicate metadata marker and reversed metadata-marker order. The consumer also
checks chronological job/step windows, ordered log timestamps, terminal
conclusions, finite exact marker sequences and completion byte/hash bindings.
Its one-MiB input ceiling is a parser bound, not observed job usage. It performs
no subprocess, actor launch, decompression, network, Git or host mutation.

## Finite operational successors

| Next actual job/input | Record needed | Capacity question still open |
| --- | --- | --- |
| Pending compiled updater/Rust tray with its separately selected 354-package builder | Two clean compile/build/check/package runs; phase endpoints and natural command results; per-build user/system CPU, peak RSS or scoped cgroup memory peak, filesystem high-water mark, artifact/log bytes, exact toolchain/input identity | Compiled Rust cost and variation; no substitution of maintained341 template timings |
| Selected FDK source/license/native workflow after its acquisition and startup blockers | Two clean builds; observed compile/link/check/package endpoints and counts; the same scoped resource/artifact fields | Actual C/C++ workload cost; planned 395 translation units/two libraries are not executed counts |
| Release-defined dependency set after metadata/correspondence and platform reconciliation | Actual input/package byte inventory and extraction high-water marks; whole fresh/upgrade/rebuild transaction with phase boundaries and retained outputs | Full-port storage, transfer, rebuild and retention costs; platform261 and unadopted624 are not selected by this proposal |
| Named builder/release maintainer and account evidence | Actual permitted runner parallelism/quota, reservation, retention policy, rebuild cadence, backup capacity and finite responsibility handoff | Sustainable throughput, ongoing staffing and emergency correction time |
| Named signing custodian and reviewed recovery workflow | Actual successful signing/recovery evidence plus custody/rotation/incident responsibility | Publication readiness; Topmem02/03 recovery refusal supplies no signer/keyhome absence proof |

Attach these measurements to the existing jobs and provenance, separating
fetch, authentication, bootstrap, compile, checks, packaging, comparison,
cleanup and publication. A measurement tool or field must be reviewed within
the existing containment/first-cause/recovery guards before execution. Record
missing fields as unknown; never infer CPU, peak RAM, disk, concurrency, costs,
security response or M2 performance from elapsed template phases. No new
measurement framework or scheduler is implemented here. Human owners for quota,
release operations and signing custody remain **unassigned** in this proposal;
an agent lane is not an ongoing maintenance commitment.

The earlier 80-leaf coverage reconciliation receipt remains byte-identical at
`56c4f8fa4cb12fea3fc9397432315521a5295db37f4bbdfa6c6259de4fa3f987`.
No shared manifests, workflows, Source actors, historical evidence, Git refs or
goal state were changed. This proposal is ready for independent retained-data
review; actual compiled/full-port capacity and release acceptance remain open.
