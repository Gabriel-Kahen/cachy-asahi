# Independent kernel Docker compatibility review

**PASS for the bounded source, local parser and mock/process compatibility correction. No actionable finding in this nine-file delta. Native Docker and kernel acceptance remain NOT RUN.**

Reviewed on 2026-10-12 against committed baseline `e596fa81f57de1b180b608c3a2d34a1dc52b98a9`, after reading `AGENTS.md`, `docs/roadmap.md` and `manifests/packages.toml`. This review owns only this document. It neither integrates the correction nor reviews another workstream's active fixes.

The held checkpoint is `artifacts/kernel-native-job/handoff-api148-start-20261012/checkpoint.json`, SHA256 `a7b5510e920225915a19ee42292dee5a8af5c3fc94f90009a9d9a8ac0d68172b`. I independently checked its nine source entries, nine held-unchanged entries and five evidence entries against actual bytes, sizes and modes. All matched before testing and after review.

## Exact reviewed source

| Path | Bytes | Mode | SHA256 |
| --- | ---: | --- | --- |
| `docs/workstreams/kernel-docker-compatibility.md` | 3865 | 0o644 | `b5f8ee9e5e365cad65c1e453f561db898f928a05f877892c99350d510554506a` |
| `docs/workstreams/kernel-native-job.md` | 12521 | 0o644 | `e004bc820886ff015f69531c928f7db1b0e0c24f14956e1e7c947d0caf908ae1` |
| `docs/workstreams/kernel-native-stage.md` | 13755 | 0o644 | `d38d2a66ae9c6d7b3b3b7e52a41924892cca2c720fa2ee600be7d0c90215a7a4` |
| `scripts/port/kernel-native-job/job.py` | 25711 | 0o755 | `0a35909fe9cdef5ec0a25c77441739810d73afe1696661c29231b01e9f1cd7dc` |
| `scripts/port/kernel-native-job/test_job.py` | 26595 | 0o644 | `db0c9770a56c22020d92f2b0e41196ac6a855652d34f05f33acb284e4af5fe27` |
| `scripts/port/kernel-native-stage/broker.py` | 26096 | 0o644 | `7623948ff99aeef29dc9dbff32b2a9f0d7eeb8f1276e80d80d76e8c359de7592` |
| `scripts/port/kernel-native-stage/image.py` | 9256 | 0o644 | `09f737f54afaaeff475a1dfe7811dae4705b465aca1b1fce33d5dc4a69a49be9` |
| `scripts/port/kernel-native-stage/test_broker.py` | 13940 | 0o644 | `87c1b01b4a42ab6c0044eafe3b082c2de2a901c32f6349745ba735008b824756` |
| `scripts/port/kernel-native-stage/test_image.py` | 13506 | 0o644 | `fe3fd91867c216fc71bfee9aae63f68af4fda98074e6ea767e7f1b2477aa03b4` |

The compatibility document is new relative to the baseline; the other eight paths have reviewed baseline deltas. Independent AST comparison identifies only `Docker.info`, `Broker._launch` and `image.request` as changed production functions, plus the two version constants. The respective baseline production SHA256s are `d827a93d0b29f617e1c4a3cdc51b6f3be8d2ff15b97abc1758834ed13b7ba08f`, `6e04f8928a7fb5548f27b321f43b3b1c23d8dde5d4f3b21c3a069259d9ca92df` and `df0f95c7e769e1b05e3af5b428dd8cf63d3f34a9f44fa030598afad0bcd060e2`.

## Compatibility and preserved behavior

The old image prefix required API 1.49, which the retained Docker 28.0.4 daemon's recorded range 1.24 through 1.48 cannot serve. The correction fixes Unix commit/tag requests at 1.48 and requires the same version to lie between the actual locally queried daemon minimum and maximum. There is no request-version negotiation. The tests refuse unavailable, inverted and malformed ranges. This establishes compatibility with the recorded range only; it does not establish the state of a current daemon.

Actual owned Unix-socket tests execute `image.request`/`wire`, capturing escaped `GET /v1.48/images/{private-tag}/json` and `POST /v1.48/commit?container={owned-ID}&pause=true&repo=cachy-asahi-kernel-private&tag={nonce}`. They verify content length, JSON body, all twelve projected fields, the original empty-entrypoint sentinel, HTTP 201 and an immutable `Id`-only response. Unexpected response statuses/keys/IDs leave `COMMIT_ATTEMPTED` durable. Existing uncertain-POST, recovered-ID-before-removal, retry, private-tag and immutable-ID absence, HTTP framing and aggregate-deadline regressions pass.

The held `scripts/ci/commit_image.py` remains byte-identical to the baseline at SHA256 `716e9aac5bd472e58da53e5def54a169f01b2c8bc7ac1fbae849f68532cf8a5c`. Its twelve fields are User, Env, Entrypoint, Cmd, WorkingDir, Labels, Volumes, ExposedPorts, StopSignal, Shell, Healthcheck and ArgsEscaped. This projection does not attest additional Config fields. Kernel stage/runtime, job runtime/public projection and workflow bytes remain held. Source diff preserves identity/nonce checks, inspected exact owned container ID, config verification, exact base-layer prefix plus one added layer, layer-size bound, recovered image-ID journaling, strict unknown-commit FAIL and both tag/ID absence checks. Five-hour stage work and both 7,200-second kernel-build budgets remain held; source/licensing/payload and resource checks were not weakened.

The start correction removes unsupported `--sig-proxy=false`; the broker now passes `start --attach <exact journaled ID>` after inspection. Cancellation, process-group reaping and journaled container cleanup remain under the existing supervisor and cleanup budgets. Real owned fake-CLI fixtures pass success, SIGINT, SIGTERM and timeout cases, assert the exact start/removal IDs and verify the CLI and descendant have been reaped. These fixtures model signal forwarding; they do not prove Docker daemon signal behavior.

The retained Moby v28.0.4 primary-source bytes (ten files) and Docker CLI v28.0.4/v29.0.0 bytes (six files) were independently rehashed against `primary-source-verification.json`; all hashes/sizes matched. I inspected API constants, the commit handler, the twelve-field configuration type and both CLI start implementations. The commit contract exists at 1.48; CLI start registers no sig-proxy option and forwards signals for non-TTY attachment through the inspected immutable ID. CLI revisions are `b8034c0ed70494a90c133461d145cd072d920d7c` and `3d4129b9ea4fa263e57984428ad908f6a7d4b94f`. This review used retained primary-source files and did not refetch them or run a daemon.

## Independently executed verification

| Check | Actual result | Scope |
| --- | --- | --- |
| `python3 -I -B -m unittest discover -s scripts/port/kernel-native-job -p 'test_*.py' -v` | 103 PASS, 3.958 seconds, zero skips | Data, mock APIs, owned processes and temporary Git fixtures |
| `python3 -I -B -m unittest discover -s scripts/port/kernel-native-stage -p 'test_*.py' -v` | 86 PASS, 10.097 seconds, zero skips | Owned Unix/loopback fixtures, fake CLI processes and small host C probes |
| Supplemental image-inspect mutations | Seven rejected as required | Wrong architecture, OS, immutable ID, Config, base prefix, extra layer and excessive Size |
| `packet.preview(root)` on held source map | Refused with `frozen-kernel-drift` | Actual source capture/verification; read-only enumeration via `closure()` alone is not verification |
| Installed Docker CLI parsing | Results below | Explicit temporary mock Unix sockets only |

The owner's claimed 103 job plus 86 stage tests and the earlier peer's 103 plus selected 83 agree with the suite structure. That peer explicitly excluded three unchanged host C compile fixtures. This review executed all 86, including `test_baseline_bug_and_candidate_fix_are_not_hidden_by_aggregate_pass`, `test_real_extracted_functions_cover_every_branch_case` and `test_unexpected_observation_fails_and_keeps_evidence`. None were excluded or skipped here. The extracted-function fixture checks the pinned baseline/candidate source and 13 branch cases per variant using a small host-compiled C program; it records actual kernel execution as NOT RUN. It is neither a complete kernel compilation nor native ARM/M2 evidence.

For independent CLI checks, `/home/gabe/.local/bin/docker` resolved to `/home/gabe/bin/docker`, SHA256 `e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e` (the retained local CLI 29.8.0). Each process used a fresh HOME and empty DOCKER_CONFIG, an environment containing only those paths, PATH and DOCKER_API_VERSION=1.48, and an explicit `--host unix://<owned temporary socket>`. No inherited context or endpoint was used.

- Old `start --attach --sig-proxy=false <64hex-ID>` returned 125 with unknown-flag error and zero socket requests.
- Corrected `start --attach <64hex-ID> --help` returned 0 and sent only `HEAD /_ping` to the mock.
- Exact corrected `start --attach <64hex-ID>` parsed successfully, sent `HEAD /_ping` followed by `GET /v1.48/containers/<same-ID>/json`, then returned 1 on the deliberate mock 404. This proves passage through flag parsing and exact-ID inspection, not a successful start or attachment.

The local `/usr/bin/docker` is absent. The local alternate binary was used solely for parser proof and does not satisfy the native job's canonical hashed `/usr/bin/docker` prerequisite. No real Docker socket was opened, even for read-only inspection.

## Closure and remaining gates

Historical kernel24 source lock SHA256 `53d5c0dba0102413256552da3534b553ce5591ceaa747980e579d4fa1359bc5d` and `packet.KERNEL_SHA` are deliberately unchanged and stale for these reviewed edits. The expected actual `packet.preview` refusal is a preserved safety boundary. Coordinator rebind of the 24-file source map, dependent 115-file source registration/closure and actual committed Git blobs/modes is separate pending work, outside this document's signoff.

No excluded check is silently treated as PASS: daemon API trial, real Docker start/attach/signal forwarding, daemon commit/config/layer/removal, full native kernel builds, kernel execution, installation, exact-M2 hardware and performance measurements were excluded and remain NOT RUN or NOT MEASURED. Live memory and disk remain UNKNOWN. The recorded API range alone cannot satisfy 15 GiB total memory, 14 GiB available memory or 30 GiB free disk; the unchanged native ARM/rootful/nonroot-client/cgroup-v2/UID-mapping/empty-inventory prerequisites still require actual evidence before a finite native job.

No source, lock, manifest, Git state, workflow, dispatch or host package was changed by this review. Temporary test inputs, sockets, subprocesses and small C fixtures were owned locally. The sole retained review write is this file.

## Coordinator source disposition

Root verifies allnine held source byte/mode pins against checkpoint `a7b5510e…`, accepts the bounded API1.48/start-command correction and the independently rerun103 job/86 stage/zero-skip plus seven negative image cases. Fixed request/guard1.48 now matches the actual retained Docker28.0.4 range; no resource or daemon execution is inferred. This source is ready for coordinator24-file transitive source/Git acceptance and115-file job packet registration. Native kernel builds, installation, M2 and performance remain NOT RUN.
