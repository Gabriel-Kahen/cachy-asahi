# Independent FDK producer correction review

The held log-stream correction and finite diagnostic plumbing have **no concrete implementation blocker** in this bounded source/fixture review. They are ready for coordinator packet refresh and the separately required workflow diagnostic-enum review. The current 128-file packet is stale, and the previous workflow schema cannot yet publish the new fixed failure codes. This is not dispatch or native acceptance.

Actual run `38223759349` remains a producer FAIL with FDK NOT RUN and **unknown root cause**. Local stream/GPG/rootfs checks cannot establish the Ubuntu hosted failure's cause. The correction must not be described as a proven fix for that run until the next actual result supplies evidence.

| Held file under `scripts/port/fdk-native-job/` | SHA-256 |
| --- | --- |
| `producer.py` | `4cf0c56e7aade2289aefb21936928f89f97dd6d79e2a31551ee80021be67c41f` |
| `job.py` | `1b6c95b1cf8c428671fa2c4636def9e41a494bc600b4a24f7d9de455dee64ef4` |
| `evidence.py` | `8a70c467fc54862f8863fc0d24bdef18138ddffeb38ee80a84c8f0aba6fe7e3d` |
| `test_producer.py` | `0104f899289498361dea62433351f08f34d1744a0b909f9c3e9aaf7dcce696d3` |
| `test_job.py` | `107ae574dbbc5f4337b01680260a417101ba7cad4498add8dca8cef5c1bf0ec3` |
| `test_evidence.py` | `76862744a19422e5137a883de7558e4b91a4faae296facddf021c5e3eaca085f` |

Read the current roadmap/inventory and `docs/workstreams/fdk-native-job.md`. The latter still ends at the previous 90-test checkpoint in the bytes inspected here, so the actual held source/tests and this review determine the corrected local result. Independently ran the current full wrapper suite: **104 tests PASS, zero skips**, 16.769 seconds. Escalation enabled owned temporary Unix-socket/fake-command fixtures only; no Docker, native build, network, host installation or default trust was used.

## Stream compatibility

The unchanged `native_arm.py` source remains `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`. Its `run` function opens a text log and passes that file as subprocess stdout, whereas `build.py` opens the container build log in binary mode. The wrapper now treats the GPG import log's real text-file descriptor as a byte sink through its buffer, flushing both layers; stdout/stderr bytes remain exact, including non-UTF8 diagnostics. Fixture-only text sinks without a buffer receive explicit backslash escapes. Signature verification retains the original separate `text=True, capture_output=True` return contract and strict decoding, so malformed status bytes refuse acceptance.

Independent `/tmp/fdk-producer-correction-independent-review.py` loads the actual unchanged native helper definitions and invokes its actual `run` with the corrected proxy and mocked command results. The real temporary text import log receives exact combined bytes, including `0xff/0xfe`; the prior strict UTF8 operation fails on that same fixture. This reproduces a compatibility defect independently of any hosted-cause assertion. The original signature capture returns separate status/diagnostic text, the native text bootstrap log receives expected output, and the original binary build-log contract receives raw bytes through `BuilderCommands`. No acquisition, compiler, recipe, container or real GPG command is executed by these four focused checks.

## Durable fixed diagnostics

Phase/outcome markers contain exactly two finite enum fields. A marker is copied into the worker receipt and persisted before the corresponding operation; raw argv, paths, command output and exception text stay in private logs. Early constructor/preflight failures preserve the initialized `preflight/not-run` marker through main's failure persistence. Runner failures, command failures, delegation refusals and cancellation have fixed outcomes. The parent recovers the last valid durable marker even when the outer worker call raises, then completes its normal ownership cleanup/publication path. Unknown fields or enum values are discarded rather than interpolated into public evidence.

The public receipt carries only a fixed derived `error_code`: the ten accepted phases and seven outcomes yield a finite 70-code set. Before/during/after codes describe the last durable marker, not a proven exception cause. Independent checks exercised all 70 combinations and poisoned each with an extra raw field: valid values map to known constants, poisons fall back to the generic failure code, and no raw marker escapes. An outer-runner exception fixture recovers `bootstrap/started`, reports `producer-during-bootstrap-failed` after confirmed cleanup, keeps FDK NOT RUN, and excludes the injected private exception string. Existing suite cases verify cancellation, late-write rewrites/retirement, early exceptions, partial evidence and malformed diagnostic refusal. No diagnostic changes a failing producer into PASS or alters the preserved original producer result schema.

## Required integration closure

The old packet SHA `2e190f75594fe5550770aa567b7729637853a99d6c2ce3b137248ed3954cbe32` still has 128 rows but disagrees with exactly the six held files listed above. This expected pending refresh is a real execution prerequisite: the source gate must fail until the coordinator regenerates and reviews the map. All 39 accepted adapter byte/mode pins and 71 original recipe hashes remain unchanged; no original producer/helper/recipe weakening was found.

The previous workflow at `c7b90461edfbc079768a189d0930c0249b1d430174590b9dc3342413796afbbf` accepts only generic `fdk-native-job-failed` for top-level FAIL. Its schema needs an explicit reviewed finite diagnostic-code allowlist before the next dispatch; arbitrary strings or relaxed public schemas must remain refused. The encoder and public/private artifact exclusions must remain unchanged. The coordinator also owns committed-source binding, packet refresh, workflow publication and actual rerun. Hosted producer/FDK success, installation, binary publication, production trust, Asahi/M2/16K hardware and performance remain unaccepted. Only this review document was edited; no source, packet, workflow, shared manifest or Git mutation was made by this reviewer.

## Coordinator source acceptance

The coordinator independently ran all 104 wrapper tests with zero skips in
16.703 seconds, then repeated all 104 against the exact copied 128-file
packet in 16.698 seconds. The first sandbox attempt retained 16 Unix-socket
setup errors; the owned socket/key fixture rerun passed. The new packet
SHA256 is `76e475f63332c66de123481b77c904254c8f0c988bdf73b0787c732d3ae70449`,
with 1,954,949 source bytes. Exactly the six reviewed source/test rows changed;
all 39 adapter and original recipe pins remain intact. This accepts the
corrected source checkpoint only. Workflow diagnostic compatibility review,
committed Git proof and actual hosted execution remain separate gates.
Historical trial 38223759349 remains FAIL with an unknown cause.
