# FDK inventory attached-start correction review

**Held source correction PASS; coordinator lock adoption and actual native rerun pending.** The corrected broker removes the unsupported `docker start --sig-proxy=false` option without changing inventory acceptance, process disposal or owned-container cleanup. No additional material defect was reproduced in this bounded review. The historical native trial remains FAIL; its unavailable private inventory streams were not recovered.

Read current roadmap/package inventory and the held workstream/source/tests. Only this document and temporary parser/data fixtures were written. No implementation/shared lock/Git edit, actual Docker daemon operation, download, codec build, package installation or hardware test occurred.

## Exact held inputs

| File | Bytes | Mode | SHA256 |
| --- | ---: | --- | --- |
| `scripts/port/fdk-native-stage/broker.py` | 26367 | 0644 | `46e9abff104c46595d6e2dd5139827874d3ade2cd99d3ed3a846466e84e63bb1` |
| `scripts/port/fdk-native-stage/test_broker.py` | 27088 | 0644 | `7aad860f04a30e3d356a15902bde37357e6a9c3be89c5aaf371dacc18e48b174` |
| `scripts/port/fdk-native-job/test_base_broker.py` | 28141 | 0644 | `c9c491236814ad8735dff1df613e49fe9a04c3b871970de1ac889defc133e3bb` |
| Workstream document | 8770 | 0644 | `bd8acb5e67f1be10ffd919176cf829fde7f16cf4ab0f8a353d674b68413bc915` |

Independently restoring only the removed flag in memory reproduces the historical broker SHA256 **`6480333ea4f6267cd55019fd7928077392bb5c052583dc07d582fc64620f20fd`** from the old 39-file lock. This proves the production change is that one argument removal; no guard, resource, cleanup or inventory code change is hidden in this source delta.

## Actual CLI parser and causal fixture evidence

Rehashed both available binaries before invoking them with fresh owned configuration/home directories and nonexistent temporary Unix endpoints. These parser-only invocations do not contact a daemon or discover/change host Docker state.

| Actual CLI | SHA256 | Removed flag | Corrected flag argument gate |
| --- | --- | --- | --- |
| Docker 28.5.0, build 887030f | `9d1ae1ce99e11f0b1a3b198dc8d510797d243a64d69eafb849770e7c670e744d` | exit 125, `unknown flag: --sig-proxy` | exit 1, missing container argument |
| Docker 29.8.0, build 88096ef | `e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e` | exit 125, same refusal | exit 1, same argument gate |

The corrected argument-gate result proves `start --attach` is a recognized command syntax; it does not prove daemon startup/build execution. Configuration directories remained empty and the owned nonexistent socket paths remained absent. The 28.5.0 binary was already retained from the owner's official-origin static archive; this reviewer made no download or detached-signature authentication claim.

Independently rehashed all retained pinned Docker source files in `/tmp/fdk-start-cli-correction-audit/source-pins.json`. Their start implementations register attach/interactive flags and show non-TTY attached signal forwarding; the signal code skips CHLD/PIPE/runtime signals and delivers other signals through the API. Source commits are 28.5.0 `887030fbe83f5368566ec3b35e15a4ba13267a62` and 29.8.0 `88096ef00576baf72a9cb45caa45c0544c40e0a7`. Real daemon signal delivery was not tested.

Independent causal reproduction `/tmp/fdk-inventory-correction-independent.py` uses the actual frozen native helper and producer delegate over the owned fake Unix/native-daemon bridge:

- Restoring only the old launch argument in memory makes the strict fake CLI reject it before inventory execution. The original helper returns `base-lock-probe-inventory`, and the actual durable/public diagnostic mapping yields the same finite public failure class reported by native trial 38239523997. Owned-container and image cleanup still run independently.
- Corrected launcher returns the exact frozen 341-package lock bytes through the same helper/delegate and passes its unchanged predicate. Owned-container/image removal and absence pass in that fixture.

This establishes a confirmed source defect capable of producing the observed public code, not the unique actual cause of the historical run. The real trial's unavailable private return/streams remain unavailable; fabricated cache/image facts in the causal fixture are explicitly synthetic.

## Independent suites and unchanged boundaries

**77 stage tests PASS, zero skips**, 17.221 seconds; **118 job tests PASS, zero skips**, 23.211 seconds. Both used approved access only to their owned temporary fake Unix daemon sockets/local CLI/process fixtures. They perform no real Docker or native codec workload.

The stage suite includes three real process tests for SIGINT, SIGTERM and timeout during attached start. The fake CLI forwards TERM to a TERM-resistant owned child; the unchanged runner escalates after its bounded grace period, kills the owned process group and reaps descendants. Tests require both process IDs gone, forwarding observed, and independent owned-container absence. Forwarding is not disposal proof, and killing a CLI does not establish container absence. The durable broker reservations and nonce/daemon/image/resource checks still govern removal and absence queries.

The job's controls bind the complete **341-package, 6674-byte lock**, SHA256 `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`. Missing final newline, unsorted/malformed/extra rows, private output and nonzero command exit remain refused. A syntactically valid extra package reaches the unchanged original helper's exact name/version set comparison and refuses. No inventory lines are filtered to force acceptance. Merged streams and output caps remain unchanged. Foreign nonce, resource/endpoint drift, ambiguous create, cleanup failure/interruption and runtime output/resource tests still pass.

## Source-map handoff and limits

Independently regenerated the proposals in memory using existing canonical serialization and source byte/mode/length rows; wrote no lock or source constant:

| Proposed successor | SHA256 |
| --- | --- |
| FDK stage 39-file map | `b83ddb865d7651c748258ac570e64fb824caf5bced8b1f415694dff7f5c187f5` |
| FDK job 128-file map | `309fcd6fbec8b7e96c83ea049804ae3134e7190d2145e81afc66d28563097f44` |
| Job `packet.py` after adapter-pin replacement | `ae345e3608c0a99a6f372cd8b925c5fa5610f9b53037933768f214305c2ffbe9` |

Membership/modes remain 39/128; proposed job source bytes total 1,982,280. The stage rebind changes only broker/test rows. The job rebind also changes its base-broker test, the successor stage lock and proposed packet adapter pin. Actual tracked stage lock remains `a7048064c0c20abd246a466035313abaf65590f3ed10d0f7927b21a346200ad6`; actual job lock remains `6884fcfed5bb2577b4420e0676512df8aeb0a232680c38a240144581c2f40194`, and actual packet.py remains `2c37ba658ded0ff4c08e48d61120f3e977d1217b48d3a9cde5d3d496542ed09e`. These stale bindings cannot authorize corrected execution until coordinator review/adoption, commit and fresh preflight.

The kernel stage has a separate forked broker and still requires its own correction; this FDK change does not fix or certify that path. Its unchanged FDK evidence dependency does not import this shared launcher. The selected codec source/recipe, original input helper, accepted 341 inventory, public schemas and error allowlist remain unchanged by this correction.

**Disposition:** accept the held three-file source correction and reviewed document for coordinator integration. Actual native FDK compilation/lifecycle/publication, real-daemon signal/cleanup behavior, kernel-path correction, Apple/M2/physical16K compatibility, recovery and performance remain separate pending/NOT RUN gates. All five roadmap requirements remain required; fixtures and parser compatibility do not constitute platform acceptance.

## Coordinator source acceptance

Root independently replays77 stage tests PASS/zero skips/17.065seconds and118 job tests PASS/zero skips/22.802seconds, with owned test sockets/processes only. The exact shared broker change removes one unsupported start option; inventory/ownership/payload/private publication guards remain in force. The independent causal old-flag restoration and real28.5/29.8 parser checks above support this concrete source correction. Current kernel fork correction belongs to the separate already source-reviewed API/start workstream; historical same-flag observations do not claim that fix was absent from today's working tree.

Source accepted for coordinator39-stage/128-job transitive lock/pin/Git acceptance and another bounded native trial. Actual previous public inventory refusal remainsFAIL, and its private stdout is unavailable; the exact hosted cause is not independently reconstructed. Codec native builds/provider/install/M2 remain NOT RUN.
