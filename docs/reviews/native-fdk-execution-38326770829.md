# Independent native FDK9 execution review

**Actual run FAIL during original-producer input acquisition. No FDK build ran.** Four exported acquisition rows report HTTP 404: the pinned Vim and Vim runtime archives and their signatures. The source registration and bounded public failure evidence authenticate; this is not native FDK acceptance or complete cleanup acceptance.

The reviewed run is [38326770829](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38326770829), dispatched once against `9ed0efa32d5177f1cc0cf6acf2a3ecea0263e2ec`. The saved dispatch records creation at 2026-10-13 00:20:41 UTC. The retained logs show checkout at that commit, `FDK_PREFLIGHT_PASS` at 00:20:51.328, then execution of the original producer/FDK controller and exit code 1 at 00:21:45.454. No new native, Git, network, Docker, compiler, GPG, installation or real-signal actor ran in this independent review.

## Committed source and evidence chain

The adopted candidate's earlier peer receipt `a366932754e66d387a018a2b1f9396e36828f71dfba98e5cfedc9989312fc2b0` authenticates all 757 indexed observations. The saved committed-source proof records 266 actual Git source queries and an exact 133-file, 2,295,977-byte copy at `9ed0efa`. This review rehashes that copy against the candidate's selected packet; it does not repeat Git queries or claim that the coordinator's later HEAD is the run commit.

| Selected input | Exact digest / closure |
| --- | --- |
| Job packet | `42fd54ae73c57e47898ca9e7b293ca0dae1d4e57ac2836292f0cdf42b79dffcf`; 133 files |
| External workflow | `056eab73b8b5fe711f15aec7cca495ed54465db16bcac82328b2ca498dd97e4c` |
| Stage map | `fbc0b0bbf0f3765729adb9193331b09903ad5b8c99d00871ece79218a8b36483`; 44 files |
| Template / reviewed inputs | `4f852126968e6b61a6bc9bc186182c435fa723d00f4776a435395ec687388235` / `43c5c8967f39687ee57fb59a17c7a6742ae4426b1b342bacb6486eea4cecc199`; 24 / 25 rows |
| Selected modern evidence | `aab9c7961bfe3cdd1fd298c7609cfcb5d9853201a110016a9f0348b6fe9fb175` |
| Frozen inputs / original recipes | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` / `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63` |

The ordered 23-source recipe and `.SRCINFO` checksums match. Original four recipes, 71 input pins and all 159 initial source byte/mode records remain intact. The workflow is an external held leaf, outside the 133-file packet; it is authenticated separately. No `verify_consumers()` replay against a different live HEAD is represented as committed run proof.

## Actual failure and cleanup limits

`producer/acquisition.json` reports 501 transport/pin observations: 497 PASS, four FAIL and zero pending. Each failed row is `http-failure` with `http_status=404`:

- `vim-9.2.1164-2-aarch64.pkg.tar.xz` and its `.sig`;
- `vim-runtime-9.2.1164-2-aarch64.pkg.tar.xz` and its `.sig`.

The frozen lock binds their exact sizes, hashes and primary URLs under `https://ca.us.mirror.archlinuxarm.org/aarch64/extra/`. The acquisition receipt itself does not export URLs; the URL attribution comes from that authenticated lock and the selected `fetch()` source. The actual final response URL is unexported. The evidence establishes those four failed HTTP results. It does not establish why the server returned 404, whether another source retains identical bytes, or the builder's present cache state. The [four-object proposal](../../artifacts/reviews/native-fdk-38326770829-root-peer-20261013/acquisition-peer/report.json) records every exact URL, size and hash; its objects total 9,790,183 bytes. Four offline data-validator controls pass without fetching or seeding anything.

The selected producer wraps `native.acquire()` and records `command-failed` on its exception. Acquisition is before GPG import/signature verification, bootstrap and original package builds. Signature authentication is explicitly `NOT RUN`; no `producer/signatures.json` was produced. The outer job exports `producer-acquisition-command-failed`, producer FAIL and FDK `NOT RUN`, with zero completed comparisons. The FDK failure-shaped default receipt has `phase=preflight`, `native_build=NOT ACCEPTED`, and all `build-1`, `build-2`, `compare` diagnostics `NOT_RUN`, null exit codes and null observations. That default `fdk-stage-failed` label does not identify an executed FDK compiler failure.

Scoped owned-image absence is true. Separately, the producer boundary reports worker cleanup FAIL and worker absence false; the FDK default receipt also does not establish owned-container absence. These observations do not prove a container remains, but they prevent complete worker cleanup acceptance. The detailed cleanup predicate, container inventory and underlying cleanup error are not exported here and remain UNKNOWN. Historical FDK8 retains its prior FAIL and UNKNOWN inner function/compiler cause; FDK9 does not reattribute it.

## Strict archive and pure workflow checks

The retained ZIP `e24f035aa56770a7ba9da366ed66cbb83e3a55dc69bb142673008b50a7dcfa67` contains exactly nine authenticated members. Every decompressed log matches its index; the aggregate log matches `workflow.log`. The encoder's one begin/end block decodes to the exact 85,825-byte public bundle `f63708f316efbbd2d8748cd3f716791779e5697febb5dbdd3d2a48da9a37264e`.

The bundle contains seven regular `public/`-prefixed JSON files totaling 439,463 bytes. Paths, uniqueness, regular member type, read bounds, duplicate JSON keys, sizes and hashes are checked without `extractall`. Its names are exactly the workflow's eight-file allowset minus `producer/signatures.json`. The Root decoder's original eight-file assertion failure is retained; seven is the valid finite failure subset. This peer's initial bare-path assertion also stopped; its correction requires the exact `public/` prefix before the unchanged allowset check.

The actual pure `validate_public()` function from the pinned workflow accepts these seven actual failure files with the authenticated modern validator and exact captured production source. The actual encoder code echoed in the run log has the same AST as the held workflow; that log code was parsed as data and never executed. Actor tripwires remain untouched and no PYC is emitted. Acceptance here establishes a well-formed, source-bound FAIL receipt; it grants no native completion, publication or hardware acceptance.

## Bounded next resolution

First recover the exact four frozen bytes into a curated cache, with recorded retrieval provenance, unchanged sizes/hashes and the existing pinned signer verification. The selected `fetch()` already accepts matching regular cache files and refuses mismatched or symlinked inputs. The current job uses its run-owned cache directory; a reusable cache needs an explicit reviewed seeding interface and its source bindings. A historical PASS receipt alone cannot supply the package bytes. Cache existence or an alternate archive has not been checked by this offline review.

If identical bytes cannot be recovered, propose a separately reviewed input snapshot change and regenerate every affected binding; retain this failed run and the original four/71/159 evidence. Do not silently skip Vim, replace it with a newer package, disable signatures, alter frozen tuples or install into the host. Separately export finite cleanup reason/inventory observations in a successor source proposal so the cleanup refusal can be resolved from evidence. This review changes no implementation source and dispatches no retry.

The [current roadmap](../roadmap.md) still requires R1–R5 and M5–M9. FDK input retrieval, native build/rebuild/comparison, provider substitution and PipeWire integration remain unfinished; installation, both M2 Air sizes, recovery, performance, publication terms and maintained full-port releases remain distinct required gates.

All captured inputs, peer controls and this document are indexed by `artifacts/reviews/native-fdk-38326770829-root-peer-20261013/receipt.json`.
