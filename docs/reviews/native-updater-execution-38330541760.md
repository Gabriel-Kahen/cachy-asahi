# Native updater10 execution review

Actual run [38330541760](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38330541760), Root-provided job `115079040321`, **FAIL before compilation**. Its four HTTP 404 acquisition failures uniquely identify the frozen Vim 9.2.1164-2 package/signature inputs for `vim` and `vim-runtime`. The outer terminal records `native-pair/process-failed/return1`; the native result records `input-authentication/ValueError`. Cleanup and recovery report PASS, with private data removed. Recovery does not attest compilation, and daemon/cache disposal remains NOT ATTESTED.

The retained log interval is October 12, 2026, 9:06:41–9:08:09 p.m. America/New_York (October 13, 01:06:41–01:08:09 UTC). The stage terminal records 82 elapsed seconds. The namespace/date in this review follows the requested UTC run naming. This is a read-only source/data review: no actor, new Git operation, workflow/source/image mutation, HTTP request or native retry is performed.

## Exact source and recorded bindings

Source commit is `0e07db1b9cd1f1fd960353ccecff91bd3367dbc3`. Root's committed source proof `artifacts/reviews/updater-directory-leaf-committed-source-proof-20261013.json` hashes to `f7834675c939263716a0157cc5e3d28bc7a0559e35b70302267d784df51419cb`. Its 86 rows total 4,248,868 bytes. This review checks each captured source hash/mode and recomputes all 86 Git blob identities; source bytes come from the authenticated registration capture, with no current HEAD substitution or Gitshow fallback.

Registration peer `b673d00c4f4a066ab2fca9ee6d320de1c5a3244ec0169b16c67dbe0745aa79bb` authenticates 248 artifact rows, all rechecked here. Root adoption `0cc5916b937a13f18f84401a2621c482fd25461c8afa616100c15d5069f58f14` and the committed proof bind these source values:

| Binding | SHA256 |
| --- | --- |
| Stage | `de7f19f58c2773896879a1997a7ea707619d47644ce0f3b4f0a7b11ce3feb3a5` |
| Source collector | `4d3e3fd9848aaed94154f786b04a5ae07c7816dcef82857b671b51555895eacb` |
| Ready map | `6dc5515b411bcaa9cff7caa844fcc623a7a0dba39cb0c28e1c6859db457438e2` |
| Actual workflow | `57de22147274c830e7098942169331819cef9b6e2c2e18220af64e24610601e1` |
| Recorded controller | `42884b2f58c4e657182de98001b023c9d3ff40a170c269309c822843611836f7` |

The captured workflow is 32,724 bytes. Its stage/source/ready literals and actual step environment agree with the terminal and proof. The raw private controller is unavailable, so its digest/host/tool binding is recorded agreement rather than a new independent recomputation. The proof/adoption's pre-run NOT RUN/PENDING fields remain historical as-of statements; this review does not rewrite them.

## Acquisition failure and the next dependency

The materializer reports PASS with 168 downloads, 167 registry sources, and regenerated sanitized source/vendor hashes equal to the frozen expected values. The native acquisition then records 527 inputs: 523 PASS, four FAIL, zero pending; signature authentication is NOT RUN. Every public `(expected_sha256, expected_bytes)` tuple uniquely matches the exact merged captured plan. Its baseline has 341 inventory entries and the updater extension adds 13, yielding 354. All four failed inputs belong to the frozen baseline rather than the updater additions.

The four captured URLs use `https://ca.us.mirror.archlinuxarm.org/aarch64/extra/` with the filenames below. Each recorded result is `AcquisitionError`, HTTP 404:

| Filename | Expected bytes | Expected SHA256 |
| --- | ---: | --- |
| `vim-9.2.1164-2-aarch64.pkg.tar.xz` | 2,086,796 | `d4f857559e5f0af1cd5a9603d31437ddc8fe35957c11bc6b8670b9a58a80ea73` |
| `vim-9.2.1164-2-aarch64.pkg.tar.xz.sig` | 565 | `38e920e436994e6516752f2057974ecd3d284b4be5887a183714175be9169524` |
| `vim-runtime-9.2.1164-2-aarch64.pkg.tar.xz` | 7,702,256 | `def07038ac8bde14c3c875ea2f37adc199e21bb237d357b1b2f00eb401d4add6` |
| `vim-runtime-9.2.1164-2-aarch64.pkg.tar.xz.sig` | 566 | `7481985526069c20b81762bbb308a0df61acf07d316f557d60e330a22627e5e3` |

Source audit and three actor-denied mocked controls confirm the ordering: acquisition records all outcomes, rejects four failures, and stops before GPG signature verification. The native build's daemon preflight precedes the audit; tool inventory, image bootstrap and worker compilation are later and are not reached by this failure. The captured implementation is `worker-build.py`; no absent `worker.py` or current primary source is substituted.

Root's next dependency is authenticated retrieval of these four exact frozen archive/signature payloads from a durable source, preserving their sizes/hashes and signature gate, or a separately reviewed baseline refresh with all dependent pins, inventories and registrations propagated. No failed row may be skipped to declare a complete input set. This review does not establish why the endpoint returned 404, whether another endpoint has identical bytes, or whether a complete future acquisition would pass signatures, bootstrap or compilation. No fresh HTTP request or input correction is performed here.

## Nine-record failure export

Strict reconstruction verifies the retained log ZIP: SHA256 `dc30453d1b7debb391d57e2808b3f5370affedc3e25875836bcde5be617b1b13`, ten regular bounded members. Three framed base64/gzip/tar exports reproduce exactly nine JSON files, with sizes/hashes agreeing with Root's indexes and retained decoded copy:

| Bundle | JSON files | Compressed bytes | Logged SHA256 |
| --- | ---: | ---: | --- |
| guarded | 5 | 25,047 | `e4480ae37f40c130dc6000df164989e226e5a21c412bbd22a8bd254e04ca09b3` |
| terminal-public | 2 | 1,212 | `5b6d15966e250fdc109855bc000ef0d6947f68fc8b87596db1147da25adde54d` |
| recovery-terminal-public | 2 | 846 | `9304071756ed32aa76cd3abe3bae08fd8e00d80f1db61643059f8bd496acd0a2` |

The guarded files are acquisition, materializer, native-result, projection and export-manifest. Each terminal directory has its terminal and export-manifest. Projection PASS means three admitted receipt records with no rejection and 22 explicitly missing later records. It grants no native PASS. This is the exact admissible failure subset; the larger 17-record native-progress capture from earlier runs is not required or synthesized.

The terminal's original `public_bundle_sha256=6b5dd027aa75667b9bd3dc6024ed0793069fe562602f0843001004ca99356002` refers to unavailable private `public-evidence.tar.gz`. It cannot be independently recomputed from the nine public records. The logged guarded digest above identifies a separate credential-guard re-export; those two hashes must not be equated.

## Receiver, cleanup and acceptance limits

The exact captured workflow's pure semantic receiver accepts this failure subset, re-exports all nine files byte-for-byte, and yields workflow FAIL, native-stage FAIL, recovery PASS. A success exit/outcome environment cannot promote the failure. The private controller/source-freeze host/tool bootstrap is statically audited and explicitly NOT replayed. Successful native-pair acceptance remains a source gate review, not a positive fixture substituted for this actual failure.

Terminal cleanup records process, Docker, GPG and private scopes PASS, empty cleanup reasons, private removal true, and raw-retention-within-budget true. Recovery PASS explicitly records `NOT ATTESTED BY RECOVERY`. These are retained receipt/recovery assertions, not a new inspection of destroyed private state. Daemon/cache disposal remains NOT ATTESTED.

Storage is shared and unlatched, reason `none`: baseline available 115,204,009,984 bytes, latest 112,604,614,656 bytes, peak observed growth 2,599,395,328 bytes, growth cap 17,179,869,184 bytes and reserve 2,147,483,648 bytes. These bounded early-failure observations establish no full two-build storage fit. Native compilation, publication, installation, physical M2/16K behavior, performance, complete overlay and R1–R5 acceptance remain NOT ESTABLISHED.

The review namespace retains strict parser controls, actor-denied ordering controls, semantic receiver controls, exact source/public captures and sealed subreceipts with hashes/modes. Counts remain separate: 28 export-parser controls, three acquisition-ordering controls, and 38 semantic receiver controls; these are source/data models rather than new actual executions. Root retains the original run logs and status. The new review namespace is `artifacts/reviews/native-updater-38330541760-root-peer-20261013/`.

There is no matching private-scan tick failure or directory leaf in updater10's terminal. Updater9 (`38319260369`) remains actual FAIL with its directory branch/component/race UNKNOWN; updater8 (`38314402583`) retains its separate ELF UNKNOWN result. This acquisition failure cannot identify either historical private leaf.
