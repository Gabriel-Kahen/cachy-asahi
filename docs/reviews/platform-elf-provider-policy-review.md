# Static ELF provider policy independent review

2026-10-12. **Final clarified52-source provider correction accepted for coordinator adoption; no confirmed remaining blocker in this bounded correction.** Fresh52 tests and independent metadata/lookup probes pass. The historical50-source restriction and its three exclusions remain recorded below. Corrected actual624 scanning, runtime ABI, installed-image correlation, physical16K, M2 and performance acceptance remain NOT RUN.

Read current roadmap/package inventory, held workstream and immutable source/actual report provenance. Ownership is limited to this document and `artifacts/reviews/platform-elf-provider-root-peer-20261012/`. No implementation, shared source map/lock, Git, actual archive scan, system state or package/loader execution was changed or performed by the reviewer.

## Reviewed immutable checkpoints

| Held path | Bytes | Mode | SHA256 |
| --- | ---: | --- | --- |
| `scripts/platform/elf_audit.py` | 26,384 | 0644 | `8422452dcd4aaa385183fdcfcd735488e4bcbc21c99f8a40ecf3014f0059c777` |
| `scripts/platform/test_elf_audit.py` | 31,661 | 0644 | `1fc8e141180989d35f761ad0247f716296e7348d165d390a02f0d88c97c84d70` |
| `docs/workstreams/platform-elf-audit.md` | 23,054 | 0644 | `5612c33a56838d21ea67aa1d3f044f8305bccce20df281316f9c6215de3ac6b8` |

Checkpoint `artifacts/platform/elf-audit-20261012/checkpoint-provider-policy.json` rehashes to `8b91c9dcb606d2c1869e8d4fdcd9e9ac0561b280813ea89abbf4a468340dbf24`. All three files were copied into a new independent PYC-free tree and verified before execution. AST comparison against actual-source `c283d4c8091286156ed319bcdfb2860073322e16a6ed3f626edc6efd00db3c35` proves **only `providers()` changed**. Every other top-level definition/constant/import, all parser/reader/output caps and all46 previous test bodies are unchanged; exactly four provider tests were added.

The historical actual624 report rehashes to `294e9576f3d3a12f3eeac1b33443b8f2b3fb2d088830f10478c53b6073a0c9a0`, source c283 and overall **FAIL-static-data-inspection**. It contains all7129 observed objects and22 parser refusals under `usr/lib/firmware/`. Its complete hash-bound payload report was independently read and used to reconstruct the archive namespace from624 package metadata. No archive or fresh ELF member bytes were read in this provider replay.

## Candidate semantics and actual metadata replay

The [gABI program-header definition](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html) permits an interpreter segment in a shared object, so its presence cannot by itself exclude a library. [Dynamic-linking metadata](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html) defines SONAME as shared-object name information. These references justify admitting a qualifying ET_DYN library with valid SONAME despite PT_INTERP; they do not prove target loader selection or relocation/symbol compatibility.

The held842245 candidate admits parsed qualifying AArch64 ET_DYN objects with explicit nonempty string SONAME, including PT_INTERP forms. SONAME, basename and verified aliases share that rule; absolute path lookup uses the same eligibility check. ET_EXEC remains excluded even with SONAME. Firmware/foreign/relocatable/parser-refused objects never enter qualifying paths. Global aliases deduplicate one exact target; distinct provider locations remain ambiguous. Relative slash-containing names and dynamic tokens remain unresolved. Every result is an observed candidate, not runtime acceptance.

Independent metadata-only execution of the new `providers()` over the unchanged historical object/namespace records shows:

| Request observations | Historical c283 | Candidate842245 metadata only |
| --- | ---: | ---: |
| Missing observed providers | 4536 | 30 |
| One global provider candidate | 13861 | 18367 |
| Interpreter candidates | 2147 | 2147 |

Exactly4509 old missing requests become candidates: libc.so.6 **4250**, libQt6Core.so.6 **224**, libcap.so.2 **35**. The three corresponding actual objects have ET_DYN, SONAME and PT_INTERP and were successfully parsed under the unchanged mapped-dynamic policy. Full object/package/path/hash evidence is retained in `metadata-reduction.json`.

The residual count is30 rather than27 because the blanket SONAME requirement newly excludes **three old basename candidates**: `perl` and `texinfo` requesting libperl.so, and `krb5` requesting liblmdb.so. Their observed ET_DYN providers have no interpreter and no SONAME. This was reported to root before adoption. It is a deliberate conservative restriction in the50-source candidate, not evidence that those library bytes disappeared or that runtime loading fails.

Root selected a narrower compatibility policy: **preserve the original qualifying no-interpreter ET_DYN basename/alias/path route; require valid SONAME for the newly admitted interpreter-bearing ET_DYN forms.** No-SONAME PIE-with-interpreter and ET_EXEC must remain excluded. The author is correcting only this policy/tests/doc. Current842245 captures and the historical actual report remain immutable. Final adoption awaits a new explicit hold and focused replay of that selected rule; no source approval is inferred from the current50 pass.

## Independent boundaries and preserved failures

Fresh copied suite: `python -B -Werror::ResourceWarning -m unittest discover -s scripts/platform -p test_elf_audit.py -v`, **50 tests,0.047 seconds,zero failures/errors/skips**. This was run once; `tests.log` retains the result. The unchanged46 include all mapped PT_DYNAMIC, range, string, overflow, archive/member/reference, provider ambiguity, link and output bounds.

Additional independent probes exercise SONAME, basename, verified alias and absolute alias lookups for an interpreter-bearing SONAME library, then refuse ET_EXEC-with-SONAME and no-SONAME interpreter forms under every lookup route. Original three ELF-DYN-1 inert files are still refused by the captured842245 parser as dynamic mapping/offset/overflow errors. Thus provider admission does not weaken the corrected dynamic source-byte relationship.

All22 historical firmware parser refusals retain their exact package/path/hash/reason. No firmware exemption or runtime-corruption reinterpretation was applied. Candidate inventory remains conservatively incomplete, and the old overallFAIL is unchanged. The metadata replay is not a new full graph/byte inspection result and supplies no fresh cryptography or actual loader execution. Missing/ambiguous findings are scoped to the observed archive namespace and policy.

Evidence in the owned review artifact directory: `capture.json`, `source/`, `tests.log`, `metadata-reduction.json`, `boundary-probes.json`. Original source/table/refusal history remains preserved. No additional concrete blocker was confirmed under the50-source candidate's stated policy; the coordinator's selected compatibility change, new held hashes and focused peer replay are mandatory next steps before source adoption. Installed image/trust/custody, source/license grants, target transaction/recovery, runtime/physical16K/M2 and production/performance acceptance remain separate unfinished requirements.

## Final clarified hold and independent closure

The preceding50-source sections are historical. Root delivered the final clarification at checkpoint `artifacts/platform/elf-audit-20261012/checkpoint-provider-policy-clarified.json`, SHA256 `3b060d6d8d99a4d952effba8cd1639a735cad38bb822973bc530fa17fa7d0a8e`.

| Final held file, mode0644 | SHA256 |
| --- | --- |
| `scripts/platform/elf_audit.py` | `72ec18c7d8580094164b3ea4c11fcff2583519b4cd861e5c436ec9d7a779401b` |
| `scripts/platform/test_elf_audit.py` | `16a5a49d0fc90c1998fb2be2ffc6dc1d5f3f9d941451b7258cd247396329f340` |
| `docs/workstreams/platform-elf-audit.md` | `930895aeb51ee76bfdbfaca9efbc2c7ac88052d240f111f65c1b56057559b817` |

Captured these exact regular single-link files into a separate new `clarified-source/` tree, preserving the intermediate50 copy. Independently compared all top-level AST outside `providers()` against adopted actual-source c283: **all parser/reader/output definitions, constants and caps remain identical**. All46 original test bodies are identical; the final tree has six added provider tests,52 total. One fresh full replay passed **52 tests,0.047 seconds,zero failures/errors/skips**; no intermediate50 suite was rerun. Captured/current bytes and mode0644 were rechecked after execution, with no PYC.

The final candidate predicate preserves qualifying ET_DYN objects without PT_INTERP, including absent SONAME, under their original basename/alias/absolute-path route. Interpreter-bearing ET_DYN requires an explicit nonempty string SONAME. ET_EXEC, no-SONAME interpreter-bearing PIE forms, invalid SONAME values and foreign/data roles remain excluded. One predicate applies to all lookup routes; alias names cannot bypass role requirements.

Independent additional route matrices confirm: interpreter+SONAME candidates in four name/path forms; original no-interpreter/no-SONAME basename, alias and absolute candidates; refusal of ET_EXEC-with-SONAME, interpreter/no-SONAME and foreign-machine forms. Multiple aliases deduplicate one resolved target. Distinct SONAME locations produce two global candidates/ambiguity while an exact absolute alias still selects its one observed target. All three original DYN1 inert poisons remain refused. These are inert fixture/parser observations, not executing a library or asserting target loader behavior.

Metadata-only replay freshly rehashes the unchanged actual report and its complete624 payload namespace reference, then applies only the clarified `providers()` to the7129 existing object records. Object data is not mutated. Results are exactly **4536→27 missing observations,4509 old omissions resolved,three original basename candidates restored,zero new missing versus historical c283**. The4509 split remains libc4250/QtCore224/libcap35. Single global candidates become18370; interpreter candidates remain2147. The intermediate omissions for perl/libperl.so, texinfo/libperl.so and krb5/liblmdb.so now regain their original observed candidate edges.

All22 firmware parser refusals retain their exact object/package/path/hash/reason, and candidate inventory remains incomplete. The original actual report remains FAIL under its original c283 source and hash; these metadata counts do not rewrite it or create a corrected624 scan PASS. Root still needs source adoption/commit, externally authenticated executable capture and an explicitly authorized new bounded archive scan. Runtime, installed image, physical16K/M2 and performance acceptance do not follow from the reduced candidate count.

Final evidence: `clarified-capture.json`, `clarified-source/`, `clarified-tests.log`, `clarified-metadata-reduction.json`, `clarified-boundary-probes.json` and `clarified-review-receipt.json` in the owned review directory. **Disposition: exact72ec/16a5/9308 source hold is ready for coordinator adoption; no additional concrete blocker found in this bounded provider correction.** The reviewer changed no source, shared pin/map, Git, package/system state or historical actual evidence.
