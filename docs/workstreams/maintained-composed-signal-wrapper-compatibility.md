# Maintained signal wrapper: exact diagnostic compatibility

**Diagnostic-only Source correction; actual06's runtime cause remains UNKNOWN.** Run 38462431231 at Source `4327634c0df33a07a7738eb56b70f781f8f18efa`, Data `999e5397ee1bd6953fb32fd43e39b69157f67207`, again retained `construct-services / TYPE_ERROR / SERVICE_CANCEL_EXIT_SET_HANDLER`, false native hook, controller exit 1, initial exit null and Source-gated cleanup PASS. The ten-kind refinement did not match. This does not identify a rejected handler, None, an API message, the failed wrapper predicate or a restoration defect. No old run is backfilled.

Primary CPython sources were resolved and retained at exact revisions:

| Release source | Revision | `Lib/signal.py` SHA256 / bytes |
| --- | --- | --- |
| 3.12.3 | `f6650f9ad73359051f3e558c2431a109bc016664` | `0363c964c90ac0b3e515de5749205e6e6454051a1211058375d84d91eab6071a` / 2495 |
| 3.14.0 | `ebf955df7a89ed0c7968f79faec1de49f61ed7cb` | `0363c964c90ac0b3e515de5749205e6e6454051a1211058375d84d91eab6071a` / 2495 |

Both pinned [3.12 signal source](https://raw.githubusercontent.com/python/cpython/f6650f9ad73359051f3e558c2431a109bc016664/Lib/signal.py) and [3.14 signal source](https://raw.githubusercontent.com/python/cpython/ebf955df7a89ed0c7968f79faec1de49f61ed7cb/Lib/signal.py) have the same assignment-then-return function body as the prior template. There is no demonstrated body-shape mismatch. Each release's commit metadata, exact signal source, importlib source loader and complete Python-2.0 license are preserved with URL, revision, mode, byte count and SHA256 in `primary-provenance.json`. Eight texts totaling 322,963 bytes were downloaded, plus the two earlier source previews, within the ten-text / 4 MiB boundary. Failed web Git-ref requests returned no source content. A normal-sandbox DNS failure preceded the explicitly authorized bounded escalated fetch; that setup failure is retained.

A focused local Python 3.14.7 compiler model demonstrates a narrower problem: identical function ASTs do not guarantee identical bytecode across lexical module contexts. The full pinned module declares `import _signal`. Compiling that module or a closed template with the same import produces a plain attribute load plus a null call marker; the old bare-function template produces the method-call form of the attribute load. The differing compared field is `co_code`; names, arguments, local variables, constants, closure fields and flags match. The installed local wrapper matches the import-context reference. The old classifier consequently retains its generic setter label for a pure model using that canonical context; the new classifier recognizes it. This proves a local diagnostic recognition defect, not actual06's hosted Python 3.12 failure cause or patch-level identity.

The [3.12 source loader](https://raw.githubusercontent.com/python/cpython/f6650f9ad73359051f3e558c2431a109bc016664/Lib/importlib/_bootstrap_external.py) and [3.14 source loader](https://raw.githubusercontent.com/python/cpython/ebf955df7a89ed0c7968f79faec1de49f61ed7cb/Lib/importlib/_bootstrap_external.py) compile source with `dont_inherit=True`. A separate inert model shows that ambient future flags can also make the old template reject an otherwise exact unflagged standard wrapper. The candidate normalizes only the optional standard-wrapper template's compilation accordingly. The pinned workflow, trusted launcher, bootstrap, issuer, native preflight, dependency entry and handoff were audited for future imports; none were found in those captured paths. This hypothetical context model therefore does not explain actual06. Its actual flags and failed predicate remain unknown.

The candidate compiles exactly two closed references: the prior bare context and the same fixed function body preceded by `import _signal`. Neither reference's module code is executed. There is no alternate body, wildcard bytecode, opcode stripping or ignored flag. Both retain exact code/constants/names/variables/signature/default/closure/global checks. The direct API traceback frame must still be the current selected wrapper's exact code and namespace. Its byte offset must lie in the right-hand-side assignment region of the **selected exact reference**, before the handler local is overwritten. The saved Source loop local is still ignored. Existing project Source hash, code, globals and context-manager guards are unchanged.

When the optional wrapper refinement refuses, nine new closed suffixes after `SERVICE_CANCEL_EXIT_SET_HANDLER_` identify the first failed check:

| Suffix | Refused boundary |
| --- | --- |
| `API_MODULE` | Exact module type and plain `signal` module name |
| `WRAPPER_TYPE` | Exact Python function type |
| `WRAPPER_GLOBALS` | Function globals are the selected API namespace |
| `WRAPPER_STATE` | Empty defaults, keyword defaults and closure |
| `WRAPPER_CONSTANTS` | Sole constant is exactly None |
| `WRAPPER_FLAGS` | Exact normalized reference flags |
| `WRAPPER_CODE` | Exact remaining typed code fields for either selected context |
| `API_FRAME` | Direct child traceback code and namespace identity |
| `API_OFFSET` | Right-hand-side assignment instruction range |

These are predicate refusal labels, not handler observations. Handler inspection occurs only after all checks pass; then the existing five kinds and two API-text codes apply. No raw names, flags, bytecode, identity, handler, message, path, frame, locals or traceback is exported. A refusal cannot become native acceptance. Optional attribution faults preserve the same exception and first observation, and the closed nine-field FAIL/source-refused/cleanupPASS projection remains below its existing 1024-byte cap.

Four new focused methods pass, together with three directly affected inherited checks. They exercise all ten handler-kind/text outcomes under both exact contexts, all nine refusals, opaque constants, same-object error and traceback preservation, first cause, privacy, optional cancellation and ambient future context. Whole primary signal modules are compiled but never executed; their exact function code fields are compared with the import-context reference. The old bare-reference and future-context failures are reproduced with inert project/API namespaces. No real constructor, process actor, signal API/delivery, probe, foreign PID, Docker, GPG, native library or cleanup replay ran. The only network operations were the authorized primary text reads. Local 3.14 models do not constitute hosted 3.12 execution.

The entire handoff module AST is unchanged except `Session.service_failure_site` and the closed enum in `Session.startup_projection`; `startup_failed`, `execute` and all other declarations remain unchanged. All 16 inherited test classes are preserved, with four expected diagnostic literals updated to the new refusal enums; one new class is appended. All 263 other selected Source rows and metadata14 remain identical. Collector common stays `92ca41005397c6cccfd70497646c0de1f2ac88a697e0fcbec4165bf5326cfc08`. No mask, restoration, cancellation, retry, handler coercion or runtime-common correction is made. Source3 bootstrap, controller, grant/runtime/callback/view contracts, earliest J and publication endpoint, receiver/profile/authority and original159/generated125/build/signature counters remain unchanged.

The exact private cascade is:

| File | SHA256 | Bytes |
| --- | --- | ---: |
| handoff | `b1be6da0f38722a350b1981bacda038f2fac018fa67efe0c3fc78f22fd20e8e7` | 147583 |
| test | `366cfccfc95793e21b5d858789f1ecc8b45f0832346ced1b3fe8ea4d8b2f8f90` | 127209 |
| bridge issuer literal | `65d254379b0cda07fa83e59abc95f693a22ff7ccbf7044e7208544af70f1aad7` | 22061 |
| Source266/metadata14 packet | `4c0a54b2f09eb19e8b8cbff4c8a3de036656e7227ad80302a235a35d629bcebd` | 94735 |
| outside workflow packet literal | `c026fada749136c563501d18b35f3c46deaf9286de6ef1479ab43436b5924582` | 10056 |

The bridge changes only its existing handoff hash; the packet changes exactly those three selected rows; the outside workflow changes only its packet literal. Baseline packet is `06fa0a48e2031feaf3821c4829f3d6f87c3cae7f56b8531dab1b59ea109080a9`. Prior author `0e6554bbc19021bae36081ecfbf0c192b5b431e6d976ac5ad81f44b4085c0488` and peer `60204391a40b8b3aa8d0289944de840c1c5662e2830c61e906adc94716950251` remain immutable. The new final receipt indexes exact captured Source, primary license/source bytes, context audit, actual06 retention, proposed cascade, guide and finite results.

Root owns independent review, adoption, new Source/Data/plan bindings and any separately selected actual trial. If refinement still refuses, the next actual closed label should identify its failed check; if it matches, the resulting kind/code still requires careful attribution. Neither outcome authorizes a restoration change without actual predicate evidence. This lane writes only its assigned proposal namespace and this guide, and changes no shared/primary/managed manifest, workflow, Git, Root registration or goal. Full R1–R5/M5–M9, both M2 Air sizes, installation/recovery, maintenance and final-system measurements remain required and unfinished.
