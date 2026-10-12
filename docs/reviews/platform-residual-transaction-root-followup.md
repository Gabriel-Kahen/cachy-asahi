# Residual transaction correction review

Disposition: **selected corrections verified by inert controls; source acceptance remains BLOCKED on unused file declarations**. No package acquisition or transaction is accepted.

This read-only review binds correction handoff SHA256 `901d5d1f8afcfc43f8ef74e0f091621c472e415868e322c1591f91019cb31a0f`. Current files match its held copies:

| File | SHA256 |
| --- | --- |
| `scripts/port/platform-residual-closure/resolve.py` | `8f0734a9747712aaa6e1f255a740fae25159c8cd266b086f72731b4c44e7a03b` |
| `scripts/port/platform-residual-closure/test_resolve.py` | `146dc3581890e187daad311ddc53506ec93a8cae93e9dc1d1d101bb3b19ece5b` |
| `docs/workstreams/platform-residual-transaction.md` | `c637f76dd0a3a3d4305ba731f368d4caedf43a5c32c8c642b57af7c52136a57c` |

All 20 new indexed artifacts and all 60 historical indexed files retain their declared sizes, hashes and modes. The 17 actual input references were streamed and rehashed. Historical receipts and source were not edited. The [audit](../../artifacts/reviews/platform-residual-transaction-root-followup-peer-20261012/initial-controls-and-hash-audit.json) records the exact bindings.

Twenty fresh tiny in-process controls, compiled from the held source without PYC, passed their expected outcomes. Ordinary single directory suffixes remain valid; seven selected malformed path spellings fail. NaN, positive infinity and negative infinity fail even in nested unused catalog fields. Selected unknown, nonempty and structured hook declarations retain distinct refusal codes. These verify the three selected corrections. The authored 54-test receipt remains historical; this reviewer did not rerun that suite or the actual contract, invoke native version comparison, acquire packages or launch a package/native actor.

**[P2] Unused malformed ownership declarations still permit PASS.** `record()` validates catalog identity and relationships, while file declarations are validated only for selected rows later in `resolve()`. A valid application root plus an unused catalog package declaring `files=['usr//']` produces overall PASS with no blocker. `usr///` and `usr/./` behave the same way. These three inert counterexamples are retained in the audit. The selected-path correction works, but the prior review explicitly required malformed unused ownership declarations to fail as well. Validate supplied path declarations before selection, retaining valid single suffixes and existing catalog/resource limits. This finding does not imply that unknown facts in every unused package must become transaction blockers.

The corrected retained actual report still exits 1 with overall FAIL. Its parsed value equals the historical report after removing only `elapsed_seconds`; this is a passive comparison, not a fresh actual replay or a performance result. It retains 377 selected nodes, 1,594 edges and 13,305 catalog entries. Blockers remain six ambiguous providers, one unavailable catalog scope, six invalid catalog packages, three missing archive pins, 38 missing signature pins, and 377 each of unknown hook/source/license/grant/maintainer decisions.

The [protected audit](../../artifacts/reviews/platform-residual-transaction-root-followup-peer-20261012/actual-protected-audit.json) verifies all 201 exact protected names/versions against the bound protected identity input and each report preservation decision. Python stays `3.14.7-1`, NetworkManager `1.58.1-1`, Perl `5.42.2-2`, and the coordinated Python alternative remains unadopted. All 27 original ELF requests remain `OPEN-not-acquired-or-integrated`; provider ELF identities remain uninspected. Twelve exact consumers are represented and 15 remain unrepresented. All 19 frontier rows have selected witnesses. The hash-bound classification continues to report all 22 firmware refusals FAIL. These metadata observations do not establish archive authentication, actual loader behavior, installation, firmware compatibility or hardware acceptance.

No shared source pins, inventories, manifests, acceptance maps, Git metadata or historical evidence changed. A narrow source correction and fresh peer check are still required before accepting this resolver source; actual transaction and release integration gates remain open independently.
