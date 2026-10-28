# Residual transaction ingestion correction review

Disposition: **PASS for the bounded source correction; actual transaction acceptance remains FAIL**. This closes the unused malformed ownership declaration finding from the [previous review](platform-residual-transaction-root-followup.md). It does not authorize acquisition or adopt a release package set.

The reviewed handoff is `artifacts/platform/residual-transaction-20261012/correction2/handoff.json`, SHA256 `745b7328011eac7b558a8f286fc63f83e29ef9385f2757dd86f0882f2b7a874e`. Current mode-0644 files match its held copies:

| File | SHA256 |
| --- | --- |
| `scripts/port/platform-residual-closure/resolve.py` | `df71e3166025849785f1bdd4543f36938d7fd191dc8d407aa420a1b61968548e` |
| `scripts/port/platform-residual-closure/test_resolve.py` | `6c8a1e159d21d41379d744fc64842cec3027629bbd92aa146fdb10c9c8280e99` |
| `docs/workstreams/platform-residual-transaction.md` | `b25d2304ad59d6ae7d8505ec57dfad18ee000c59c3cf591889a2efb872d0afce` |

All 20 new indexed artifacts and all 80 previously indexed artifacts were independently rehashed with size/mode checks. The 17 actual input references were streamed and rehashed. Fresh mode-0400 source captures and the [binding audit](../../artifacts/reviews/platform-residual-transaction-root-correction2-peer-20261012/binding-and-passive-audit.json) are retained in the new reviewer namespace. Historical sources, holds, receipts and review documents remain unchanged.

`file_declarations()` now runs during `record()` ingestion for every supplied anchor and catalog row, before package selection. It requires a bounded ordinary list of strings, rejects duplicates, absolute/empty/control-character paths and empty/dot/parent components, and preserves exactly one ordinary directory suffix. A malformed unused catalog declaration becomes a finite `invalid-catalog-package` blocker with `invalid-file-path` reason instead of silently permitting overall PASS. The selected ownership map then uses those validated declarations. Unknown unused archive/file/hook/review facts remain nonblocking; this correction validates supplied declarations without requiring every unused candidate to acquire release approval.

**61 tests passed**, zero failures, errors or skips, from a fresh isolated no-PYC held capture. Five additional independent old/new causal comparisons passed: `usr//`, `usr///` and `usr/./` in unused declarations pass the previous source but fail the corrected source, while canonical single suffixes and unknown unused facts continue to pass. The runner was retained before execution, uses tiny metadata/ordinary scratch fixtures and blocks external process entry points. The [control receipt](../../artifacts/reviews/platform-residual-transaction-root-correction2-peer-20261012/source-controls.json) preserves exact outcomes. No actual contract replay, native version comparison, GnuPG, package/device/network actor or system mutation ran in this review.

Passive parsed comparison confirms the new retained actual report equals the preceding report after removing only `elapsed_seconds`. Its owner-recorded exit remains 1 and status FAIL. It retains 377 selected nodes, 1,594 edges, six ambiguities, 19 witnessed frontier rows and 201 exact protected identities, including Python `3.14.7-1`. The previously verified protected decisions and exact original 27 OPEN requests are unchanged by that equality. Twelve exact consumers are represented, 15 remain unrepresented, provider ELF identities remain uninspected, all 22 firmware refusals remain FAIL, and the coordinated Python alternative remains unadopted. Missing catalog/archive/signature/hook/source/license/grant/maintainer facts and actual closure failures remain blockers. Elapsed time is not a performance measurement.

No remaining actionable issue was found in this bounded ingestion correction. Archive authentication, actual loader behavior, ARM/16K execution, firmware, installation, release integration and exact M2 validation remain unestablished. No shared maps, manifests, workflow, source pins, Git metadata or historical evidence were edited by the reviewer.
