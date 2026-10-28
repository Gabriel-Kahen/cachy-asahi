# Repository endpoint exporter correction

The three independently reported P2 defects are corrected in the existing three
authorized product files. No prior receipt, review packet, shared manifest or
other implementation file was rewritten. The original author receipt
`9a0383ad25553d3368a846f3b23b9d34dd156b8881c79de78d8047c8ca126ab4`
passed its complete 36-owned/4-external verification before the repair. Exact
preimages of all three product files and that receipt are retained in the
[correction capsule](../../artifacts/reviews/full-port-endpoint-exporter-correction-20261014/).
The old receipt's product bindings are now historical preimages; the final
verifier resolves those three through their matched captures without altering
the old seal.

| Defect | Correction and regression |
| --- | --- |
| Source tree roots and stable/promotions/withdrawals directories could be0777 | `tree()` validates its own root, and `describe()` checks every consumed managed Source directory before reading its contents. Real temporary-directory permission cases verify refusal before payload/signature reads, for preview and apply. |
| Reused generation omitted the final Source/withdrawal recheck | The final `describe(...) == plan` check runs for both new and reused generations after endpoint validation and before pointer selection. A genuinely signed same-owner withdrawal injected after reused-generation validation now refuses and preserves the old selection. Final-validation error identity is preserved. |
| POSIX `//tmp/...` could hide physical source/endpoint overlap | `canonical()` requires the exact single-slash anchor before overlap/GPG-home checks. The physical nested-endpoint alias is refused, along with double-slash Source/home aliases; ordinary absolute paths remain accepted. |

The exporter Source delta is limited to those four replacement spans. A
byte-exact inverse check against the held preimage confirms that signature,
release, promotion, withdrawal, source-delivery, copy, bounds, locking and
selection machinery outside the fixes is unchanged. Documentation describes the
stricter path/directory checks and mandatory final recheck. Only the exporter,
its focused tests and endpoint guide are proposed for adoption.

Validation: **26 author tests and six held independent countermodels pass**.
Tests use real local temporary files and ephemeral TEST-key signatures. Positive
stable/hardware gate acceptance remains the existing explicitly modeled seam;
the unchanged real gate verifier separately refuses the synthetic stable
fixture. No production trust, network publishing, installed packages, ARM/M2
execution, performance or full-port acceptance is inferred.

The intermediate 25-case author run passed the first two corrections. The
intermediate independent six-case run passed five and exposed the third
double-slash defect; its FAIL log is retained. Final logs, source diffs, precise
pins and the read-only verifier are in the new capsule. The final receipt is an
author Source candidate awaiting independent review and Root integration, not a
Git/publication proof or supported release.
