# Updater worker diagnostic registration

October 12, 2026. Source registration and independent consumer review pass;
committed-source proof and actual ARM execution remain separate pending gates.

The corrected ten-source hold is `bb4e77ed`; its independent worker/parent
review is `f45ba9cc`. The new stdlib diagnostic helper is a real input in the
23-source PKGBUILD and matching `.SRCINFO`, rather than an extra installed file.
The ready map grows from 63 to 64 package rows; all eight root rows and original
archive pins are unchanged. The collector's exact package-count requirement
grows to 64; its file/byte limits and custody checks are unchanged. The actual
closure has 86 files and 4,180,952 bytes, with no PYC in the captured copy.

Independent registration/consumer receipt `b925ad39` verifies 33 controls,
including 57 workflow causal cases. Modern success requires both complete
diagnostic groups and both fixed 4KiB selectors bound to each parent's already
validated container State, controller, image and entry. A diagnostic cannot
replace compilation, package validation, clean-pair comparison, distinct worker
identities or cleanup. Missing/unbound data stays unknown. Parent raw-record
hashes are distinct from reformatted selector hashes.

READY is `84eb3a020ed0cca3fe977feabc2b18bcaf6c6ae3811a5df5129c700ed9d8012f`;
stage is `3b38a7de9adea343dbc3cc08e3909e23b840ca12f0211e40e38afd7172b92012`;
collector is `4d3e3fd9848aaed94154f786b04a5ae07c7816dcef82857b671b51555895eacb`;
workflow is `52320dfb23f192b3d22a1161e58cc0c8fcb65464f29688457461699af2516ba4`.

The old collector's rejection of the new 64-row map and an initial synthetic
test's outdated 80-file assertion remain explicit. Root also directly reran a
held consumer test that rewrote its indexed `tests.json`; this derivative is
recorded in the independent review, without claiming the previous artifact
hash still matches. All source/workflow bindings remain exact. Evidence resides
under `artifacts/reviews/updater-worker-diagnostic-registration-20261012/` and
`artifacts/reviews/updater-worker-registration-root-peer-20261012/`.

Actual updater4 remains FAIL with its inner cause unknown. This registration
does not establish native compilation, installation, M2/16K behavior, measured
performance or complete distribution acceptance.
