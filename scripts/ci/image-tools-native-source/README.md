# Image-tools native Source factory

This factory prepares the complete, pinned native image-tools lifecycle Source
from genuine parent `111f14d2b21b220d86912d5ead978848c7ef1cb0`. It only reads and
copies authenticated source bytes. It does not execute parent code, download
inputs, build packages, sign, install, invoke Docker, publish or dispatch.

```
python -I -B scripts/ci/image-tools-native-source/prepare.py \
  --parent /absolute/held-parent --output /absolute/fresh-native-source
```

The parent must have the exact 191 files, modes and Git tree recorded in the
profile; only top-level Git checkout metadata is ignored. The output contains
202 files with a complete source map, the original package's exact native input
bundle, native build/install/remove actors, failure retention and passive reader.
Whole parent, maintained payload and expected output hashes are checked before
emission. Existing destinations refuse. A checksum regression control binds both
native workflow aliases to the actual maintained `native/common.py` bytes.

The new Source retains the corrected parent cache/transport contracts, native
349-package dependency inventory, ordinary-user clean build pair, TEST Required
ALPM transaction, installed/moved synthetic image CLI workflows and exact
restoration requirements. Native tool hashes must come from the held native
builder. Existing host signed ext4 evidence and package bytes remain frozen.
No change to the host package recipes or shared package inventory is part of
this factory.

The path-scoped CI runs Source-only factory and lifecycle controls on Python
3.12/3.14. It checks out the fixed Git parent as source data; it never dispatches
the generated native workflow. To run locally, set `IMAGE_TOOLS_PARENT` to that
held parent and run `test_factory.py`. Any generated native operation requires
Root's independent source/ref/parent checks, once-only dispatch decision and
original capsule custody. Never repeat an uncertain POST or an immutable
original GET.

The generated reader requires complete actual selectors and an externally
pinned capsule digest before opening originals. TEST trust, fabricated control
receipts and successful Source tests cannot establish native installation,
Asahi/M2, bootability, performance or release acceptance. Native actuals remain
NULL until Root independently qualifies a real run.

Finished development changes target `main`. Hardware and release acceptance
remain separate from development integration.

A diagnostic-only successor retains at most32 typed rows from each already-performed legacy post-reap group scan. It never adds a scan, changes waits/signals/clocks, or changes the strict PRESENT_OR_REUSED refusal; numeric matches may be reused. The full Image reader validates the added failure DATA. No lifecycle fix or native pass is claimed until fresh evidence identifies and resolves the retained membership condition. Run only the new test_group_census_diagnostic.py with IMAGE_TOOLS_NATIVE_SOURCE bound to the exact proposed Source for its focused DATA controls.
