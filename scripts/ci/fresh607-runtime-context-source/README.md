# Fresh607 runtime context source

Reproduce exact public1192 `3a7cacaee84de54200acabaca2769fb5e757fa25`
from the complete public1189 parent
`606e31cf03f66043bdbc13a44dcc8559ebe81ec7`.

```sh
python3 -I -B -Werror scripts/ci/fresh607-runtime-context-source/prepare.py \
  --parent /ABS/public1189 --output /ABS/fresh1192 > /ABS/authorization.json
```

The output must be absent, canonical and disjoint from its parent and this
factory. Every parent and output file is checked. A fixed profile pins all
transform inputs, and late input changes refuse before output creation. The
factory executes only its closed pure source transform; it does not execute
parent code or run package, producer, installer or VM actors. All actual
selectors remain NULL in its receipt.

The emitted runtime scopes the legacy auditor's `common` import to its exact
legacy module and restores existing globals. Its temporary expanded604 cache
has an explicit ownership/closed-member lease; after607 materialization it
removes only that cache, requiring both verifier homes absent. The original
producer cleanup, whole604 owner and all package/signature/target/security and
runtime clocks remain held. The emitted source guard reconstructs all1189
bytes and executes every original source gate.

These fix the two qualified native1189 failures: an import collision before
VM startup and a secondary readonly-cache cleanup failure. Native1192 run
40218574007 is a separate validation trial; this source factory grants no
native, VM, cleanup, M2, performance or release acceptance.

The hosted Python3.12/3.14 matrix checks out both pinned public parent and
legacy `b6b17e5f6b322f160f7eeb22c8a01380a3c854cd`, reproduces1192, runs
five factory/refusal and five runtime groups, then runs the entire1192 source
entry under300 seconds. Runtime controls use the actual legacy import/digest,
real tiny synthetic readonly604 cache, sibling/link/metadata/owner/verifier
refusals and actual integration retirement/error calls. Their private files
are disposable host fixtures, with no package installation or guest authority.

For local controls, set `FRESH_RUNTIME_PARENT`, `FRESH_RUNTIME_SOURCE` and
`FRESH_RUNTIME_LEGACY` to those exact ordinary source directories. Run
`test_source.py` and `test_runtime.py` with `python3 -I -B -Werror`.
