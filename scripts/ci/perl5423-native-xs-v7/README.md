# XS v7: serialize the fixed sandbox path at the runner call

This additive constructor creates Source326 and restores the complete exact
Source321 v6 body/mode/map/tree. It changes one call argument in actor():

```diff
-runner.execute('/inputs/xs-plan.json', a['plan_sha256'], sandbox_path,
+runner.execute('/inputs/xs-plan.json', a['plan_sha256'], str(sandbox_path),
```

The actor constructs sandbox_path as Path('/tmp/xs-sandbox.json'). The frozen
runner first reads it through preflight.read(), which converts paths to strings,
then directly calls preflight.path(sandbox_path) while checking external operands
at runner/run.py:176. That API accepts only canonical strings. Retained v6
actor-result reports `ValueError: canonical shell-safe absolute path`; the
separately retained runtime/plan/admission DATA and maintained frozen code
reproduce the same error on that exact Path operand. The Original contains no
native traceback, so the callsite is explicitly a faithful validation-prefix
reproduction, not a claimed retained traceback.

`reproduce.py` verifies the actual faithful35328B TAR pin, reads only the two
whitelisted bounded JSON outputs, joins plan/admission hashes and derives the
Path-valued caller argument from the pinned maintained v6 actor AST. It runs
trusted maintained validation code with DATA reads and the sandbox gate fenced.
The old argument fails before sandbox/stage/command activity; the string argument
passes every unchanged strict external-path check and reaches the fenced sandbox
gate. No artifact/Source actor, Perl, compiler, Docker, custody or publication
operation runs in those controls.

The global ordinary path guard and runner are byte-identical. Exactly12of13
consumer files, all other native functions, held/accepted inputs, compiler-image
and preparation delegates, cap0/CHOWN separation, NoCopy volume policy, preentry
receipt, evidence ABI, command/resource budgets and native/XS refusal flags remain
unchanged. The v6 ALPM inventory-bound reader and primary-error policy remain
intact. The hosted entry changes only the revised native hash and v7 outer alias/
operation. Dedicated/generic workflow bodies are generated into the private Source
DATA output; no maintained shared workflow is edited.

Five original leaves are archived under previous-v6/: native.py, entry.py,
workflow.yml, provenance.json and source-map.json. `inverse()` restores all321
original files and validates the exact original map/tree; the existing v6 inverse
continues321→316, followed by the previously qualified316→311→305→298→272/original200
lineage. Independent Reader7 owns that full check separately. New actual Source,
ref, run, job, approval, authority, artifact, image and Reader selectors remain NULL.
Closed failed v6 run43753943999/job132933814476/artifact14178075955 is never replayed
or given XS acceptance. The v7 frame is recorded in reader7-interface.json.

Thirteen fenced DATA controls pass, covering actual prefix reproduction, global
path rejection, exact whole-native inverse,12 unchanged consumers, full frame and
archived-leaf integrity, entry/workflow literals, budgets and unissued scope.

```sh
python3 -I -B test_source.py \
  --previous-xs-source /EXACT/SOURCE321 \
  --retained-v6-materialization /ROOT/FAITHFUL/V6/MATERIALIZE
python3 -I -B prepare.py --previous-xs-source /EXACT/SOURCE321 \
  --profile-sha256 8a2d76467267eefaa052aa512750b30ea2546f79707961c159e61596ee68c76a \
  --output /FRESH/PRIVATE/SOURCE326
```

These are Source DATA construction and local validation only. There is no v7
native run, XS result, operational Reader, installed lifecycle, native16K/M2,
performance or release acceptance. Root separately reviews/publishes Source,
issues fresh actor resources/admission/custody and decides whether to run once.
