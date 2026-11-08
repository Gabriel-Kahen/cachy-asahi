# JSON native workflow descriptor

`scripts/ci/native_admission/workflow_descriptor.py` reads workflow bytes as DATA. It reports the original byte count/SHA256, every exact job runner selector, the decoded concurrency expression, its resolved group, the literal cancellation flag and the resolution proof. It performs no file, API, process or network operation and imports no workflow Source or reader. Script/condition/environment contents remain inert JSON data.

This descriptor grants no runner allocation, resource, operation, signing, namespace, native or coexistence authority. A selector such as `ubuntu-24.04-arm` does not prove an allocated hosted VM. An admission caller still needs its independently reviewed raw-body/mode/OID/Source certificate, genuine run/attempt/dispatch inputs, all actual job/runner identities, resource scope, scheduler and every existing freshness/custody/crypto gate. In particular, successfully describing D91 is not permission to overlap its signed generic16K VM lifecycle with Release.

## Supported subset

The reader accepts one complete UTF-8 JSON object, at most 256 KiB, 64 structural levels and 50,000 nodes. Duplicate keys anywhere, malformed or trailing JSON, nonfinite numbers (including exponent overflow), surrogate strings, oversized integers, wrong scope types and unknown relevant keys are refused with fixed reasons. Inputs must be plain bytes; caller-provided dispatch inputs must be a plain dictionary with plain string keys/values. One local snapshot binds the input fingerprint and resolved group consistently.

Root keys are exactly `name`, `on`, `permissions`, `concurrency`, `jobs`. The event scope supports only `workflow_dispatch` and its reviewed string/choice input-definition fields. A job must select a literal string runner and have bounded step objects; supported job keys are `name`, `env`, `if`, `runs-on`, `steps`, `timeout-minutes`. Strategies, reusable job calls, job containers/services and additional relevant keys are unsupported. This is a descriptor for that narrow subset, not a complete GitHub Actions schema validator. Step contents are opaque; successful parsing does not establish that a workflow is executable or safe.

Up to 32 jobs may use the same one reviewed selector: `ubuntu-24.04-arm`, `ubuntu-24.04`, `ubuntu-22.04` or `ubuntu-latest`. Mixed selectors, self-hosted labels, selector arrays/objects and runner expressions are refused. Concurrency must have exactly a string `group` and a boolean `cancel-in-progress`; the boolean is reported faithfully, including true. Policy must independently decide which value is permitted.

Literal groups use only ASCII letters, digits, `_` and `-`, up to 200 characters. The only supported expression is exactly:

```text
updater607-generic16k-${{ inputs.source }}-${{ inputs.case }}
```

It requires the reviewed Source input definition (`string`, required true), exact ordered case options (`normal`, `precommit-exit86`, `postcommit-exit87`, required true, default normal), and the caller's complete exact dispatch-input dictionary. Missing optional values are not defaulted; extras are not ignored; choices are validated. The selected Source must be 40 lowercase hex characters. The caller supplies genuine dispatch data and independently joins that SHA to the actual run/Source. The reader cannot acquire or authenticate it.

No evaluation, generic interpolation, expression functions, extra expression, alternative context or whitespace-normalized expression is supported. Resolution constructs the fixed prefix plus the validated Source/case strings. The descriptor preserves the decoded expression exactly, the two resolution bindings and a SHA256 fingerprint of the complete canonical dispatch-input dictionary. The full raw workflow SHA256 preserves original formatting/escaping differences. Retain and independently rejoin the original bytes when using that proof.

Generic YAML parsing remains explicitly unsupported (`unsupported-format`). Keep an existing independently reviewed literal-YAML path separate; do not guess format or silently fall back after a JSON refusal. The held literal Release YAML fixture demonstrates that refusal and is never interpreted or executed.

## DATA-only use

```python
from scripts.ci.native_admission.workflow_descriptor import describe_workflow

# Both arguments are already acquired, pinned DATA supplied by the caller.
descriptor = describe_workflow(raw_workflow_bytes, dispatch_inputs=exact_dispatch_inputs)
assert descriptor.authority == 'DATA_ONLY_NO_RESOURCE_NATIVE_OR_COEXISTENCE_AUTHORITY'
# Independently qualify descriptor.workflow_sha256, actual Source/job identities,
# operation, resources and scheduling before any admission action.
```

The focused controls use the genuinely published D91 JSON body (118,082 bytes; SHA256 `3d44fa32f528145458ed02424b99e7625608d246267a1e496a504393c2fe13a3`) and the genuine typed dispatch inputs as read-only fixtures. Hostile controls cover duplicate keys, nonfinite/oversize/deep data, wrong types and fields, mixed/self-hosted/dynamic runners, expression changes, missing/extra/coerced dispatch data and source/case grammar. An audit control checks that parsing inert script strings performs no import, compile/exec, file, process or network action.

Run only the focused DATA controls:

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/native_admission/test_workflow_descriptor.py
```

The dedicated `.github/workflows/native-workflow-descriptor-data.yml` runs these same 23 controls on hosted `ubuntu-24.04` with Python 3.12 and 3.14 for matching pull requests and Main pushes. Checkout and Python setup use pinned actions; the job has read-only contents permission and a ten-minute timeout. It executes the helper controls only.

Shared workflows/manifests, current admission packets, native Sources and readers remain unchanged. Future admission integration requires an explicit separately pinned review. A successful descriptor or CI run grants no native or coexistence authority.
