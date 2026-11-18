# First hosted Qt 6.12 GUI server pair

This adapter connects the workflow owner to the sealed hosted helpers at
523d436cf4fdcf35ad830782ac7f72a4b47ea6df, the input acquisition and binder
at dec43c97fb9fb01d20202f77706c38e65ad49f20, and the exact R128 owner and
signed349 runtime at eed0513b957ef265b334a7762bdfba4f50afd500. Select the
two Python files in this directory as the entry program. Use the runtime
Source constructor's independent whole pins and its split frozen-lock stage.

## Workflow handoff

The workflow verifies the original owner dispatch, pins the whole approval
and runtime checkout, and enters the Root systemd scope
`cachy-qt612-gui-server-controller-${GITHUB_RUN_ID}-1.scope`.
The scope uses the retained 512 MiB memory, zero swap, one CPU and 64-task
controller domain and a 21,030-second runtime.

Run the exact independently selected entry in that scope.

```sh
python3 -I -B "$RUNTIME_SOURCE/scripts/ci/qt612-gui-server-pair-adapter/entry.py" \
  --workflow-root "$WORKFLOW_ROOT" --runtime-source "$RUNTIME_SOURCE" \
  --r128-source "$R128_SOURCE" --approval "$ROOT_APPROVAL" \
  --approval-sha256 "$ROOT_APPROVAL_SHA256" --output "$FRESH_OUTPUT" \
  --runner-uid "$ORDINARY_UID" --runner-gid "$ORDINARY_GID"
```

The Root approval has kind `ROOT_QT612_GUI_SERVER_PAIR_APPROVAL_V1` and the
fields `issuer`, `approved`, `mode`, `repository`, `live_ref`,
`workflow_sha`, `issued_utc`, `expires_utc`, `runtime_source` and
`inputs`. Mode is `pair-only`. The distinct `runtime_source` contains
`ref`, `commit`, `tree`, `map` and `entry`. The five input roles are
`portable_selection`, `route_plan`, `md4c_signature`, `md4c_certificate`
and `md4c_authority`. Each file selection has a checkout-relative `path`,
`bytes` and `sha256`.

The service uses the exact 1,034-byte path-free R128 MD4C TEST authority
projection with SHA-256
`cc3dd84c1f96b5204df4e2edd33b10cc4e7907d460c68a311b6122a8c1fca712`.
It joins R128 Source, numeric run and job, attempt 1, original log and
verification receipt pins, detached archive/signature/public certificate
pins, the TEST fingerprint and its creation and expiry epochs. The retained
TEST certificate expires at epoch 1795065286. The bootstrap window must
finish before that expiry.

The workflow supplies `QT612_ACTIONS_READ_TOKEN` to the Root scope for
the one archived log read for job 134591565463. The adapter validates the
whole log before extraction and follows its one signed archive redirect
without forwarding the token. The lookup of the current attempt's numeric
job ID is a separate credential-free metadata read. Root stages the exact
two frozen parent locks from the independently selected workflow checkout,
using the runtime Source's `stage_helpers` reader before importing tools.

## Ordinary service and evidence

Root makes its protected service and stage binding files in
`FRESH_OUTPUT.authority`, a fresh sibling of the quota output. Root starts
the retained ordinary service and publishes its initial marker after
observing the live PID, start time and cgroup. The service checks that
marker, its kernel limits and the same private daemon, socket and ext4.
The ordinary work directory admits writes while its sticky ownership
protects the Root-owned acquired and bound inputs.

The Root scope's observed monotonic start bounds 240 seconds for transfer,
2,700 seconds for the signed349/356 window, 18,000 seconds for the pair, and
90 seconds for physical cleanup. Root needs enough UTC authority for the
whole 21,030-second scope. The bound portable packet must already select
the sealed pair-only pipeline. Before admitting either build, Root opens
the observed immutable image on the private daemon and independently
reads its exact 356-package inventory as the ordinary UID/GID. Root then
writes the fresh binding for this run, numeric job, source map and image.

Root waits for the natural ordinary service exit, revalidates the raw pair
export and copies it before unmounting. Uploadable data only appears at
`FRESH_OUTPUT/evidence/` after both service PIDFDs retire, two absence
observations pass, the loop detaches and storage is absent. The final
`FRESH_OUTPUT/owner-report.json` contains the selected evidence, exact late
binding and cleanup receipt. Qualification is for the exact raw pair. The
lifecycle is `NOT_RUN` and native acceptance is unset.

Run the offline controls with
`python3 -I -B -Werror::ResourceWarning scripts/ci/qt612-gui-server-pair-adapter/test_adapter.py`.
Set `QT612_TEST_R128_SOURCE` and `QT612_TEST_MD4C_AUTHORITY` to select the
retained Source and path-free authority. Set `QT612_TEST_RUNTIME_SOURCE`
and `QT612_TEST_RUNTIME_MAP_SHA256` to select the independent portable
fixture. The test process rejects network and process entry.
