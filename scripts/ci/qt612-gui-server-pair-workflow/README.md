# Hosted Qt 6.12 GUI server pair

`native-arm-qt612-gui-server-pair.yml` is a manual development workflow for
one `gui_server` pair on the GitHub `ubuntu-24.04-arm` runner. It has a
six-hour job limit, shares the native source workflow concurrency group, and
admits only the repository owner’s first attempt. The Root operator must
also account for native, local VM, and other heavy trials outside that group.

Root selects two separate refs before dispatch. The live branch carries the
registered workflow, and its actual workflow commit is `workflow_sha`.
The dependency branch carries an immutable runtime Source with its own exact
`ref`, `commit`, `tree`, `map`, and `entry` in `runtime_source`. The map is
`source-map.json` with a closed set of ordinary files and exact modes. The
approved `entry` is `scripts/ci/qt612-gui-server-pair-adapter/entry.py` and
must match its indexed body. A separate checkout supplies the exact retained
R128 controller Source. The two frozen Qt F recipe locks are each
verified by whole-file pins in the live workflow checkout.

The workflow accepts `approval_json` and the independently reviewed
`approval_sha256` of its exact bytes. The JSON has
`kind: ROOT_QT612_GUI_SERVER_PAIR_APPROVAL_V1`, `issuer: Root`,
`approved: true`, `mode: pair-only`, the exact `repository`, `live_ref`,
`workflow_sha`, `runtime_source`, `inputs`, and integer UTC epoch fields
`issued_utc` and `expires_utc`. `inputs` names `portable_selection`,
`route_plan`, `md4c_signature`, `md4c_certificate`, and `md4c_authority`.
Each input, map, and entry descriptor contains `path`, `bytes`, and `sha256`.
The public authority projection contains the historical receipt digest and
scoped TEST trust. The current authority must cover the applicable startup
and scoped work windows. Use a fresh approval for each attempt.

The workflow checks the dispatch and both Source identities before passing
control to the Root adapter. The adapter owns the 12 GiB allocation and
2 GiB outer reserve gate, streamed acquisition of 567 pinned public
operands inside the owned ext4 volume, and the signed 349-to-356 image
bootstrap. The Actions read token is passed to the Root adapter alone. Its
authenticated log material fetch is fixed to R128 job `134591565463` and
must verify the whole original plus the selected md4c package member. The
separately pinned detached signature, certificate, and authority underpin
TEST-only package trust. Pair mode builds twice serially, compares the exact
archives, and qualifies the current pair independently. A pair result carries
no lifecycle, release, or hardware acceptance.

After successful Root readback and cleanup, the workflow rechecks the
atomically promoted closed pair evidence and the Root owner report. The
three-day artifact is named `qt612-gui-server-pair-<workflow-sha>-<run>-1`.
It includes the two public recipe `.SRCINFO` leaves and the rest of the
verified manifest. On a hold, the operator can inspect the bounded job
status and adapter diagnostics in the workflow log.

Run the passive controls with
`python3 -B scripts/ci/qt612-gui-server-pair-workflow/test_workflow_entry.py`.
