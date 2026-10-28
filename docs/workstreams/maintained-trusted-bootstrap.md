# Maintained trusted bootstrap proposal

This private executable source proposal is under `artifacts/reviews/maintained-trusted-bootstrap-proposal-20261013/`. It adapts the published trusted launcher/bootstrap to the separately reviewed maintained259/266 canonical source root. Primary code, workflows, maps, Git, signing and actual dispatch are unchanged by this lane. Root still chooses and registers every actual commit, source packet, workflow and per-run authority.

The final proposed launcher is SHA256 `dd6a119f596cd2cd56b3d50587be6cb3bf47a24f9e5020c1cee481351bda9c8b`; its bootstrap is `1675fa4834f556f1eec5d10f2f53b20d0475dd1a922b4c80fb0adc38f95e9391`. The clock issuer remains byte-identical to published `9e3271b8cb21e7be1940c2aa9f17f84357d0a438ed45a19ad34ae226ec9d4581`. Launcher/bootstrap were derived from published `9628d60d…` / `507e5ac1…`. This Source3 is outside the maintained native source unions, so it does not require changing native/controller/handoff/authority/maps or the installer issuer pins from the [maintained composed proposal](maintained-composed-successor.md).

## Explicit maintained selection

| Composition | Selected source rows | Metadata pins | Callback |
| --- | ---: | ---: | --- |
| `repository-svg-maintained-v1` | 259 | 14 | `Development.consume` |
| `installer-preflight-maintained-v1` | 266 | 14 | `Development.consume` |

The trusted selection envelope has exactly13 fields: the prior source commit/rows, metadata pins/hex, three maps, callbacks and peer receipt pin, plus schema3, purpose `root-selected-maintained-v1-development-source`, composition, baseline ID, lineage and source packet SHA. Its baseline ID is `maintained-native-baseline-v1-vim-9.2.1178-1`, lineage `SUCCESSOR_NOT_HISTORICAL_ORIGINAL`. Historical compositions, headers, pins and mixed selections refuse.

Metadata14 adds the reviewed maintained manifest and the existing canonical builder inventory to the previous twelve entries. Inputs `beca39e0…`, inventory `fc853bd6…` and integration `5d0f6b1d…` bind the maintained variant; native `a8b6ed89…` and recipes `20d846cd…` remain inherited. The original159-source producer implementation, its160-file view,125 generated fixtures, four recipes/71 recipe inputs, sole producer and two dependency captures retain the separately reviewed maintained contract.

Bootstrap `prepare` creates the existing grant17/runtime3. Grant17 replaces `original_view` with `baseline_view`; its inner schema2 has nine exact fields, including the baseline ID, with purpose `maintained-v1-159-copy-view`. Metadata argv paths use `output/repository-handoff/maintained-view`. `verify_checkout` rechecks the retained versioned envelope, exact grant/view/runtime shapes, invocation hash and existing physical bytes/modes/custody. `Owned`, directory reads, freshness, runtime observation and failure disposal retain their published implementation. Runtime observation never falls back to a caller-created contract.

## Code, Source and Data commits

The Root launch plan has six exact top-level fields: `root_pins`, `code_commit`, `data_commit`, `composition`, `git_sha256` and `development_sha256`. Root pins remain five fields: selection SHA, peer receipt SHA, source rows SHA, SourceCommit and CLI SHA.

CodeCommit selects only the two fixed trusted bootstrap/issuer delivery paths; the launcher body itself must also be fetched and verified against its fixed SHA by the trusted Root workflow. SourceCommit selects the canonical checkout, packet, grant and workflow job identity. DataCommit selects only `.github/bootstrap/development-selection.json` and `.github/bootstrap/development-source-peer.json`. The launcher requires DataCommit different from SourceCommit and verifies their tree diff contains exactly those two paths. That content-diff check does not prove commit ancestry; Root records actual ancestry separately if it requires a descendant.

The new workflow must run at SourceCommit, keeping actual `GITHUB_SHA == GITHUB_WORKFLOW_SHA == SourceCommit`. CodeCommit is never substituted as the clock's workflow identity. The launcher fetches trusted bodies from explicit CodeCommit, rather than silently reading checkout code. Envelope mode, baseline and packet SHA must agree with the external Root plan before preparation. Canonical Source bytes/modes and the committed packet still require actual Git verification; a prefixed artifact copy is insufficient.

The acyclic publication order is:

1. Freeze and publish the reviewed trusted bodies at CodeCommit.
2. Freeze the canonical maintained source/packet and new outside-union workflow at SourceCommit. Embed fixed code-body hashes/CodeCommit only where Root's workflow requires them; take SourceCommit identity from authenticated job environment.
3. After SourceCommit exists, derive a reviewed peer receipt, then selection bytes that include its hash. Commit only those two data files at DataCommit.
4. Register the complete external Root plan after all actual commits and byte pins exist.

SourceCommit cannot embed its own literal identity or a selection/peer/Root-plan digest whose content already contains SourceCommit. That creates a hash cycle. Peer bytes must not contain their own hash or the later selection hash. The external plan remains outside the SourceCommit workflow's contents; accepting an arbitrary dispatch input is not external Root registration.

[`derive-delivery.py`](../../artifacts/reviews/maintained-trusted-bootstrap-proposal-20261013/derive-delivery.py) supplies two data-only phases. `selection` takes explicit actual Root SourceCommit, canonical packet/root, peer bytes and CLI pin, then emits exactly the two canonical data files under this private namespace. `plan` subsequently takes actual CodeCommit/DataCommit and Git pin and emits the six-field external plan. It never queries Git, modifies the canonical worktree, reads host tools, publishes a workflow or grants authority. Its six controls use declared dummy commit strings solely as models; these are not guessed registrations.

## Retained clock and workspace lifecycle

Root must capture the first preparation entry before fetching or importing the launcher and pass it as `preparation_entry` to `launch_composed`. The fresh sibling workspace reservation, bootstrap delivery and preparation share that original entry+60 endpoint. The launcher does not remove the original workspace or foreign paths; it retains inode/FD ownership through child exit and attempts every registered retirement.

After preparation, the unchanged issuer creates one clock with its own issued time and endpoint `E = issued + 10800`. The launcher captures the earliest post-issuance controller entry before checkout and passes it unchanged to the controller. Work uses `J = min(E - 120, entry + 10080)`; later startup cannot extend J. These are separate preparation and issued-clock phases, not a claim that clock issuance occurred at the earlier preparation entry.

Checkout and verification use J, and the child must start before J. The parent retains the same E while waiting for the controller's existing publication tail; no second clock or renewed allowance appears. The inherited streaming path forwards bounded chunks without adding the Git-command total4MiB cap to publication. Signal masks/handlers/timers, process-group cleanup, first exceptions, workspace and private descriptor retirement retain their published predicates. Actual process disposal and whole-job timing still require execution evidence.

## Verification and remaining delivery

Separate receipts bind actual bootstrap interfaces, actual launcher functions with inert actor boundaries, helper models, source-preservation assertions and lane peer review. Bootstrap tests run both actual selection → preparation → private physical checkout verification → maintained `Sources.preflight` paths; only fixed CLI/socket observation is stubbed. Launcher controls label mocked code/data delivery, clock/domain, signal/process/Git boundaries and do not authorize native execution. Earlier fixture/reporting errors remain retained; no failed source predicate is skipped to claim a passing route.

Root's managed canonical worktree is a delivery target, not proof of a final SourceCommit. Root owns its branch/commits, exact Git blob/mode witness, mode-specific committed packet, reviewed outside-union workflow and isolated trigger choice, inline Root launcher/CodeCommit pins, external plan registration, actual runtime observation and invocation. The retained `native-arm-development.yml` lacks the required explicit maintained composition and cannot launch this proposal unchanged. No workflow was written or dispatched here.

Root's independently retained standalone native run remains separate. Its cleaned image is unavailable for composed authority, and its successful builds/signatures cannot substitute for the actual suspended original producer/context in this route. Actual maintained composed native execution, whole-job timing/cleanup, signatures, installation, both M2 sizes,16K/P0 validation and full R1–R5 completion remain unfinished.
