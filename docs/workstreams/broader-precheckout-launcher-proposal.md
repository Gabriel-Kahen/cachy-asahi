# Private precheckout launcher proposal

This retained proposal connects the accepted external bootstrap and clock issuer
before any repository checkout. It is source and synthetic-model evidence. It
does not select a production SourceRows tuple, dispatch a workflow, issue a real
grant or clock, run Git/network/native actors, or establish ARM/M2 acceptance.
Root owns source adoption, the primary workflow, maps, final selection and peer
data, runner selection, and Git publication.

The proposal lives in
[`artifacts/reviews/broader-precheckout-launcher-proposal-20261013`](../../artifacts/reviews/broader-precheckout-launcher-proposal-20261013/).
Its callable implementation is `launcher.py`; `test_launcher.py` models delivery,
bootstrap, issuer, checkout, signals and child processes. `root-first-step.py`
embeds the exact separately hashed launcher body and is runnable only with the
manual Root environment inputs. `workflow-excerpt.yml` shows that same trusted
inline body as the first step, before checkout. Its runner label is a placeholder.
Neither specimen has been executed against GitHub or a runner.

## Fixed bodies and authority

The bootstrap is the accepted disposal-correction body with SHA256
`507e5ac1cecbb1a82d38f2bdee077d24cc73e69b4f9f4f8ae1cbbaab05ee92d4`.
The issuer is the accepted clock body with SHA256
`9e3271b8cb21e7be1940c2aa9f17f84357d0a438ed45a19ad34ae226ec9d4581`.
The launcher fetches these exact bytes from fixed canonical paths in
`Gabriel-Kahen/cachy-asahi` at `GITHUB_WORKFLOW_SHA`, which must equal
`GITHUB_SHA` and the selected code commit. Root must first register those bytes
at the proposed paths `.github/bootstrap/development-bootstrap.py` and
`.github/bootstrap/development-clock-issuer.py`. Those paths are a proposal,
not a claim that an accepted published commit already contains them.

The trusted inline workflow pins the launcher body separately. There is no
launcher self-hash field and no new actor-contract field. The workflow excerpt
uses `/usr/bin/python3 -I -B -S`; Root must review the runner/interpreter trust
base as well as the literal body. The live primary workflow is untouched.

The private plan has exactly five keys: `root_pins`, `data_commit`,
`composition`, `git_sha256`, and `development_sha256`. `root_pins` has the
accepted bootstrap's five keys: `selection_sha256`, `peer_receipt_sha256`,
`source_rows_sha256`, `source_commit`, and `cli_sha256`. The permitted modes are
`repository-svg` with 258 source rows and `installer-preflight` with 265.
These are exact enums and row counts, not evidence that either final tuple has
been admitted. Fixtures use explicitly synthetic commits and hashes.

Root selects a later, separate data-only commit containing exactly the two
fixed selection/peer paths. The source commit and data commit must differ.
The launcher requires the Git tree diff between them to contain exactly those
two paths. Substantive peer content, its hash, the SourceRows hash, Docker CLI
hash, Git hash and development-packet hash remain manual Root inputs. The
bootstrap's required `source_peer_preflight` string is a structural check;
it does not grant authority to select or execute Source.

Root must dispatch the final reviewed **code** ref and supply the later data
ref and pins as manual inputs. Embedding the later data commit SHA or hashes
inside the earlier workflow/code commit would create a commit/hash cycle.
The specimen therefore has no selected data commit or default pin literals.
It passes inputs through environment values rather than interpolating them
into shell code. It does not add a second producer, Source authority, code
view, issuer, or allowance.

## Preparation, clock and child handoff

The inline specimen records a monotonic entry before validating/importing its
embedded body or assembling the plan. One `entry + 60` preparation endpoint
covers that work, the four fixed code/data downloads, and accepted bootstrap
preparation. Downloads have canonical origin, fixed paths, exact hashes,
bounded bytes and remaining-time socket timeouts; redirects and environment
proxies are refused. A separately network-downloaded launcher header would
need its own reviewed entry handoff so that it could not renew this interval.

Preparation creates the unchanged 17-field grant and three-field runtime
contract. The one accepted issuer then creates the unchanged 12-field clock
with an allowance of 10,800 seconds. The launcher merges its exact six returned
path/hash environment bindings into the sole child invocation; relying on
`GITHUB_ENV` to update the current process would be insufficient.

Immediately after issuance, before Git copies, the launcher records the early
entry and computes

```
J = min(workflow_end - 120, early_entry + 10080)
```

Checkout, bootstrap verification, packet authentication, and controller spawn
eligibility share that exact J. The Root-owned controller needs the proposed
optional `--controller-entry-monotonic` bridge. It must record actual entry
before argument/Source reads, validate the supplied finite non-boolean entry
against the same clock domain and `issued <= supplied <= actual_entry`, and
use the supplied entry only to shorten its existing cutoff. The absent flag
retains the legacy local-entry behavior. `controller_bridge_cutoff()` is a
finite source-model vector for that contract; it does not implement or admit
the production controller change.

The child is invoked once through a fixed Python/controller argv, never a shell
or a check-only second invocation. Its supervisor receives the original
`workflow_end` for the controller's existing final publication interval, with
`spawn_deadline=J` checked after argument/environment materialization and signal
masking immediately before `Popen`. This keeps late preparation from spawning a
child while preserving the publication window. Streaming controller stdout
does not impose a new aggregate four-MiB cap on its already bounded publication;
each write is checked for deadline and progress. Git reply capture retains that
cap and a ten-second cleanup reserve. The workflow's 180-minute scheduler
timeout is an outer cap, not an attestation of this monotonic clock.

## Checkout and custody

Git uses the fixed canonical HTTPS repository, the two selected 40-character
commits, a manually pinned root-owned single-link executable, and six fixed
commands. It requires an absent workspace, disables hooks, credential helpers,
external/file protocols, recursive submodules and redirects, sanitizes its
environment/config, checks the data-only diff, and verifies the final HEAD.
There are no caller-controlled URLs, command strings, arbitrary paths or refs.
Git/process behavior remains modeled in this packet, rather than actually run.
The specimen does not arrange an absent workspace on a real Actions runner.
If that runner precreates `GITHUB_WORKSPACE`, this launcher refuses it; Root
must review a fresh, nonoverlapping workspace handoff before actual adoption.
It must not remove an existing checkout implicitly to satisfy that condition.

The accepted bootstrap's `Owned` descriptors stay open through checkout,
`verify_checkout`, packet reading, and child exit. Reads and preparation are
masked around the accepted synchronous operations to retain custody during
INT/TERM/ALRM delivery. Every descriptor retirement is attempted separately;
the accepted `Owned.close()` first-error behavior is not used. Foreign identity
and close faults prevent a healthy result. The first execution failure survives
later cleanup faults. Success also checks the original workflow endpoint after
retirement and after timer/handler restoration.

The proposal deliberately retains private files/directories and any partial
checkout. It does not recursively remove cache/output trees or claim physical
absence, revocation, or complete filesystem disposal. Process supervision makes
finite TERM/KILL/reap/group/pipe attempts with waits bounded by the retained
endpoint. OS syscall scheduling, persistent close faults, same-UID interference,
and actual descendant behavior are not proved by these fixtures. A deadline
check is not proof that every cleanup syscall completes before that deadline.

## Review and integration limits

Independent review retained the original late-retirement and signal-control
findings, their corrections, and the later pre-spawn latency finding. Historical
receipts bind their exact historical bytes; final test and peer receipts bind
the final launcher. Parent evidence records source hashes, checks, artifacts
and remaining limits in `receipt.json`. Review/test counts overlap and are not
added into a claimed count of unique implementation tests.

Root still needs its substantive final source peer, the final 265-row selection
and later data commit, its controller bridge, source/body registration, and
primary-workflow adoption. The packet alone establishes none of those. It
does not alter the original source/fixture/recipe boundary, actor schemas,
platform policy, package manifests, Asahi stack, or hardware acceptance gates.
