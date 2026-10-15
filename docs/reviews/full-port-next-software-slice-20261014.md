# Full-port next software slice

The finite Source audit identified a missing repository-maintainer operation:
materialize the existing verified stable store as an immutable versioned local
endpoint and atomically update its managed selection. Root assigned this slice;
the implementation is in the three new files
`scripts/release/export_repository.py`, `scripts/release/test_export_repository.py`
and `docs/repository-endpoint.md`. Shared manifests and existing implementation
files were held.

The [audit evidence](../../artifacts/reviews/full-port-next-software-slice-20261014/audit-evidence.json)
captures 24 authoritative inputs, inventories 1,333 script/package paths and
records eight Source-gap assertions. `release.py` exposes only stage, verify,
promote and withdraw. Its `promote` returns `published: false`; `withdraw` returns
`clients_contacted: false`. The release interface explicitly leaves endpoint
regeneration open. The development client blocks stable scope, and source
material export is package-specific recipient delivery rather than a repository
endpoint operation.

The audit retained all responsibilities and acceptance gates:

| Coverage | Existing work and remaining requirement |
| --- | --- |
| R1/M5; A01/A05/A12 | Recipes, native build and local signed-store foundations exist; complete release coverage, target closure and maintained publication remain open. Endpoint materialization is a concrete missing software step. |
| R2–R3/M7; A02/A07/A14 | Protected-stack and native experiment work exists. Both exact Air records, target updates/recovery and final measurements remain mandatory; exporter results supply none. |
| R4/M6; A04/A13 | Setup/helper and tool candidates exist. Full Apple-aware management and the coherent desktop remain open. Updater policy still lacks its production trusted caller and exact later transaction binding. |
| R5/M8; A03/A06/A15 | Disposable installation/repository/onboarding tools do not supply the new-user production path. Base/key/endpoint selection, trust enrollment, complete install and both-size recovery remain open. |
| R1–R5/M9; A08/A09/A10/A11 | Capacity and permanent custody, independent contribution/installation, remaining reuse/upstream outcomes and a subsequent maintained full release remain required. No gate closes through this slice. |

The prioritized deliverable uses existing release/signature/promotion/withdrawal
machinery rather than a new trust protocol. Its finite acceptance is exact byte
preservation of packages/signatures/databases/source sidecars, complete signed
promotion and withdrawal binding, meaningful plan/apply, retained generations,
atomic selection, and preservation of the old live endpoint on precommit
failure. Refusal controls cover missing signatures/gates, foreign keys,
cross-release binding, withdrawn selection, partial withdrawals, path escape,
symlinks/hard links, writable inputs, concurrent locks, tampering and copy/source
drift. Postcommit I/O uncertainty is reported as materialized uncertainty.

Two other concrete gaps were inspected but not assigned in this slice:
production repository trust enrollment (installation guide supplies manual
steps and no accepted key/base/endpoint), and the updater's trusted release
caller (`asahi-policy.py` evaluates caller-supplied observations without binding
the later rolling transaction). They remain corrective implementation work.
The exporter neither substitutes for them nor reduces full-port scope.

Implementation validation and immutable pins are in the adjacent review
namespace. The first test attempt could not start its sandboxed ephemeral GPG
agent and ran zero cases. The second signing attempt passed 17/18 cases; its
remaining assertion expected `synthetic` while the real gate first refused
`gate identity mismatch`. That expectation was corrected. Later retained runs
exercise the actual temporary filesystem and signing fixture; stable positive
gates alone are explicitly modeled. No host trust, package installation,
service, hardware, Git or network publication operation occurred.
