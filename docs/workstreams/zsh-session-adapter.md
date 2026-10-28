# Session-borrowed Zsh adapter

Status: source implementation and finite source-only controls; held for Root
combined review and registration. Actual Session integration, native builds,
Docker execution, installation, signing and M2 hardware validation are NOT RUN.
The roadmap and development inventory remain the acceptance contract.

Only `scripts/ci/development/zsh_session.py`, `test_zsh_session.py`, this new guide
and `artifacts/reviews/zsh-session-adapter-20261013/` are owned here. The published
Zsh helper, actual Session/controller/packet/maps/workflow, generic policy and
selected Zsh manifest are unchanged by this worker.

## Borrowed custody

The public API is
`run_zsh(controller, root, output, cache=None, *, session, actor_contract_raw)`.
It requires the actual captured `development_repository_handoff.Session` and
`Sources` classes, checks their declared implementation/state through the existing
Sources verifier, and calls the actual `Session.original_context` with the same
Controller before work, between attempts and after finalization. It does not
create a SourceAuthority, original view, BytesLoader or original native producer.
The real suspended loader and native/Controller frames remain Session's checks.

The five-key context is root, immutable receipt bytes, receipt SHA, original nine
namespaces and two projection aliases. The adapter compares the actual namespace
objects and retained receipt/root before and after use. A detached dictionary,
same-named class or replaced namespace cannot supply this authority. Positive
orchestration tests explicitly replace that boundary as a model; they do not
establish a real original context or execution grant.

The helper is obtained only from the actual graph's closed `zsh` dictionary with
`zsh_addon` and `zsh_session`. Both module file paths and the adapter's actual
`sys.modules` identity must match. Source guards authenticate the parent's
captured bytes before child bootstrap/validation. The child builder/comparator
embeds exactly captured original build, compare and package-checker bytes; the
private Docker gate embeds captured addon and adapter bytes. No source reload,
ambient project import or PYC supplies authority.

`validate_attempt_session` derives SHA/mode rows from actual immutable
receipt.files and requires equality to `Sources.original_rows`. It preserves the
held validator's metadata/member/payload/provenance checks while replacing its
SourceAuthority data access and unmasked readers. Native-output inputs must equal
the captured original input lock, binding the341-package baseline and epoch to
the reviewed original source. The actual original image and Controller remain
required. The selected package remains0.7.1-1/MIT, twelve sources and six payloads.

## Actor and deadline bounds

The runtime contract remains exactly cli_sha256, endpoint_identity and env; its
existing canonical hash must equal the Session grant. Fixed local CLI/socket,
actual tool identities, native runner/source/run/attempt and private empty tool
state are checked before dispatch. No new credential, alias, GPG or installation
flow is created.

Zsh total is `min(J, start + 1200)`, work is
`min(total - 120, start + 1080)`. All later work/cleanup uses these retained
endpoints. Child gate configuration receives the parent's exact endpoints before
reading config, verifies their equality afterward, and keeps gate work subordinate
to the existing270 cap. No work budget is renewed at child startup or cleanup.

The original341-package image and held container policy are retained: nonroot
runner UID/GID, arm64, no pulls/network/capabilities, read-only root,
no-new-privileges,512 pids,4GiB memory,4 CPUs,4GiB `/tmp` and four exact mounts.
The gate retains create → inspect created state → start/attach → inspect actual
exit grammar. Attach code alone is not the container exit code. Two distinct
clean environment IDs/CIDs, both native attempt validations, exact inventory and
strict archive-byte comparison are required. Cleanup checks the bound intent,
configuration and observed absence rather than accepting a CID file alone.

Reusable held primitives include the exact Docker/container grammar, pair
validation, quotas/node bounds, process disposal and receipt FD/identity custody.
Read-capable tools/validators/tree/destination/removal are Session-specific
adaptations: they use a64KiB bounded reader with masked allocation, known FD
identity before unmask, same-endpoint checks and bounded identity-aware disposal.
Receipt partial writes check the endpoint between writes and before commit.
Supervisor arguments/environment are materialized before the final masked
pre-Popen check. First failure survives later ordinary mask/tool/cleanup faults.
Persistent descriptor or receipt uncertainty stays failure/cleanup UNKNOWN.

Successful finalization verifies each retained helper receipt before retiring its
custody record, restores the selected helper registry state, then checks handlers,
deadline and actual Session context again. Exact retired ownership is retained
locally so a post-context failure can invalidate matching owned selectors without
adopting a foreign file. Failure never clears sticky uncertainty to obtain PASS.
Public output contains only fixed receipts; raw logs/workspaces/archives are not
exported through the adapter's public selectors. Stage PASS remains provisional
until the sole original producer and repository terminal/cleanup acceptance pass.

## Required Root graph and registration work

The [contract audit](../../artifacts/reviews/zsh-session-adapter-20261013/contract-audit/audit.md)
and implementation-review records describe the exact proposed changes. They are
not changes to the live Session.

Root must select the later composition and matching `Development.consume_zsh`
callback through authenticated packet/grant agreement. Before the first existing
graph capture, after view preparation and before original loader entry, load both
Zsh modules through captured Sources, register their exact `sys.modules` entries,
and add a closed two-entry `zsh` namespace dictionary. Phase1 keeps its six keys;
the later graph adds only zsh. Include both namespaces in the first observation;
the second adds only the actual original nine/aliases and verifies prior
non-original identities unchanged. No third capture or callback-time admission
is proposed. Zsh runs before the unchanged KSM → ARM → client → virtual order.

For these exact namespaces, Root must bind captured function code/globals,
defaults, closure cells, class bases/slots/descriptors and required scalar/container
policy/imported dependency state. Existing graph_identity already validates
ordinary project class method code; its gaps do not justify a blanket namespace
exception. Narrowly admit the held helper's actual
`contextlib.contextmanager` wrapper alongside the existing exact named decorator.
Keep the new adapter's named contextmanager wrapper equally authenticated.

Receipt lifecycle rules must retain the actual four helper state objects
`_RECEIPT_FILES`, `_RECEIPT_FDS`, `_RECEIPT_UNCERTAIN` and
`_PROCESS_DISPOSAL_UNCERTAIN`. They begin empty and are restored empty only after
healthy witnessed retention. During work, admit only bounded owned output
path/parent/inode/hash/FD records from the reviewed writers. Failures do not reset
uncertainty. Context checks during active writes need this precise lifecycle;
requiring empty registries at every mid-stage check would reject healthy work.
Budget's local io_uncertain records are diagnostics, never a deadline/grant
authority. Its end/work_end are selected once; child clipping cannot enlarge them.

The proposed five registration paths are exactly:

```text
scripts/ci/development/zsh_addon.py
scripts/ci/development/test_zsh_addon.py
scripts/ci/development/zsh_session.py
scripts/ci/development/test_zsh_session.py
manifests/reviewed/zsh-native-addon.json
```

Root owns the actual contract, selector/path union, source maps, final parent
hashes, workflow and committed custody. Preserve original159/view160,
fixtures125, recipes4 and inputs71, grant17/runtime3/status22/live12, the one
original producer and actual callback roles. The actual graph extension and
selected manifest are prerequisites, not successful integration proved here.

## Evidence and limitations

The parent's independent39-file capture passes58 source-only tests with zero
skips/errors/failures/PYC and unchanged owned source pins after the run. Both
author and peer frozen captures also pass58. Actor/network/process launches are
blocked and signal operations modeled. Private files exercise actual FD and
receipt ownership; complete private metadata fixtures exercise the adapted
validation predicates. No real archive decoder/compiler/Docker/GPG/image/native
actor runs. The published helper's source/tests remain unchanged.

Earlier38/43/47 captures and receipts remain immutable history. New transitive
read routing explicitly changes three newly created projection-test fixtures and
the orchestration setup; all other prior47 test-method ASTs remain unchanged.
These fixture changes do not alter the held helper's original94 tests. Independent
probes retain five initial old RED/new GREEN findings and the separately reproduced
held-reader pending-control leak; four new routed entry controls are GREEN.
Independent11 controls and overlapping fresh suites are not added to58.

Finite checks establish source/model behavior, not actual Session authority or
hard real-time syscall/scheduler completion. Persistent close faults can leave
known or unprovable resources while reporting UNKNOWN. Cleanup/retention after
endpoint expiry can be unavailable; a returned FAIL does not prove every earlier
disk selector was rewritten or removed. Root must check returned status, trusted
clock, terminal acceptance and cleanup rather than treating an old PASS file as
authority. Source registration, combined parent/owner peer review, actual dispatch,
native package pair, installation, exact-M2 hardware and performance remain open.
