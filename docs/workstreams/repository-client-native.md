# Native repository-client input handoff

October 12, 2026. This implementation owns only
`scripts/port/repository-client-native/**` and this document. The roadmap and
package inventory were read before implementation. Existing repository-client
adapter/gate and their review packet remain frozen. No shared CI/workflow/source
maps, Git state, native dispatch, host trust or installation were changed.

The new [collector and consumer](../../scripts/port/repository-client-native/README.md)
implements authenticated source execution, immutable 341-package metadata
collection, artifact/build provenance consumption, independent public-only GPG
verification and a post-terminal admission interface. Actual native end-to-end
execution remains **NOT RUN**; a failed aggregate or missing accepted observations
cannot be promoted through local fixtures.

The immutable-base collector reads real local package `desc`/`files` data and
cross-checks actual read-only pacman queries. It binds the actual image,
bootstrap, complete inventory and input snapshot. Its worker has no network or
capabilities and uses read-only source/input/root mounts. Docker's original full
CID is registered before start, verified against name/image, removed by ID and
checked absent by both name and ID. Cancellation, creation uncertainty or daemon
query failure cannot establish cleanup PASS.

An independent `receive_base` consumer reconstitutes the base from all raw local
records, cross-checks query bytes and the exact successful worker command graph,
and returns the finite 689-file approval map for a new purpose-specific export
hook. It requires an external result hash; an export manifest cannot authenticate
itself. No arbitrary state tree or public-key home enters that approval map.

The provenance consumer requires actual complete retained evidence for both
builds of each selected archive. It independently compares archive bytes and
checks package identity, source/recipe inputs, generated metadata, license
payloads, build entry/generator bytes, inventory and image/architecture. It
preserves recipe-origin versus workflow commits and original native versus
generated synthetic roles. Historical build receipts are external observations;
this collector does not re-execute those builds or claim stronger cleanup proof
than their receipts contain. A separately reviewed generic protected/coordinated
policy has no supported Mac models and supplies no Asahi platform coverage.

Independent crypto checks all six exact public repository inventories, package
and DB signatures/contents, embedded signatures, strict config, negative
differences and signed aliases. Current-clock GPG checks run with public keys in
private homes; no host keyring, keyserver, private key or local-certification
import is used. Snapshot integrity is explicitly separate from current
authorization: seven A objects are REVOKED, while eight B objects are valid at
observation. Positive checks retain all invalid/expired/revoked status refusals.
Retained pre-revocation native logs establish only the externally accepted
observation history; they cannot become current A authorization.

The held gate requires fifteen unqualified `VALID` entries. The new
[successor proposal](../../scripts/port/repository-client-native/gate-successor-proposal.json)
defines typed request/receipt references, snapshot and terminal phases, exact
object/artifact/native-command bindings and preserved admission predicates.
The current orchestration interface refuses that incompatible boundary with
**NOT RUN**, without signing or client execution. This is a concrete unfinished
contract gate, not a successful native handoff.

Coordinator integration consists of these bounded additions:

1. Register the seven new production source bytes/modes and authenticated entry
   in a separate reviewed source packet; no PYC enters it.
2. Invoke `collect_base` while the immutable builder is available, retaining raw
   observations and the collector's actual cleanup receipt. Preserve native
   runner/job/attempt/commit authority outside those observations.
3. Assemble an externally pinned provenance request from actual same-job original
   or generated build pairs and their locked source ancestry. Supply reviewed
   generic policy/license pins separately; never derive policy approval from
   observation collection.
4. Supply genuine original repository launch/name/CID cleanup. Existing
   name-only cleanup is insufficient. Preserve complete raw admission material
   in a bounded private same-job channel and keep public output projected through
   the unchanged generic credential guard.
5. After `native.main` returns and terminal integration/public export/cleanup
   acceptance passes, run the independent crypto attester. Original private A/B
   keys stay destroyed; the public attester needs none.
6. Review and pin a phase-aware successor gate/adapter. Then register a separate
   fresh worker for TEST restaging, preserving original phase receipt hashes and
   new signer/database lineage. Until this succeeds, post-terminal restaging is
   refused. A consumer callback before final cleanup must not manufacture PASS.

Local tests exercise real GPG/repo-add, authenticated CLI entry, forbidden crypto
statuses, exact artifact/DB/alias checks, source/PYC refusal, bounded
decompression, CID-controlled removal and actual INT/TERM child/publication
cleanup. Native/daemon/build/admission control fixtures are explicitly modeled.
The local review lock records exact tested source pins and counts. Native source
behavior, generic installation, M2/16K checks, stable promotion, production trust,
endpoint publication and performance remain distinct unfinished gates.

## RCN1 signal-transition correction

The root independent reviewer reproduced a live owned Python child after actual
TERM arrived between the first and second cleanup-handler installation. The
original 107-test packet remains historical; its passing tests did not cover
that transition. The retained root probe is
`artifacts/repository-client-native/root-peer-review-20261012/cleanup-entry-probe.py`
with its JSON observation. The probe disposed only its own leaked child.

The same causal regression failed against the original runtime and passes against
the correction. `common._signal_handlers` kernel-blocks INT/TERM before recording
all old handlers and installing the pair. It restores the complete pair under
the same block, consumes only transition events that were originally unblocked,
restores the exact prior mask and then routes those events. Deferral records and
relays them until owned cleanup has finished. Tests also exercise both entry
installs, restoration, partial installation failure, original blocked/pending
state, nested disposal, child masks and actual default TERM exit after cutoff.
Restoration attempts both signals even after a setter fault, retries at most once
when the disposition differs, finishes mask/pending handling and reports the
first error. Fault controls run before and after the real setter for both signals.

This correction changes only the new native runtime/tests and necessary docs.
The original native source map/review lock stay held pending coordinator refresh;
the 79-test repository-client gate and its lock are unchanged. Updated source
hashes and test counts are proposed as a checkpoint, not adopted source or actual
native execution.

Coordinator adoption, October12: current seven-source map50638283 now binds the
independently closed RCN1 correction. The historical107 metadata is preserved in
artifacts/reviews/repository-client-native118-adoption-20261012. Current118
author test execution and34 independent focused tests validate source behavior;
the new phase-aware gate is in development and native acceptance remains NOT RUN.
