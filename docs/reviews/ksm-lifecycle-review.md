# Independent KSM lifecycle source review

Review outcome: **source acceptance blocked by three reproduced boundary defects** in the frozen candidate below. This is a bounded independent source/fixture review for the proposed native trial. Native lifecycle execution, package installation, Asahi/M2 compatibility, 16K hardware, management activation, publication and performance are **NOT RUN**. An independently running broader build job does not establish execution of this unwired adapter.

Read `AGENTS.md`, `goal.md`, the revised roadmap, package inventory and `docs/workstreams/ksm-lifecycle.md`. All five complete-port responsibilities remain mandatory and incomplete. The diagnostic GPL candidate is an intermediate foundation; it does not satisfy KSM management or the full installation/release lifecycle.

## Reviewed bytes and local validation

All six actual file hashes matched the declared source handoff:

| File under `scripts/port/ksm-lifecycle/` | SHA-256 |
| --- | --- |
| `stage.py` | `21a986dd12459d1c4d4896d5c19276308b194021539f5c7232ec76a3098b178d` |
| `test_stage.py` | `48adf7b7c16897982c5a05c01d238912a2493e70644b0f055f16d99cc86a768b` |
| `contract.py` | `bfce5d9a5e8a9626cdedb121f299dafd730b13e484d1c4be7ba917207e4d161b` |
| `test_contract.py` | `13c7273a83cf3b67330f76380c05c14aa8af6ff4d7173c43d607d5c8b25e4258` |
| `worker.py` | `f5fa5ddd227d4c857a0b762f29d3f584141fc4ea9025a7b06bc6a35a1ba0d7da` |
| `test_worker.py` | `9f3b2b86b05982a50e74bc8c9c8ac13cb69e3e21c155b6c4c7cded4ca9ee3a94` |

The frozen original client stage `00d4f5fb14158c22da1575f0527e59791d60536bff4f365b6b60995942c6c73d` and source guard `4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100` are dependencies, not newly modified implementation.

Independently ran `python -B -m unittest discover -s scripts/port/ksm-lifecycle -p 'test_*.py'`: **107 PASS, zero skips**, 1.733 seconds. These include four real Ed25519/SHA256 checks in disposable TEST-only GPG homes. The first restricted run encountered four GPG-agent socket errors and one temporary Unix-socket error; rerunning the same suite with access to those ephemeral sockets passed. No Docker daemon, network, host installation, default keyring or default trust was used. Fixture Docker/native/package results remain mocks.

Additional independent counterexamples are in `/tmp/ksm-independent-review.py`. They mutate only temporary fixtures and mock boundary observations; implementation was not edited. The cancellation case uses the real frozen receipt writer, actual temporary file/fsync and actual chmod, with the signal handler's cancellation flag injected at the chmod boundary.

## Required corrections

1. **Docker operations can cross an unobserved daemon change.** `stage.py:183–203` checks daemon identity before a batch, then executes the name query, create, inspect, start and post-execution inspect without checking identity before each operation. Cleanup has the same gap between its initial identity check and inspect/removal/absence queries. The immutable Unix endpoint string alone does not pin its socket or Docker executable. In the independent phase fixture, the initial name query changes daemon A to B; both create and start occur on B. Restoring A before the next identity check produces a phase PASS. Add a single checked execution boundary covering every query, launch and cleanup operation, with the expected daemon and accepted CLI/socket identity checked for each operation. Do not rely on the unchanged endpoint string or a later check. Test drift immediately before create/start and between cleanup queries.

2. **Cancellation after durable lifecycle PASS leaves a successful result.** `worker.py:637–640` persists the authoritative receipt and then changes its permissions inside `defer_signals`. A cancellation remembered during that chmod sets `base.CANCELLED`, but neither the stored receipt nor the selected exit status is revised afterward. The independent fixture completes the real frozen `finalize_receipt`, injects cancellation during the actual chmod, and observes `CANCELLED=True`, exit zero and durable `status=PASS`. Make the permission transition part of pre-finalization work, or otherwise persist cancellation-aware FAIL after that transition. Verify cancellation during this exact operation and post-receipt disposal, rather than only before the status is selected.

3. **The nonroot controller accepts a privileged effective identity.** `stage.py:243` checks only real UID nonzero. A complete controller fixture with real UID 1000 but effective UID/GID zero still returns PASS. Require a positive, matching real/effective UID and GID before Docker or input access; reject set-ID/root-effective and mismatched identities. The private signing UID and runner real UID do not establish the controller's effective privilege.

All three findings were sent promptly to the coordinator. Until corrected, the workstream's earlier statement that independent source review is closed must not be used as acceptance of these reviewed bytes.

## Positive scope and remaining evidence limits

The data-only contract bounds file reads and decompression, refuses links/special files and unknown package members, validates the exact 15-input approved map `f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44`, and checks both authenticated consumed provenance digests. Distinct clean environments, native build-command grammar, entry script, image, inventories, archive bytes, payload and both metadata hashes are bound. `.BUILDINFO` correctly distinguishes makepkg tool version `7.1.0` from installed pacman package `7.1.0.r9.g54d9411-2`. Supplied provenance assertions still require the coordinator's actual same-job build selection; fixture assertions are not native execution proof.

The package contract accepts only five reviewed regular root-owned payload files with their exact modes, GPL notice/license/provenance hashes and dependency. Scriptlets, hooks, protected paths, unknown relations and additional payloads are rejected. The bootstrap/image/current-input bindings use the exact accepted 341-package lock and refreshed inputs. Signing is a separate nonroot readonly phase; lifecycle uses a disposable writable container with the finite `0xcb` capability mask, private IPC, network off, resource bounds and exactly the source/output binds. No management or sysfs-writing operation is provided.

Public certificate checks restrict identity, one-day validity, Ed25519 signing primary, full fingerprint and absence of subkeys; signature checks restrict primary identity, SHA256 and invalid/expired/revoked status. Real local GPG fixtures passed tampering, wrong-primary and isolated local-certification tests. Private keys and raw logs are excluded from the curated public receipt.

The lifecycle code checks full inventories before/after install, remove, reinstall and final removal; file ownership/modes/hashes, finite pacman ownership paths, nonroot probes, preserved user fixture and image hooks are checked. Hook basename masking and `--noscriptlet` avoid package/image hook execution. Positive pacman operations inspect both streams for known ancillary failures even with exit zero. Fixture 4K/16K conversions are mathematical checks, not hardware claims.

Existing tests cover ambiguous create, unrelated ownership, daemon drift at current checkpoints, known-ID/name absence, private deletion failure, cancellation before current finalization, and denied cross-UID process cleanup. Such failures remain controlled FAIL; private-artifact retention is reported honestly. Those useful checks do not close the three reproduced gaps above. Only this review document was edited in the repository; no source, lock, shared manifest, CI or Git change was made.
