# Independent repository-client native input review

2026-10-12. **The historical 107-test hold was blocked by RCN1. The exact corrected held runtime below closes RCN1 and is accepted within this bounded source-review scope.** Historical fresh-copy suite: **107 PASS, zero skips**; corrected independent focused suite: **34 PASS, zero skips**. Coordinator map/packet adoption and actual native end-to-end collection/admission/restaging, host trust, installation, endpoint publication, M2/16K hardware and performance remain **NOT RUN**.

The roadmap/package inventory and the workstream's separation of generic-builder observations, synthetic artifact ancestry, snapshot integrity and current signer authorization remain applicable. This reviewer owns only this document and `artifacts/repository-client-native/root-peer-review-20261012/`; no implementation, shared maps/locks, Git, workflows, dispatch, host Docker or installation was changed or executed.

## Held source and actual validation

Verified before copying:

| Held input | SHA256 |
| --- | --- |
| `source-map.json` | `1d38b5f9009636121b0c78f7c63b3ac63c809e841375bfa3e3bafa9eb4b6e290` |
| `review.lock.json` | `5b22ba656cd326c47ab3899378f670ff14adf4ed2b1ceb4a64f0d1abd0fc0cc7` |
| `common.py` | `cf1d5ab3bade457a85436d832555a35596d82f19e15e20a8569d7accb8c927f8` |
| `base.py` | `94a8e2898b062a0efd0f567d1f4f472bd04d6ff5a1573cd09f3bf8d1f556cddd` |
| `crypto.py` | `3e229ff4c543f462bc04c1a428ec4dfc0f029192885cfdd06821fcb2a85df967` |
| `entry.py` | `5889e0358bd0a04122e6cfcb061337f1dc415b064ba92f46ae47893a5747e0c8` |
| `orchestrator.py` | `9323498b61d3cedbb0f99bd45564a3f26572ed7e560d75f260eef932c7f957ff` |
| `provenance.py` | `772f23676ec047117a2d6089e33afb60d7d552d3a03d62543d505183b611345b` |
| `worker.py` | `9a513a59da3cbb58d54c236759e3299072e14194e4d297df911072daa241b060` |

All **16 declared owned source/test/document/map/proposal files** match hashes, sizes and modes. The four held adapter/gate/release/client dependencies also match their declared hashes; the existing stage review lock remains exactly `f1fa8ba782fd245264057de2b546b458aef49a3858376a724e0f063db6be2147`. A fresh independent copy contains those 20 files plus the externally checked review lock. Post-test/probe rehash finds no byte/size/mode drift, symlinks or bytecode in the copied tree.

Actual command in that copy: `python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/port/repository-client-native -p 'test_*.py' -v`. Result: **107 run, zero failures/errors/skips, 15.697 seconds**. Authorized bounded fixtures include actual local TEST GPG/repo-add and temporary private homes, real source-authenticated CLI execution, small local process/signals and actual archive parsing. Docker/native/build/admission authorities are modeled. No host keyring, keyserver, production signing, container or native package transaction was used. These source checks do not satisfy native end-to-end acceptance.

## RCN1 — interruption entering the cleanup deferral leaves the owned child alive

Location: `common.py:264–265`, used by `Commands.run()` cleanup at lines 350–360.

`defer_cancellation()` installs INT then TERM handlers without first blocking them. It also records the previous handler only after `signal.signal()` returns. During cleanup, TERM arriving just after the first INT remember-handler installation still invokes the caller's raising TERM handler. Construction is interrupted before the guard yields, so the process kill/wait/stream disposal inside `Commands.run()`'s finally block never executes.

Independent `cleanup-entry-probe.py` uses the exact captured `common.py`, an actual isolated five-second Python sleeper in its own process group and a 0.03-second command bound. The probe distinguishes installation from restoration and targets the **second installation** of the INT remember handler, specifically the cleanup guard after the child has been registered. It delivers actual SIGTERM to its own process under the module's normal `cancellation_handlers()` caller.

Actual result in `cleanup-entry-probe.json`: `KeyboardInterrupt` propagates and **the owned child is still alive after `Commands.run()` exits**. The reviewer then explicitly kills its own process group, waits for that child and closes its streams in an independent finally block. No process was left behind; no Docker or native operation occurred. This is not a speculative registration race or a mocked process return.

Required correction: make handler setup/restoration transactional under a preserved signal mask, record prior state before installation, and ensure cleanup cannot be skipped by interruption entering or restoring its guard. Repeated INT/TERM must propagate after owned process-group kill/reap/stream disposal, preserving nested pending cancellation and the caller's handlers/mask. The same helper protects Docker cleanup and public crypto-home teardown, so a PASS local suite alone cannot close this process ownership defect. The coordinator was notified immediately; this reviewer made no source edits.

## Boundaries independently audited

**Source execution:** the CLI requires isolated/no-bytecode Python before adjacent imports, captures the exact seven-source map under an external digest, checks modes/bytes before compiling source strings, and installs captured modules for transitive imports. The collector snapshots only the three authenticated worker modules into its private read-only source grant. Held gate/client/release sources are authenticated before the post-terminal interface inspects them. The coordinator still must authenticate the entry script itself and register the complete packet/Git closure; a generated source map is not its own authority.

**Base observations:** collection requires externally pinned image/bootstrap/inventory/input bytes, exact 341 records and matching actual pacman query records. CID registration occurs before start; cleanup targets the known ID and checks both ID and name absence. Creation uncertainty, malformed identity, missing cleanup or an unsuccessful worker cannot establish acceptance. `receive_base()` independently reconstructs the base from raw local records, checks the exact successful nine-command sequence and exact source grant, rechecks mapped bytes and refuses additional paths. Its finite exporter approval is **689 files including the externally pinned result**, not a recursive public grant. These are static/fixture conclusions; the actual immutable-base collection is not run locally.

**Provenance and licensing:** consumption captures bounded externally mapped archive, recipe, validation, build environment, inventory and comparison bytes. It checks archive equality for both distinct environments, metadata/source relationships, actual `.BUILDINFO` recipe hash, installed license text, entry/generator source and frozen fixture ancestry. The map is revalidated before return. An independent updated-artifact fixture confirms all four records retain `execution=synthetic` with `actual_compilation=native`; generated bytes use evidence hashes without fabricated Git commits, and their original ancestry and generator/workflow commit remain explicit. Those fixture build receipts are modeled and cannot become native observations merely by supplying hashes. Generic protected/coordinated policy and license inputs remain separately externally reviewed and pinned; no supported Mac model or Asahi coverage is inferred.

**Cryptographic phases:** the copied suite executes real TEST GPG and six exact temporary repository inventories. The attester uses public certificates in isolated private homes, disables key retrieval/autostart, checks current expiry/self-signatures and verifies all exact packages, DB/file DBs, aliases, embedded signatures and negative differences. Snapshot integrity remains `SNAPSHOT_ONLY`; terminal authorization distinguishes **seven revoked A objects and eight B objects valid at observation**, including GPG's possible exit-zero revoked verification. An additional independent machine-status matrix refuses all 16 forbidden positive statuses; revoked exit0 and exit1 both return REVOKED, never current VALID. These extra status inputs are synthetic parser cases, separately labeled from actual GPG execution in the suite. Original native verification/local-certification logs are external historical observations, not newly established native authority or B-key continuity.

**Terminal admission/publication:** admission requires successful terminal aggregate stages, successful public/binary acceptance, known original CID plus name/ID absence, explicit cryptographic phases, exact data/signature bindings and metadata authority. Private cleanup, byte/source/tool rechecks and bounded finite publication precede attester PASS. These barriers remain subject to RCN1 under interruption. The existing schema1 gate's fifteen unqualified VALID entries remain incompatible with revoked-A authorization; `post_terminal()` truthfully returns **NOT RUN**, launches no signer or client, and marks B continuity false. `gate-successor-proposal.json` is a proposal only. No root registration or native-restaging acceptance is implied by reviewing these interfaces.

## Evidence and disposition

Retained under `artifacts/repository-client-native/root-peer-review-20261012/`: `copy-receipt.json`, `source/`, `tests.log`, `cleanup-entry-probe.py`/`.json`, `semantic-probes.json` and `review-receipt.json`. All fixture homes and the counterexample child were disposed within their bounded scope. The historical `5b22…` source hold was **BLOCKED on RCN1** pending the correction and replay recorded below. Shared frozen predecessor stages remain unchanged. Actual collection, original repository cryptographic acceptance, native end-to-end admission/restaging, installation, publication, hardware and performance gates remain open.

## Held RCN1 correction: independent source closure

The author subsequently held these exact mode0644 bytes:

| Corrected input | SHA256 |
| --- | --- |
| `common.py` | `92ca41005397c6cccfd70497646c0de1f2ac88a697e0fcbec4165bf5326cfc08` |
| `test_common.py` | `be76e12659b8e810da2fb394c1b1e5dc88dfeab76f1951e8d712c91f20ae7f3f` |

I authenticated and captured those two files into a new reviewer-owned correction copy. The other six production modules, unchanged tests, gate proposal and four held dependencies remain byte-identical to the independently reviewed historical packet. Only the two expected explanatory docs additionally change. The historical `source-map.json` (`1d38…`) and `review.lock.json` (`5b22…`) are still untouched and must not be presented as binding the corrected runtime. Computing the single production-map digest update independently produces the proposed **`50638283c25bc76ec66bd47988227e31022cbad3bac16354d9db8ca7081dccc3`**, matching the coordinator's supplied proposal. The candidate is retained only in the owned artifacts; this reviewer did not adopt a shared map or lock.

The original actual cleanup-entry TERM probe was replayed against captured `92ca…` with the identical schedule. It still observes the injection and propagates `KeyboardInterrupt`, but now the registered child has already exited/reaped before the command returns. The focused fresh-copy suite executes **34 tests, zero skips/errors/failures, 0.844 seconds**. Independent whole-suite discovery finds 118 tests. The author reports its complete exact copied **118 PASS, zero skips, 15.258 seconds**; that full execution is author-reported, distinct from this reviewer's historical full107 run and current focused34 run. The redundant full TEST GPG suite was not rerun during this narrow correction review.

Four additional independent partial-restoration fault schedules target INT and TERM, both before and after each real setter. Each reports the controlled OSError after the protected body completes, restores **both** original handlers and the exact prior mask, and leaves the pending stack empty. A before-set fault makes exactly two bounded attempts; an after-set fault makes one because the actual original disposition is already installed. These are real handler changes with controlled setter faults, not native execution.

The correction blocks INT/TERM before capturing the complete previous handler pair and before installing/restoring either handler. It consumes transition events only for signals originally unblocked, preserves originally blocked pending signals and the original mask, and relays cancellation through nested deferrals after disposal. Partial setter failure cannot prevent restoration of the other signal. Focused tests also cover both entry installations, restoration signals, nested disposal, originally blocked/pending state, real child masks, and actual default TERM exit after the documented guard cutoff. The original leaking-child mechanism is no longer reproducible in this held copy; the independent fault schedules find no residual material defect in the narrowed correction.

**Disposition: RCN1 CLOSED; the exact held `92ca…`/`be76…` source delta is accepted for coordinator-owned map/packet adoption.** This is not acceptance of the stale historical source map, a committed new packet, a phase-aware successor gate, native execution, endpoint publication or hardware. The existing79 predecessor remains frozen; the concrete successor gate is still required before the deliberately refused post-terminal restage can run.

Correction evidence is under `artifacts/repository-client-native/root-peer-review-20261012/rcn1-corrected/`: `capture.json`, fresh `source/`, `cleanup-entry-probe.py`/`.json`, `focused-tests.log`, `restoration-probe.py`/`.json`, `proposed-source-map.json` and `review-receipt.json`. Post-probe rehash finds no captured source drift. Historical107 source files, failed probe and receipts remain preserved above.
