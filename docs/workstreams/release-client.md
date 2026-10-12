# Offline release-client workstream

October 11, 2026 (America/New_York). **Implemented; 37 local tests PASS**, no skips. Python 3.14.7/GnuPG 2.4.9 on x86_64 Linux. Python syntax, CLI help and whitespace checks pass. Native ARM client execution, package installation, hardware acceptance, production custody/trust, endpoint publication and public updater safety are **NOT RUN**.

This is an R1/R5 release-maintenance foundation for the full port. M3/M5/M8/M9 and A06/A08/A12/A15 remain unaccepted; neither four package builds nor this client completes R1–R5. The revised goal, roadmap, outline, acceptance matrix and package inventory were reread. Only `scripts/client/**`, this report and `docs/release/client.md` are owned here. Existing release tooling/interface, shared manifests, CI files and Git state are unchanged. Client code is excluded from the initial V01–V09 native pipeline freeze.

## Frozen interface

[Client contract](../release/client.md) defines two finite commands:

- `build`: explicit bundle/output/namespace/sequence/issued-utc/expires-utc/full-primary signer; writes a new unsigned DEVELOPMENT envelope outside the existing bundle. Caller signs exact bytes separately with a deliberately selected external key. The source CLI never creates keys or signs.
- `verify`: explicit bundle/metadata/signature/public-keyring/full-primary signer/namespace/existing private state-dir; optional independently known `minimum-sequence`; read-only checkpoint checking by default. Only explicit `--apply` atomically commits after all acceptance checks and temporary verification cleanup. Scope is DEVELOPMENT only with no stable override.

Envelope and release-record signatures are verified with a copied binary public keyring, pinned full primary (or bound subkey), private temporary home, no default options/keyring/retrieval/import/dirmngr/autostart, SHA-256+ status checks and actual observed file hashes. Both repository databases and every package have their detached signatures checked; consumed signature bytes must match the signed release payload map. The client has no package manager, recipe execution, download, trust-import or publication action.

The private 0700 directory's inode is cooperatively locked. A validated singly linked 0600 checkpoint binds namespace/scope/signer, highest sequence, exact envelope and release hashes, issuance and applied time. Lower sequence, same-sequence different bytes, future/expired/overlong metadata, namespace/signer replay and backward clock movement fail without advancing state. Atomic replacement is the commit point; a final directory-sync failure reports an applied checkpoint with explicit durability uncertainty. Local state loss/reset and trusted-clock assumptions are documented.

This wrapper checks declared/consumed bytes and signatures. It deliberately requires the existing release semantic verification separately: no `.PKGINFO`, repository record, complete-directory/symlink inventory, provenance/dependency/protected-stack or promotion/hardware gate is inferred. Extra files/aliases outside declared/consumed targets are ignored. Missing state is a visible cold start, not proof of the newest release.

## Actual validation and review

`python3 -B scripts/client/test_client.py`: **37 PASS in 1.360 seconds**, no skips. Real ephemeral-GPG cases include primary and bound-subkey success, mixed-keyring wrong primary, SHA1 rejection, revoked and expired primary, unsigned/tampered envelope/release/package/database rejection, same-sequence/lower-sequence replay, freshness/namespace/stable refusal, unchanged external public ring, default read-only CLI, existing checkpoint preservation and valid-signature replacement race rejection. One adapter test consumes an actual unchanged `release.py stage` synthetic bundle created with real repo-add/bsdtar/vercmp/GPG, without installation or semantic-gate mocking.

Portable cases additionally cover duplicate/float/nonfinite JSON, invalid schema/unknown fields, symlink/traversal/noncanonical/hardlink/FIFO paths, bounded input sizes, all full-status error/expiry/revocation cases, private permissions, directory locking, atomic failure cleanup and before/after-commit sync outcomes. Full-call precommit cleanup/fsync/replace failures preserve an existing checkpoint. Status-only tests are not mislabeled as real expired-signature execution; an additional real expired-primary case is included.

Two bounded read-only subagents reviewed state/path/locking/atomic behavior and GPG/target/freshness behavior. State reviewer found no concrete defect; suggested full-call failure regressions were added. GPG reviewer reproduced a valid re-sign race: package/database `.sig` bytes reread after inspection could differ from the signed payload map. The verifier now hashes the actual consumed signature bytes against that map; the real SHA512 replacement regression fails before checkpoint commit. The GPG reviewer reran all 37 tests and independently confirmed this concrete gap closed, with no new finding from the minimal fix. Root's independent review also required the documented separate release semantic gate. No reviewer modified source or supplied hardware/native-client acceptance.

Source freeze:

| File | SHA-256 |
| --- | --- |
| `scripts/client/client.py` | `3025aa0e167c836e31c949e0915d4ee82a1007dc0fada598b4895240c82f5f97` |
| `scripts/client/test_client.py` | `a1a6a844ad4c0fd394a407529c5c7039f2a9e2bb43b63ee90a4e1e925701e144` |

No private fixture home/key/certificate is retained in this workstream; tests kill their own agents and delete temporary homes. The CLI copies only externally supplied public material for verification and deletes its temporary verification state before apply. Production key bootstrap/rotation/revocation distribution, authenticated time/state persistence, key compromise resilience, maintained full-port releases and target recovery remain separate required work. The coordinator may integrate this frozen source in a later native stage after reviewing all inputs; this worker does not dispatch or modify the pipeline.

## October 12 bounded native-stage adapter

`stage.py` and `test_stage.py` are additions for the later same-job coordinator follow-up. The frozen `client.py`/`test_client.py` above are unchanged. **39 adapter regressions PASS locally, no skips**; CLI help, AST syntax and whitespace checks pass. These regressions use portable fixtures, bounded local helper processes, signal injection and mocked Docker responses. They do not run Docker, emulate native execution or run the client tests in ARM. **Actual native execution of the 37 client tests remains NOT RUN.** No CI/workflow, builder, Git, dispatch or frozen repository handoff was changed.

The coordinator calls `run_stage(args)` from its main thread or invokes the CLI in the same native job, consuming its already-provisioned local immutable image and actual bootstrap/package receipts. It creates a disposable test container from that image; it never builds another image, downloads anything, installs packages or invokes repository/onboarding transactions. The actual Linux coordinator architecture, local Docker daemon architecture, image architecture and in-container architecture must be ARM. There is no runtime architecture override.

```sh
python -B scripts/client/stage.py run \
  --image sha256:ACTUAL_NATIVE_BUILDER_IMAGE_ID \
  --bootstrap /NATIVE_EVIDENCE/bootstrap.json \
  --bootstrap-sha256 REVIEWED_ACTUAL_BOOTSTRAP_SHA256 \
  --packages /NATIVE_EVIDENCE/packages.lock \
  --packages-sha256 89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f \
  --source /REVIEWED_SOURCE_SNAPSHOT \
  --stage-sha256 REVIEWED_STAGE_SHA256 \
  --guard-sha256 4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100 \
  --output /FRESH_CLIENT_EVIDENCE
```

Image/receipt placeholders must be replaced with reviewed actual values. Bootstrap must say `image-provisioned` and bind that immutable image, the exact accepted input lock (`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`) and the complete canonical 341-package inventory. Both the image’s `/builder-packages.lock` and its real `pacman -Q` inventory must match. Updater’s separate 354-package extension and derived installed/onboarding images are outside this stage. A changed builder/guard/package set requires a new reviewed adapter pin; mutable tags, missing packages, extra packages and unbound bootstrap assertions fail. The coordinator must verify the receipt’s origin against its actual job; a JSON declaration alone does not authenticate an image.

The adapter copies only six pinned regular source files into a private controller snapshot: stage, both frozen client files, frozen `release.py`/`test_release.py`, and the independently pinned `source_suites.py` environment guard. Existing integration source snapshots omit client files, so the coordinator must supply this reviewed addition explicitly. Guard source hash is fixed to the reviewed version above; the stage adds mandatory presence of all five protected proc children. No sanitizer dependency or full checkout/host credential directory is mounted. Minimal snapshot and bootstrap/lock/contract are mounted read-only; the entire container root is read-only.

The container uses the coordinator’s nonroot UID, all capabilities dropped, no-new-privileges, private PID/IPC namespaces, no network beyond loopback and no host sessions, devices, sockets or keys. Before any fixture key work, it must be PID1 with fresh tmpfs/output, and pass the actual mount/capability/device/socket guard. Docker creation and stopped-state inspection independently enforce the fixed bindings and resources. Limits are two CPUs, 1 GiB RAM with swap disabled, 64 PIDs, 256 file descriptors, a 256 MiB private tmpfs and a 300-second attached-worker deadline. Commands/log pipes are drained with a 1 MiB bound; private test-log/files receive a 1 MiB file-size limit. No raw test or attach diagnostics leave the container/controller scratch. Resource failure remains FAIL; increase a limit only through a reviewed adapter change.

The worker clears inherited environment, uses fixed tool paths and isolated Python startup, and sets private tmpfs HOME/TMPDIR/GNUPGHOME/XDG paths. It preflights real GPG/gpgconf/repo-add/bsdtar/vercmp/pacman/Python, loads exactly the unchanged client test module and demands **37 unique successful tests, zero skips/errors/failures**. It exports only known test identifiers/statuses/counts and source/image/input hashes. An aborted suite records FAIL with unknown counts rather than pretending a complete count was measured. Existing synthetic release-adapter fixtures are retained as tests, not labeled native installation or accepted repository evidence.

TERM/INT handlers interrupt execution; spawn signal masking prevents losing an untracked child. Cleanup defers repeated cancellation while killing/reaping namespace processes (including daemonized TEST agents), deleting all private tmpfs data, removing the named container and checking its name/ID absence against successful daemon queries. The controller also confirms stopped/exit-zero/no-OOM/no-runtime-error state and unchanged isolation. The final public `receipt.json` is created with mode 0600 only after container/controller cleanup. Cancellation observed during receipt write/fsync rewrites FAIL before returning. Raw key state, TEST key homes, sockets, traceback text, credentials, signatures and private logs are never exported. Cleanup failure overrides stage PASS; forced host/job loss still requires the coordinator’s job-level finally cleanup of its resources.

A read-only peer review found and verified closure of receipt-retention binding, cancellation cleanup, stopped/OOM and signal-during-receipt-write issues. The prior 34 local regressions include full mocked-controller success/cancellation/malformed-receipt/removal/OOM paths and real injected TERM/INT at receipt fsync. The peer executed no stage or native tests. This prepares source-test execution only; production client semantics, key custody/bootstrap/rotation, maintained releases, actual repository/onboarding lifecycle and M2 recovery remain separate unaccepted work.

| Added source | SHA-256 |
| --- | --- |
| `scripts/client/stage.py` | `00d4f5fb14158c22da1575f0527e59791d60536bff4f365b6b60995942c6c73d` |
| `scripts/client/test_stage.py` | `796822f78c16a172c5202e719c4dad875f868c5e823f38e312fcc93c55933378` |

After the repository correction interruptions, this worker rechecked all six source pins and the accepted 341-package inventory without finding drift. The current 34 adapter regressions pass again, no skips. The actual completed-job `38205521065` bootstrap receipt passes the adapter’s binding/schema check against its real package lock (bootstrap SHA-256 `1917efb43675357c3afb598f06f729fc4a91bfb49600dd70b286993d28bb4e19`; package-lock SHA-256 unchanged above). This verifies interface compatibility with retained actual bootstrap evidence; it does not prove that completed job’s image is still available or that client tests ran. Execute the adapter against the next same-job live accepted image and its newly reviewed bootstrap hash, then retain its bounded public receipt. Native client execution remains NOT RUN.

## Independent review corrections: daemon and exact case identity

Root’s independent client reviewer found that later Docker operations could follow a changed default context after discovery. The adapter now validates the initial local Unix endpoint, then passes explicit `docker --host=VALIDATED_ENDPOINT` to every subsequent info/image/create/start/inspect/remove/list invocation, including cancellation/failure cleanup. The public controller receipt retains that validated endpoint. A complete mock two-context regression changes the default to an unreviewed TCP daemon immediately after discovery and verifies every later actual command vector remains bound to the original endpoint, including both removal-absence queries. Remote/unreviewed endpoints remain refused. No Docker operation was run during these local regressions.

The reviewer also demonstrated that count/regex/uniqueness checks alone accepted 37 invented portable case identifiers with no GPG cases. PASS now requires the exact checksum-bound case set derived from unchanged `test_client.py`: **17 PortableTests and 20 GPGTests**. The worker’s successful case recording and controller’s PASS receipt validation use that set; failed/aborted receipts keep sanitized semantics. Regression fixtures now use real frozen IDs. Additional checks reject 37 unique invented portable IDs, all 20 GPG cases replaced by invented portable cases, and verify exact IDs against an independent AST read of the frozen source/hash. No client behavior or frozen client-test bytes changed.

Current validation: **39 adapter tests PASS**, no skips; AST syntax and trailing-whitespace checks pass. The six-file snapshot still binds the same frozen client pair, release pair and guard; only stage/test-stage additions and this report changed. All native client execution, production/hardware acceptance, CI integration and dispatch remain NOT RUN/unchanged. Updated stage/test hashes are in the table above for the coordinator’s recheck and refreeze.
