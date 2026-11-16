# Current-stage public retention v3

`retention_current_v3.py` provides a callable DATA-retention boundary for the new executor. It implements selection, stable reads, public projections, staging validation, encoding and the existing log envelope. It runs no actors, GPG, network, package extraction or package code. Construction, retention and a producer PASS establish no final component, hardware or release acceptance.

The selectors were audited against owner/route commit `bc47942d` and Reader adaptation `1da96c5e`. Those modules belong to other owners and are not copied or changed here. This commit changes only the new retention module, its tests and this document.

## Executor API

```python
result = retention.retain_stage(
    stage, output, destination,
    binding=binding, profile=profile, inputs=inputs,
    public=public_refs, public_roots=approved_public_directories,
    streams=command_index_refs, encoder=trusted_log_evidence.bundle,
)
retention.emit(result, workflow_log_stream)
```

`stage` is exactly `backend`, `ui` or `lifecycle`. `output` is the completed actual stage output; `destination` must be a fresh disjoint child of an existing ordinary directory. Binding fields are exactly `source/ref/run/job/attempt/source_lock`, with actual typed IDs, attempt1 and the whole Source-lock pin. `profile` and `inputs` are the owner's Source-bound objects, not code imported from output. No selection accepts an arbitrary directory to copy.

`public_roots` explicitly lists at most16 approved public input directories. Every external public reference must lie below one of these roots. References have exactly `{path, bytes, sha256}`. Private/hidden keyring, trust, home, credential, cache, storage and launch paths are refused before opening. Ordinary ancestors are opened with `O_NOFOLLOW`; files must be regular and single-link. Whole reads bind device/inode/mode/link-count/UID/GID/size/mtime/ctime before/after and at the current path; only atime is excluded. Empty command logs are retained.

The executor must supply these exact public roles:

| Stage | Public roles |
| --- | --- |
| All | `context`, `domain`, `inventory`, `public_test_key`, `image_qualification`, `runtime`, `admission` |
| Lifecycle additionally | `prior_backend`, `prior_ui` (whole prior public capsules) |

The inventory is the complete typed350/374/372-line backend/UI/lifecycle inventory, respectively. The key body must be public armor. Runtime, qualification and admission JSON are retained as public projections, removing launch/configuration/credential fields. Whole original and projected pins are distinguished in the retention manifest. Historical public TEST decisions/proofs and input archives/signatures are selected from actual `inputs.setup8`; UI also selects `inputs.first_login_backend`. Raw current GPG status text, signature bytes and the whole selected public key are retained without running GPG.

Context/domain receipts must have exactly `schema:1`, `kind`, `operation`, `stage`, `binding`, `facts`. Kinds are `CURRENT_ONBOARDING_PUBLIC_CONTEXT_V3` and `CURRENT_ONBOARDING_PUBLIC_DOMAIN_V3`; operation is `first-login-enrollment-ui-current-v2`. Context facts contain actual `architecture:aarch64`, `page_size:4096|16384`, `image` matching route owner facts, and optionally `execution_domain`.

Domain facts contain `execution_domain` and nonempty `observations`. Lifecycle additionally requires `signature_policy` with exact architecture/Required signature levels, offline-verifier/public-TEST booleans, private-home retirement state and the actual route signature-config pin; the private config body is never opened. Build stages forbid that lifecycle-only role. Each observation is `{kind, body, source_pin}` with the whole pin of its owner's original observation. Container and retirement observations are required; a status-only producer PASS is refused. Container body is exactly `{cid,name,image,state}`, with the actual admitted image and typed `Running/ExitCode` state (optional public `Status/OOMKilled/Dead/Pid`). Retirement body is exactly `{cid,status,absence_verified}`. Actual container/retirement CIDs must match for COMPLETE evidence; unknown/failed state or absence remains HOLD. Additional image/native-daemon/signature-policy observations have closed public keys. Raw Docker Config/HostConfig/Env/Mounts/storage/launch configuration and case-variant credential fields are forbidden. The executor/owner must produce these public observations from its actual inspected records before calling retention; retention never invents them.

`streams` contains whole command-index references, not directories:

| Stage | Required stream indexes |
| --- | --- |
| Backend/UI | `admission`: `owner-state/admission/commands.json`; `retirement`: `owner-state/retirement/commands.json`; `proxies`: exactly12/6 distinct `owner-state/proxy-*/commands/commands.json` references |
| Lifecycle | `administrative`: `owner-admin/commands/commands.json`; `outer`: `outer-owner/commands/commands.json` |

The executor obtains those exact references from its owned command streams; retention does not discover proxy directories by walking output. The fixed `commands/commands.json` must equal the actual route command index. Log names and original whole pins are checked. Empty successful absence logs remain bodies. Inspection/create/start/native-daemon stdout is classified before opening and excluded because it may contain private launch configuration; its public observations must be in the domain receipt. Command projections retain step, result, log pin, channels and sanitized supervision; private argv/cwd and free-form launch errors are omitted. Known missing supervision/launch-error receipts retain UNKNOWN/HOLD, never a natural-success inference.

## Stage-specific material

Backend retains both `a/b` archives for enrollment and first-login; UI retains both UI archives. Each clean slot requires the actual provenance, its complete declared public outputs (`build.log`, validation, both inventories, generated SRCINFO, environment/config hashes and isolated builder makepkg/pacman metadata), exact recipe snapshots and the package archive. Unknown provenance roles refuse. Provenance projections omit raw Docker launch commands while preserving the complete file/recipe/artifact pins and clean identity. Both compressed bodies must match. The original strict comparison log must equal the route receipt and assert byte, installed-content, PKGINFO and BUILDINFO equality. Check logs cannot omit check invocation or contain failed/skipped checks. Build intents/results and cleanup retain public identity/retirement projections with original source pins; raw inspections are excluded.

Lifecycle retains four signed archive/signature pairs, local preservation/private-retirement facts, final outer receipt facts, complete indexed public inventory/payload/ownership/stat/hash/help/removal logs and both prior-stage capsules. The six protected-state entries remain only strict `{files,bytes,sha256}` summaries; no home, keyring, package-cache or mounted tree is read. Final outer receipt is joined to `route.outer_retirement`; the intermediate `receipt.json` is not substituted. Preservation drift, private-retirement uncertainty, non-natural commands or unmatched outer retirement remains HOLD.

## Reader integration and refusal

The legacy Reader's private `inside.json`, `owner-state/proxy.json`, code-carrier launch captures and private signature-config replay are deliberately unsupported. None is opened. The new Reader must consume `route.public.json`, `provenance.public.json`, projected command/owner receipts and the actual public context/domain observation bodies. It must replay the retained packages, comparisons, public signature statuses, inventories, payload ownership and preservation facts, and verify prior-stage capsules. It must not turn a projection, producer PASS or manifest hash into proof of a body that was not retained. A direct unmodified v2 private-launch replay is incompatible and must refuse.

Normal retention requires the complete stage-specific material set. Missing package/provenance/log/public roles, malformed/unknown roles, privacy violations, aliases, drift or caps refuse before encoding. This is not an early-build-failure directory scraper. When an otherwise complete stage has uncertain cleanup, the capsule is retained with `evidence_state:HOLD`; it never erases PENDING/HOLD or fabricates retirement. On any retention/encoding exception the executor must preserve its existing HOLD/PENDING report and original cleanup authority, with no publication/acceptance fallback.

The return value includes `directory`, `manifest`, opaque `capsule` bytes, `capsule_pin`, `evidence_state` and `Root_acceptance:null`. Manifest component/hardware/release acceptance fields are also null. Limits are8MiB per file,16MiB total logical DATA,512 file members,8MiB encoded output. Staged files are fresh single-link0444 DATA; only their freshly generated closed namespace is walked. Exact file and directory membership and whole bodies are checked before and after the encoder. No original stage/private tree is handed to the encoder.

Pass only the trusted maintained `scripts/ci/log_evidence.py::bundle`, source SHA256 `a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5`, carried/loaded as trusted Source code by the constructor/executor. `emit` uses its existing `CACHY_ASAHI_EVIDENCE_BEGIN <fixed-name> sha256=... bytes=...`,76-column base64 and matching END format. No new archive or log format is introduced.

Run the inert controls from the repository root:

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/payload/native/test_retention_current_v3.py
```

The tests model all three stages with tiny inert package/log/receipt bodies, aliases, private-read tripwires, drift, caps and HOLD. They also exercise the actual maintained encoder and its outer evidence envelope without executing or extracting any package. Constructor pin updates, executor calls, public observation production, Reader adaptation and Source-CI wiring remain their owners' explicit integration steps. No native/hardware/release qualification is performed by these controls.
