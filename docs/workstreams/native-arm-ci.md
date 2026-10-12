# Native ARM CI workstream

Owned paths: `scripts/ci/**`, `.github/workflows/native-arm-build.yml`, `docs/native-arm-ci.md`, this report. Shared manifests, Git state, other workers' scripts/recipes and host packages were not changed. No external chat messages, issues or workflow dispatches were sent.

The early paragraphs below are historical source-audit receipts. Current original
native build acceptance is coordinator-reviewed PASS in run `38189520114` at
`ebd5812640b0b69f5c09a47752b739e37e338754`; the new integration execution remains
NOT RUN. The final controller handoff at the end supersedes earlier proposals.

A free native ARM route is source-confirmed: the public repository has Actions enabled, and GitHub documents `ubuntu-24.04-arm` as a free standard ARM64 runner. Actual runner execution is **NOT RUN**. Implemented bounded manual probe/audit/build workflow with pinned checkout, public-repository guard, read-only permissions, serialized execution, timeouts and evidence carried in logs without artifact/cache uploads.

Authenticated dated official rootfs locally: August 2026 archive, SHA-256 `42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319`; GPG exit zero with complete `VALIDSIG` for `68B3537F39A313B3E574D06777193F152BDBE6A6`. Pinned keyring source commit `29432c01130efc4ad297dfe8f487d5b79cbaf8e9`, key/trust/revocation file byte hashes. Retained exact rootfs/signature and all dependency bytes locally; no ARM executable was run.

Captured official repository database hashes, signed base inventory (165 packages) and a print-only full upgrade/dependency transaction (248 packages, 702,096,424 package bytes). Downloaded and verified all 248 original `.pkg.tar.xz` packages and signatures; matched their signed metadata to the frozen database. Package source/license fields, installed paths, `.BUILDINFO` and hooks are retained in private local audit evidence. The predicted final builder inventory is 341 packages; actual native installation remains **NOT RUN**. All 249 payload signatures passed locally. Full receipt is `scripts/ci/source-audit.json`; exact commands, input hashes and trust limits are in `docs/native-arm-ci.md`.

Implemented strict HTTPS/content pins, isolated GPG verification, rootfs-inventory binding, original xz archive inspection, copied-context rehashing, native/local Docker rejection gates, scratch bootstrap, offline required signatures, documented `/dev/null` ALPM hook masks, disabled package scriptlets, explicit in-image ldconfig, UID/GID mapping, immutable resulting image ID/lock checks, all-four recipe hash freeze, existing build runner invocation, two fresh attempts and strict byte comparison. The input lock is a candidate snapshot; no image ID or native PASS is invented. The corrected setup package handoff is complete, and all four current recipes are frozen in `scripts/ci/recipes.lock.json` as a candidate for independent coordinator review. Its SHA-256 is `8906c36f5cbcdb0e1e70798e6db23be1d30f45385d57af0094a1cd509c7a89d0`. A pure read-only canonical/package/license synchronization guard runs before freezing/building.

Independent bounded subagent supplied trust research and focused regression tests. Reproduced and fixed hash/parse races, copied rootfs replacement, partial-file cleanup, truncated signer status, duplicate package metadata, unreviewed hooks and missing/empty evidence handling. Tests also cover unsigned database attribution, separate dependency members, full recipe set, root/non-ARM rejection, rootfs metadata and bounded evidence. Final execution: **45 CI regression tests PASS**, Python compilation PASS, all 249 real GPG signature verifications and 248 signed package-metadata inspections PASS. The real audit evidence bundle also fits the configured log limits. The local x86_64 native probe correctly fails without running Docker builds. Receipts are in `scripts/ci/source-audit.json`.

Integration issues for coordinator/build owner:

- Build owner resolved the original `.xz` format incompatibility; source-verified original zst/xz/gz support. The shared provisioner still requires a preexisting registry digest, so the authenticated dated-rootfs bootstrap is an explicit scratch alternative before existing immutable-image build/compare contracts. Original signed bytes are never renamed/recompressed. No shared provisioner edits made by this worker.
- Build owner resolved the desktop `.SRCINFO` comment/exact-diff gap. Source-verified normalization removes only full comments/blank lines and preserves field/value/order plus effective metadata binding. No validation is disabled or package omitted. Coordinator must run setup canonical-source sync before final recipe freezing/dispatch.
- Retain the original signed rootfs/dependency cache and audit output in a durable private store. Current `/tmp` cache is real but temporary; official dependency mirror filenames may disappear. Missing blobs stop CI; a hash is not availability.
- Review/pin the final recipe lock and integrate source before dispatch. Native bootstrap, native builds/rebuild comparison, target installation and exact M2 checks remain **NOT RUN**.

No package manifest status changes proposed beyond recording this source-audited candidate builder route and actual receipts. Do not change package/native/release gates to PASS from these source checks or YAML.

## Corrected helper handoff check

Read-only final-handoff check found canonical helper, packaged CLI and provenance all match `a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`; the canonical/package/license guard passes. Updated package host validation records version `0.1.0-2` and corrected regression checks. The package-worker workstream still marks its refresh reopened, so final recipe freezing remains deferred until that worker finishes its handoff. No Git/push/dispatch action taken. Existing authenticated cache remains `/tmp/cachy-asahi-native-arm-audit`; all 501 pinned files were rehashed successfully (1,531,607,913 bytes). Final native CI regression suite remains 45 PASS.

Package-worker completion was subsequently observed: reopened marker removed, corrected canonical/package/provenance identity passed. Froze all four current recipes in `scripts/ci/recipes.lock.json`, SHA-256 `8906c36f5cbcdb0e1e70798e6db23be1d30f45385d57af0094a1cd509c7a89d0`; re-inspection immediately matched every frozen input. This is a candidate source freeze for independent coordinator review, not native execution or package acceptance. Coordinator remains sole Git/push/dispatch owner.

## Virtual integration contract revision 2 — owner interfaces reconciled

Proposed orchestration contract for coordinator routing, October 11, 2026. Native original build pair evidence has now been verified by the coordinator; the new integration stages remain **NOT RUN**. The revision-1 single common CLI/guard proposal in `docs/native-arm-ci.md` is superseded by these explicit adapters. No worker module or existing guard is replaced by a duplicate common module.

Shared host contract: reviewed immutable native image + exact sorted base package lock; signed ALARM input lock unchanged; actual native original archive records + separately labeled changed fixture archive records; accepted source commit and a full integration-source SHA-256 map. Freeze **before execution** all five integration scripts/tests, generated offline fixture recipe inputs/manifest, CI controller/exporter and every original source suite mounted for testing. No symlinks, missing components, moving sources or drift. The coordinator alone commits/pushes/dispatches. CI host performs only source/artifact copying/checks and Docker orchestration; no host pacman, user-account, package-trust or real-signing-key operation.

### Stage adapters and mounts

1. **Fixture builds:** tools-owned `fixtures.py` produces deterministic reviewed changed recipes for **all four** package names. Every upgrade has greater exact version and at least one changed installed payload. Keep fixture provenance, source hashes, generated `.SRCINFO`, two native clean build attempts and byte comparison separate from original candidate records. A reinstall of baseline bytes cannot satisfy upgrade checks. Generator CLI remains to be finalized by its owner; CI freezes its concrete output before dispatch.
2. **Lifecycle:** use the build owner's current exact CLI: `python3 -B /runner/lifecycle.py --execute-disposable-container --contract /inputs/lifecycle.json --contract-sha256 <full-hash> --output /out/lifecycle`. `/runner` and `/inputs` are read-only; only new `/out` persists; a new writable-root Docker container supplies `/scratch` tmpfs. Set fresh nonce/image env values required by owner guard; enforce aarch64, actual container marker, writable overlay, read-only inputs, loopback-only network and no host mutation-path mounts. Drop all caps then add only CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID; no-new-privileges, private PID, no devices/display/audio/services/Docker socket. Root inside the actual container performs real package transactions; installed helper runs as actual non-root alarm or owner-created fresh users. Use owner guard unchanged; an env flag alone is insufficient.
3. **Installed-image handoff:** lifecycle owner must explicitly leave/reinstall original **baseline** versions after testing fixture upgrades. Before commit, independently assert all four exact installed versions and **every** baseline payload hash, plus package ownership and the expected base+four package inventory. Clean fixture accounts/homes, test transaction/cache state and ALL secret signing/private-home residue from writable root, including the base builder's disposable pacman local-trust private-key directory; TEST private-key homes must live only in tmpfs. Preserve public trust receipts as data, not private keyrings. Emit sanitized `installed-packages.lock` and payload-check/cleanup receipts. CI uses a uniquely named container **without --rm** only for this stage, waits for successful exit/verification, `docker commit`s that exact container, records immutable derived ID and lock, then removes only its own container. Failed cleanup/hash checks forbid commit. Bind mounts/tmpfs are not part of the committed image; there is no Docker socket inside it.
4. **Repository:** preserve release owner's different interface: `python3 -B /runner/repository.py --inputs /inputs/manifest.json --inputs-sha256 <full-hash> --allow-disposable-repository-test`. Fresh root process in a **read-only-root** native container; `/runner` and `/inputs` read-only, dedicated `/scratch` and `/test-home` tmpfs, `/out` new/public evidence only. Pacman mutates ONLY the explicitly copied `/scratch/system` root/database/cache/keyring, never container/host `/etc` or package DB. Pass baseline and changed fixture arrays using the owner's `{path, sha256}` schema; retained archives are exactly original/fixture native outputs. Key rotation/revocation uses expiring TEST-only keys under `/test-home`; no secret state/copy-root is exported or committed. This stage does not supply the installed onboarding image.
5. **Onboarding:** retain performance owner's **host orchestrator** CLI: `python3 scripts/integration/onboarding.py --image <derived-installed-ID> --expected-packages <installed-packages.lock> --expected-packages-sha256 <hash> --source examples/development/hello.c --source-sha256 <hash> --output <new-raw-onboarding-directory>`. Owner creates a fresh network-disabled, capability-dropped, no-new-privileges, read-only-root native **non-root** container with owned tmpfs and explicit input hashes. No account/package/trust setup here. Root confirmed frozen image already supplies Vim/Nano/GCC and dependencies; missing commands/packages fail by exact name, never current-mirror installation.
6. **Desktop:** run owner script as non-root inside a separate fresh read-only-root container with mutable caller-owned tmpfs and dedicated evidence: `CACHY_ASAHI_INTEGRATION_CONTAINER=1 python3 -B /runner/desktop.py --package /inputs/<original-desktop-archive> --package-sha256 <hash> --runtime-lock /inputs/base-packages.lock --output /out/desktop`. Use the derived installed image, while the owner verifier binds unchanged base versions and limits extras to four originals. No DRM/input/audio/display/session sockets mounted; original archived payloads only. Parser/subset checks are software evidence; compositor/session/graphics/M2 gates stay NOT RUN/BLOCKED exactly as owner reports.
7. **Full native source suites:** fresh non-root native, read-only-root base image; complete reviewed source snapshot mounted `/source` read-only; new public `/out`, caller UID/GID-owned tmpfs for HOME/XDG/TMPDIR/work. Run all existing tests (`tests/`, hardware, release, benchmarks, setup, CI, integration and package synchronization fixtures) with `python3 -B` and `PYTHONDONTWRITEBYTECODE=1`. Release tests now have real repo-add/bsdtar/vercmp/GPG in frozen native userspace; record actual tests/skips and do not label skipped cases passed. No inherited host home, Git credential state or bytecode writes into source. Test-key temporaries are private tmpfs, never published.

### Resource/provenance and evidence contract

Containers run serially. Initial limits: lifecycle 4 CPUs/6GiB RAM/4GiB scratch; repository copied-root stage 4 CPUs/8GiB RAM with **6GiB** scratch and separate bounded key home, subject to an actual native root-subtree/disk preflight. A copied target can be several GiB: measure required `/usr`, `/etc`, selected `/var/lib/pacman` bytes plus headroom; exclude `/proc`, `/sys`, `/dev`, `/run`, inputs/runner/output mounts, homes and secrets. If the required copy does not fit, record exact sizes and FAIL/NOT RUN; do not silently omit dependencies, switch to host root, add swap or paid resources. Onboarding/desktop use owner bounds and correct tmpfs UID/GID ownership. Record image IDs, accepted commit, input/source hashes, capabilities/mounts, exact commands, exit status and container names/page size; generic ARM/4K execution is never M2/16K proof.

Evidence will be in separate explicit **sanitized** per-stage directories/bundles, not raw container trees. `scripts/ci/integration_export.py --raw <raw-dir> --output <new-public-dir>` allows regular UTF-8 JSON/log/txt receipts only; excludes/rejects nested GPG/private/home/scratch state, symlinks/hardlinks/nonregular files, credential/private-key markers, archives and binary content. Limit 4MiB per file and 16MiB total **including** manifest; violations emit named-path/size/reason diagnostics and fail export, with no silent truncation or rejected content. Original/fixture MIT archives may be copied separately only by reviewed controller artifact hashes. Source rootfs/dependency archives, TEST secret keys, copied roots, transaction private state and real HOME contents never enter public logs/artifacts. Use separate bounded bundles for original native-build records, fixture-native records, lifecycle, repository, desktop, onboarding and source-suite tests; preserve every failed stage's public diagnostic bundle. No real release identity or paid artifact/cache service is introduced.

Exporter source implemented by a bounded subagent; **12 regression tests PASS** locally, with no Docker/native/integration execution. Its CLI exits 0 clean, 1 for explicit rejected inputs and 2 for infrastructure/root/output refusal. Arbitrary disguised credentials cannot be inferred from filenames/text alone: owners/controller must construct deliberately public output; the exporter is additional enforcement, not authorization to dump scratch/home state.

### Remaining interface decisions for root/owners

- Lifecycle requires signed baseline+upgrade archives and a trusted ephemeral TEST signing key. The existing native candidate artifacts are unsigned. Root must route an explicit TEST-only signature-preparation adapter to CI/release/lifecycle owners: key generation/signing ONLY in a fresh isolated container scratch; export public certificate/fingerprint and detached signatures only; lifecycle may import/locally trust that pinned public key only after its real-container guard. No host private-key generation or signature-check bypass. Repository's private copied-root signing experiment is a separate key lifecycle and must not be used as an implicit installed-image provider.
- Lifecycle needs the explicit baseline-installed/verified/cleaned handoff above for commit; current draft CLI must expose that behavior/result before CI assumes it.
- Tools fixture CLI/output manifest and deterministic all-four recipe files must finish before source freeze. Current source missing/under construction is not an accepted frozen suite. Root validates/routs the concrete contracts before integration dispatch.

## Coordinator-approved TEST signer adapter

Root assigned `scripts/ci/sign_fixture.py` and tests to this worker. Host CLI will be:

```text
python3 scripts/ci/sign_fixture.py --image sha256:IMMUTABLE_NATIVE_BASE_ID \
  --manifest /absolute/archive-manifest.json --manifest-sha256 REVIEWED_HASH \
  --output /absolute/new-public-signature-output
```

Manifest schema 1: `{purpose: "TEST-ONLY-integration-signatures", source_commit: 40-hex, archives: [{path: relative archive beside manifest, name: one of four original names, version: exact ALPM version, role: "original" | "upgrade-fixture", sha256: 64-hex}]}`. Exactly four originals and four greater-version changed upgrade fixtures are required; controller binds payload changes through fixture/build evidence. The adapter snapshots/hash-checks archives and manifest, probes native/local image, and runs **non-root alarm** in a fresh read-only-root, cap0/no-network container. Inputs and adapter code mount read-only below `/inputs`; private GNUPGHOME and verification home exist only in unmounted owned `/tmp` tmpfs. New `/out` contains public certificate, detached signatures and JSON fingerprint/expiry/hash/verification receipts only. No package, recipe, account or host signing-key operation. Real mount/native/non-root/no-new-privileges/no-caps checks run before any GPG command; spoofed env flags cannot satisfy them.

The host controller validates the exact public output file set, public-certificate armor, archive/signature bindings, fresh temporary-public-key verification and full expected signer `VALIDSIG` records before using outputs as lifecycle input. Generic UTF-8 evidence exporter remains unchanged: it never copies binary signatures or arbitrary `.asc`. Public TEST certificate and signatures are consumed/exported only by this explicit hash-bound adapter; no secret-key export command exists. Fingerprint/expiry/type are TEST-only and cannot satisfy production trust/promotion gates. Actual signer/native integration remains NOT RUN until coordinator dispatch.

## Final frozen integration controller handoff

Implemented `scripts/ci/integration.py`, native `integration` mode, workflow input
`integration_sha256`, isolated TEST signer, independent installed-image handoff,
source-suite adapter and separate bounded public stage publication. Every concrete
owner CLI is wired, including onboarding's required original baseline full-payload
manifest. Lifecycle commit requires exact stopped image/container identity, exit
zero, bound READY receipt, all required cleanup/payload/inventory assertions and
full original base-plus-four lock. Repository and source-suite outer failure logs
are retained; dependent stages explicitly say NOT RUN after prerequisite failure.

Read-only subagent review found and resolved private-state hash exposure in binary
exclusion inventory, unfiltered exception text in final summaries, contradictory
component/export status and overlapping raw/public evidence output roots. Focused
regressions enforce those boundaries. Sensitive trees are pruned before contents
are enumerated/read/hashed; summary/control receipts pass the same exporter. The
only binary public export is the explicit rehashed four MIT fixture archives;
arbitrary nontext component material remains excluded. Public publication attempts
all stage bundles even if an earlier bundle exceeds its limits.

Actual local validation: **141 CI boundary regression tests PASS**; all frozen
source modes/hashes and all generated fixture modes/hashes rechecked; complete
readonly source snapshot recreated and deterministic fixtures regenerated with
exact equality. This validation ran only local source/mocked operations, never
Docker, ARM package installation, TEST private-key generation or a native suite.

Reviewed candidate freeze for coordinator independent review:

- `scripts/ci/integration.lock.json` SHA-256
  `641be67646a40f396f6aaff7c24dcfa4af2c91d4734c99a30702df6e472d54c8`.
- 151 source files plus 125 deterministic generated fixture files; source trees
  scripts/tests/packages/examples plus root LICENSE/AGENTS/README and workflow.
- Original recipe lock SHA-256
  `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`;
  unchanged signed input lock
  `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41`.
- Original recipe source commit `ebd5812640b0b69f5c09a47752b739e37e338754`,
  epoch `1791748800`; actual accepted new checkout must equal workflow GITHUB_SHA.
- Excluded independently active `scripts/virtual` and `scripts/client` batches are
  never imported/invoked/claimed tested. Documentation and shared acceptance
  manifests are outside this executable freeze and remain coordinator-owned.

The derived installed image is runner-local/private. Visible cleanup does not
remove private bytes from Docker parent layers; nothing commits/pushes/exports it
as a distributable release image. Hardware, 16K Asahi, compositor/audio/session,
performance, production trust/promotion/publication and exact-M2 onboarding remain
NOT RUN. Native integration itself remains NOT RUN until coordinator dispatch.
Coordinator retains sole Git/commit/push/dispatch ownership; no host mutation,
paid service, Git operation or external chat message was performed by this worker.

## Corrective review handoff after complete-port roadmap update

Read the updated goal, roadmap, outline, acceptance matrix and inventory. The
full maintained port is mandatory; this native four-package integration remains
its development foundation, not R1–R5 completion. No shared goals/acceptance or
package inventory was edited by this worker. The old candidate integration lock
is invalidated; it was not regenerated or dispatched while the coordinator
reconciles/finalizes source scope.

Fixed independently reproduced child nonce/image forwarding and public repository
status naming blockers. The handoff forwards only its verified identity plus an
explicit base environment; six exact public repository logs are hash-bound to
producer receipt labels before neutral filename projection. Unknown GPG paths,
private trees, changed status bytes and inherited credentials still refuse.

Corrected C1–C5: exact runtime mount/device/socket/capability/NNP guards; bounded
process-group cancellation and safe final failure records; bounded Docker removal
with independently verified absence; underlying overlay `/tmp` cleanup/check;
fixture failure diagnostics retained in finally. Lifecycle receives KILL solely
for demoted-child cleanup; repository/derived read-only verification retain five
capabilities. Handoff commit restores accepted base image Config USER/CMD/
ENTRYPOINT/WORKDIR and exact Env; nonce/image live only in process environment.
A new fresh-container read-only verifier checks the committed full inventory,
all baseline payloads/ownership and actual private/tmp view before installed image
handoff is accepted. Lower-layer erasure remains explicitly unclaimed.

Successful signer artifacts now retain exactly verified public certificate + eight
signature bytes/archive bindings. Successful repository public output uses an
explicit bounded cert/database/package/signature/regular-alias allowlist bound to
owner's public receipt hashes; negative cases remain available for offline review.
No private homes, GPG state, copied target roots or standalone sensitive revocation
files are exported. Generic UTF8 exporter remains unchanged. Separate bundle cap:
12MiB approved binary payload, followed by the existing 16MiB-expanded/8MiB-compressed
publication limits. TEST keys expire one day after creation; receipt fingerprints,
expiry and signature timestamps are preserved. Later offline checking must account
for intentional expiration rather than treating test identity as production trust.

Current actual local execution: **210 CI mocked/boundary tests PASS**, including
36 handoff, 49 signer, 30 source-suite, 33 controller and 5 derived-image cases;
45 original CI and 12 exporter cases remain passing. Diff whitespace check PASS.
No Docker, ARM package execution, host private-key generation, physical checks,
Git/push or dispatch was performed by this worker. Native integration remains NOT
RUN. Initial source scan excludes independent active virtual/client/experiments/
port and packages/tools batches, with a regression; they are never invoked or
claimed tested by initial integration.

CLI remains `native_arm.py integration --inputs-sha256 HASH --recipes-sha256 HASH
--integration-sha256 NEW_REVIEWED_HASH --cache NEW_OR_PINNED_CACHE --output
NEW_NATIVE_EVIDENCE --integration-output NEW_SEPARATE_INTEGRATION_EVIDENCE`.
The accepted checkout must equal GITHUB_SHA; source/cache/native/integration
roots must be disjoint. Coordinator alone regenerates/reviews final freeze,
commits/pushes/dispatches and accepts actual native receipts.


Final bounded re-review reproduced and corrected two more failure-path assertions:
summary publication failure now replaces any aggregate PASS receipt with sanitized
FAIL; committed-image checks reject symlinked ancestors of `/home` and every
private cleanup view. Both have dedicated regressions. Current aggregate remains
210 PASS, no skips, under mocked command/signal boundaries. No known unaddressed
owned implementation blocker remains in this source handoff; actual native guards,
resource limits, signing/expiration, committed-image behavior and full integrated
receipts still require the coordinator's reviewed native execution. No final
freeze was regenerated after the corrective work.


Lifecycle final guard refresh: updated only `test_installed_handoff.py` positive
kernel/device/protected-proc/null/directory-mask fixtures and zero inheritable/
ambient capability observations. The real guard still runs before contract reads;
new negative kernel role/security and null-device identity cases retain the
pre-mutation refusal requirement. No production guard or controller was weakened.
Final current aggregate: 210 CI tests PASS, including 36 handoff tests. Root must
include this refreshed test source in its final freeze after lifecycle ownership
is declared stable. No freeze/dispatch was performed here.

### Run 38200957061 source-snapshot correction

Coordinator-reported actual native run 38200957061 terminated FAIL. Acquisition,
signature verification, exact 341-package bootstrap and all four original recipes
built twice with strict byte comparisons passed. Fixture generation then failed:
the blanket package-evidence exclusion omitted 25 mandatory original recipe-lock
inputs. The copied native integration suite also reported 15 missing-input errors.
The desktop source verifier aborted with exit -6; its terminal output was rejected
by the generic text exporter for control bytes, so the abort cause is unknown.
These failures remain failures; no later stage or hardware acceptance is inferred.

Source correction restores package audit text and every exact reviewed recipe
input, including force-tracked historical logs. Generated package archives and
unlocked ignored logs remain excluded. Missing reviewed inputs fail the scan.
The active platform tree joins the separately owned follow-up exclusions. Freeze
and preflight now generate fixtures from their rehashed copied source tree rather
than the live checkout. The original recipe lock remains unchanged at
`20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.

Actual local copied-tree regression: 151 source files copied, all 25 mandatory
evidence files present, all 125 generated fixture hashes/modes exactly match the
original fixture map, and **116 integration tests PASS** with no skips from that
snapshot. Logs/receipt are `/tmp/cachy-ci-copied-regression-kru4a8g8/`. The focused
controller suite has **37 tests PASS**. This is local source/test evidence; the
corrected native integration has not been dispatched by this worker. Coordinator
retains sole review/refreeze/commit/push/dispatch and run-acceptance ownership.

The desktop correction projects only known terminal `.txt` receipts to escaped
readable public text, accompanied by raw/projected SHA-256 and byte counts. No
raw terminal bytes are copied. The exporter/private-marker rules are unchanged;
the same private-content policy also screens raw and terminal-normalized text
before any public projection or raw hash receipt. Failure/cancellation paths
retain these diagnostics. A fresh owned mode0700 XDG_RUNTIME_DIR is supplied under
the guarded tmpfs HOME. Hyprland verification is still enabled and the original
abort cause remains unknown until a native diagnostic is retained. Final local
CI suite: **226 tests PASS, no skips**, including 37 source-suite and 37 controller
tests; diff whitespace check PASS. An actual local ephemeral freeze followed by
copied-source preflight also passed for the final 151-file source and 125 fixtures,
with the original fixture map unchanged. Its temporary receipt is
`/tmp/cachy-ci-corrected-preflight-73wlhr1u/regression.json`; the shared integration
lock was not edited. No corrected native run, shared refreeze, Git action, host
package/account/key change or physical check was performed by this worker.

### Run 38202483407 lifecycle/export correction

Actual retained run 38202483407 remains **FAIL**. Original four recipes and all
four changed fixtures each built twice and passed byte comparisons; TEST signing
and its nine public exports passed. Native source suites passed all **474 tests,
zero skips**, including the desktop source verifier. Lifecycle itself reports
PASS/all checks PASS/`baseline_handoff_ready=true`; the handoff receipt is READY
with 345 packages. The overall lifecycle stage still failed with ValueError before
committed-config/installed-image/read-side verification receipts, and the exporter
independently rejected eight package inventory maps. Neither component PASS nor
READY establishes an accepted derived image or complete integration result.

Exact exporter diagnosis: the credential-field heuristic matches `secret` at
the end of the legitimate `libsecret` package key followed by a colon. The host
now projects only the eight known inventory paths after strict regular-file,
JSON/schema/token and complete accepted stage-inventory equality checks. It
exports explicit name/version rows, original SHA-256/byte count, and separate
public projection hashes/byte counts. Reinstalled inventory correctly binds the
upgrade fixture versions. Unknown inventory paths and other text still pass the
unchanged generic guard; malformed or unreviewed maps cannot use the projection.

All `verify_commit` assertions replayed successfully from retained public
contracts/signature/archive rows and a reconstructed 345-row lock whose SHA-256
exactly matches the READY receipt. The deleted raw lock metadata and Docker
inspection replies were not recoverable, so the primary runtime refusal remains
unresolved. New fixed refusal codes and operation/Config-field-name diagnostics
will retain that exact distinction without exception text or arbitrary Env
values/hashes. No Docker Config constraint was weakened to guess a cause.

Source-only inventory reconstruction from the actual 341-row native lock and
retained original/upgrade archive rows passed all eight projections through the
unchanged exporter; receipt `/tmp/cachy-ci-inventory-replay-8lohzwnz/regression.json`.
Those bytes are explicitly reconstructed, not recovered original JSON evidence.
The derived-image guard also closes the reported device/socket alias gap with a
bounded ordinary-filesystem metadata scan before contract/query execution; 12
focused verifier tests pass. The new library candidate is excluded alongside
tools from the initial snapshot while its separate maintained-port stage is
active; every original locked recipe/evidence input remains required.

The repository owner's separate cache-directory correction is outside this
worker's edits. No shared lock, Git action, native dispatch, package/account/key
mutation or hardware check was performed for this correction. Coordinator must
review/refreeze the stable combined sources before the next native attempt.

Final local verification: **250 CI tests PASS**, including 42 controller, 13
inventory-projection and 12 derived-verifier tests, with zero skips. An actual
ephemeral freeze and copied-tree preflight passed for 153 source files; all 125
fixture hashes/modes still match the prior original fixture map. Both copied-tree
suites passed: 250 CI tests and 117 integration tests, zero skips. Temporary
receipt/logs: `/tmp/cachy-ci-lifecycle-copied-qjdjv2e9/`. This local test lock is
`a115acf811a40274eb3fd76b7c0029d0f943c114fc9e382a2b297cb481c9de40`;
the shared `be827...` integration lock and original `20d846...` recipe lock remain
unchanged. Corrected native execution and acceptance remain pending coordinator
review/refreeze/dispatch; the primary fourth-run handoff refusal is unresolved.

### Run 38205521065 Config restoration correction

Actual native run 38205521065 remains **FAIL**. Its new diagnostics identify
`lifecycle-config` after image commit, with changed `Cmd`, `Entrypoint` and
`Labels`. Lifecycle component and all eight validated inventory projections
passed; the public lifecycle export passed. Original/fixture builds and TEST
signing passed, and all **499 native source tests passed, zero skips**. No
accepted installed-image or overall integration PASS follows from those results.

The retained runner reports Docker **28.0.4 / API1.48**. Its pinned primary
[commit implementation](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go)
fills an empty requested command from the runtime container when the requested
entrypoint is also empty; a nil entrypoint also inherits runtime execution.
That explains why empty command reset instructions cannot alone establish
restoration. It also materializes an empty Labels map. The exact reset sentinel
`Entrypoint: [""]` avoids the command-inheritance branch, and Docker's
[create implementation](https://github.com/moby/moby/blob/v28.0.4/daemon/create.go)
then clears that exact sentinel for a fresh container.

Actual local metadata-only probe on rootless x86 Docker **29.8.0**, server
API **1.56**, with probe requests pinned to API **1.51**,
reproduced empty-array command inheritance and confirmed sentinel commitment,
empty resulting command and sentinel reset in a new container. An owned empty
tar image, two never-started containers and derived metadata images were used;
no image/container process or ARM program ran, no existing image was changed,
and every owned container/image was deleted with independent absence checks.
Receipt: `/tmp/cachy-config-probe-receipt-4qbp04gs/result.json`. The different
engine/architecture makes this metadata evidence, not native Docker28 acceptance.

The controller now supplies accepted portable Config directly through bounded
local Docker API JSON, with explicit command arrays and the sentinel only for
an empty base entrypoint. It normalizes only that sentinel and null/empty Labels
for semantic comparison. Nonempty labels and all executable commands/entrypoints
still compare exactly; the Env comparison and test-identity rejection are
unchanged. Fresh immutable-image/read-side checks remain required. Unknown
response bodies and Config values are not diagnostic output. Original recipe
inputs and the shared integration lock are unchanged; root owns the next
review/refreeze/commit/dispatch and actual native result acceptance.

Independent review reproduced a derivative-ownership gap after commit response
failure or later Config/fresh-verifier refusal. The correction uses a newly
generated, prechecked private local recovery tag and registers it before the
API POST; valid immutable image IDs are registered before inspection. Failed
verification/cancellation removes only that owned derivative and verifies
image/tag absence, preserving the builder. Ambiguous API outcomes remain FAIL
with `cleanup_uncertain=true`, even if the currently observable tag/image was
removed. A connect interruption closes its unassigned socket before propagation.
HTTP timeout is per socket operation, not a claimed total request deadline.

Successful derivatives now have an explicit controlled lifetime: onboarding,
desktop and any registered same-job consumers run before final owned derivative
removal. Final cleanup is part of authoritative summary acceptance; the summary
is sealed after that removal, and cleanup/callback failure cannot preserve PASS.
No initial consumer exposes an image ID as usable after controller return.
The native entry accepts an internal callable consumer hook while retaining its
unchanged CLI modes, original four-package predicate and pin checks. Separate
future sources under `scripts/ci/development/` are excluded from the initial
scanner, so their future packet can be implemented without disturbing this
correction checkpoint or the 125 original fixture bytes.

Repository semantic projection now validates the exact generated contract before
rewriting `base_versions`: source commit plus nonce, image ID, daemon architecture,
runner script SHA-256 and upgrade kind must match, with no extra/missing binding
fields. The same check precedes repository PASS acceptance. Only the complete
accepted base map becomes explicit package/version rows; all other fields remain
subject to the unchanged generic credential filter. Raw/public hashes and byte
counts bind the projection without rewriting a FAIL status into PASS.

### Stable correction checkpoint (October 12)

Independent read-only review found no material blocker in ownership recovery,
controlled consumer lifetime/final cleanup, cancellation or repository contract
binding. The stable candidate copied-tree preflight binds **157 source files**
and the unchanged **125 fixtures**; **309 CI tests and 119 integration tests PASS**,
zero skips. The ephemeral candidate lock hashes to
`e8fad9905d743c3287fbed9ca4041272e925bc4ba4aab339ecdc4430d05b3dac`;
receipts are `/tmp/cachy-ci-commit-copied-vaa94f6c/{regression.json,ci-tests.txt,integration-tests.txt}`.
The shared initial lock remains
`a115acf811a40274eb3fd76b7c0029d0f943c114fc9e382a2b297cb481c9de40`,
and the original recipe lock remains
`20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.
Coordinator must independently review, commit, freeze and schedule the next
native run. This checkpoint is local source readiness; run 38205521065 remains
FAIL and Docker 28.0.4 ARM execution of the correction remains NOT RUN.

The initial source is held stable while a separate future development packet is
implemented under its excluded `scripts/ci/development/` directory and separate
workflow. No initial fixture, four-package predicate or generic credential
policy is widened. Consumer callbacks must record failed outcomes or raise; a
false return value alone does not fail the initial aggregate.

Coordinator checkpoint: independently repeated all 309 CI/119 integration tests
from `/tmp/cachy-asahi-r6-copied-qvi3gme7/source`, zero skips, and matched all 125
fixture bytes/modes. The shared initial lock is now explicitly refreshed to
`e8fad9905d743c3287fbed9ca4041272e925bc4ba4aab339ecdc4430d05b3dac`;
the former `a115...` bytes are preserved with the historical fifth-run evidence.
The original recipe/input locks remain unchanged. Independent focused ownership,
Config and repository-binding review passed 150 checks at the exact source hashes
recorded in `docs/reviews/commit-image-review.md`. Actual native rerun is pending;
none of these copied-source checks changes the fifth run's FAIL.

### Seventh-trial source checkpoint (October 12)

Run **38212287407 remains FAIL**. Its actual retained evidence passes all 560
native source tests without skips, installed 345-package lifecycle/Config/fresh
read-side verification and final owned image absence, plus software onboarding.
The desktop component says `desktop-container-verifier-pass`; publication alone
rejects `desktop/command-19.txt` and `desktop/command-20.txt` for ANSI control
bytes. Repository positive signing/metadata phases now pass; its separate owner
corrects mixed pacman diagnostics in the untrusted negative snapshot. These
results do not pass the aggregate, M2/16K/hardware or full-port gates.

The narrow desktop publication helper validates the complete known receipt,
externally supplied image/nonce/archive/runtime-lock/source authority, exact
22-command vector and complete log bytes against recorded stdout/SHA256. It
projects only the two bound Hyprland verifier SGR presentation logs into plain
UTF-8. Unknown logs, other controls, malformed/changed receipts and credential
markers remain refused under the unchanged generic policy. The original
receipt and acceptance flags remain unchanged. Before export, the controller
rechecks the receipt through a guarded read against the validated SHA/byte count;
the after-projection hardware-PASS replacement regression is refused. Source
commit in the projection index is caller authority, not an intrinsic assertion
in the desktop receipt.

Held source: `integration.py`
`3633427707da0f93f9f3900cc1036596815f85000bf53e7ea2c6fbd22bbb3be2`;
`test_integration.py`
`dde5c23742fe8a06d753adc54402e4956c31e74f482d87f55d28b3d8bebdca56`;
`desktop_projection.py`
`d2eab5230e2979e3cb9a39cd985c84018c5d38f430ed9c923e0577d3672d9203`;
`test_desktop_projection.py`
`4871d91ecec77cfb38ec2f1350d4b7a33689186c46017161528156400b44ae48`.
`native_arm.py` is unchanged at `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.

**331 CI and 125 integration tests PASS**, no skips, both in the worktree and
copied source. The ephemeral initial candidate hashes to
`be5363dfb9f11b39f42fc419bebaa9cbaa11780fce1aa5cde2cedc25629766bb`,
binds **159 sources/unchanged 125 fixtures**, and copied preflight passes. Receipt
and logs: `/tmp/cachy-desktop-copied-g_ui08ll/{regression.json,ci-tests.txt,integration-tests.txt}`.
No shared lock/Git/dispatch was mutated by this worker; coordinator owns the
seventh native freeze and actual execution. The publication correction has only
local replay/source-test acceptance here.

## Repository private-root ldconfig launcher correction

The release owner source-audited pacman `7.1.0.r9.g54d9411` at commit
`54d94116164b0b2202c6061c4a59c6f3e70820d8`: its built-in private-root ldconfig
runs after commit and can emit errors while the transaction still returns zero.
The owner separately implemented exact six-cap observations, positive ancillary
error rejection and the bound missing-database-signature case. That source audit
and the seventh-run inventory changes do not establish error-free native execution.

The CI launcher now has a fixed boolean `repository_ldconfig` option requiring
root, the exact repository nonce-name shape and default root capabilities. Only
`Controller.repository()` opts in. It adds exactly `SYS_CHROOT`; the existing
rootcaps interface still refuses that capability, lifecycle retains its separate
KILL opt-in, and all other launch capabilities, read-only/network/NNP/cgroup/mount
and resource limits remain as before. No arbitrary extra-capability parameter was
introduced. Three new regressions cover the added argument, refusal boundaries
and the actual repository launch against the owner's exact `0x400cb` guard.

Worktree suites pass **334 CI/137 integration tests, zero skips**. A bounded
independent reviewer found no material defect and passed all six focused
capability/launch tests. Reviewed CI source hashes are:

| File | SHA-256 |
| --- | --- |
| `scripts/ci/integration.py` | `cb6145d94e1b384d2fedc459fbc4b94fe6a53bcb0834d0e90c2ab5a56dd61eb1` |
| `scripts/ci/test_integration.py` | `62fa9a3843721ccd63fa7b9a4a577cefc1df8db80984255ed4d57b0b2ab046de` |

The owned ephemeral candidate at
`/tmp/cachy-repository-chroot-copied-atuj7npt/integration.lock.json` hashes to
`9cfbd847bd2969aadf700b1ebb9943680b064b0ec6570726cdd9389aa31db0bb`.
Actual freeze/snapshot/copied preflight passed with **159 source files and the
exact unchanged 125 generated fixture records**. Only the launcher/tests and
release owner's repository/tests differ from the historical `be5363` map.
Coordinator adoption, committed Git/fresh-checkout proof, development packet
rebind and corrected native execution remain pending. This worker wrote no shared
lock, Git state or dispatch and made no Docker/host package/trust mutation.

Copied suites also passed **334 CI/137 integration tests, zero skips**. The final
receipt is `/tmp/cachy-repository-chroot-copied-atuj7npt/regression.json`. A final
read confirmed all 159 selected worktree bytes/modes match the ephemeral candidate.
The corrected CI launcher and tests are **HELD at the reviewed hashes above**
for coordinator adoption and the subsequent combined packet rebind.

Coordinator adoption: root independently regenerated the same `9cfbd847...`
159-source/125-fixture lock and checked every current selected byte and mode.
Root repeated the full **334 CI / 137 integration tests**, zero skips; the real
temporary GPG fixture required the permitted local socket environment. The
[independent launch/diagnostic review](../reviews/repository-chroot-review.md)
passed 26 focused tests, 320 single-bit capability deviations, NNP rejection and
replays of the retained actual positive/missing-signature diagnostics.
The shared initial lock is now adopted. Commit/fresh-checkout proof and the
corrected actual native trial follow separately. The broader packet remains
historical until its client, virtual and ARM-C01 corrections are jointly frozen;
it is not needed to execute the corrected original integration alone.
