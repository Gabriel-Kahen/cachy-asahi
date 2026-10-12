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
