# Seventh native run independent evidence review

Run **38214941784**, source
`81aabca9a9657a74deb3780430bd55dd3deabc6f`, October 12, 2026.
**Aggregate integration remains FAIL.** Lifecycle, installed software onboarding,
desktop execution/publication and source suites passed. The repository records
eight passing cases, then fails its ninth case's diagnostic classifier before
the required after-snapshot. Complete repository acceptance remains FAIL.

Read the current roadmap and package inventories first. This review parses and
hashes retained evidence and reads frozen source only. No Docker/native rerun,
package/system operation, source/shared-lock, workflow or Git mutation occurred.
No hardware, headless guest, full independent onboarding, performance, release
or R1–R5 acceptance follows from these generic ARM software checks.

## Independent retained-byte and provenance checks

Reviewed `artifacts/ci/38214941784/decoded`. The coordinator's strict decoding and
workflow-marker authentication are input provenance; this review did not repeat
remote marker attestation. Independently compared **877 regular members in 12
compressed bundles** with their decoded bytes and verified **585 accepted public
export entries** against exact sizes/SHA-256. All matched.

The frozen initial integration-lock hash independently matches
`be5363dfb9f11b39f42fc419bebaa9cbaa11780fce1aa5cde2cedc25629766bb`:
159 source files and 125 generated fixture files. Frozen repository runner hash
`72a604cf7ed99f9711755ef318ce9ce62af263006918c3a03d69c906830c5173`
matches the retained source/image/nonce/daemon/synthetic-upgrade contract.
Recorded execution is an aarch64 hosted ARM VM/container with 4K pages, not M2
or 16K-page execution or independent physical attestation.

## Fresh installed image and final owned cleanup

The generic builder is
`sha256:532f0c818f1e6a1279ae8a8d752800c6969c6164082459a4843b3d84465dc69a`;
the accepted derivative during this job is
`sha256:1395edb2c7cf7a5a2a01bb4ba259fda67eadbd09d65c21dfbe6c0fd624a6eb47`.

Rechecked the exact **341 base plus four original packages = 345** inventory,
READY/installed/fresh/onboarding lock hash equality, base/READY receipt bindings,
and all 18 original payload hashes across READY, fresh verification and installed
onboarding. Original archive hashes/versions agree between fresh verification
and onboarding. READY has 347 PASS checks, including underlying tmp emptiness
and private-state cleanup; fresh read-only verification reports PASS.

Accepted and derived semantic Config are identical: USER `alarm`, WORKDIR `/tmp`,
empty executable arrays and Labels, exact base PATH Env, and no lifecycle test
identity. The receipt is canonicalized, rather than a raw daemon Config dump.
The installed image ID is identical throughout fresh verification, onboarding,
desktop authority and final cleanup. Private recovery ownership is recorded,
the handoff container's absence is verified, and the final summary records owned
image cleanup PASS with verified absence and no uncertain outcome. Intermediate
RETAINED status denotes its lifetime through consumers; the image was deleted
before controller return and cannot be reused across jobs. Parent-layer erasure
is not claimed.

## Installed software onboarding

Matching inner/outer contracts report **SOFTWARE PASS** on that installed image.
All 13 journey commands exit zero: setup preview/apply/repeat, software terminal,
Fish/Zsh startup, scripted Vim edit, compiler version, compile/execute hello,
removal and subsequent shell startup. Setup's 40 and release's 19 tests have no
errors, failures or skips. The inner receipt records aarch64, nonroot UID/GID1001,
cap0, loopback-only networking, a read-only root and matching original payloads.

This is an automated software PTY and noninteractive Vim/compile journey.
Full independent contributor onboarding, GUI/editor usability, actual target
installation and hardware remain NOT RUN; no performance comparison occurred.

## Desktop raw verifier and corrected publication

Raw `desktop.json` reports `desktop-container-verifier-pass` for installed
inventory/payload, Lua syntax, native Hyprland default/optional config checks,
Waybar JSON syntax, display-free GTK3 CSS parsing and the audited Mako subset.
The component, public exporter, control stage and final desktop stage now all
report PASS.

Independently checked the projection's receipt hash/size and both complete raw
stdout hashes, then compared the actual public logs with removal of precisely
numeric/semicolon SGR sequences. Command19 is 385 raw/341 public bytes; command20
is 402 raw/358 public bytes. Both public hashes/sizes agree with the projection
index, with no residual ESC bytes. No unrelated log or result flag was rewritten.
The public index's source is external accepted controller authority; the legacy
producer receipt itself does not echo a source-commit field.

Hardware, graphics acceleration, portal/audio/session and optimization remain
NOT RUN. Headless compositor is BLOCKED/not attempted because DRM is excluded;
Waybar/Mako applications are not installed and were not run. Successful parser
verification and publication do not establish a compositor session or frame.

## Eight recorded repository case passes, with explicit bounds

The copied-root repository has a separate scope: **341 base plus four originals
and one synthetic repository fixture = 346 packages** after installation. It is
not the four-package 345 installed image. Independently checked all eight
before/after snapshots against every unchanged base version and all 19 tracked
payload paths. The eight retained case records are:

| Case | Recorded result and independently checked state |
| --- | --- |
| Untrusted signer A | PASS; nonzero transaction, identical 341-row inventory/payload snapshot |
| Trusted baseline full install | PASS; exit zero, complete baseline four plus fixture1 installed |
| Untrusted rotation to B | PASS; nonzero transaction, complete baseline snapshot unchanged |
| Trusted full upgrade to B | PASS; exit zero, all four changed derivatives and fixture2 installed |
| Full rollback to retained A | PASS; exit zero, entire after-snapshot equals the original successful baseline installation snapshot |
| Tampered package signature | PASS; nonzero transaction and unchanged baseline snapshot |
| Tampered database signature | PASS; nonzero transaction and unchanged baseline snapshot |
| Missing package signature | PASS; nonzero transaction and unchanged baseline snapshot |

Rechecked **26 hash-bound successful package/database GPG status logs**: exit
zero and exactly one complete VALIDSIG matching the appropriate TEST signer A
or B primary fingerprint. Direct negative GPG receipts record NO_PUBKEY for A
and BADSIG for the tampered package/database, with nonzero exits and matching
hashes. Pacman rejection diagnostics and all five negative after-snapshots agree
with those recorded case outcomes. This is independent inspection of executed
cryptographic receipts, not a fresh GPG verification of deleted repository
binaries or production key/trust acceptance.

**Ancillary execution bound:** trusted positive logs112/126/134 exit zero and
their full inventory/payload transitions are confirmed, but each ends with
`could not change the root directory (Operation not permitted)` and
`error: command failed to execute correctly`. The frozen fixture disables
scriptlets and masks installed hooks. The log does not identify the exact
ancillary command behind this chroot diagnostic. Do not describe these positive
cases as error-free transactions, successful ancillary execution or complete
hook/cache behavior on a target system. The diagnostics remain visible and were
reported to the coordinator.

## Ninth missing database signature case remains FAIL

Command175 exits 1 and records a literal local retrieval error for missing
`/scratch/repos/active/integration.db.sig`, followed by failure to synchronize
databases. The producer classifier raises
`missing-database-signature-rejected: failure lacks signature/trust diagnostic`.
There is a before-snapshot and **no after-snapshot**, and no ninth PASS record.

The observed error identifies the expected missing signature path but does not
retrospectively complete the case's state-invariance check. Full repository
acceptance, subsequent revocation/final-upgrade cases and stable promotion remain
unpassed. TEST private state removal is recorded and the repository container's
absence is verified. Production trust and publication remain NOT RUN.

## Builds, suites and aggregate result

The coordinator's `root-build-verification.json` reports PASS for all four
retained original archive pairs, with complete bytes, payloads, PKGINFO and
BUILDINFO equal. This review reads that comparison result; it does not repeat
its execution or a native build. Distinct recorded containers are not independent
machine attestation.

Independently summed actual source-suite receipts: **588 tests, zero skips, all
PASS**, including 331 CI and 125 integration tests. The overall summary remains
FAIL because the repository stage failed. No discrepancy was found in checked
byte, inventory, payload, Config, projection, source or image chains. The missing
after-snapshot and ancillary chroot diagnostics are explicit evidence bounds.

| Key retained receipt | SHA-256 |
| --- | --- |
| `summary/result.json` | `6256fd8033c6799f165960dd3a9d45ba390ef1043595d172c3c5bd895f415ccc` |
| `lifecycle/committed-image/result.json` | `6ef65d815c390b346f2f9fc19d710aa8d332d047f27cc8438b1c892282dfa0f6` |
| `onboarding/artifacts/result.json` | `fedee86ef28c88677880ee23cc56f25cac7dc18556901a1880e59af9fb698717` |
| `desktop/desktop/desktop.json` | `8036999cce46cad31d163a749b14547fdfd4476bd365ac4535ff2549316e20c1` |
| `desktop/desktop-terminal-projections.json` | `d9f0579a118a0b9ce63858ae3e3e995a64440d89b127d219378c57752c5cba3f` |
| `repository/result.json` | `570a8c089f6d2a2ba91beb96b592de5374243e6624ae2a62615ee4f1bea5b34c` |
| `source-suites/result.json` | `c2170f3f8711bf2deee28e08ebd723124bd130ae3700f97ea9f6a4d674e89bed` |
