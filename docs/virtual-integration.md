# Nonphysical development and acceptance

Active goal: continue implementation and meaningful software validation until
remaining progress genuinely requires physical-machine access. This is a finite
software integration batch, not a substitute for the full outline's machine gates.

Coordinator owns branch `codex/virtual-integration`, Git integration, workflow
dispatch, shared manifests and final execution records. Six existing GPT 6.1 Sol /
high chats have distinct source ownership. No worker changes another's files or
shared manifests; failures become owned corrective work and relevant rechecks.

| Gate | Owner / source | Required actual evidence | Current state |
| --- | --- | --- | --- |
| V01 Reviewed derivative upgrades | Tools / `scripts/integration/fixtures.py` | Deterministic new recipes, original/derivative pins, retained diffs, changed payload and version for each package; native build provenance | IN PROGRESS |
| V02 Host mutation prevention | Each runner; independent review | Refusal before writes/commands outside its exact disposable contract, bounded subprocess cleanup, no real HOME/accounts/keyrings/devices/sockets | IN PROGRESS |
| V03 Installed package lifecycle | Build / `scripts/integration/lifecycle.py` | Strict signed pacman install, fresh/existing users, setup/repeat/interruption/recovery, changed-package upgrade, removal/reinstall, preserved user bytes/modes and base inventory | IN PROGRESS |
| V04 Repository/trust transactions | Release / `scripts/integration/repository.py` | Signed package/database verification, real install/full upgrade/rollback, tamper/missing-signature rejection, ephemeral test-key rotation/revocation; private keys excluded from evidence | IN PROGRESS |
| V05 Desktop software checks | Desktop / `scripts/integration/desktop.py` | Installed template ownership/bytes and actual native parser checks; bounded software/headless runtime if supported by audited stack, limitations recorded | IN PROGRESS |
| V06 Fresh-user development journey | Onboarding / `scripts/integration/onboarding.py` | Verified installed immutable image, original payload hashes, fresh nonroot PTY/shell/setup/editor/compiler/run/removal journey with commands and diagnostics | IN PROGRESS |
| V07 Native source tests | CI | Existing helper, release and tooling tests execute in locked native ARM userspace with actual interpreters/Arch tools; skips visibly retain their unmet coverage | IN PROGRESS |
| V08 Integrated evidence retention | CI / `scripts/ci/` | Source/recipe/input locks, native runner provenance, actual commands/status/archive hashes, sanitized bounded bundles, retained failure diagnostics and original inputs | IN PROGRESS |
| V09 Independent integration review | Independent reviewer | Reproduced material defects resolved, actual native results checked against locks/artifacts, no physical/stable claims inferred | IN PROGRESS |

## Separate disposable execution stages

Lifecycle tests need a writable, disposable container root for real pacman and
account operations. Repository tests propose a read-only container root and a
separate copied client root/database/cache/keyring under private scratch. The
onboarding and desktop journeys use a verified installed immutable image and a
fresh nonroot, read-only-root container. These are distinct contracts: the CI
adapter must supply each runner's exact paths, mount/security flags, input schema
and source hashes. One blanket container policy is insufficient.

Before committing an installed image, verify every overlay version and installed
payload hash against the intended original archives, preserve the frozen base
inventory, and remove test signing material/user fixtures. Bind the handoff to
its actual image ID, install receipts and complete inventory. Ownership alone
cannot prove an executable was unchanged.

All package installs, trust imports, system account changes and test client roots
stay inside explicitly guarded disposable containers. No host home, package
manager database/keyring, display/audio socket, GPU device or Docker socket is
mounted into the integration runners. Host orchestration invokes Docker only;
research/build scripts do not install packages on the host. Fixture GPG identities
are labeled TEST ONLY, expire quickly, have no production custody, and private
homes/keys/sockets never enter output bundles.

## Evidence limits

The existing generic signed ALARM builder contains native ARM tools and software;
it is not the actual Asahi target snapshot. Original archives are real development
packages. Modified upgrade fixtures are test derivatives and cannot be selected
for a supported release. VM software PASS does not pass Apple GPU acceleration,
firmware/boot, speakers/protection, battery/thermals, lid sleep/wake, 16K runtime,
macOS partitioning or either exact M2 model. Full stable promotion, complete
onboarding, performance reports and later maintenance remain separate gates.

No performance experiment runs without a bounded frozen plan, and no optimization
is added merely to create activity. After V01–V09, reassess the outline for remaining
nonphysical work rather than assuming that any absent Mac stops development.

## Next bounded software work

After the initial integrated run, two additional outline gaps can still advance
without a Mac: release-client freshness/anti-rollback verification, and a generic
QEMU guest compositor proof. The former is an offline metadata/state prototype
with caller-pinned verification keys and explicit fixture scope; it installs no
packages and cannot bypass stable gates. The latter has a source-audited generic
virtio/DRM/Mesa route, an isolated signed tooling extension and one bounded
20-minute trial; guest boot/compositor/frame acceptance still requires actual
execution. Neither is an Apple hardware emulator or M2 support evidence.

The authoritative scope update `506f259` makes the complete ARM port (R1–R5,
M5–M9) required. These gates provide infrastructure for that destination, not
the stopping scope of development. Parallel coverage, applicable-tool,
installation-route and native-experiment work is assigned in
`docs/orchestration.md`. Broader reviewed package implementation follows those
audits without waiting for unavailable target hardware; target-only acceptance
continues to require each exact machine.
