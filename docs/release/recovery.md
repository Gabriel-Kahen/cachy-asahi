# Release recovery and signing policy

Status: **source-audited policy, October 11, 2026**. Operator procedures, public trust bootstrap, installation, upgrades, key rotation/revocation distribution, and boot/session recovery are **NOT RUN**. No production identity, permanent signing key, published endpoint, or supported M2 recovery path is established by this document. The coordinator selected the root MIT license for original project material; upstream license audits and all build/hardware gates remain required.

This is the operational contract for the local release workstream. The implemented local repository CLI and exact evidence schema are documented in [the release interface](interface.md). Research and repository tools must not install packages, alter the host pacman configuration/keyring, repair a running machine, distribute trust, or publish/upload artifacts. Only an explicit caller-supplied signing identity may sign local artifacts; private key custody stays outside the checkout and build execution.

## Evidence required before stable use

Release approval requires linked records bound to the exact release ID, package hashes, base repository snapshot, and machine/version set. A signature proves the authorized key signed particular bytes; it does not establish package safety, dependency compatibility, reproducibility, or M2 functionality.

The release record must include:

- Reviewed source pins, source verification, upstream licenses/notices, project license, dependencies, contents, file ownership, configuration behavior, and install/remove hooks for the complete selected package set.
- Native aarch64 clean-build logs and pinned toolchain/transitive inputs; a second independent clean-build comparison with any reproducibility limits stated.
- A compatible full base/overlay package set and transaction review, including conflicts, replacements, versioned dependencies/provides, and protected Asahi components.
- Exact supported-machine functional, install/remove/reinstall, previous-release upgrade, interrupted/failed upgrade, and boot/session recovery results. Record M2 Air 13-inch and 15-inch independently; a limited release may name only the size actually validated.
- Named ongoing release/custody/recovery owners, reviewer signoff, retained recovery bundle, release notes, and a tested trust-bootstrap/update path.

Missing, FAIL, or NOT RUN evidence blocks stable promotion. An emergency label or a boolean approval cannot bypass these requirements. Synthetic local tests establish only the tooling behavior exercised by those fixtures.

## Retention and compatible updates

Keep immutable release bundles separate from mutable staging/stable selections. As a minimum policy, retain the current release, two preceding accepted releases, every release still advertised as an upgrade starting point, and all incident-related releases until the incident and retention review close. Capacity shortages block a new promotion rather than silently deleting the only recovery set. Quarantine unsafe artifacts from installable selections while preserving restricted forensic copies.

Each bundle retains package archives and detached signatures, repository database/file-list archives and signatures, release manifest/checksums, public verification material and signer fingerprints, provenance/logs/reviews, acceptance evidence, configuration migration/removal records, and the tested recovery instructions. Retain or identify retrievable, verified base packages/repository snapshots needed for the tested compatible set; overlay archives alone cannot restore a previous base ABI. The local package cache is an additional convenience, not the retention archive.

Repository database removal hides an entry; it does not uninstall a deployed package. `repo-add` can also delete old package files when its removal option is used. Recovery archives must therefore be independent of routine repository maintenance. [Upstream repo-add manual](https://man.archlinux.org/man/repo-add.8.en)

Evaluate base and overlay together for each normal upgrade. Record the complete installed baseline and candidate transaction, repository precedence, protected kernel/firmware/graphics/audio/boot packages, ABI requirements, and all changed hooks/configuration. Repository ordering can select an overlay package with the same name ahead of a base package regardless of version; reject unintended shadowing. [Upstream pacman.conf manual](https://man.archlinux.org/man/pacman.conf.5.en)

Use the upstream-supported full-system upgrade model against the tested repository combination. Do not prescribe refresh-then-selective upgrades, dependency-check bypasses, broad file-overwrite bypasses, or permanent package holds as compatibility fixes. Pacman resolves transaction dependencies; that does not prove runtime ABI or hardware compatibility. Its full upgrade mode and optional downgrade mode have different behavior, so switching repository selections alone is not a rollback. [Upstream pacman manual](https://man.archlinux.org/man/pacman.8.en)

If an upstream base update invalidates the accepted overlay, pause affected promotion, reproduce the incompatibility, and prepare a compatible overlay or tested overlay-removal path with the full base update. A temporary deferral must name an owner, deadline, security exposure, and exit condition. Do not promise that a historical base snapshot is safe indefinitely or require users to construct an untested partial upgrade.

## Signing custody and planned rotation

The following are project policy proposals, not established key infrastructure:

1. Assign a human release custodian and alternate, with a separately named reviewer. Agents and transient CI workers are not ongoing custodians. Document access, expiry monitoring, incident authority, and recovery coverage without recording secrets.
2. Keep a certification-capable primary key offline and use a bounded signing subkey on a separate signing workstation or hardware token. Keep private material, agent sockets, passphrases, and revocation certificates out of build containers, agent environments, CI artifacts, repositories, and release bundles. Maintain encrypted offline backups and test restoration privately.
3. Sign only frozen reviewed hashes in a controlled promotion workspace. Record both primary and signing-subkey fingerprints, key validity, signing command/tool version, artifact hashes, reviewer, and result. Reject default-key fallback or unexpected signer selection. Verification must check the authorized fingerprint and validity as well as cryptographic success.
4. Before first public use, privately test backup/recovery and prepare a primary-key revocation certificate. GnuPG distinguishes creating this certificate from importing it to revoke the key; publishing updated public material is a further operation. GnuPG also supports signing subkeys and expiry changes. [GnuPG key management](https://gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html)
5. Schedule rotation before expiry. Prepare replacement public material outside the project checkout, independently verify fingerprints, review custody, and test verification on a disposable keyring. If only a subkey rotates, distribute the updated primary certificate containing its new binding. If the primary identity changes, authenticate that transition through the established trust channel; an old-key signature is useful only while that key remains trustworthy.
6. Exercise migration from every supported starting release, then distribute the authenticated public-key/keyring update before requiring the new signer. Keep a documented overlap window and retire the prior signer after migration. Retained packages requiring fresh signatures must be independently checked before re-signing; signatures and release records remain versioned rather than overwriting forensic evidence.

GnuPG's secret-subkey export supports keeping the primary secret off the signing machine, but exports remain secret material and require protected transport. This feature is not evidence that the proposed custody boundary has been established. [GnuPG operational commands](https://gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html)

## Public trust bootstrap and revocation

Public trust distribution is a future human-operated release activity. Publish full fingerprints and key material through the established authenticated channels, with independent fingerprint confirmation, release identity, intended use, validity, and update/revocation procedure. Merely downloading a key from the same potentially compromised repository does not independently authenticate it. Never locally trust a key because its user ID resembles the project name.

Require both package and database signatures and trusted authorized keys for the eventual project repository; verify the effective configuration, including overrides. Optional signature policy accepts unsigned objects. A local signature test in an isolated GPG home does not test pacman trust bootstrap. [Upstream pacman.conf signature policy](https://man.archlinux.org/man/pacman.conf.5.en)

For suspected compromise, immediately stop signing/promotion and restrict affected selections. Preserve logs, key-state snapshots, signed artifacts, and the estimated exposure interval. The custodian and reviewer determine primary versus subkey scope, then revoke the affected material using the controlled custody environment. Authenticate replacement trust independently of a compromised key. Public incident notices, keyring updates, mirror changes, and user contact are operator actions outside local tooling.

Distribute updated revoked public certificates and, if an audited project keyring package is eventually adopted, its revoked-key list. Pacman keyring import and trust are distinct operations; its revoked list disables a key regardless of other trusted state. Pacman signature policy rejects revoked keys. Test actual client convergence and failure behavior; possession of a revocation certificate does not update client keyrings. [Upstream pacman-key manual](https://man.archlinux.org/man/pacman-key.8.en), [pacman.conf signature policy](https://man.archlinux.org/man/pacman.conf.5.en)

Retained packages signed only by an affected revoked key may become unusable under required verification. Do not disable signatures to recover them. Re-audit/rebuild or independently establish trustworthy bytes, then issue replacement signatures with an independently authenticated safe identity and a new reviewed release record. Preserve the old artifacts as incident evidence. An expired-key incident likewise needs a tested authenticated key update or replacement path.

## Emergency withdrawal

1. Freeze stable promotion and record the incident ID, affected releases/hashes, signer status, symptoms, severity, and exact machines/base sets. Keep known-good retained bundles available for investigation.
2. Remove the unsafe candidate from the installable selection or suspend that selection if no compatible safe set exists. Create and verify replacement signed metadata in a new local revision; preserve the previous metadata and all incident records. Future endpoint deployment must switch a complete verified selection consistently, rather than exposing mixed databases/packages.
3. Specify separate remedies for users who have not upgraded, have cached the candidate, already installed it, or cannot start a session/boot. Repository withdrawal does not reverse an installed transaction. Require a tested fix-forward, complete compatible downgrade, or proven system restoration path for each supported state.
4. For a package regression with a trustworthy signer, prefer a reviewed fixed release that follows normal version ordering. A previous release selected as recovery still needs compatibility evidence for the machine's current base. For a trust incident, follow revocation/replacement first; do not re-sign unchecked artifacts.
5. The operator issues an authenticated advisory with affected hashes, required actions, safe release, and limitations through the established channels. No automatic user contact or public distribution occurs in local scripts.
6. Reopen stable only after independent review, affected lifecycle/recovery tests, required functional checks, and a linked incident resolution. Record an unresolved state plainly when safe recovery is unavailable.

Signed old metadata may still verify cryptographically. Release IDs and withdrawn-release records help local tooling reject stale selections, but pacman signatures alone do not establish freshness or retract cached installed packages. A public anti-replay/update-state design and client test remain required before promising that protection.

## Exact-machine recovery exercise

Before deliberate failures, the hardware owner records machine size/model, full package/configuration baseline, storage/boot arrangement, free space, user-data backup, release hashes, and an independently verified way to regain access using the chosen Asahi base. Validate recovery entry and backup restoration before causing a failure. Preserve the working Asahi boot/firmware/kernel/graphics/audio stack; no PC bootloader, generic live media, partition rewriting, or another Mac's rescue instructions are assumed.

For each case below, retain the pre-state, exact action/commands, observed failure, recovery actions, logs, restored package/base set, configuration/user-data checks, and post-recovery functional baseline. Reserve one system-changing job per machine.

| Case | Required observed outcome | Current result |
| --- | --- | --- |
| Candidate upgrade from previous accepted release | Complete compatible base/overlay transaction and functional baseline | NOT RUN |
| Interrupted download | Safe retry with verified complete artifacts | NOT RUN |
| Controlled transaction interruption | Determine actual database/files/hook state; restore consistency and function | NOT RUN |
| Session/service failure | Regain access through verified fallback; restore package/configuration state | NOT RUN |
| Compatible retained-release recovery | Restore the complete tested set and preserved user changes | NOT RUN |
| Boot failure | Enter actual Asahi recovery path and restore a usable machine | NOT RUN |
| Signing rotation/revocation | Authenticated trust transition; reject invalid signer without verification bypass | NOT RUN |
| Independent onboarding and recovery | Another operator follows the documented path successfully | NOT RUN |

Do not assume a failed transaction is atomic. Inspect installed package metadata, files, hooks/services, pending configuration merges, and pacman logs before selecting repairs. A database-only edit is not restoration of package files. Pacman provides consistency/file checks and preserves designated configuration changes through `.pacnew`/`.pacsave` behavior, but package-owned and user-owned configuration still require the recipe-specific lifecycle review. [Upstream pacman manual](https://man.archlinux.org/man/pacman.8.en)

Snapshot existence, a successful repository verification, or an emulated rollback cannot satisfy boot recovery. Restore package database, filesystem, configuration, and platform state coherently; restore user data separately where needed. Stop and record a blocker if retained inputs, authenticated trust, access, or a compatible full transaction are missing. Exact commands must be published from the successful hardware exercise, not filled in from generic Linux assumptions.
