# Release workstream

Status: **implemented and locally tested with synthetic fixtures** on October 11, 2026. No native ARM build, installation, M2 acceptance, actual stable overlay promotion, trust bootstrap, public repository publication, key distribution or hardware recovery has occurred. M3 is incomplete.

## Delivered within exclusive ownership

- `scripts/release/release.py`: self-contained stdlib CLI for signed local staging, checksum/provenance/dependency verification, evidence-gated local stable selection, retention and withdrawal. Explicit externally supplied full fingerprint/GPG home; no key generation/import, default-key fallback, pacman/config mutation, installation, network access or publishing.
- `scripts/release/test_release.py`: 19 tests using temporary synthetic archives and ephemeral GPG homes. Keys explicitly identify synthetic tests, expire after one day and are deleted along with artifacts; only each test home's agents are stopped. One test mocks gates to test atomic selection mechanics; modeled complete gate-schema tests alter only in-memory fixture flags, never the signed synthetic bundle or actual promotion policy.
- `docs/release/interface.md`: exact CLI, storage, input schemas, raw build bindings, machine checks, blocked cases, integration proposals and primary upstream references.
- `docs/release/recovery.md`: source-audited retention, full base/overlay upgrade, withdrawal, key custody/rotation/revocation and physical recovery policy. Operational steps are explicitly NOT RUN.

All new original scripts carry MIT SPDX headers. Root project LICENSE was selected by the coordinator; observed SHA-256: `51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7`. Each real release must retain and checksum the license actually applicable to its source commit. This does not resolve upstream package license gaps.

## Actual validation

Host: x86_64 Linux, Python 3.14.7; installed repo-add/pacman 7.1.0, GnuPG 2.4.9, libarchive/bsdtar 3.8.9 and vercmp. No host package installation or upstream code download was needed. Project scripts require Python 3.11+.

Commands executed:

```sh
python3 scripts/release/release.py --help
python3 -m py_compile scripts/release/release.py scripts/release/test_release.py
python3 scripts/release/test_release.py
git diff --check -- scripts/release docs/release docs/workstreams/release.md
```

Result: **19 tests passed in 1.654 seconds**, compilation passed, CLI help passed. Whitespace check passed; these new files are untracked until coordinator Git integration, so that command alone is not a complete tracked-diff review. The suite exercises the actual CLI's staging, verification and withdrawal; real package and repository signing/signature checking; checksum/signature/symlink tampering; full fingerprints; expiry and revocation; dependency epochs/versioned/unversioned provides; conflicts/ownership/protected scope; missing/synthetic promotion gates; modeled raw build and exact-machine schema; matching one machine/version record; retained withdrawal and frozen gate-object activation mechanics. Fixtures are explicitly synthetic and are not ARM or M2 evidence.

Independent bounded review found and fixed: ordinary repo-add symlink validation, GnuPG expired-key success-status acceptance, storage symlink escape, rereading unchecked gate data during promotion, nested manifest filenames omitted from hashes, noncanonical ownership collisions, and machine-record/version inconsistency across lifecycle gates. Real ephemeral-key tests reproduce expired `EXPKEYSIG` and revoked-key rejection. Verification rejects unacceptable key/signature status even when GnuPG exits zero; signing immediately verifies its own result.

## Stable gates and interfaces

Promotion requires a signed, checksum-frozen artifact set, resolved project license, pinned sources, named release/custody/recovery owners, independent package review, **two native aarch64 clean-build records**, retained logs/recipe inputs/dependency locks, byte-identical second archives, and exact advertised M2 Air functional/install-removal/upgrade-recovery records with raw evidence. Every gate is bound to release ID, signed release digest, source commit, base inventory, license and complete artifact checksum map. A boolean or synthetic record cannot promote.

Raw build integration uses the current `scripts/build/build.py` output without editing build-owned files: `provenance.json` must report native execution and static success; image, clean environment, exit status, command, artifact set, recipe input hashes, every generated file and original package lock are bound back to retained evidence. Release assembly adds explicit path-to-evidence mappings and checksum/retention augmentation for the transitive dependency lock. Reproducibility is currently stricter than the build comparator's content-only success; use its `--require-bytes` mode. Documented content-only exceptions require future reviewed schema/tooling, not a silent bypass.

The base inventory is the complete intended installed transaction plus dependency closure, rather than a bag of alternative repository packages. The checker resolves versioned virtual providers through installed vercmp, checks all effective runtime dependencies/conflicts and canonical file ownership, rejects protected platform replacements, and requires exact coordinated compatibility versions. This is a conservative static check, not a replacement for libalpm transaction execution or ABI/hardware tests. Raw logs and reviewers remain trusted factual attestations; signatures do not prove physical execution or eliminate forged operator claims.

Manifest proposals for coordinator reconciliation only: explicit selected package set, immutable base snapshot/inventory hash, full protected-platform names, coordinated exact dependency versions, exact supported models, artifact/source/license/provenance/evidence hashes, staging/stable release IDs and authenticated withdrawal state. No shared manifest, README, roadmap, outline, orchestration record, root LICENSE, another worker's code, or Git state was edited by this workstream.

## Remaining blockers and accountable next steps

| Gate or boundary | Status | Owner / next action |
| --- | --- | --- |
| Selected real artifact/base/compatibility inventory | NOT AVAILABLE | Coordinator reconciles audits and captures complete target inventory |
| Native clean aarch64 build pair and retrievable dependency artifacts | NOT RUN | Build owner supplies verified builder/image/snapshot, raw records and actual locks/artifacts |
| Package source/license/hook/configuration review | INCOMPLETE | Package owners and independent reviewer close gaps for every selected package |
| M2 Air 13-inch and 15-inch physical records | NOT RUN | Hardware owner supplies each exact machine's frozen baseline/acceptance, lifecycle and recovery logs |
| Real signed repository install and release-pair upgrade/recovery | NOT RUN | Release/hardware owners execute on each advertised size after the above gates |
| Permanent signing custody, alternate and trust distribution | NOT ESTABLISHED | Human release custodian establishes external custody and authenticated public transition procedure |
| Public endpoint, freshness/anti-replay behavior and publication | NOT IMPLEMENTED / NOT RUN | Release operator reviews deployment/client design and tests bootstrap; CLI intentionally never publishes |
| Key rotation/revocation distribution and revoked retained artifacts | NOT RUN | Custodian follows documented re-audit/re-sign/new-record process; no expiry/revocation verification bypass |
| Content-only reproducibility exception | UNSUPPORTED | Coordinator/build reviewer defines an evidence-backed policy if native byte identity cannot be achieved |
| Retention capacity, crash durability and old-base security suitability | OPERATOR GATES | Operator verifies capacity/retained inputs and recovery; local atomic rename is not a power-loss claim |
| Current upstream pin/security freshness | NOT AUTOMATED | Maintainer records current security/compatibility review; immutable pins are not freshness evidence |

Retained releases are never pruned automatically. Local withdrawal records deny normal verification/promotion and deselect the affected current release while preserving forensic/recovery bytes. They do not retract cached metadata, uninstall packages, revoke trust or establish safe downgrades. Production recovery and all machine mutation remain unexecuted, owned by the hardware/release track.
