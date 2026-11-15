# Perl 5.42.3-1.3 installed lifecycle Source

This finite adapter upgrades the exact signed Frozen272 baseline Perl in a **separate disposable writable native ARM4K installation container**, checks the installed interpreter and package state, and rolls back through normal trusted ALPM. It does not repurpose the read-only nonroot build container. Source authoring and DATA controls do not establish installed, native16K, M2, performance or release acceptance.

## Current evidence

- Implementation/refusal controls: 32 Python controls pass on the authoring host; no Docker, ALPM, GPG or Perl actor is invoked by these controls.
- Candidate archive DATA inspection: 22,071,176 bytes, SHA256 `647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22`; 3,262 entries, including three metadata entries, and 54 ARM64 ELFs. No `.INSTALL` is present. DATA inspection does not execute the package.
- Accepted build provenance supplied by Root: Source `25dc3e65bdb6137c87a9409067fe9b2cf6e9763f`, native pair run `43692477455`; both full harnesses passed. Root component decision: `artifacts/development/orchestrator-resume-20261114/Root-perl-hosted-intake-r1/Root-native-component-decision.ACTUAL-r1.json`, 5,804 bytes, SHA256 `27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1`.
- This adapter's actual signing, image admission, container execution, Reader execution and installation/rollback: **NOT RUN**. All actual selectors remain null in the templates.

The frozen baseline is **Perl 5.42.3-1**. Its exact archive is `perl-5.42.3-1-aarch64.pkg.tar.xz`, 16,017,184 bytes, SHA256 `f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f`; detached signature: 566 bytes, SHA256 `f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca`. `prepare.py` selects it from the frozen lock as DATA. It does not use a mirror or substitute the historical 5.42.2 archive.

## Files and ownership

All implementation lives in `scripts/port/perl5423-installed-lifecycle/`. `common.py` binds the finite identities and verifies inputs. `prepare.py` assembles a closed DATA capsule; `producer.py` owns its one container; `actor.py` performs the finite installed lifecycle; `probe.pl` checks the actual installed runtime; `read_result.py` checks retained original result consistency without executing package code. `helpers/owned_child.py` and the bounded archive decoder are byte-identical copies of existing project helpers. `helpers/archive.py` reuses the existing Perl archive inspector's bounded read routine, including genuine package hardlinks.

No shared manifest or workflow is changed. Root owns source integration, signing, image creation, runtime admission, real execution and independent acceptance. The XS worker owns its separate consumer source; this adapter never imports or edits that worker's files.

## Root inputs required before sealing

1. The exact frozen inputs lock and expected349 inventory, from `artifacts/development/orchestrator-resume-20261114/Root-perl-hosted-source-r1/source-tree/original/native/desktop574-inputs.lock.json` and `expected349.lock`. Their required SHA256 values are `b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9` and `579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453`.
2. The Root-accepted candidate archive and the exact baseline archive/signature above.
3. A **fresh external Root TEST signature** for the unsigned candidate. Root creates the key/signature outside all package and build actors. The public certificate must have an explicit `TEST ONLY` UID at `@test.invalid`; the exact 40-character primary fingerprint is a required selector. No production signing credential is used or admitted.
4. Public-only `pubring.gpg` and `trustdb.gpg` carrying ordinary trusted baseline signing public keys and the fresh TEST public key. Root prepares and validates this combined public trust bundle outside actors. Both candidate and baseline signatures must validate against the explicitly admitted primary fingerprints. The actor receives no secret key directory or secret key files, refuses secret-key records, and disables agent/dirmngr autostart and automatic key retrieval.
5. A Root-qualified immutable native Linux ARM64 image built from the exact genuine 349 signed bootstrap. It must contain the ordinary baseline user `alarm`, Python 3.14+, pacman, GPG, runuser and the exact baseline Perl. No image volumes or healthcheck are admitted. The immutable image's exact Root-reviewed `base_labels` dictionary is bound by admission/qualification and compared against image inspect; empty labels are valid only when explicitly reviewed as empty. Inherited labels are merged with the separate `cachy-asahi.perl-lifecycle.*` ownership namespace; collisions and unknown additions refuse. Its existing public baseline keyring must contain `pubring.gpg` and `trustdb.gpg`. Root must retain the original signed bootstrap provenance and review the exact original Perl archive's ALPM install metadata, configurations and hooks before admission. `baseline-review.json` records those pinned metadata/config/hook paths; the adapter restores the exact baseline package interface without guessed path exclusions. Runtime checks independently require every exact baseline package name/version and all baseline Perl package bytes/modes/owners.
6. An available native ARM4K rootful Docker daemon and fresh private caller-owned input/output parents. The future bind path must be a literal absolute path without aliases or mount-option punctuation. Root separately reviews the installation domain below, including ordinary hooks inherited from the frozen bootstrap.

Input assembly is read-only toward archives, keys and the original source tree. Example, with Root-owned concrete paths substituted:

```sh
python3 -I -B scripts/port/perl5423-installed-lifecycle/prepare.py \
  --baseline-lock ROOT_FROZEN_DESKTOP574_INPUTS_LOCK \
  --expected349 ROOT_FROZEN_EXPECTED349 \
  --candidate ROOT_EXACT_CANDIDATE_ARCHIVE \
  --candidate-signature ROOT_FRESH_TEST_SIGNATURE \
  --baseline ROOT_EXACT_BASELINE_ARCHIVE \
  --baseline-signature ROOT_EXACT_BASELINE_SIGNATURE \
  --public-keyring ROOT_COMBINED_PUBLIC_PUBRING \
  --public-trustdb ROOT_COMBINED_PUBLIC_TRUSTDB \
  --test-public ROOT_FRESH_TEST_PUBLIC_ASC \
  --output ROOT_PRIVATE_FRESH_CAPSULE_DIRECTORY
```

The emitted source-map pins every actor/helper, both payload maps, both archives/signatures, the public trust files and the frozen349 lock/inventory. Unmapped files, secret material, aliases, hardlinked input operands and changed inputs refuse. Package hardlinks are separately handled as legitimate archive/installed DATA.

## Separate installation domain

`domain.json` fixes uid/gid 0:0, writable disposable container root, no network, two CPUs, 2 GiB RAM with no swap, 128 tasks, init, no new privileges, readonly `/inputs`, and bounded private `/work`, `/run` and `/tmp` tmpfs mounts. It drops all capabilities and adds only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`, `SETFCAP`, and `SYS_CHROOT`. These cover root ALPM ownership/metadata, ordinary-user probes and ALPM's ordinary chrooted hooks. There is no `SYS_ADMIN`, host PID namespace, device access, Docker socket or writable host bind inside the actor.

The producer checks actual image/daemon identity and visible local Docker storage, requires at least 1 GiB/10,000 free inodes before creation, and records before/after storage observations. It creates the exact Root-selected name with exact operation/admission/Source labels, validates actual Docker inspect data, attaches once, observes natural container exit, exports bounded original DATA and removes only that exact owned container ID without `rm -f`. Its CLI children use the existing WNOWAIT/direct-final-waitpid owned process helper. Cancellation, forced child retirement, OOM, unexpected mounts, resource differences, unknown ownership or uncertain cleanup prevent success. Cancellation may stop the exact owned container; it cannot become successful native evidence. Missing create ownership is reported explicitly instead of guessing a cleanup target. Writable image storage has checked headroom and finite exact package inputs, rather than a per-container filesystem quota; the tmpfs limits are hard filesystem bounds.

The actor checks actual ARM64/4096-byte pages, root credentials, capability masks, NNP, readonly inputs/writable root, cgroup limits, network interfaces, namespaces and mount records. Source-map/domain bytes and the external Root operands are checked before package mutation. This is a Root runtime admission boundary, not an interactive user approval flow.

## Finite transaction and comparison

The actor first checks all 349 package names/versions and the archive-derived baseline Perl payload. It preserves existing account files and baseline public trust/config/hooks. It creates ordinary `alarm`-owned site-module and configuration edits under a fresh `/home/alarm/.perl5423-lifecycle` fixture, and verifies them after every transition, including a real ordinary-user module load.

Both the candidate TEST signature and original baseline signature receive normal trusted verification. Two refusal transactions precede the upgrade: the candidate under a private copy of baseline-only public trust, and an altered detached signature under combined trusted public keys. Each must fail for the expected trust/signature reason with unchanged package bytes/database/inventory. Original global trust is never used as a mutable actor GPG home.

The five observed stages are:

1. Baseline `5.42.3-1`.
2. Normal trusted `pacman -U` candidate `5.42.3-1.3`.
3. Normal trusted repeated `pacman -U` candidate, exercising ALPM's same-version reinstall.
4. Normal trusted `pacman -U --needed` candidate, requiring the actual up-to-date skip diagnostic and an unchanged local database.
5. Normal trusted `pacman -U` exact original signed `5.42.3-1` archive.

Every stage requires exactly 349 package names/versions, with only the explicit Perl version substitution; exact `pacman -Qlq perl` ownership paths; archive-equivalent installed bytes, mode, uid/gid and real hardlinks; and `pacman -Dk` dependency/database consistency. Real installed `/usr/bin/perl`, installed `Config.pm`, loaded `/usr/lib/perl5/5.42/core_perl/CORE/libperl.so` process mappings, shared/threaded IV64 ARM configuration, arithmetic, base64 and threading probes run without ambient Perl path overrides. The candidate deterministic `Config{cf_time}` is checked.

Rollback compares the union of old/new package paths against the original snapshot, including absence of candidate-only paths. File/link bytes, modes, owners and mtimes must match; shared directory mtimes are retained as explicit normal ALPM transaction differences. All 349 local database contents must match after normalizing **only** Perl's `%INSTALLDATE%` value and mtimes on the local-db root and the recreated baseline Perl database directory/files. Raw before/after database maps, both install timestamps and every changed row are retained. Other packages' database bytes and mtimes remain exact. Account file contents must remain exact. The ordinary pacman log must retain the original bytes as a prefix; its final size/hash is recorded.

The ordinary-user fixture is preserved through transactions and removed only by its recorded directory identity in cleanup. No user is added or removed; passwd/group/shadow/gshadow hashes must match. The ordinary user's home-directory mtime changes when this temporary fixture is created/removed; raw before/final metadata records this residual. Private trust, temporary package copies and tmpfs work disappear with the owned container. This does not claim bit-identical whole-root restoration: ordinary hook caches/logs and container filesystem allocation are outside the package-owned comparison.

Normal frozen bootstrap hook masks remain visible in the pinned baseline lock and retained hook snapshot. This adapter adds no hook mask or `HookDir` override; it does not qualify unmasked supported-target hook behavior. Baseline Perl is a required dependency, so the adapter does not attempt full uninstall or use dependency bypasses such as `-Rdd`, `--nodeps` or forced overwrite. Dependency-protected removal refusal is not exercised by this finite adapter.

`upgraded-handoff.json` contains actual readonly upgraded payload/probe DATA. Its image/container selectors remain null: the container continues to rollback. Root may separately prepare/admit a readonly upgraded image for the XS worker. This handoff alone is not an executable XS environment or external XS acceptance.

## Actual execution and review

Root fills `qualification.TEMPLATE.json` and `admission.TEMPLATE.json` only after independently reviewing real prerequisites. The qualification must have the exact schema enforced in `producer.py`: status `ROOT_ADMITTED_FOR_FINITE_COMPONENT_TRIAL`, native `aarch64`, page size 4096, runtime domain `SEPARATE_ROOT_WRITABLE_NATIVE_ARM4K_ALPM_V1`, concrete immutable image, exact `base_labels` dictionary and Source/fingerprint identities, and signing-credential scope `EXCLUDED; fresh Root TEST signing performed outside actors`. `baseline_source` names the accepted Perl build Source carrying the frozen baseline references. The admission binds the qualification hash and uses container name `cachy-perl-lifecycle-` plus its explicit run identifier.

```sh
python3 -I -B scripts/port/perl5423-installed-lifecycle/producer.py \
  --admission ROOT_FILLED_ADMISSION_JSON --admission-sha256 ROOT_ADMISSION_SHA256 \
  --qualification ROOT_FILLED_QUALIFICATION_JSON --qualification-sha256 ROOT_QUALIFICATION_SHA256 \
  --source-map-sha256 ROOT_CAPSULE_SOURCE_MAP_SHA256 --output ROOT_FRESH_EVIDENCE_DIRECTORY

python3 -I -B scripts/port/perl5423-installed-lifecycle/read_result.py \
  --evidence ROOT_ORIGINAL_EVIDENCE_DIRECTORY --inputs ROOT_EXACT_CAPSULE_DIRECTORY \
  --source-map-sha256 ROOT_CAPSULE_SOURCE_MAP_SHA256 \
  --producer-report-sha256 ROOT_RETAINED_ORIGINAL_PRODUCER_REPORT_SHA256
```

The read-only consistency reader authenticates original exported DATA against the externally retained producer-report hash, checks every original stdout/stderr pin and owned retirement record, checks all stages/refusals/inventories/probes/rollback and requires natural owned cleanup. It grants no independent acceptance authority. Root must review and qualify the exact Source/Reader and actual result, including refusal diagnostics, runtime evidence and all exceptions. Source/build acceptance does not qualify this installation trial; a successful installed ARM4K component trial still does not qualify native16K, either M2 Air model, performance or release.
