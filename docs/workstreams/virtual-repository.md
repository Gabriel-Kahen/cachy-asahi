# Disposable native repository integration

Status: runner implemented and source reviewed. All 43 boundary/regression checks pass locally, no skips. Native run `38212287407` passes copied-base inventory, repo-add and signing, but fails the first negative transaction’s inventory comparison; repository transaction acceptance remains **FAIL / unfinished**. This work owns only `scripts/integration/repository.py`, `scripts/integration/test_repository.py`, and this report. CI orchestration and native dispatch belong to the coordinator. No production signing identity, publication or M2 hardware acceptance is supplied.

## CI interface

Run in a new disposable **native aarch64 Docker container** with immutable image identity, read-only overlay root, no network, root inside the container and an actual root-owned `/.dockerenv`. The preprovisioned image needs Python 3.11+, pacman/repo-add, GPG/gpgconf, bsdtar, vercmp and the four original packages' dependency closure. It must not already have project/TEST packages installed.

```sh
python3 /runner/repository.py --inputs /inputs/manifest.json \
  --inputs-sha256 REVIEWED_MANIFEST_SHA256 --allow-disposable-repository-test
```

Required environment:

- `CACHY_ASAHI_REPOSITORY_CONTAINER=1`.
- `CACHY_ASAHI_DISPOSABLE_REPOSITORY`: fresh 32-character lower-case hexadecimal nonce, matching the manifest.
- `CACHY_ASAHI_IMAGE_ID`: immutable `sha256:` plus 64 lower-case hexadecimal characters, matching the manifest.

Required mounts: `/inputs` and `/runner` read-only; empty writable nodev/nosuid tmpfs `/scratch` and `/test-home`; empty dedicated writable evidence directory `/out`. `/runner/repository.py` and `/inputs/manifest.json` are fixed paths. Do not mount host system/home/tmp paths, expose a Docker socket or pass devices. Use `--read-only --network=none --user=0 --cap-drop=ALL --security-opt=no-new-privileges`; suggested additional capabilities are CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID. All five actual capability sets (effective, permitted, bounding, inheritable, ambient) must stay inside that five-cap mask; CAP_KILL and all other bits are rejected. Actual NoNewPrivs must be 1. No privileged mode or SYS_ADMIN is allowed. The guard independently checks an exact fixed mount allowlist, required Docker pseudo-filesystems and security flags/subtree roots (including all five read-only protected proc children), standard character-device identities, root-owned Docker metadata, null-device masks, and absence of sockets or hardware paths. Unknown/nested input, runner, output, proc, run and arbitrary runtime mounts are refused before input processing/output/key/package commands. These are observed kernel/filesystem properties; environment flags cannot substitute for them. Native execution and available tmpfs/memory allocation still require actual CI verification.

The runner measures the regular-file footprint of the base before copying and requires that free scratch space exceed that footprint by 64 MiB. Set bounded tmpfs and container memory allocations sufficient for the actual image, archive copies and transaction overhead; insufficient capacity fails before copying. The root remains read-only. Package transactions target `/scratch/system`, a private copy of `/usr`, `/etc` (excluding GPG homes), and the base package database. Hooks are masked and scriptlets disabled. All package/key/trust mutation occurs inside the disposable container; research/build scripts and host package state are not installation targets.

## Manifest and adapter

JSON fields required by the runner:

```json
{
  "schema_version": 1,
  "purpose": "disposable-generic-repository-test",
  "execution": "native-aarch64-disposable-docker",
  "allow_system_mutation": true,
  "daemon_arch": "aarch64",
  "nonce": "FRESH_32_LOWERCASE_HEX",
  "image_id": "sha256:IMMUTABLE_64_LOWERCASE_HEX",
  "source_commit": "ACCEPTED_40_LOWERCASE_HEX",
  "script_sha256": "ACTUAL_RUNNER_64_LOWERCASE_HEX",
  "upgrade_kind": "synthetic-changed-package-fixtures",
  "baseline": [],
  "upgrade": []
}
```

`baseline` and `upgrade` each contain exactly one archive for every original package: `cachy-asahi-hyprland-settings`, `cachy-asahi-fish-config`, `cachy-asahi-zsh-config`, and `cachy-asahi-setup`. Each row contains `name`, exact ALPM `version`, `archive` (relative regular file below `/inputs`), archive `sha256`, and complete regular-file `payload_sha256` map (relative `usr/...` paths excluding package metadata). The runner compares these fields with the actual archive bytes/metadata and rejects hooks, install scripts, symlinks and writes outside the reviewed data/helper scope.

Every upgrade row must be a reviewed derivative with a greater version, different archive bytes, changed installed payload and unchanged dependency/provides/conflict/replaces relations. All four changed derivatives are mandatory. They are TEST fixtures, not accepted production releases. A separate tiny data-only package is generated for tampering and rollback probes; it never substitutes for upgrading the originals.

The CI signing adapter and [lifecycle runner](virtual-lifecycle.md) may reuse the same pinned archive rows, source/image identity and observed native architecture. They run in separate containers: lifecycle uses a writable disposable root, whereas this runner requires a read-only root and separate tmpfs scratch/signing homes. This repository runner verifies archive SHA-256 and payload pins, then signs those exact bytes with its **own** ephemeral TEST keys. Incoming lifecycle `signature_sha256` fields are not used to establish trust here; their separate verification remains the lifecycle runner's responsibility. No lifecycle/production key is imported into the repository verifier.

## Transaction and trust checks

Pacman uses an explicit private config, root, database, cache and GPG directory. Both package and repository signatures require `Required TrustedOnly`; no `--nodeps`, `--overwrite`, `--dbonly` or signature bypass is used. Successful `-Syyu`/`-Syyuu` transactions must preserve the complete copied-base version inventory and match every expected original package version, ownership path, payload hash, regular-file type and exact archive-derived mode/uid/gid. Exit zero alone cannot pass an upgrade.

The implemented sequence is:

1. Sign baseline repository with TEST A; reject it before trust bootstrap.
2. Import/locally certify the exact public TEST A fingerprint; install all four originals and the probe.
3. Reject TEST B before rotation; import/locally certify B; fully upgrade all four originals and the probe.
4. Fully roll back to retained A baseline and verify restored original versions/payloads.
5. Reject a tampered probe whose updated checksum is in a correctly signed B database but whose original package signature is stale. Reject a separately tampered database signature. Also reject separately missing package and database signatures. All four failures must leave package inventory and owned-file types, hashes, modes, owners and symlink targets unchanged.
6. Import A's revocation privately, require GPG revocation evidence and reject A in pacman. Fully upgrade through unrevoked B and check dependency consistency and installed file presence.

The two signing identities and certification identity explicitly say `TEST ONLY`, use full fingerprints and expire after one day. Private keys, GPG homes, trust databases and standalone revocation certificates stay in unbound `/test-home` tmpfs. Cleanup removes them on success and ordinary failure; cleanup failure records FAIL. Docker destruction remains mandatory, including after timeout/forced termination. No permanent trust bootstrap or production identity is created.

## Evidence and limits

Output retains raw command/exit/diagnostic receipts and SHA-256 hashes, public TEST identities/certificates, signed package/database snapshots, explicit pacman config, complete package inventories, owned payload snapshots, source/image/contract identities, and a machine-readable `result.json`. Repository file aliases are exported as regular copies; directory aliases are recorded in a signed public JSON map. Output contains no symlinks, signing homes, secret keys, standalone revocation certificate or copied installed root. This is a raw public TEST evidence directory: the generic UTF-8 CI exporter must receive a projection of its JSON/log/txt receipts. Public certificates, signatures and MIT package/database snapshots need the controller's separate explicit hash-bound artifact path; they must not bypass the generic exporter's binary/archive rejection policy.

Portable tests exercise host refusal, mount boundaries, signature-status identity/expiry/revocation rejection, negative-transaction immutability, mandatory original payload/version checks, root-prefixed ownership output, receipt fidelity, public export and private cleanup. Most cases mock package/GPG commands; the copied-root query and later signed repo-add fixture use preinstalled host tools against private test data. They do not prove native transaction behavior. Peer reviews found pacman's root-prefixed `-Ql` paths, a negative-case symlink blind spot and missing positive mode/owner checks. Normalization uses the copied target root; negative snapshots now use lstat types without reading through symlinks, and successful payloads must match numeric archive mode/uid/gid. Regressions include identical-content symlink replacement, nonexecutable helper modes, and owner/group mismatch. A real read-only bsdtar fixture confirms archive-header mode/owner retention; no host package/key/trust mutation was used. Native CI must still verify GPGME/pacman trust interoperability, repository transactions, memory/capability sufficiency and all eleven case receipts.

This copied generic builder environment is not an Asahi machine. Boot, graphics, audio, suspend, 16K pages, M2 compatibility, performance, production key custody, published repositories and stable promotion remain **NOT RUN**.

## Source freeze after critical review fixes

The R1 lstat/type and R2 archive mode/uid/gid findings are corrected with regressions. The guard now independently observes the exact mounts, all five capability sets, NoNewPrivs, devices/sockets and required read-only proc protections. A read-only peer closure check confirmed all five proc omission reproductions are refused and all **34 tests PASS** before the first native attempt. The later copied-root regression brings the current suite to **35 PASS**, no skips. Python syntax and whitespace checks pass. Source is ready for coordinator review/native dispatch; no native transaction was run by this worker.

| File | SHA-256 |
| --- | --- |
| `scripts/integration/repository.py` | `72a604cf7ed99f9711755ef318ce9ce62af263006918c3a03d69c906830c5173` |
| `scripts/integration/test_repository.py` | `d920f0f86208a1ab12e22153e0e5b5d765eeb520ef27f7a74913e3c2fad862e5` |

CLI/schema remain as specified above; payload metadata is derived from the checksum-bound archives and introduces no new caller row field. Guard records are retained in `result.json`. The client prototype is a separate source freeze and excluded from the initial V01–V09 pipeline.

## October 12 native copied-root correction

The coordinator’s native run `38202483407` reached the repository stage after authenticated inputs, fixtures/signing and all 474 source-suite tests passed. Its `076-copied-base-inventory.txt` reported that `/scratch/cache` supplied to `--cachedir` did not exist. `copy_base()` now creates the dedicated empty cache before the first `pacman -Q`; `select()` still clears/recreates it for each repository transaction. Signature requirements, explicit copied root/database/GPG paths and complete baseline inventory preservation remain unchanged.

A new small copied-root regression actually invokes the installed pacman in read-only query mode against a private fixture database, with no key operation, package install or host database mutation. Before the fix it reproduced the exact missing-cache diagnostic. Once that was corrected, it exposed the missing integration sync database warning being merged into inventory text. Query commands `-Q`/`-Ql` now return stdout only to their inventory/ownership parsers while retaining both stdout and stderr bytes in the command receipt log. Nonzero query exits still fail, and all transaction/trust command behavior is unchanged. The fixture asserts exact inventory, cache existence before any repository selection, strict signature config, private database/cache paths and retained warning evidence.

Current local validation: `python -B scripts/integration/test_repository.py` **35 PASS**, no skips; AST syntax and trailing-whitespace checks pass. The copied-root query used this x86 host’s real pacman; it is not a native installation/upgrade pass. Full native repository transactions, trust rotation/revocation and hardware acceptance await the coordinator’s refreeze and rerun. No CI, workflow, Git, dispatch, host installation or trust state was changed. Client-stage implementation was paused for this correction; its separate source files are not part of this repository handoff.

## October 12 native repo-add correction and CI projection handoff

Native run `38205521065` (freeze `a115`, source `e75ead7` as reported by the coordinator) passes the earlier copied-cache inventory check and all 499 native source-suite tests, but fails the repository stage at `087-repo-add-baseline-A.txt`. This reviewer read that exact decoded receipt: `mktemp` could not create `/tmp/repo-tools.XXXXXXXXXX` on the read-only root, then repo-add reported it could not create its temporary database-building directory. Decoded container cleanup confirms removal and absence. No repository installation/upgrade case passed merely because input/fixture/signing bindings passed.

Each repo-add invocation now receives a fresh mode-0700 `TemporaryDirectory` directly under the guarded `/scratch` tmpfs through an explicit `TMPDIR`, while retaining the exact signer `GNUPGHOME`, full fingerprint and unchanged `--include-sigs --sign --key` command. The temporary directory is outside exported `/scratch/repos` and is removed on success or command failure. The root remains read-only; no `/tmp` mount, capability, signature requirement, alias behavior, copied-base check or transaction case was relaxed.

The new regression failed before the fix at its assertion that repo-add receives an existing private scratch TMPDIR; it did not reach the host repo-add invocation. The actual read-only `/tmp` failure is established by the native ALARM shell receipt above. Local `/usr/bin/repo-add` is the CachyOS x86 ELF 7.1.0 implementation; the independent reviewer observed that it can succeed with a nonexistent inherited TMPDIR, so the local regression does not reproduce the native shell’s mktemp failure. After the fix, the host regression verifies the explicit private TMPDIR assignment and creates a signed repository with a real one-day ephemeral TEST signer, verifying both database signatures. It asserts private scratch placement/mode, exact signer home, deletion of the temporary directory and preserved database alias/signatures. A separate injected repo-add-failure regression writes partial temporary state and confirms cleanup on failure. All keys and raw fixture evidence are confined to the test temporary tree; signer agents/homes are cleaned up and no host package or default trust state is changed. This local x86 repo-add implementation differs from the native script, so actual native database creation and the complete eleven transaction cases still require the coordinator’s refreeze/rerun. **37 tests PASS locally**, no skips; AST syntax and whitespace checks pass.

**CI owner handoff (no CI edits here):** decoded `export-manifest.json` rejected the known repository `result.json` as `private-key-or-credential-content`; the reported offending semantic field is the producer’s `base_versions` package-name→version map (the `libsecret` key matches the generic field heuristic). Keep the generic content guard unchanged. The controller should project only the known repository result path/purpose after matching its source/image/nonce contract to the accepted runner and validating the complete `base_versions` map for exact equality with the independently accepted full builder inventory. Preserve package names/versions as structured `{name, version}` rows and retain raw result/inventory hashes, package count and authority description. Project only this validated semantic field; do not encode/rename arbitrary unknown results or suppress rejection of credentials elsewhere. Unknown paths, malformed/extra/missing versions, mismatched source/image/nonce and real credential/private-key content must continue to fail. Existing command/log/signature/alias bindings and the CI owner’s validation/export ownership remain intact. The coordinator must forward this exact authority/schema requirement to the CI owner before accepting the next export; this reviewer did not modify their files or dispatch.

## October 12 sixth native run: strict local inventory and diagnostic separation

Actual run `38212287407`, source `932cf45`, passes the prior cache/TMPDIR fixes and baseline repository signing. It fails `untrusted-A-rejected: rejected transaction changed inventory/payload`. Independent inspection of retained 104/106 command receipts and snapshots shows the complete 341 package rows and 19 owned-file states unchanged. Before capture includes the missing integration database warning; after capture includes an import-PGP-key prompt on stdout and unknown-key errors. Returning only stdout was insufficient because pacman loads registered sync databases and can prompt on stdout even during `-Q`. No transaction/hardware acceptance is inferred from this diagnosis.

The runner now creates a dedicated options-only `query-pacman.conf`, preserving `SigLevel = Required TrustedOnly` and `LocalFileSigLevel = Required TrustedOnly` but registering no sync repositories. Only the local `-Q`, `-Ql`, `-Qk` and `-Dk` operations select it; `-Syyu`/`-Syyuu` retain the existing strict signed transaction config and all explicit private copied-root/database/cache/GPG paths. No diagnostic lines are filtered from inventory. Every inventory row must match the exact bounded ASCII package-name/version schema, duplicates/blank/control/prompt/extra lines are refused, and counts are bounded. The actual immutable image’s local database must yield exactly 341 rows; the copied inventory must equal that complete map. The coordinator remains responsible for binding that immutable image to the accepted full bootstrap/package lock.

Snapshot comparisons now use package maps plus unchanged owned-file states; canonical text in snapshot JSON records the accepted map without diagnostic contamination. Queries after baseline establishment require all baseline versions intact and allow no extra identities beyond the four originals and the synthetic probe. Positive verification still requires the exact complete expected inventory; negative verification still requires exact before/after map and payload equality. Real package/version, extra-package, mode/owner/type and payload changes remain failures.

Query stdout and stderr are retained as separate exact byte files with individual receipt hashes (`log`/`sha256`, `stderr_log`/`stderr_sha256`). Full transaction diagnostics remain captured unchanged. GPG exit 2 for unknown keys was already nonzero rejection under the earlier expected-1 flag; actual negative commands now record the explicit `expected = nonzero` policy, retain the actual exit code and still require trust/signature diagnostics where specified. Exit zero cannot satisfy a rejection.

Validation: **43 tests PASS locally, no skips**, independently repeated by the focused read-only reviewer with real temporary GPG/repo-add. Added regressions cover stdout/stderr byte/hash separation, all query/transaction config choices, strict malformed/duplicate/diagnostic inventory refusal, unchanged negative maps despite changing stderr, real package/baseline changes and explicit GPG exit-2 rejection. Existing mocked copied-root/pacman regressions and the real signed-repository fixture remain passing. The reviewer found no new source blocker and edited no files. AST syntax and whitespace checks pass. No shared CI, initial locks, Git, dispatch, host installation, default trust or accepted client/release source was changed. Root/CI must refreeze these corrected sources and rerun the entire native repository sequence; all remaining transaction cases and acceptance remain unfinished. Separate KSM work was paused for this correction.
