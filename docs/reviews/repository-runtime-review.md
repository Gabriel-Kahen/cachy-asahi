# Repository runtime correction review

Reviewed 2026-10-12 by the independent integration reviewer. Scope is the repository runner correction following native run `38205521065`, its bounded tests, and the immediate controller/export contract. No implementation, manifest, Git, Docker, host package database, host trust store, or native workflow was changed or executed by this reviewer. The updated roadmap and package inventory were read first; local checks do not satisfy native transactions, complete-port acceptance, or physical M2 validation.

## Snapshot and actual failure

| Source | SHA-256 |
| --- | --- |
| `scripts/integration/repository.py` | `519c1bbc12a2fd02e036f67c162190f2b017e86ed7b7c192b6bbb994809fe5d9` |
| `scripts/integration/test_repository.py` | `30b76ba8dd9a9e3c74c085f5282fb1001e3cc6fdbae40ffdc423112dee0473c5` |

The retained native log `artifacts/ci/38205521065/decoded/repository/087-repo-add-baseline-A.txt` reports `mktemp` failing to create `/tmp/repo-tools.XXXXXXXXXX` because `/tmp` is read-only, followed by repo-add refusing database creation. This stage failed before successful repository transaction evidence; the earlier original-package build results do not make this stage pass.

## Correction and boundary review

`Integration.repository()` now creates a fresh `TemporaryDirectory(prefix='repo-add-', dir=self.scratch)` and gives only the repo-add child an environment containing that directory as `TMPDIR` and the explicit TEST signing home as `GNUPGHOME`. Python creates the temporary directory with mode `0700`; the context covers command execution and removes partial files on success or an exception. The inherited process environment is copied, rather than modified.

The CI launch still makes the container root read-only. `/scratch` remains a dedicated mode-0700, bounded, nodev/nosuid writable tmpfs; `/test-home` is a separate private tmpfs. The runner continues to reject unexpected mounts, nested mounts, excess capabilities across all five observed sets, missing no-new-privileges, sockets/hardware devices, host invocation, and mismatched source/nonce/image/manifest identities. The correction neither introduces a writable `/tmp` mount nor relaxes signature policy.

Signing and verification remain bound to disposable TEST identities and explicit homes/keyrings. Both generated database archives are verified against the expected complete fingerprint and SHA-2 signature status. Pacman targets the copied root, private database/cache/keyring/config/hook directory, with `Required TrustedOnly`. Successful install/upgrade/rollback cases still require the complete expected inventory and original package payload bytes, modes, and numeric ownership. Negative signature cases require both a signature diagnostic and unchanged inventory/payload types.

The temporary repo-add directory is a sibling of `scratch/repos`, so the public repository exporter does not copy it. Public repository aliases are converted into regular copies with a signed alias record; private key homes and standalone revocation material are outside that export tree. The controller's bounded binary adapter selects public certificates, signatures, database/package outputs and explicit TEST records by exact evidence hashes. Generic credential filtering and inventory-log projection remain separate CI-owner work; this review does not authorize broadening that guard.

Runner cleanup visits all private-home entries, including partial state from failed key creation; failed private-file removal forces a FAIL receipt. Agent process disappearance is not asserted solely from file removal: the enclosing disposable-container removal remains the final isolation boundary.

## Independent checks

The full command was `python3 -B -m unittest discover -s scripts/integration -p 'test_repository.py' -v`: **37 tests attempted, 36 PASS, 1 ERROR, zero skips**. Passing cases include private scratch mount requirements, trust/status rejection, copied-root-only pacman paths, actual read-only copied-root inventory query, archive ownership/modes, successful transaction payload checks, rejection of equal-byte symlink replacement, normalized public exports, repo-add failure temporary-directory cleanup, partial private-state cleanup, and cleanup failure preventing PASS.

The error is `test_real_signed_repo_add_uses_private_scratch_tmp_and_cleans_it`, at TEST key generation before repo-add executes. A separate short owned temporary GPG home reproduced the cause: private `gpg-agent` exits 2 with `error binding socket .../S.gpg-agent: Operation not permitted`. The sandbox therefore prevents this reviewer from independently completing that signed fixture. No default GPG home/keyring was used; the temporary probe was removed and its private agent cleanup was attempted. This is an environment limitation, not a reproduced failure of the TMPDIR correction, and the owner-reported 37-test pass is not substituted for an independent pass.

A separate temporary fixture called the current `Integration.repository()` with signing and the outer command mocked, but executed real coreutils `mktemp -d --tmpdir repo-tools.XXXXXXXXXX` using the exact environment supplied to repo-add. With an unavailable inherited global TMPDIR, the control mktemp failed. With the runner's override, mktemp created a mode-0700 child inside the fresh mode-0700 scratch directory. Injected `Refused`, `TimeoutExpired`, and `KeyboardInterrupt` each propagated and left neither temporary directory nor partial file behind; the inherited environment and unavailable global path were unchanged. This validates the actual temp-tool path and Python cleanup boundary, not signatures or pacman transactions.

An additional unsigned local repo-add control showed why native evidence is necessary: this host's `/usr/bin/repo-add` is an x86-64 ELF, CachyOS pacman `7.1.0`, and succeeds even with a nonexistent inherited TMPDIR. It is not the ALARM shell implementation producing the retained native mktemp diagnostic. That control is not counted as a native failure reproduction or a signed acceptance check.

## Outcome and limits

No new actionable source defect was reproduced in the bounded correction, trust, temporary-state, export, and failure-cleanup review. The source correction is ready for a controlled native retry, subject to the coordinator's source freeze and remaining CI projection work. Native repository acceptance remains **NOT PASSED** until a new exact-source run completes the actual signed repo-add and all intended pacman cases with retained, reviewable evidence. No install/visual/physical M2 or complete R1–R5 acceptance follows from these local checks.
