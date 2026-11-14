# Repository enrollment 0.3.0-1: finite installed revocation delivery

November 14, 2026. **PASS: unsigned host package assembly and relocated synthetic
TEST transition/revocation previews.** Native ARM, ALPM installation/lifecycle,
M2 and production incident acceptance remain **NOT RUN**.

The NEW `packages/tools/cachy-asahi-repository-enrollment-v3` recipe builds the
same `cachy-asahi-repository-enrollment` package at `0.3.0-1`. It reads the exact
finalized `0.2.0-2` private runtime from Root's integration worktree, preserving
all eight Python files byte-for-byte, and adds only `scripts/repository/revoke.py`
from source commit `c24756c597b6cc71b3d43a3119601384f90eed45`. Three held v2 files
differ from the worker's older checkout; the held archive bytes were retained,
not reconstructed from that older source tree. Existing recipe directories,
source tools, shared selections and workflows were not changed.

The base archive's SHA-256 is
`caac87988e949acc7155218bcc0f43e3387a16aebe4957b895b276cdf2949655`.
New provenance retains that base context and all eight original identities,
plus all nine final runtime paths, lengths, modes and SHA-256 values. The new
sorted USTAR/gzip source archive has zero timestamps/ownership and mode 0644:

```text
private-source.tar.gz
36605 bytes
SHA-256 f9513c8162656944784f3196bafee20b8c726dde0880fafc38235211e0ac83c0
```

The installed payload is exactly 15 files: one isolated launcher, nine private
Python files totaling 144105 bytes, three documentation/identity files and two
license/notice files. Configure, rotate and transition retain their finalized
runtime; the launcher adds `revoke`. There are no trust/configuration hooks,
`.INSTALL`, ALPM hook, service, `/etc` or `/var` files. Check fixtures are not
installed. Runtime dependencies remain Python >=3.11, gnupg, pacman, coreutils
and libarchive; bubblewrap and util-linux are check-only namespace dependencies.

## Actual checks

- `makepkg --verifysource --noconfirm`: all nine declared local source pins pass.
- `REPOSITORY_ENROLLMENT_HIDE_ROOT=/absolute/checkout makepkg --nodeps --noconfirm`:
  package `check()` and unsigned assembly pass. Dependency checks are bypassed;
  no prerequisite installation or source downloading is attempted.
- Actual `package()` staging, moved-prefix execution, all four command help
  dispatches and version `0.3.0` pass. Runtime and payload maps match every file.
- Retained real signed TEST release-transition preview and invalid-signature
  refusal pass, including zstd-compressed package and declared-source checks.
- Actual installed `revoke` previews a real revoked public certificate and
  refuses the non-revoking original. It runs under mapped-root user namespaces
  with source/fixture trees hidden, loopback-only networking and poisoned caller
  Python variables. No revocation apply occurs in package checks; all target
  configuration/keyring bytes remain unchanged.
- The exact payload-removal inverse preserves an unrelated user file.
- Independent archive readback verifies all 15 payload files plus the three
  package metadata files, all nine private runtime hashes and lengths, original
  v2 identity preservation, package version/architecture and runtime dependencies.
- `git diff --cached --check`: passes.

The first package-check attempt was stopped by the retained GPG helper's
home-outside-repository guard in the new check setup. The test's repository-root
argument was corrected; no runtime file changed to bypass the guard. The
successful check requires actual user/network namespaces. Namespace limitations
fail visibly, without a host-root fallback or fabricated preview result.

The successful unsigned host archive is retained in the worktree's ignored
`work/repository-enrollment-v3-host-20261114-r2/` directory:

```text
cachy-asahi-repository-enrollment-0.3.0-1-any.pkg.tar.zst
53628 bytes
SHA-256 59caa797e8ff247f1790fb95c7ec8552f19d3211d378bfd9ba54caccfb9b5f47
```

This is one host assembly, not a native/reproducible build pair. Source revocation
apply and partial recovery remain covered by the separately recorded 12-case
mapped-root source suite; this packaging check does not qualify installed apply,
production distribution/freshness, client convergence or incident acceptance.
The package is an opt-in next-PR successor; no shared manifest selects it.
