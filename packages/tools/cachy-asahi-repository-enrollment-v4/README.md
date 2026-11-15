# Repository enrollment tools0.4.0

Opt-in candidate `cachy-asahi-repository-enrollment` **0.4.0-1**. This NEW recipe
preserves all nine0.3.0-1 runtime files exactly and adds same-primary certificate
refresh. Existing recipes, qualified artifacts and manifest selections are not
changed. Native ARM, installed ALPM lifecycle, M2 and release acceptance are NOT RUN.

The finite runtime has ten Python files,153283 bytes. `payload-map.json` and
`source-provenance.json` bind each original body, size and installed mode. The
source context is genuinely public commit
`b4ad0dee38c23b34c020e31fe98803bd6817e892`; local archive/per-file digests remain
the exact byte authority. The deterministic USTAR/gzip archive has no directory,
link, generated cache or unrelated repository members. Its metadata is fixed
uid/gid/mtime0, mode0644, sorted member names and gzip mtime0. Original packaging
and source are MIT; notices and license are installed.

## Installed commands

The launcher resolves its own installed prefix and invokes fixed `/usr/bin/python3
-I -B` with a literal helper path and separately passed arguments:

```sh
cachy-asahi-repository-enrollment --help
cachy-asahi-repository-enrollment configure --help
cachy-asahi-repository-enrollment rotate --help
cachy-asahi-repository-enrollment transition --help
cachy-asahi-repository-enrollment revoke --help
cachy-asahi-repository-enrollment refresh --help
```

Preview remains default. No package hooks initialize a keyring, configure pacman,
import/sign keys or select a server. Only an explicit applicable `--apply` changes
the selected local root. No command installs packages or implies release acceptance.
Rotation, transition and revocation semantics remain unchanged. Transition retains
the snapshot URL; revocation quarantines the managed repository without deleting
public trust. Primary changes remain rotation operations.

For planned same-primary expiry renewal or a new signing subkey, independently
authenticate the new complete public certificate, retain the exact current public
certificate matching the managed hash, then preview:

```sh
cachy-asahi-repository-enrollment refresh \
  --fingerprint "$UNCHANGED_PRIMARY_FINGERPRINT" \
  --expected-current-certificate-sha256 "$CURRENT_CERTIFICATE_SHA256" \
  --current-public-key /srv/cachy-asahi/current-public.asc \
  --public-key /srv/cachy-asahi/renewed-public.asc
```

Apply requires root and safe root-owned inputs; add `--apply` after review. The
existing enrolled key must already be valid and fully trusted. Expired/revoked
current primary, unsafe/secret/multiple-primary/wrong-primary candidates, stale
CAS, foreign transaction lock or changed inputs refuse. It is not incident repair.
GPG effective public views check completeness and reject encoding-only/stale
updates; normal public import preserves existing trust according to GPG rules,
then only the managed certificate hash changes. No local signing/key deletion is
requested, and snapshot URL/global configuration remain fixed.

Keyring import and include replacement are separate mutations. Failures report
possible partial changes; imports are retained. Inspect the actual include/ring
before retrying. If import succeeded but include replacement did not, the retained
old certificate permits retry with the same expected old hash. A completed
refresh requires the new hash and current/new certificate inputs for a checked
no-op. The command neither authenticates the system clock nor establishes which
certificate is globally newest. See the project certificate-refresh guide for
full policy and uncertainty details.

## Build and package checks

Runtime dependencies: Python>=3.11, GnuPG, pacman/pacman-key, coreutils and
libarchive. Release verification uses bsdtar, including zstd support; no Python3.14
compression module or separate zstd executable is required by this runtime.
Check dependencies: bubblewrap and util-linux. Source inputs are local pinned
files; `makepkg` never obtains signing credentials. Do not install dependencies on
a host implicitly or run package functions as root.

```sh
makepkg --cleanbuild --force
```

The real check function stages and relocates the complete package, hides the
source trees in a loopback-only bubblewrap namespace and poisons caller Python
environment variables. It exercises every installed help route, a real dual-signed
release transition and tamper refusal, real revocation preview and non-revoking
refusal, then same-primary renewal through the relocated `refresh` entry point.
The latter uses disposable mapped-root apply with a newly added signing subkey;
its signature fails before import and verifies trusted afterward. Stale CAS
refuses, correct successor CAS gives a no-op, and global configuration is exact.
Deleting all16 package-owned leaves preserves a foreign user file. No host-root
fallback, package installation, real repository endpoint or network fetch is used.
Private signing keys exist only in fixture-owned temporary signer homes and never
in the package/runtime/target. Removal here is payload inversion, not an ALPM claim.
