# Repository enrollment tools 0.2.0

An opt-in successor recipe for the same `cachy-asahi-repository-enrollment`
package, version **0.2.0-1**. It retains `configure` and `rotate` and adds
`transition`, connecting an authenticated dual-signed release handoff to explicit
local trust rotation. No manifest selection, release promotion or publication
is implied. The separate 0.1.0 recipe and its evidence remain unchanged.

```bash
cachy-asahi-repository-enrollment --version
cachy-asahi-repository-enrollment configure --help
cachy-asahi-repository-enrollment rotate --help
cachy-asahi-repository-enrollment transition --help

cachy-asahi-repository-enrollment transition \
  --bundle /srv/cachy-asahi/transitions/release-1-to-2 \
  --before /srv/cachy-asahi/staging/release-1 \
  --after /srv/cachy-asahi/staging/release-2 \
  --expected-current-fingerprint OLD_PRIMARY_FINGERPRINT \
  --fingerprint NEW_PRIMARY_FINGERPRINT
```

Preview is the default. Only an explicitly supplied `--apply` changes local
trust/configuration, and apply requires root. The transition command requires an
enabled managed repository and a currently usable trusted old key. The managed
fingerprint and public-certificate SHA-256 must match the signed predecessor;
the successor bytes come only from the verified bundle. Retained inputs must be
safe canonical owned trees. The full handoff is reverified under the existing
pacman lock; observed-current/configuration checks and fresh UTC overlap checks
guard import/local signing. Historical `--as-of` is diagnostic preview only and
is forbidden with `--apply`.

Apply retains the existing snapshot URL, signature policy and old trust. It does
not select/accept the successor snapshot, install/update packages, contact users,
publish/distribute trust, revoke keys or establish incident recovery. A later
failure may retain an imported/local-signed successor; inspect the reported
`keyring_may_have_changed` and actual state before retrying. No trust rollback or
old-key removal is automatic. Current external revocation remains unknown from
offline exports. Compromise requires independently authenticated incident
recovery, not reliance on an old-key handoff signature.

The installed private runtime is exactly eight original Python files: enrollment,
rotation, authenticated repository bridge, release transition, release comparison,
complete release verifier, optional declared-source association verifier, and
public signing-expiry inspection. `source-provenance.json` pins source paths,
revision, lengths and per-file SHA-256; `payload-map.json` lists exact installed
runtime identities. The deterministic private source archive preserves only
that finite closure. No checkout discovery, whole-repository runtime or network
source acquisition occurs. The launcher uses fixed `/usr/bin/python3 -I -B` and
resolves its private runtime relative to its own installation prefix.

Runtime dependencies are **Python >=3.11, gnupg, pacman, coreutils and libarchive**.
Python 3.11 supplies `sys.exception`, exception notes and file hashing; all Python
imports are standard-library imports. Package/database archive inspection uses
`bsdtar` from libarchive, including zstd-compressed inputs through libarchive's
compression support. This runtime neither imports `compression.zstd`/Python
tarfile nor runs a `zstd` executable, so it does not require Python 3.14 or a
separate zstd CLI. Pacman supplies pacman-key and vercmp; coreutils supplies
readlink/dirname and utilities used by pacman-key. Bubblewrap is a check-only
dependency for relocated tests with source trees hidden and networking isolated.

The recipe installs only the launcher, private Python files, documentation and
licenses. It has no `.install`, ALPM hook, service, `/etc` or `/var` payload;
building, installing/upgrading or removing the package does not enroll a
repository or alter existing trust/configuration. Invoking an explicit apply is
a separate operator action. Upgrading replaces the package's private runtime;
the old 0.1.0 private flat paths are removed by normal package ownership.

`check()` stages the actual package and moves the prefix. It exercises all
command help/version dispatch and a real signed TEST release transition,
including zstd-compressed package archives and declared source associations, with
the checkout/fixture source hidden and a loopback-only network namespace. It
checks unchanged target configuration/keyring bytes, tamper refusal, environment
isolation and an exact payload-removal inverse preserving foreign user content.
The fixture helper is check-only and is not installed. This host evidence does
not establish native ARM builds, ALPM installation/lifecycle on Asahi, supported
M2 behavior, production key custody/distribution or stable acceptance.

```bash
makepkg --verifysource
REPOSITORY_ENROLLMENT_HIDE_ROOT=/absolute/source/checkout makepkg --nodeps --cleanbuild --force
```

`--nodeps` skips dependency checks and never installs missing dependencies; ensure
the listed runtime/check tools already exist. A native clean-build pair and
actual target package/configuration/key lifecycle remain required separately.
