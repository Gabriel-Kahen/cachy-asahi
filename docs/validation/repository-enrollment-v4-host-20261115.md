# Repository enrollment0.4.0-1 host package

The NEW unselected recipe `packages/tools/cachy-asahi-repository-enrollment-v4`
adds an installed fixed-argv `refresh` command. All nine0.3.0-1 private runtime
bodies remain exact; the only additional runtime body is `refresh.py`. The
source context is genuinely public commit
`b4ad0dee38c23b34c020e31fe98803bd6817e892`. No existing recipe, manifest, workflow,
qualified artifact or package selection changed.

Ordinary x86_64 host `makepkg --cleanbuild --force --noconfirm` passed with normal
runtime/build/check dependency checks enabled, without `--nodeps`, dependency
installation or package installation. `REPOSITORY_ENROLLMENT_HIDE_ROOT` selected
the complete development checkout for the source-hidden checks. Source sums,
check(), fakeroot package(), archive creation and final16-leaf payload byte
comparison all passed.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `cachy-asahi-repository-enrollment-0.4.0-1-any.pkg.tar.zst` | 54229 | `bd9693900dba3bb28a8575d14213deb05ea7f34eada411ba167d5b2ef8c3ba00` |
| `private-source.tar.gz` | 37798 | `3ad158d06e0a084bf734beac5b8e76d622e354fb690ae8bed4af67a60c44222b` |

The exact finite runtime contains ten files/153283 bytes. The package contains16
payload leaves: launcher, ten Python bodies, three documentation/provenance files
and two license/notice files, plus normal package metadata. `.SRCINFO` and
PKGBUILD pin all nine local source inputs. The deterministic USTAR/gzip member
map, body lengths/hashes/modes and inherited nine-body subset are checked. No
private key, hook, automatic configuration or trust action is packaged.

The actual check staged and moved the payload, hid the source checkout/bootstrap/
recipe trees, provided hostile Python environment variables, and isolated the
network to loopback. All five installed command help routes and the version
route worked. Real disposable signed transition preview/tamper refusal,
zstd/source-association verification and primary-revocation preview/non-revoking
refusal remained passing.

The relocated `refresh` entry point then processed an independently constructed
TEST renewal and new signing subkey. Its real signature failed before import;
preview preserved every target byte; mapped-root `--apply` completed normal
pacman-key public import and changed only the managed certificate hash. The
snapshot URL and global pacman configuration stayed exact. The new subkey
signature verified trusted afterward. A stale expected hash refused without
mutation; the observed successor hash/current certificate produced a no-op.
Removing every package-owned payload leaf preserved a foreign user file.

Three earlier check failures were retained privately: the inherited preview-only
keybox fixture lacked pacman-key's ordinary `pubring.gpg`; an unnecessary empty
legacy secret-ring file triggered GPG migration; and a no-op comparison initially
included the test's own intentional current-certificate replacement. The final
public-only fixture uses an initialized public ring and compares state after its
own input edit. Production runtime and security predicates were unchanged while
correcting these test-fixture issues. Only the final artifact above is build credit.

Existing dependencies supplied Python3.14.7-2, GnuPG2.4.9-3.1,
pacman7.1.0.r9.g54d9411-4, coreutils9.11-2.1, libarchive3.8.9-1.1,
bubblewrap0.13.0-1.1, util-linux2.42.4-1.1 and fakeroot1:1.37.2-3.1.
Release archive compression uses libarchive; Python compression.zstd is not a
runtime requirement. No signing key entered package/runtime/target payloads.

This establishes host package assembly, relocated CLI behavior and disposable
mapped-root trust/configuration changes. It is not an installed ALPM lifecycle,
native ARM build pair, accepted target dependency transaction, M2 validation,
production trust distribution or release acceptance. Those remain NOT RUN.
