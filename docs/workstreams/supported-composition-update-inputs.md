# Exact three retained maintenance archive inputs

November 14, 2026. The three exact updates in the [unapproved 626-package
maintenance proposal](supported-composition-maintenance.md) now have freshly
checked, retained archive/signature inputs. **Input validation passes; the
maintenance proposal and complete supported-system result remain HOLD.**

No acquisition adapter was needed. Existing `authenticate_missing.archive_spec`,
`bound_bytes`, `verify`, `pkginfo`, `archive_coverage.expected`,
`authenticate.observe`, and `package_checks.elf_check` compose for this finite
DATA check. No network requests, package execution, installation, native actor,
image assembly, shared-policy edits or publication occurred.

## Exact bytes and custody

All archives are `aarch64.pkg.tar.xz`; each detached signature is 566 bytes.

| Package | Version | Archive bytes | Archive SHA-256 |
| --- | --- | ---: | --- |
| python | 3.14.8-1 | 13588352 | `5e00dbb30ab55fd160d64205e1f3418c8bcf5b295ff07bf9af7ad4ab85bc6984` |
| networkmanager | 1.58.1-2 | 3635024 | `f33cae0f6f19f33eea879cec1db3fe7c90d0b80931e8f5b67b9391adf7185754` |
| perl | 5.42.3-1 | 16017184 | `f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f` |

| Package | Detached signature SHA-256 |
| --- | --- |
| python | `ee28ca566685118f6048b859691802ddc6a1c0772581371a7d9cab2d3405c2f0` |
| networkmanager | `bebccab9c829f4d0b8e2278084c71fa99fdd8250c9dfb5330265813b9ebc4ca5` |
| perl | `f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca` |

The catalog references are the original retained
`artifacts/platform/target-metadata-20261012/core.db` (256696 bytes,
`5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08`)
and `extra.db` (10613897 bytes,
`66cfbeae024c325e19ba7334afcb0ff2ab892ba4f0789216b358648f7647b480`)
in `/home/gabe/Documents/ChatGPT/cachy-asahi`. The invocation rechecks these
references before selecting the exact named entries. Archive size/SHA and
detached-signature size/SHA match their catalog fields, including the embedded
signature bytes. Catalog signature authentication is not established by this
check.

Python and Perl came from the retained
`artifacts/platform/coordinated-python-20261012-auth/cache/`; NetworkManager came
from `artifacts/maintained-desktop-authentication-current2-run-20261015-actual01/tmp/cachy-asahi-port-auth-cache/`.
The report records complete source paths and independent private copies of all
six files. There were no version substitutions or network freshness checks.

## Actual checks and limits

`gpgv` independently verifies each archive in a temporary public-only keyring
under primary `68B3537F39A313B3E574D06777193F152BDBE6A6`. The retained
`coordinated-python-20261012-auth/keys/alarm.gpg` is 3098 bytes, SHA-256
`6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f`,
separately bound by `authenticate_missing.KEYS`, rather than selected from the
package's claimed signer. This proves mathematical signatures under that
retained identity. Independent owner authority/trust is not accepted here;
current external revocation/freshness remains unknown. A fresh verification
operation does not refresh the certificate's external status.

Actual `.PKGINFO` identity, architecture, dependency, provides, conflicts,
replaces and license declarations match the exact catalog records. Safe archive
inspection retains file/link, `.BUILDINFO`, scriptlet/hook and license-notice
observations without extracting or executing the payload.

| Package | Inspected paths | ELF files | Static AArch64/16K errors | Unexecuted hooks |
| --- | ---: | ---: | ---: | ---: |
| python | 3198 | 81 | 0 | 0 |
| networkmanager | 368 | 18 | 0 | 0 |
| perl | 3231 | 54 | 0 | 1 |

The existing structural validator examines ELF64 machine/program headers and
`PT_LOAD` size/alignment/congruence. These 153 static observations do not
establish execution, ABI-consumer compatibility, native build provenance,
recovery, installed-system behavior or M2 acceptance. Perl's retained
`usr/share/libalpm/hooks/detect-old-perl-modules.hook` is 229 bytes, SHA-256
`c96c0b5ea4874f8ef6a1582d3389ad5ce566bc316de411e14bf2fb870510507f`;
it was not run. None of the three archives contains a regular file under
`usr/share/licenses/` according to the existing observer. Declared licenses
remain recorded; corresponding source, license/grant closure and maintainer
acceptance remain holds.

Real negative controls changed only a copied signature or the expected version:
the damaged Python signature was rejected with verifier exit1 and each of the
three wrong-version expectations refused with `PKGINFO mismatch: pkgver`. Raw
GPG statuses/diagnostics and all structural observations remain in the report.

## Reproduce this retained invocation

The one-off evidence script and outputs are local ignored artifacts, not a new
product adapter. The script invokes the existing DATA APIs, caps CPU/address
space, disables core dumps and creates an exclusive private output. From
`/home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114`, the actual
command was:

```sh
python3 -B work/supported-composition-inputs-20261114/validate-retained.py \
  /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-inputs-20261114/result
```

Repeat with a new absent output path. The retained invocation script is 8416
bytes, SHA-256
`a942d7d3df7b1bdfc3c61fa9b8d7f4b51c0061133e721e0dca5246ec02c048a8`.
It uses the existing validators at source commit
`b532fa76c17a57b25066b8e8f5b48c8857d85941`; their exact hashes also appear in the
report.

`work/supported-composition-inputs-20261114/result/validation.json` is 15842
bytes, SHA-256
`b09a3198d4433543d8616e5c423cd88fcd47e7a19c099aa05059127d8f1749a7`.
Its `packages[].archive.private_copy` and `signature.private_copy` references
point to the six exact usable files under `result/cache/`. It also binds the
public certificate, `.PKGINFO` bytes, detailed payload/ELF observations and
retained source paths. The original protected-policy failure and explicit
UNAPPROVED maintenance proposal remain unchanged. These inputs close this
three-archive availability/inspection gap; they do not authorize the proposed
626-package transaction or supply the remaining system's evidence.
