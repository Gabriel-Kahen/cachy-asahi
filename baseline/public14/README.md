# Retained public ARM development inputs

Fourteen unchanged upstream public ALARM archive/signature files (seven packages), retained for the existing frozen native345 and desktop574 development inputs. Total original binary/signature bytes: **4,123,282** (about3.93MiB). Nothing is rebuilt, repacked, installed, executed or resigned here. These are CI data, not project-built packages, a supported system or a production release.

Locked mirror requests failed with404 in producer38818723463, audio auxiliary38820239504 or transaction16 actual38820921623. Exact held copies were checked against unchanged native345 lock beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f and desktop574 lock b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9. Original signatures are retained. Byte checks are not fresh GPG authentication; native signature gates remain mandatory.

| Original file | Bytes | SHA256 | Locked origin |
| --- | ---: | --- | --- |
| curl-8.22.0-1-aarch64.pkg.tar.xz | 1281188 | `5461bb97fca88b237d17db833622789eedca390634a6d2fb2e3b71287e52acb2` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/curl-8.22.0-1-aarch64.pkg.tar.xz |
| curl-8.22.0-1-aarch64.pkg.tar.xz.sig | 566 | `2523ff1b88dfc1ed910ad90d44c04387a86c397bf8043b518cad1c33dd9524e8` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/curl-8.22.0-1-aarch64.pkg.tar.xz.sig |
| libarchive-3.8.9-1-aarch64.pkg.tar.xz | 513496 | `030848f1d81d2558f3efacbf7d435f53f8809266c22d4744354ed90f8f46fe4d` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/libarchive-3.8.9-1-aarch64.pkg.tar.xz |
| libarchive-3.8.9-1-aarch64.pkg.tar.xz.sig | 566 | `f8153448fa459fe3fd7eb65f0741b14352af77f9d32634b49f85bba5fc68f247` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/libarchive-3.8.9-1-aarch64.pkg.tar.xz.sig |
| openssh-10.6p1-1-aarch64.pkg.tar.xz | 1228712 | `28522c0cb098994889b8186315f7629bf1d75931487f16a237dd3e93bbdbaa10` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/openssh-10.6p1-1-aarch64.pkg.tar.xz |
| openssh-10.6p1-1-aarch64.pkg.tar.xz.sig | 566 | `2b6ebf8553f7b10ba22f768adc7dbcbd00ce983364a0000f85ed13d11cb44ac1` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/openssh-10.6p1-1-aarch64.pkg.tar.xz.sig |
| pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz | 904012 | `0e7a5a731727b50e5453f9946afed63456ca6d7015ec0044426489dc78134e3d` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz |
| pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz.sig | 566 | `86824e704f0f19a7e065b63a8e553c9cadf3b4c49dbeb3f367435d2f557ac26f` | https://ca.us.mirror.archlinuxarm.org/aarch64/core/pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz.sig |
| uwsm-0.27.0-1-any.pkg.tar.xz | 87248 | `d7efdda151008fa354ade5276b8ff92f9682c63f9a749304ae91ccd36cf19549` | https://ca.us.mirror.archlinuxarm.org/aarch64/extra/uwsm-0.27.0-1-any.pkg.tar.xz |
| uwsm-0.27.0-1-any.pkg.tar.xz.sig | 566 | `651f3022fc7b4e78e698685d2ae89c85f45935e55e1f453b78bf84148f5ac767` | https://ca.us.mirror.archlinuxarm.org/aarch64/extra/uwsm-0.27.0-1-any.pkg.tar.xz.sig |
| xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz | 27344 | `6cc9149138662041aa13c6ec027c074c67ee411848e38c349232acd9d97fca98` | https://ca.us.mirror.archlinuxarm.org/aarch64/extra/xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz |
| xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz.sig | 566 | `cb12e8a377cd9a8f4718faa270f7b5ca0834e7b72b70c073338f57bfea31b4d3` | https://ca.us.mirror.archlinuxarm.org/aarch64/extra/xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz.sig |

## Additive zlib pair for desktop574

Actual38852742618 failed acquisition of the unchanged zlib1:1.3.2-3 pair at its pinned ca.us URL. The original twelve source rows/bytes are unchanged. The two appended files match the frozen desktop574 input row and both retained local copies exactly:

| Original file | Bytes | SHA256 |
| --- | ---: | --- |
| zlib-1:1.3.2-3-aarch64.pkg.tar.xz | 77320 | `7e31b465e09e8e61375578b8e26ed883906e126e0c0ef1c75b7ccccfa95a58c4` |
| zlib-1:1.3.2-3-aarch64.pkg.tar.xz.sig | 566 | `ec8d454359ded82cd5dfe368de1cb16303e88ca2b180fba9bcb44ba75a6a7e9d` |

Declared license Zlib, dependency glibc, project https://www.zlib.net/. Locked origin is https://ca.us.mirror.archlinuxarm.org/aarch64/core/ with these exact filenames. Existing retained acquisition notes also record byte-identical files from the Archboot October2026 release archive; that is provenance context, not a new mirror or trust policy. No new download or signature verification was performed for this additive proposal. The prior twelve rows' joint native345/desktop574 joins remain unchanged; the new pair was checked against the exact desktop574 input row here.

## Declared licenses and source association limits

| Package | Declared licenses | Recorded project URL |
| --- | --- | --- |
| libarchive | BSD-2-Clause; BSD-4-Clause-UC; Apache-2.0 OR CC0-1.0 OR OpenSSL | https://libarchive.org/ |
| pacman | GPL-2.0-or-later | https://www.archlinux.org/pacman/ |
| uwsm | MIT | https://github.com/Vladimir-csp/uwsm |
| openssh | 0BSD; BSD-2-Clause; BSD-3-Clause; ISC; LicenseRef-Public-Domain; MIT | https://www.openssh.com/portable.html |
| xorg-server-common | LicenseRef-Adobe-Display-PostScript; BSD-3-Clause; LicenseRef-DEC-3-Clause; HPND; LicenseRef-HPND-sell-MIT-disclaimer-xserver; HPND-sell-variant; ICU; ISC; MIT; MIT-open-group; NTP; SGI-B-2.0; SMLNJ; X11; X11-distribute-modifications-variant | https://xorg.freedesktop.org |
| curl | curl | https://curl.se/ |

All original archive members and notices remain intact. Package-specific license/notice members were found for libarchive, uwsm, openssh, xorg-server-common and curl. Pacman declares GPL-2.0-or-later but this archive has no package-specific usr/share/licenses/pacman member. The retained coordinator audit records notice-member hashes.

Recorded versions/project URLs associate binaries with upstream projects; they do not establish complete corresponding-source, packaging-recipe, patch or license closure. This source tree does not include corresponding source archives or claim that every publication/source obligation is resolved. Any required source/notice accompaniment remains a coordinator responsibility. No new upstream sources were retrieved to fill those gaps. This supplies no affiliation, target/M2 compatibility or release acceptance claim.

## Exact seed use

Desktop, audio and measurement workflows can select the same new immutable asset commit and run this same seed.py. The interface remains only --cache; each workflow keeps its existing private build-cache destination and commands. For the maintained desktop574 workflow that destination is "$RUNNER_TEMP/desktop574/context/deps". The index retains the exact native574 input-lock SHA256 b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9. There is no job-specific logic or new secret.

Select this isolated source with a full immutable40-hex commit through the already pinned actions/checkout action, then run `python3 -I -B retained-public-inputs/seed.py --cache "$RUNNER_TEMP/alarm-cache"` before early native acquisition. The stdlib-only script verifies the fixed index and all fourteen source files, then validates existing same-name cache entries before copying missing ones. It preserves unrelated cache files and never overwrites an existing target. An interrupted publish may leave a valid prefix; the next invocation checks every file again. It does not claim atomic publication of the whole set.

The fixed index is SHA256-bound in seed.py. Source symlinks, missing/extra source files, mismatched bytes, unsafe cache directories and existing conflicting targets fail. No downloader, new secrets, mirror fallback, package installation, whole574 rehost or version/lock/signature-policy change is introduced. Both early native345 and later desktop574 consume this same existing cache. Existing producer/downstream/trust/payload gates stay unchanged.

The complete source consists only of fourteen original input files, index.json, seed.py, test_seed.py and this README (eighteen files). Root owns commit creation, publication and CI dispatch. Tests use copied file fixtures; no package content is executed.
