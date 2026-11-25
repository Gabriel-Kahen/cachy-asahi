# Maintenance recipe custody and source correspondence

## R132 custody recheck, November 25, 2026

Four of the six signed maintenance archives have exact PKGBUILD bytes.
The [offline recipe reader](../../scripts/port/supported-composition/index_maintenance_recipe_history.py)
matched both NetworkManager builds and the Perl and Python rollback builds.
The two forward builds still need original build-time inputs.

| Direction | Package version | Signed BUILDINFO recipe SHA-256 | Custody |
| --- | --- | --- | --- |
| Forward | NetworkManager 1.58.1-2 | `74938989e5a6eeac41350e05068aaabf4e9d7411116dcfe189d6cfae1b1b72a4` | Exact |
| Rollback | NetworkManager 1.58.1-1 | `10f0c0bd59e7598dfd34ad1658f90dd9537ce5fb41e5af916fa07214c68560af` | Exact |
| Forward | Perl 5.42.3-1 | `c2baa2348228937f72de62581cca687039a976ac2cef93928ee3909b18fa6ed7` | Held |
| Rollback | Perl 5.42.2-2 | `c8eb30f67445159807c70914c492a32326e65a92146c3d406e426bec8d15df41` | Exact |
| Forward | Python 3.14.8-1 | `b694b720c69f90803d20da64413f0573f61ea8582f20a09865ff91e1350196c0` | Held |
| Rollback | Python 3.14.7-1 | `24eb77be6752bdcb1a6459fb8177fa0d46becc18f54acf480441f4b6f3ca96b5` | Exact |

Both eight-file custody seals verified. The original archive join still binds
the six vendor archive and detached signature pairs. Its staged forward
NetworkManager and Perl archives moved out of the original paths. The replay
used the retained bytes in
`~/.cache/cachy-asahi-maintenance-disposable-guest-20261118/transport-r1/forward/`
after checking both sizes and SHA-256 values against the join. The temporary
join and configuration copies recorded the two changed archive paths and the
resulting enclosing reference and digest changes. The recipe reader rechecked
all six archive and signature pins and reproduced both retained receipts
byte-for-byte after reversing those path and digest changes. Signature evidence
for this replay comes from the original pinned archive join.

The fresh configuration copies and receipts are in
`~/.cache/asahi-r132-relocated-replay-20261125.c88p14rj/`.

| Replay receipt | SHA-256 |
| --- | --- |
| `buildtime.ACTUAL.json` | `f3e994a549b69ae9bdf3258aa71124dfaeedf7c94bc331258fc3e95445964356` |
| `history.ACTUAL.json` | `212fe7712378db915144dfc15b09361452f317bd20b03816fc543d5701d73684` |

The public workunit bodies held in
`~/.cache/asahi626-buildtime-source-recovery-DATA.lngnrOhm/` contain Python
3.14.10-1 and Perl 5.44.0-1. Their retained bytes, candidate recipes and checksum
append projections leave both forward hashes unresolved. Use the original final
PKGBUILD bytes for the two signed builds, or the original queued workunits with
the verbatim `makepkg -g` output for replay against the pinned Plugbuild client.
The unsent request draft and four exact recipe bodies are in
`~/.cache/cachy-asahi-r132-plugbuild-custody-20261118/actual/`.

A later November 25 search verified the retained recovery pack seals and
checked both required digests across its 795,235 file/member records.
Neither digest appeared. Anonymous public reads again returned newer
workunits, errors on the original builder log routes, no exact Software
Heritage object, and no Wayback availability at the signed build dates.
The exact Common Crawl retry returned HTTP 503, so that archive remains
inconclusive. The signed Perl and Python forward recipe gaps remain open.

| Later recovery evidence | SHA-256 |
| --- | --- |
| Recovery pack and public archive audit | `0532e40a9f7cdb79922019e147fc56094604019e83e6211384e8351a0e4ffe9f` |
| Fresh public body and response checks | `4a4b9592f051b92a70c13e13057670e49c2801889b5ad354e1dd677021474bfc` |
| Exact Common Crawl retry | `222886029858e32bc834fc1f4ce8a5804a3893d320943b8be21f434d180c9f47` |

Complete corresponding source, license review, production trust and support
approval remain open for the [626-package proposal](supported-composition-maintenance.md).
The [R132 guest record](../validation/asahi626-maintenance-emulated-arm16k-20261118.md)
covers the signed lifecycle in the emulated 16 KiB AArch64 environment.

## Candidate source intake, November 14, 2026

The original intake retained exact-version candidate packaging and source
materials for Python 3.14.8-1, NetworkManager 1.58.1-2 and Perl 5.42.3-1. Each
retrieved raw PKGBUILD differed from the signed archive's BUILDINFO recipe hash.
The pinned candidate materials can support a future maintained rebuild. The
[three archive records](supported-composition-update-inputs.md) describe that
intake.

## Recipe identification

The actual inspected archive BUILDINFO records require:

| Package | Required PKGBUILD SHA-256 |
| --- | --- |
| python | `b694b720c69f90803d20da64413f0573f61ea8582f20a09865ff91e1350196c0` |
| networkmanager | `74938989e5a6eeac41350e05068aaabf4e9d7411116dcfe189d6cfae1b1b72a4` |
| perl | `c2baa2348228937f72de62581cca687039a976ac2cef93928ee3909b18fa6ed7` |

Hashing 75484 retained files named PKGBUILD found no exact match. Official
metadata identifies the exact-version ALARM commits
[Python 373b5d20](https://github.com/archlinuxarm/PKGBUILDs/commit/373b5d20b459d1ca60712db4f50eafa0d053ee26)
and [NetworkManager f0465782](https://github.com/archlinuxarm/PKGBUILDs/commit/f04657820faf2fdaa99e33fbb4bf1352c637e46a).
Their raw PKGBUILD hashes are respectively
`d45168c0062a407bde36f31398733a5e799dac044041fd38f18e9f9da6620153`
and `c8110ce5d3e6c5c3556ed597bab3a0f4b600e649dbb869ddfb69d520b013908b`.
The [Arch Perl 5.42.3-1 recipe at commit 0264e08d](https://gitlab.archlinux.org/archlinux/packaging/packages/perl/-/raw/0264e08d302d7ae91c53d8bb78b9a7753c0ab67f/PKGBUILD)
hashes to `49d38142582afe912295a914a9a9d856367e7fd8e8d4cc1518a79cf40595ca48`.
These are candidate recipes with exact observed identities, not recovered
BUILDINFO recipes.

The three exact Arch version tags also failed correspondence. ALARM's
`core/perl/PKGBUILD` URL returned404; its path history records removal. A guessed
public builder-repository lookup also returned404. Those observations remain
in the request records. Fifty finite diagnostic raw/arch-line-replacement/
arch-line-append variants of the five exact-version candidate recipes also
failed. These diagnostics are not documented builder provenance and no
normalization was accepted. Further recipe archaeology was timeboxed.

## Retrieved DATA inputs

Thirteen objects were retrieved, totaling 59812321 bytes, under enforced limits
of 128 MiB/object and 512 MiB total. No object exceeded 24.2 MB. Earlier metadata
responses were individually capped at 2 MiB. No newer version or revision was
substituted on failure.

| Candidate source | Representation and exact pin | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Python | Official [Python 3.14.8.tar.xz](https://www.python.org/ftp/python/3.14.8/Python-3.14.8.tar.xz) | 24130644 | `c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73` |
| NetworkManager | [GitLab HTTP snapshot](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/archive/7406dfbcc35beed79bf2734e3e7376ead320bd99/NetworkManager-7406dfbcc35beed79bf2734e3e7376ead320bd99.tar.gz), commit7406dfbcc35beed79bf2734e3e7376ead320bd99 | 13056926 | `843306ad54a3006ef7a60ba62932a3a2015cc87d46bd438fd5ac906d952c88d6` |
| Perl | [GitHub HTTP snapshot](https://codeload.github.com/Perl/perl5/tar.gz/bc3dab4d4f66de5ea67dda34e5feb5230a54c603), commitbc3dab4d4f66de5ea67dda34e5feb5230a54c603 | 22610875 | `16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725` |

The Python release tarball, exact-commit `EXTERNALLY-MANAGED` and declared
`927eb448aad6436d794ec9f55780013e25609600.patch` all match the candidate recipe's
SHA512 declarations. Six Perl packaging files from the exact Arch packaging
commit also match declared SHA512 values: `config.over`, the three `perlbin`
shell files, and the old-module detector script/hook. These are nine direct
checksum comparisons.

The NetworkManager 1.58.1 tag metadata resolves to the named commit; Perl's
v5.42.3 annotated tag bfedb80da3c7c928c3acc902747d12b7c910948c resolves to its
named commit. HTTP source snapshots have independently observed size/SHA pins;
they are **not claimed equivalent to makepkg's Git-archive checksum
representation**. Tag signatures and external revocation/freshness were not
independently authenticated. The two additional Perl prepare commits
`568e6fd238867bb9e99fa3f47cba3169009239e0` and
`54cf3d44cbbedd17d774e9a37921963e8fd5d0cb` were retained as inert patch data with
their own observed SHA pins. No patches were applied.

Safe streaming archive inspection retained 14 regular notice-name candidates:
six Python, three NetworkManager and five Perl, including top-level Python
LICENSE, NetworkManager COPYING variants, and Perl Artistic/Copying. The Perl
name match also includes `t/porting/copyright.t`; a name match is not a legal
classification. All source archive paths were checked without materializing
their trees or following links. This non-exhaustive notice observation does
not establish source/license/grant completeness or legal acceptance.

## Existing-tool replay and retained evidence

No product adapter was needed. The discovery invocation fetched only inert
bytes. The existing source-delivery descriptor reader validated every observed
pin. Existing source-cache private publication APIs imported local copies;
cache receipt creation had transport explicitly disabled. The ordinary
source-cache CLI then verified all 13 objects offline. A real copied
EXTERNALLY-MANAGED cache object was corrupted, refused, restored, and the full
offline verification passed again. Every cache receipt keeps legal/source
completeness acceptance false and its revision explicitly UNBOUND.

The first one-off import caller confused an ID reader with a path reader. It
failed before publication/network. Its empty cache and diagnostic remain
retained; the corrected invocation used a new private cache.

Local ignored evidence lives under
`/home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-update-sources-20261114/`:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| source-inputs-report.json | 7941 | `acc2199dfc5281a728551806c489fe44dbcdc8073c44f4a8e164d58b42572cca` |
| materials-report.json | 23095 | `fe5746c1fe414c9167b477e2d5b331afbf3aff52c57e52202a7b46e0140ce981` |
| recipe-binding.json | 12682 | `637cce08a1a73d3c0952d3f4e2f49bc4bee88d38a82f840bba021ee51e2fdd40` |
| source-cache-inputs.json | 21819 | `e8c33e22fe95b02dff4dd795be779c038424db50d2270a0073d0bf7428a881a4` |
| cache-cli-verification.json | 5473 | `981dbbfacfa01a2970bfeae4454f59ac6b37ac4a5c5819d753e3c1cc2f6211e7` |

The report binds the invocation scripts, request records, prior exact archive
validation, candidate recipes/variants, source snapshots, patches, local files,
notice observations and cache inputs. `cache-cli-command.json` retains the exact
successful argv. From this worktree, repeat the offline check with:

```sh
base="$PWD/work/supported-composition-update-sources-20261114"
python3 -B scripts/maintenance/source_cache.py verify \
  --cache "$base/source-cache" --inputs "$base/source-cache-inputs.json" \
  --inputs-sha256 e8c33e22fe95b02dff4dd795be779c038424db50d2270a0073d0bf7428a881a4 \
  --max-bytes 536870912 \
  --id candidate-source-0 --id candidate-source-1 --id candidate-source-2 \
  --id candidate-source-3 --id candidate-source-4 --id candidate-source-5 \
  --id candidate-source-6 --id candidate-source-7 --id candidate-source-8 \
  --id candidate-source-9 --id candidate-source-10 --id candidate-source-11 \
  --id candidate-source-12
```

No upstream/package code, makepkg sourcing, build, install or native actor ran.
Recipe custody, binary correspondence, source/legal completeness, current
signature freshness, native execution, complete-system behavior and both M2
hardware acceptance gates remain held.
