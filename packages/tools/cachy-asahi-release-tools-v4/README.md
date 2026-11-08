# cachy-asahi-release-tools 0.4.0-1

Opt-in successor adding installed `endpoint-pack` and `endpoint-unpack`
commands for portable, verified repository generations. The v1–v3 recipes,
source helpers and historical/native Sources remain unchanged. Selection and
canonical inventory adoption are separate coordinator decisions.

```sh
cachy-asahi-release-tools endpoint-pack \
  --generation /absolute/source-generation \
  --expected-generation "$AUTHENTICATED_GENERATION_SHA256" \
  --public-keyring /absolute/authenticated-public.gpg \
  --signer "$AUTHENTICATED_PRIMARY_FINGERPRINT" \
  --output /absolute/private-storage/new-endpoint.tar

cachy-asahi-release-tools endpoint-unpack \
  --archive /absolute/transferred-endpoint.tar \
  --archive-sha256 "$INDEPENDENTLY_RETAINED_ARCHIVE_SHA256" \
  --expected-generation "$AUTHENTICATED_GENERATION_SHA256" \
  --public-keyring /absolute/authenticated-public.gpg \
  --signer "$AUTHENTICATED_PRIMARY_FINGERPRINT" \
  --output /absolute/private-storage/new-generation
```

Pack verifies the generation, writes a canonical plain USTAR archive and returns
its SHA-256 in JSON. Retain and authenticate that digest independently before
unpacking. The generation hash identifies an unsigned inventory: authenticate
it, the binary public certificate and full primary fingerprint separately.
Both commands enforce the current signature, release/source, promotion and
actual hardware guards; there is no bypass. A withdrawal-only generation can
be transported with a null repository route. Transport does not establish
freshness, newer withdrawals, installation authority or production trust.

Archive entries contain only regular files: `export.json` first, then the
inventory's sorted files. Directories and inventory-bound repository aliases
are reconstructed in private staging. The unchanged merged PR396 transport
rejects links, special files, PAX/GNU/sparse extensions, noncanonical headers,
unexpected members, hashes, sizes, padding and trailing data. It streams in
64 KiB chunks with the existing member/payload limits and a deadline checked
between I/O operations. Unrepresentable USTAR paths or sizes are refused.

Outputs must be fresh canonical absolute paths, disjoint from input, beneath
an existing caller-owned parent without group/world writes. Select a concrete
generation, not a producer's `current` alias. Archive files are published `0444`;
unpacked directories are `0700` and files `0444`. Publication is atomic and
does not replace existing entries. Prepublication failure cleans private
staging; failure after rename can leave a complete output for inspection.
Success exits 0 with JSON, refusal exits 1 with JSON stderr and no success
stdout, and argument errors exit 2.

`endpoint-copy` retains its existing preview/`--apply` interface. The five
original commands—`sbom`, `source-export`, `recipe-pack`, `recipe-unpack`,
`sbom-compare`—retain their exact 0.2 launcher and seven frozen helpers under
`legacy-v2/`. The current endpoint tree is separate. All derive paths from the
installed prefix and work after moving that prefix without checkout imports.
Before either new archive command imports code, the launcher verifies fixed
size/SHA-256 pins for the nine current endpoint files, including the transport
and its dependency manifest. The transport independently verifies its seven
unchanged helper pins.

`source-provenance.json` records exact paths, revisions, licenses, sizes and
hashes for all 17 retained runtime files. The transport and manifest come from
PR396 head `a6a9f947f889175925b86c4e8b337d116429bd28`, merged as
`cb90e05e1ffbf262353a874a5b598aa1939799b3`. `payload-map.json` declares
23 installed files and modes. All retained project sources use the included
MIT license. External dependencies—Python >=3.14, zstd, GnuPG, libarchive and
pacman—retain their own licenses. No command installs dependencies, fetches
data, signs content, activates repositories, changes trust/checkpoints or
executes transferred package content.

```sh
python3 -I -B check_package.py --recipe-root "$PWD"
python3 -I -B -Werror::ResourceWarning test_package.py --recipe-root "$PWD"
makepkg --verifysource --nodeps --nosign --noconfirm
makepkg --cleanbuild --nodeps --nosign --noconfirm
```

Use a separately provisioned private build copy. All 31 flat source inputs are
local and individually pinned by PKGBUILD/.SRCINFO. Test-only archives preserve
complete unchanged 0.2 and 0.3 recipes; neither is installed. The dedicated
workflow runs real TEST-GPG/filesystem controls, relocated installed CLI paths,
archive integrity/refusals and exact legacy comparisons without skips. Positive
synthetic stable API cases model only the existing hardware gate; real CLI
stable refusal and signed withdrawal transfers keep verification unchanged.
Moved-prefix Python observation allows only the selected interpreter's
stdlib/platstdlib, retained prefix and explicit fixture/output/private GPG
directories. It does not audit GPG child internals or across legacy execv.

The same package name supports a normal version upgrade. Downgrade restores
the prior package's exact launcher/runtime; removal owns only the declared
payload and preserves operator outputs outside the prefix. There are no hooks,
services or configuration files. Private file-ownership inverse and host `any`
archive verification are distinct from dependency resolution, native ARM/16K,
ALPM lifecycle, target installation and physical M2 tests. Those remain NOT RUN
for this version. Performance is NOT MEASURED; release is NOT ADMITTED.
