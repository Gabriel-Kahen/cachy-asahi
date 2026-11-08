# cachy-asahi-release-tools 0.3.0-1

Opt-in, independently versioned successor adding an installed
`cachy-asahi-release-tools endpoint-copy` command. The current inventory still
selects neither this package nor a release; inventory adoption remains separate.
The v1/v2 package directories and all historical/native Sources are unchanged.

```sh
cachy-asahi-release-tools --version
cachy-asahi-release-tools endpoint-copy --help
cachy-asahi-release-tools endpoint-copy \
  --generation /absolute/source-generation \
  --expected-generation "$GENERATION_SHA256" \
  --public-keyring /absolute/authenticated-public.gpg \
  --signer "$AUTHENTICATED_PRIMARY_FINGERPRINT" \
  --output /absolute/private-storage/new-generation
```

Preview verifies the source and prints counts without creating output. Add
`--apply` to copy. The output must be absent and disjoint from the source, with
an existing caller-owned parent without group/world writes. Paths are canonical
absolute paths without symlink components; select a concrete generation rather
than a producer's `current` alias.

The exact, unchanged PR382 copier verifies source/staged/published views using
the retained endpoint verifier, streams all recorded files and withdrawal
records, preserves repository aliases, and atomically publishes without
replacing a destination. Directories are `0700`; copied files are `0444`.
Failures before publication remove private staging. A post-rename failure may
leave a complete output for inspection. Source and external keyring stay intact.
Output exit/status behavior is the original copier's: preview/apply success 0;
refusal 1 with JSON stderr and no success stdout; argument errors 2.

The generation hash identifies an unsigned inventory snapshot. Authenticate the
hash, full primary fingerprint and binary public certificate independently.
Current signature, release/source, promotion and actual hardware checks remain
mandatory; there is no bypass. Withdrawal-only generations retain a null
repository route. Copying does not establish freshness, newer withdrawals or
revocations, installation authority, production trust, native ARM/M2 behavior,
recovery or release acceptance. It does not configure pacman, change trust or
checkpoints, activate repositories, fetch data or run copied package content.

The five original commands retain their original 0.2 implementation and frozen
profiles: `sbom`, `source-export`, `recipe-pack`, `recipe-unpack`, `sbom-compare`.
Their exact launcher and seven Python modules are retained beneath the private
`legacy-v2/` prefix. The new launcher forwards their original arguments and exit
codes through isolated Python. Endpoint-copy uses a separate seven-file current
runtime beneath `endpoint-current/scripts/`; the two helper versions are not
mixed. Both trees derive paths from their own installed location and continue
working after moving the entire prefix, without checkout reads.

Dependencies are Python >=3.14, zstd, gnupg, libarchive and pacman. Endpoint-copy
uses `gpg`, `bsdtar`, `vercmp`, Linux flock/fsync and libc renameat2; old commands
retain zstd. No dependency is installed automatically by a runtime command.
`source-provenance.json` records all 15 exact MIT code origins/revisions/hashes,
including the copier from PR382. `payload-map.json` declares all 21 installed
paths, source bytes and modes. The package retains the project MIT license and
notices; external executable dependencies retain their own licenses.

```sh
python3 -I -B check_package.py --recipe-root "$PWD"
python3 -I -B -Werror::ResourceWarning test_package.py --recipe-root "$PWD"
makepkg --verifysource
makepkg --cleanbuild --nodeps --nosign --noconfirm
```

Run build commands only in a separately provisioned private build copy. They do
not install the package. Runtime/test sources are local and individually pinned
in PKGBUILD/.SRCINFO; test fixtures include an unchanged complete 0.2 recipe.
Tests use real TEST-GPG/filesystem operations. Positive synthetic stable API
cases model only the existing hardware gate; real CLI stable refusal and
withdrawal copying use unchanged verification. Moved-prefix Python observation
is limited to the selected interpreter's stdlib, retained prefix and explicit
case directories; it is not a claim to audit external GPG internals or an execv
boundary. Synthetic fixtures remain host evidence.

The same package name upgrades 0.2 to 0.3 using normal package ownership. A
downgrade to retained 0.2 restores its old launcher/runtime. Removal owns only
the 21 declared files and leaves operator outputs outside the prefix alone.
There are no hooks, services, configuration files, signing actions or host
installation in this candidate. Private staging/upgrade/inverse tests and a host
`any` package build are separate from native ARM/16K, ALPM lifecycle, installed
target and physical M2 validation; those remain NOT RUN for this version.
