# Copy a verified repository generation to offline storage

The existing [endpoint recipient](../../../docs/release/endpoint-client.md)
requires a manually copied generation. This command performs that copy from a
local disk, mounted transfer medium or already downloaded directory. It needs
neither the maintainer's original release store nor a signing key/GPG home.

Preview the exact selected generation and destination:

```sh
python3 -B scripts/release/endpoint_copy_v1/copy_endpoint.py \
  --generation /absolute/source-generation \
  --expected-generation "$GENERATION_SHA256" \
  --public-keyring /absolute/authenticated-public.gpg \
  --signer "$AUTHENTICATED_PRIMARY_FINGERPRINT" \
  --output /absolute/private-storage/new-generation
```

Add `--apply` to copy. The output must be absent, outside the source, and have an
existing caller-owned parent without group/world writes. Paths must be canonical
absolute paths with no symlink components. Select a concrete generation rather
than the producer's `current` alias. Any output basename is supported.

The command calls the current endpoint verifier before copying, verifies the
staged copy and source again, then publishes with the existing Linux atomic
no-replace helper. It verifies the published destination once more. All recorded
regular files, `export.json`, signed withdrawals and repository symlink aliases
are copied; parent directories are created as needed. It streams files without
extracting archives or running copied content. Directories are private `0700`
and copied files are read-only `0444`. Output is never merged into or substituted
for an existing directory, file or symlink. No repository `current` pointer is
changed.

Dry-run success prints `planned-local-endpoint-copy` with counts/bytes and
`output_created: false`. Apply success prints `copied-local-endpoint` and
`output_created: true`, retaining the existing verifier's observed selection,
withdrawals, repository route and verification flags. Both exit 0. Refusal exits
1 with JSON on stderr and no success record on stdout. A failure before
publication removes private staging. A post-rename I/O, custody or final-check
failure may leave a complete output; inspect that directory rather than retrying
with the same name. Source files and the external keyring are not modified.

This reuses the existing 16,384-member / 8 GiB tree limits and requires Python
3.11+, Linux flock/renameat2, GnuPG, bsdtar and vercmp. Nothing is downloaded or
installed by the command. Use controlled local storage: the shared source lock
is cooperative, and final checks do not prevent later filesystem changes.

The generation hash identifies an unsigned inventory snapshot. Authenticate it,
the full signer fingerprint and binary public certificate independently. Current
release/package/database/promotion signatures, complete release semantics,
source associations and real promotion/hardware gates remain mandatory. There
is no bypass option. A withdrawal-only generation can be copied without a
selected repository; its repository route remains null.

Copying does not establish freshness, discover newer withdrawals/revocations,
rotate keys, change trust/checkpoints, configure pacman, activate a repository or
authorize installation. Existing `freshness_established`,
`installation_authorized`, `production_accepted`, `network_used`, `trust_changed`
and `state_changed` flags remain false. Synthetic TEST fixtures do not establish
native ARM/M2, installed recovery, production trust or release acceptance.

```sh
python3 -I -B -Werror::ResourceWarning scripts/release/endpoint_copy_v1/test_copy.py -v
```

Focused tests reuse the existing endpoint/export fixtures with actual TEST-GPG,
repository metadata and filesystem operations. Positive synthetic stable cases
model only the existing hardware/promotion gate; the real CLI refuses that
synthetic stable release. Withdrawal-only CLI copying uses real signatures and
the unchanged real verifier without a hardware seam. The dedicated source-only
workflow also runs the existing endpoint recipient suite.
