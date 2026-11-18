# Verify the declared install inventory of an offline development kit

Use this check before staging a transaction from a portable development kit.
The existing kit receiver authenticates the release, repository databases,
selected package archives and opaque lock evidence. This command also checks
whether the signed base inventory and overlay describe the exact name/version
set in an independently selected target lock.

```sh
python3 -I -B scripts/release/install_inventory/verify.py \
  --kit /absolute/received-kit --kit-sha256 "$EXPECTED_KIT_SHA256" \
  --signer "$AUTHENTICATED_FINGERPRINT" --namespace "$EXPECTED_NAMESPACE" \
  --minimum-sequence "$SEQUENCE_FLOOR" --state-dir /absolute/receiver-state \
  --target-lock /absolute/target.lock --target-lock-sha256 "$EXPECTED_LOCK_SHA256"
```

Use the verifier from a trusted checkout. The kit pin, signer, namespace,
sequence floor, checkpoint and target lock pin are external inputs. The command
reads the existing portable format and never executes the receiver carried in
the kit. The lock is the existing pacman `-Q` name/version format, one record per
line with a single ASCII space and a final newline. Order does not affect the
comparison. The exact supplied bytes must match the independently selected hash.
Duplicate names, non-ARM package records and stale or changed inputs are refused.
The target lock and declared base are bounded to 1,024 package records each. The
existing offline-kit file, size and overlay count limits still apply.

After cryptographic kit inspection, the command re-reads the signed release,
spec and base documents and verifies their digests before using their contents.
The two base references and snapshot IDs must agree. Selected overlay packages
replace the corresponding declared base packages by name. Protected base names
must remain present and cannot be replaced by the overlay. The comparison
reports missing, extra and version-mismatched package names. Success returns a
`matched-development-install-inventory` JSON receipt with the signed release,
base and external target-lock hashes and the three package counts. A refusal
exits 1 with a diagnostic on stderr and no success receipt.

This checks declared names and versions and retains the existing kit's package
and database signature checks. The target lock carries no archive hash or
architecture. Base-archive availability, dependency solving against an actual
target, package installation, trust changes, production release acceptance and
M2 validation remain outside this check.

The tests use genuine disposable TEST signatures. They also use the exact
retained generic ARM4K/ARM16K TEST607 name/version lock and verify that a
different signed kit cannot satisfy it. The retained decision does not carry
the complete signed TEST607 archive cache needed to authenticate that actual
candidate again.

```sh
python3 -I -B scripts/release/install_inventory/test_verify.py
```

## Resolve a staged install offline

Use `preflight.py` when the installer has both a portable overlay kit and a
staged ALARM base repository. It uses the existing base `staging.json` and
`staging.json.sig`, immutable ALARM archive lock, and overlay kit formats. Supply
all pins and both repository fingerprints from the caller's trusted handoff.
Supply the base repository's binary public export separately. The archive lock
pins the original ALARM fingerprint, public key files, package archives,
detached signatures, and root filesystem. The base directory contains `repo/`
and the root filesystem and key files at the paths named in that lock.

```sh
python3 -I -B scripts/release/install_inventory/preflight.py \
  --kit "$KIT" --kit-sha256 "$KIT_SHA256" \
  --namespace "$NAMESPACE" --signer "$OVERLAY_SIGNER" \
  --minimum-sequence "$SEQUENCE_FLOOR" --state-dir "$RECEIVER_STATE" \
  --target-lock "$TARGET_LOCK" --target-lock-sha256 "$TARGET_LOCK_SHA256" \
  --base-repository "$BASE_REPOSITORY" --base-lock "$BASE_ARCHIVE_LOCK" \
  --base-lock-sha256 "$BASE_LOCK_SHA256" --base-receipt-sha256 "$BASE_RECEIPT_SHA256" \
  --base-signer "$BASE_SIGNER" --base-public-keyring "$BASE_PUBLIC_KEYRING"
```

The preflight checks the declaration, verifies the detached signatures of all
selected archives, rechecks both signed repository indexes, and compares the
package records and embedded signatures in the sync databases. It then asks
pacman to print the complete `aarch64` transaction with `Required TrustedOnly`,
using private public-key trust and an empty scratch root. The result binds each
resolved name and version to its expected repository. The archive and root
filesystem byte budget is 2 GiB, with one private archive snapshot at a time.
Python, GnuPG, bsdtar and pacman must already be installed.

Success emits `verified-offline-install-preflight` and the exact plan SHA-256.
Add `--include-package-inventory` to include the verified, name-sorted
`package_inventory` in the same receipt. Each row records the resolved name,
version, architecture, repository, archive filename, archive SHA-256 and
detached signature SHA-256. When the overlay replaces a base name, the receipt
lists the chosen overlay archive, even if the two packages share a version.
The default receipt omits the inventory.
Refusals emit diagnostics without a success receipt. The command downloads
nothing, installs nothing, and leaves caller trust and receiver state untouched.
The result is scoped to the inspected inputs and does not establish a supported
Asahi installation, M2 validation, or release admission.
