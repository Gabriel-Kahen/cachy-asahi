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
