# Explicit primary revocation and repository quarantine

`scripts/repository/revoke.py` implements a local incident operation for the
currently managed `cachy-asahi` signer. It previews by default. Explicit `--apply`
disables the owned repository selection before importing a cryptographically
validated primary-key revocation. This is source CLI software, not an incident
service, production trust distribution or a packaged successor-enrollment flow.
It requires the existing sibling `enroll.py`, Python, GnuPG and `pacman-key`.

## Required operator inputs

Retain the exact original public certificate used for managed enrollment. Its
raw SHA-256 must match the managed include's `key-sha256`. Also obtain a complete
updated public certificate containing the selected primary's valid
self-revocation through the operator's authenticated incident process. The
custodian creates the revocation in their own controlled environment; this tool
never accesses private custody, generates a revocation or fetches a certificate.

Select the full uppercase primary fingerprint and exact original-certificate
SHA-256 explicitly. These caller pins identify the intended existing managed
selection. A valid primary self-revocation proves cryptographic authorization;
it does not establish independent incident authentication, freshness, publication
or that the operator has selected the latest available incident information.
The report marks external freshness `UNKNOWN`.

Both input files and their directories beneath the selected root must be
root-owned and non-writable by group/others. Files must be regular, single-link,
separate exports outside the live keyring. Symlinks, secret-key packets,
multiple primaries, foreign primary identities and non-revoking certificates are
refused. Binary public exports and one complete public ASCII armor block are
supported. Bare `.rev` files, subkey-only revocations and designated-revoker
certificates are outside this first version: it requires the selected primary's
own key-revocation signature. Missing exact original bytes are a blocker; a live
export or same-fingerprint file is not an interchangeable SHA-256 witness.

The initialized pacman keyring must already exist. Preview never initializes or
repairs a missing trust database. Alternate `--root` paths exist only for
mapped-root disposable validation; this is not a supported alternate-root
installer.

## Preview and apply

These variables are caller-selected values, not supplied production identities:

```sh
sudo python3 -B scripts/repository/revoke.py \
  --expected-current-fingerprint "$EXPECTED_PRIMARY_FINGERPRINT" \
  --expected-current-certificate-sha256 "$ORIGINAL_CERTIFICATE_SHA256" \
  --current-public-key /etc/pacman.d/operator-public.gpg \
  --revoked-public-key /etc/pacman.d/operator-revoked-public.gpg
```

Preview may need root privileges to read the protected files/keyring. It only
reads target state; public GPG inspection and merging occur in new private
temporary homes. Inspect the JSON report and its original/current identity,
updated-input SHA-256, validated import hash, verified revocation count and
current live revocation observation. Repeat with `--apply` to mutate the
explicitly selected root.

Every primary revocation packet from the updated export is individually merged
into a fresh, public-only copy of the exact original certificate. The selected
primary must become revoked, and real GPG `--check-sigs` must verify its
self-revocation. A colon/JSON declaration alone does not authorize the change.
A genuine foreign revocation appended to the selected certificate is refused,
even if a valid selected-primary revocation is also present. Tampering with the
selected revocation fails the actual cryptographic check.

The live import is a sanitized public export of the original certificate plus
only those validated primary revocation signatures. New user IDs, subkeys or
other updates in the candidate are not added by this operation. This follows
GnuPG's [revocation merge semantics](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html):
creating a revocation certificate and importing it to revoke a key are separate
operations. No secret keyring is copied into the validation homes.

## Quarantine and partial-state recovery

Apply obtains the existing pacman `var/lib/pacman/db.lck` exclusively and repeats
observed-file checks. An existing lock is preserved and causes refusal. The
expected primary and original certificate hash must exactly match the recognized
managed include; edited or foreign configuration is preserved for manual repair.

The owned Include block is removed from `pacman.conf` first. All unrelated bytes
are retained, and the exact managed include file remains **unselected** as the
quarantine/CAS record. No repository is selected before or during the subsequent
revocation import. The selected identity is imported through the existing
`pacman-key --add`, and the live selected primary must then be observed revoked.
No local signing, key deletion, base-key replacement or successor enrollment is
performed. The existing base public certificates and unrelated configuration
remain intact in the exercised cases.

This is not one atomic transaction. The report separates:

- `config_changed`: a known completed configuration replacement.
- `config_may_have_changed`: an attempted rename may have taken effect, including
  a directory-flush failure after rename.
- `repository_enabled`: the observed post-error selection, or `null` if unsafe or
  damaged state prevents inspection.
- `quarantine_record_preserved`: whether the exact selected identity/pin is still
  observable in the owned record, or `null` when it cannot be inspected.
- `keyring_may_have_changed`: import was attempted and may already have succeeded.
- `revocation_confirmed`: live revoked state was explicitly confirmed.

If quarantine succeeds but import fails, the repository stays disabled. If
import succeeds before a later failure, the key may already be revoked even
though confirmation was not reached. Keep the include and both public inputs;
inspect actual state and retry the same exact pins. A completed retry is a no-op
when the repository is already disabled and the selected primary already
revoked. No failure automatically re-enables a repository or rolls back trust.
Do not run enrollment to bypass partial quarantine.

After successful revocation, existing enrollment with the old original
certificate cannot re-enable the repository: importing old public material does
not remove the existing revocation, and the old key fails the trust check.
Separately authenticated replacement trust requires its own reviewed recovery
process. Disabling/removing the quarantine record alone is not that process.

The selected primary's revoked state applies throughout the shared global pacman
keyring, including other uses of that identity. This operation does not withdraw
remote releases, repair installed packages, distribute an advisory, disable
signature verification or restore a boot/session. Retained artifacts signed only
by the revoked primary need separate incident handling.

## Actual validation

```sh
python3 -B -Werror::ResourceWarning scripts/repository/test_revoke.py
```

The focused suite uses real disposable TEST keys, GPG signatures/revocations and
`pacman-key` under mapped-root user namespaces. No host-root fallback or actual
host trust/configuration mutation occurs. On November 14, 2026, all 12 cases
pass in 31.1 seconds with zero skips on the development host. They exercise read-only preview,
initialized-keyring refusal, successful quarantine/import, real `REVKEYSIG`,
no-op repetition, existing-enrollment refusal, already-revoked current keys,
exact primary/certificate CAS, binary/armored exports, secret/multiple/foreign/
non-revoking/tampered input refusal, foreign locks and unsafe files, preserved
base keys/unrelated bytes, concurrent edits, failed import, actual import followed
by injected failure, and post-rename flush uncertainty with successful retries.

These disposable software results do not qualify authenticated remote
revocation delivery, production freshness/custody, client convergence, a complete
incident response, native ARM, M2 hardware or release acceptance. Packaging and
integration into a supported incident workflow remain separate work.
