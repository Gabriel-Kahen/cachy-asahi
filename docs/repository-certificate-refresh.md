# Refresh an enrolled repository certificate

`scripts/repository/refresh.py` implements planned expiry renewal and addition of
signing subkeys under the **same** trusted primary fingerprint. Preview is the
default. Explicit `--apply` imports public updates, then replaces only the managed
include's public-certificate hash. It keeps the selected snapshot URL and strict
package/database signature policy. It does not fetch, install packages, change
a release selection, delete keys, or request local signing.

The existing enrollment and rotation implementations remain unchanged. Rotation
still handles a different primary; revocation still uses quarantine. This new
command is source tooling, not included in the frozen enrollment package recipes.

## Inputs and use

Independently authenticate the complete successor public certificate and unchanged
primary fingerprint. Retain the exact previous public certificate whose SHA-256
appears in the managed include. Both files must be separate from the live keyring,
under the selected root, single-link ordinary files with safe ownership and modes;
all ancestors must satisfy the existing enrollment path rules. Apply requires a
root-owned selected root and root privileges. Alternate roots are for disposable
tests, not a general chroot installer.

```sh
python3 scripts/repository/refresh.py \
  --fingerprint "$UNCHANGED_PRIMARY_FINGERPRINT" \
  --expected-current-certificate-sha256 "$CURRENT_CERTIFICATE_SHA256" \
  --current-public-key /srv/cachy-asahi/current-public.asc \
  --public-key /srv/cachy-asahi/renewed-public.asc
```

Inspect the preview, then run the same command as root with `--apply`. The managed
fingerprint and certificate hash must still match the expected values. The
repository must already be enabled with an initialized, safely owned pacman
keyring and a fully trusted, currently usable certificate. Missing trust, expired
or revoked current primary, disabled enrollment, edited policy, unsafe paths and
an existing pacman transaction lock refuse. This is planned renewal before
expiry; it does not repair an incident or silently weaken expiry/revocation policy.

The retained old input must match the managed hash exactly. Both inputs must
contain exactly one public primary with the expected fingerprint and a currently
usable signing key. Secret, extra-primary, revoked and expired candidates refuse.
GPG evaluates validity using the real process clock, including again inside the
transaction lock. The tool supplies no artificial `as-of` date and cannot establish
that the machine clock is correct or that a successor is the newest certificate
available elsewhere.

## What is checked and changed

Isolated public-only scratch keyrings import the retained old certificate, the
candidate, and the existing trusted certificate. GPG's `export-minimal` views must
show a genuine old-to-new effective certificate change, and merging existing
public material with the candidate must give the candidate's effective view.
A candidate omitting effective existing material or an older export refuses.
Changing armor/encoding alone is not a refresh. These are GPG effective public
views, not a guarantee that every raw packet or third-party certification is
unchanged; independent operator authentication remains necessary.

Apply uses the existing pacman lock and observed-input comparisons. It repeats
input, actual keyring, validity and effective-view checks inside that lock.
Normal `pacman-key --add` merges the public updates into the existing keyring.
There is no key deletion or new local-signing request. Full local validity must
still hold afterward, and the actual merged effective certificate must exactly
match the reviewed successor before the managed include is replaced. The new
include retains its original permissions and all other managed policy fields.
Global pacman configuration and unrelated repository trust are preserved.

Normal GPG merging retains existing material according to GPG's rules. This tool
does not promise byte-for-byte keyring preservation during apply, repair trust,
remove already known revocations, or make keyring import and config replacement
one atomic transaction. Fully trusted signature verification after adding a new
subkey is exercised in the disposable tests.

## Partial failure and retry

The report separately records `keyring_may_have_changed`,
`config_may_have_changed` and completed `config_changed`. An import error may have
partially changed the keyring. An import-success/config-failure leaves imported
public material present; the prior include stays intact if replacement never
occurred. Concurrent edits are preserved and refused rather than overwritten.
A failure after rename, such as directory fsync failure, can leave the successor
include present even though `config_changed=false`; the uncertainty flag is true.
Inspect the actual include and keyring before choosing the next expected hash.
Nothing automatically rolls back trust or configuration.

If import succeeded while the include still has the old hash, retry with the same
authenticated old and successor files. Their independent old-to-new comparison
permits reconciliation of an already imported successor. If the include already
has the successor hash, use that observed hash and provide the successor as both
current and new certificate for a checked no-op. A stale expected hash always
refuses. Retain both certificate inputs until the transition is resolved.

## Validation and limits

Run `python3 -I -B -Werror::ResourceWarning scripts/repository/test_refresh.py -v`.
The suite uses real GPG and normal pacman-key operations in fresh disposable
user-namespace roots, with no host-root fallback. It checks preview keyring-byte
preservation, renewal/new-subkey verification with full trust, strict effective
pacman policy, CAS and idempotency, rejected unsafe/secret/multiple/other-primary/
expired/revoked inputs, known revocation and older-export refusal, lock/input/
keyring races, retained import retry, concurrent include preservation and
post-rename uncertainty. Missing tools or unavailable user namespaces explicitly
skip; that is not a passing lifecycle result.

On the implementation host, all15 tests passed with no skips on Python3.12.13
and3.14.7 using real GPG/pacman-key and disposable mapped-root apply operations.
These checks establish software behavior in disposable roots only. They do not
establish an accepted release, trust distribution, native ARM/M2 operation,
installed enrollment-package delivery or target update/recovery acceptance.
