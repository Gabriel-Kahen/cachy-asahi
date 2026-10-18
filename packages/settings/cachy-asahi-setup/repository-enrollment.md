# Explicit repository enrollment

`scripts/repository/enroll.py` previews, enables, or disables one operator-selected
`cachy-asahi` repository. Enabling requires a separately obtained public
certificate and an independently authenticated full primary-key fingerprint.
This is a local operator tool; no production endpoint or signing identity is
accepted by this implementation.

Python 3.9 or later, GnuPG, and `pacman-key` must already be installed. The base
pacman configuration and initialized keyring must already exist. The tool never
initializes, resets, replaces, or deletes the base keyring. Setup-package delivery
is separate work.

## Use

Obtain the selected URL and public certificate through the release operator's
chosen process. Authenticate the expected fingerprint through an independent
channel before running this tool. Place a public-only export in a root-owned
location such as `/etc/pacman.d/operator-public.gpg`, outside the live keyring.
The file and its directories beneath the selected root must not be writable by
group or others; symlinks, hard-linked files, and secret-key material are refused.
The tool does not copy a certificate out of an untrusted user-writable location.

Preview is the default. These variables are operator inputs, not supplied release
values:

```sh
python3 -B scripts/repository/enroll.py enroll \
  --snapshot-url "$SNAPSHOT_URL" \
  --public-key /etc/pacman.d/operator-public.gpg \
  --fingerprint "$EXPECTED_PRIMARY_FINGERPRINT"
```

Inspect the JSON preview, including the exact fingerprint, certificate SHA-256,
URL, and managed include. To make the selected changes, run the same command as
root with the global `--apply` option before `enroll`:

```sh
sudo python3 -B scripts/repository/enroll.py --apply enroll \
  --snapshot-url "$SNAPSHOT_URL" \
  --public-key /etc/pacman.d/operator-public.gpg \
  --fingerprint "$EXPECTED_PRIMARY_FINGERPRINT"
```

The accepted URL is canonical HTTPS with a lowercase hostname and this path:
`/<optional-prefix>/generations/<64-lowercase-hex>/release/repo`. Credentials,
ports, query strings, fragments, mutable `latest` paths, and other schemes are
refused. This path selects a location; it does **not** prove the remote server is
immutable, that its contents match the path, or that the release is current. The
CLI makes no network request and does not inspect remote repository contents.
Normal pacman operations subsequently verify signatures on downloaded databases
and packages.

On apply, the tool imports the exact inspected public certificate, locally signs
the authenticated primary fingerprint using the existing pacman keyring, and
checks that GnuPG considers that primary fully or ultimately valid. It then
creates `/etc/pacman.d/cachy-asahi.conf` and selects it through a marked Include
block appended to `/etc/pacman.conf`. The owned repository policy is:

```ini
[cachy-asahi]
SigLevel = PackageRequired DatabaseRequired TrustedOnly
Server = <selected-snapshot-url>
```

Both package and database signatures are required, regardless of a base
`DatabaseOptional` setting. Pacman's existing global keyring remains the trust
source: this does **not** restrict this repository to one exclusive signer.
Existing trusted base keys remain trusted. Authenticating a primary fingerprint
does not itself establish release authorization, freshness, or a future
revocation-distribution policy.

An identical enabled selection with a valid trusted key is a no-op. Selecting a
different explicit snapshot URL with the same certificate updates only the
managed include. A different certificate or fingerprint is refused while managed
state exists; rotation requires separate operator review and disabling first.

To preview or apply disable:

```sh
python3 -B scripts/repository/enroll.py disable
sudo python3 -B scripts/repository/enroll.py --apply disable
```

Disable removes only the recognized Include block and exact recognized managed
include. Repeating disable is safe. Imported public keys and local signatures are
retained, because other configuration may rely on that trust. Neither operation
refreshes databases, installs or removes packages, or changes services or Asahi's
platform stack.

## Preservation and recovery

Unrelated configuration bytes, including edits outside the managed block, are
preserved. Managed state that was edited by another tool is refused and left for
manual resolution. The tool checks the Include graph for duplicate or unowned
project sections, malformed or incomplete configuration, and wildcard selection
that could accidentally activate a newly created managed include. Only absolute,
non-variable Include paths are supported. Enrollment refuses a custom `GPGDir`.
Filesystem ownership, modes, file identities, and observed bytes are checked
again before mutation; a changed input stops the transaction.

Apply takes the existing root's ordinary `var/lib/pacman/db.lck` exclusively. An
existing lock is preserved and causes failure. Each configuration replacement is
written to a private temporary file in the same directory, flushed, and renamed
atomically, retaining an existing file's owner, group, and mode. This is not one
atomic transaction across the keyring and both configuration files:

* Enrollment changes trust first, writes the managed include next, and selects it
  last. A failure before selection can leave an unselected managed include.
  Repeating the same enrollment completes that recognized state; disable removes
  it.
* Disable removes the selection first and then the include. An interrupted disable
  can leave an unselected include that another disable removes.
* An import or local-signing failure can leave a public certificate or local
  signature in the keyring. There is no automatic trust rollback. Failed apply
  reports `keyring_may_have_changed` and `config_may_have_changed` conservatively;
  `config_changed` records known completed edits. Inspect the error and actual
  state before repeating the same selection or disable.

Unknown or damaged managed state requires manual resolution; a rerun deliberately
does not overwrite it. Abrupt process death or storage failure can leave temporary
files or the transaction lock. Investigate any lock against active pacman/keyring
work before removing it manually; this tool never removes a pre-existing lock.
Disabling the repository does not revoke or remove trust. Any key revocation or
trust removal needs a separate decision accounting for other users of that key.

## Validation and limits

The focused test file uses real GPG, `pacman-key`, and `pacman-conf` in disposable
filesystem roots under a mapped-root user namespace. Its eleven tests passed on
2026-10-15. They cover preview, successful enrollment and effective mandatory
package/database signature policy, idempotency, snapshot switching, disable,
preservation of base trust and unrelated edits, unsafe inputs, changed inputs,
and actual import followed by an injected local-signing failure. A configuration
write failure also exercises orphan-include recovery. Only disposable fixture
GPG daemons are stopped during cleanup.

```sh
python3 -B scripts/repository/test_enroll.py
```

The tests require unprivileged user namespaces and the installed GPG/pacman tools;
they have no host-root fallback. `--root` exists for these disposable roots and is
not a supported installer or alternate-root package-management interface. Preview
only reads target inputs and uses a private temporary GPG inspection home. No host
trust store, host services, repository network endpoint, or package transaction was
changed by validation. Native target installation, accepted release identity,
authenticated key rotation/revocation delivery, M2 hardware operation, and
performance remain untested by this work.
