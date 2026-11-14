# Repository enrollment tools 0.3.0

An opt-in successor recipe for `cachy-asahi-repository-enrollment`, version
**0.3.0-1**. It preserves the exact finalized `0.2.0-2` eight-file runtime and
adds primary revocation/quarantine as a ninth private Python file. The existing
0.1 and 0.2 recipe directories remain separate. No shared package selection,
production trust, release promotion or publication is implied.

```sh
cachy-asahi-repository-enrollment --version
cachy-asahi-repository-enrollment configure --help
cachy-asahi-repository-enrollment rotate --help
cachy-asahi-repository-enrollment transition --help
cachy-asahi-repository-enrollment revoke --help
```

The launcher resolves this installation's private prefix and runs fixed
`/usr/bin/python3 -I -B`. Configure, planned rotation and authenticated transition
behavior remains the same as 0.2.0-2. A transition preserves the selected snapshot
URL and does not accept/install a successor release; it requires the old signer
to remain usable. Changed or revoked current signers need incident recovery.
Preview is the default for all four commands; only explicit `--apply` can mutate
selected local trust/configuration. Package operations never invoke the commands.

## Revocation and quarantine

Obtain and authenticate incident inputs through the operator's chosen process.
Select the exact expected managed primary fingerprint and original certificate
SHA-256; retain the original enrollment certificate bytes. The second file is a
complete updated public certificate containing that primary's valid self-revocation.

```sh
cachy-asahi-repository-enrollment revoke \
  --expected-current-fingerprint "$EXPECTED_PRIMARY_FINGERPRINT" \
  --expected-current-certificate-sha256 "$ORIGINAL_CERTIFICATE_SHA256" \
  --current-public-key /etc/pacman.d/operator-public.gpg \
  --revoked-public-key /etc/pacman.d/operator-revoked-public.gpg
```

Preview may need root privileges to read protected inputs. Apply requires root;
use the same command with `--apply` only for the intended selected root. The
initialized keyring and input files/directories must satisfy the tool's root
ownership, permissions, canonical path and single-link checks. Inputs must be
separate public exports outside the live keyring. Binary and single public armor
blocks are supported; bare `.rev` files, designated revokers and subkey-only
revocations are outside this first implementation.

Each primary-revocation packet must independently make the selected original
primary revoked in a new public-only GPG home, with a cryptographically verified
self-revocation. Secret, foreign, multiple-primary, non-revoking and tampered
inputs are refused. Live import uses only the original certificate plus those
validated revocations; additional candidate user IDs/subkeys are not imported.
Explicit caller pins identify the selected managed identity. They do not supply
independent incident authentication or freshness; external freshness remains
UNKNOWN in the report.

Apply holds the existing pacman lock, removes only the owned Include block from
`pacman.conf` first, and retains the exact unselected managed include as the
quarantine/CAS record. It then imports the validated public material and confirms
that the selected live primary is revoked. It never removes keys, locally signs
or enrolls a successor, fetches material, installs packages or weakens signatures.
The selected primary becomes revoked throughout the shared global keyring;
unrelated base public certificates and configuration bytes are preserved.

This is not atomic across configuration and keyring. A rename can take effect
before a flush failure; import can succeed before later confirmation fails.
Inspect `config_may_have_changed`, `repository_enabled`,
`quarantine_record_preserved`, `keyring_may_have_changed` and
`revocation_confirmed`. Preserve the record and public inputs and retry the same
exact pins after inspection. A partial failure keeps selection disabled; no
failure automatically restores trust or re-enables the repository. Completed
repeat is a no-op. Existing enrollment using old public bytes cannot remove an
existing revocation or re-enable that revoked signer. A separately authenticated
replacement needs its own reviewed recovery process.

## Finite delivery and checks

The private runtime contains the eight finalized 0.2.0-2 Python files plus
`scripts/repository/revoke.py`. Provenance records both the retained base archive
and its per-file identities, the revocation source revision, and all nine exact
file hashes/lengths/modes. The deterministic USTAR/gzip source archive has sorted
members, zero timestamps/ownership, and mode 0644. No whole-repository runtime or
checkout discovery is shipped. The two source test fixtures are check-only code
and are not installed.

Runtime dependencies are Python >=3.11, gnupg, pacman, coreutils and libarchive.
Archive inspection uses bsdtar/libarchive, including zstd inputs; no separate
zstd CLI or Python 3.14 compression module is required. Bubblewrap and util-linux
are check-only dependencies for source hiding, network isolation and mapped-root
preview. All tools must already exist; the recipe does not install prerequisites.

`check()` stages the actual package, moves its prefix, hides source/fixture trees,
isolates the network to loopback and poisons the caller Python environment. It
retains the real signed transition preview/tamper control, adds real revoked
public-certificate preview and non-revoking-certificate refusal through the
installed launcher, and checks target bytes remain unchanged. Root ownership is
exercised in an unprivileged mapped-root user namespace; package checks do not
apply revocations or require privileged host mutation. Namespace capability is
required: missing user/network namespace support fails visibly without a
host-root fallback. The source revocation suite separately exercises disposable
mapped-root apply and partial recovery; it is not installed.

The package contains exactly 15 files: one launcher, nine private Python files,
three documentation/identity files and two license/notice files. No `.install`,
ALPM hook, service, `/etc` or `/var` payload is included. Installing/upgrading or
removing it changes only package-owned payload; user trust/configuration is
managed exclusively by explicit commands. Tests verify the exact removal inverse
preserves unrelated content.

```sh
makepkg --verifysource
REPOSITORY_ENROLLMENT_HIDE_ROOT=/absolute/source/checkout makepkg --nodeps --cleanbuild --force
```

`--nodeps` bypasses dependency checks and does not install missing dependencies.
Unsigned host assembly, relocated synthetic TEST previews and source apply tests
do not qualify native ARM builds, ALPM lifecycle, production incident distribution,
client convergence, M2 operation or release acceptance.
