# Repository enrollment tools 0.1.0

This opt-in original MIT package delivers the existing repository enrollment and
planned key-rotation tools as an installed command. It needs Python >=3.11,
GnuPG, pacman and coreutils. It supplies no repository URL or signing identity.
The copied helpers retain their existing behavior and source identities.

Authenticate the release operator's public certificate and full primary-key
fingerprint independently. Place the public certificate in a root-owned regular
file outside the live keyring. An initialized base pacman keyring is required.
Use an explicit immutable-generation HTTPS URL from the operator. Example
variables below are inputs; this project has no accepted production endpoint.

```sh
cachy-asahi-repository-enrollment configure enroll \
  --snapshot-url "$SNAPSHOT_URL" \
  --public-key /etc/pacman.d/operator-public.gpg \
  --fingerprint "$EXPECTED_PRIMARY_FINGERPRINT"
sudo cachy-asahi-repository-enrollment configure --apply enroll \
  --snapshot-url "$SNAPSHOT_URL" \
  --public-key /etc/pacman.d/operator-public.gpg \
  --fingerprint "$EXPECTED_PRIMARY_FINGERPRINT"
```

Preview reports the exact proposed configuration. Apply changes the managed
include and imports/locally signs the selected public key. Package and database
signatures are both required; the existing global pacman trust remains in use.
The tool does not authenticate remote contents or freshness. No network request,
database refresh, package installation, service or platform change is performed.

```sh
cachy-asahi-repository-enrollment rotate \
  --expected-current-fingerprint "$EXPECTED_PRIMARY_FINGERPRINT" \
  --public-key /etc/pacman.d/successor-public.gpg \
  --fingerprint "$EXPECTED_SUCCESSOR_FINGERPRINT"
cachy-asahi-repository-enrollment configure disable
sudo cachy-asahi-repository-enrollment configure --apply disable
```

Rotation requires independently authenticated successor identity and a still
usable, trusted current key. Pass `--apply` to the rotation command only after
inspecting its preview. It retains old trust and the selected snapshot URL.
Compromise/revocation recovery and authenticated transition delivery are separate.

Installation only owns the launcher, private Python helpers, documentation and
licenses. There are no install hooks, services or configuration backups.
Removing/upgrading this package leaves operator-created pacman configuration,
public imports and local signatures intact. Disable explicitly before removal
when the repository should no longer be selected. Failed operations can leave
public trust imported or configuration changed; inspect the JSON recovery fields
and actual selected state before retrying. No automatic key removal occurs.

The launcher resolves its own prefix and invokes isolated Python, so extracted
and moved payloads can be inspected with `--help` and `--version` without host
installation. Use `configure --root /absolute/disposable/root ...` only for
explicit test roots. Package checks exercise real public-key inspection and
preview/refusal through a relocated payload; they do not establish native ARM,
ALPM installation, production trust or M2 acceptance.
