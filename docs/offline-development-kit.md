# Portable offline development kit

`scripts/release/offline_kit.py` fills the transfer gap between an existing signed
**development** repository and an inspect-only disconnected receiver. It retains
the existing `client.py` envelope and release formats and copies the unchanged
client and source-delivery helper. It does not promote a development repository,
change pacman/GPG trust, fetch anything, sign, update a checkpoint or install.
Python 3 and GPG must already be installed on the Linux receiver. Assembly also
requires Linux `renameat2` with `RENAME_NOREPLACE`; absence refuses without a
weaker publication fallback.

The kit contains the exact signed release payload, DBs, package archives,
signatures, internal repo aliases, signed development envelope, binary public
key export, three receiver scripts, their actual project license (`receiver-license.txt`),
and `kit.json`. The latter is a transport
inventory; it is **not** a new signature or trust authority. A required lock
record must already exist in `spec.json` evidence and the signed release payload.
The kit retains that bounded JSON object byte for byte; it does not turn its
contents into an installation grant. An unsigned external lock cannot be added.
Missing lock evidence requires a newly prepared and signed development release.

From a reviewed checkout, with an existing private 0700 client state directory:

```sh
python -B scripts/release/offline_kit.py assemble \
  --bundle /srv/development/staging/dev-42 \
  --metadata /srv/delivery/development.json \
  --signature /srv/delivery/development.json.sig \
  --public-keyring /srv/delivery/public.gpg \
  --lock-evidence integration.lock.json \
  --namespace dev.example --signer FULL_UPPERCASE_PRIMARY_FINGERPRINT \
  --minimum-sequence 42 --state-dir /srv/client-state \
  --output /srv/out/offline-kit
```

`public.gpg` must be a finite binary public export produced separately with
`gpg --export FINGERPRINT`. Secret packets, armor, unknown packet types and
partial packet lengths are refused before any kit output is created. No signing
home or arbitrary producer directory is copied. Output must be a fresh path in
a caller-owned parent without group/world writes. Assembly validates both the
original inputs and the completed snapshot. Publication uses a single atomic no-replace directory rename: an existing or
concurrently substituted destination is never overwritten or followed. A failure
after that rename can retain the complete destination with uncertain durability;
the command returns failure and the output must be inspected before reuse.
Inspection refuses incomplete inventories and unreadable or foreign directories.

Transfer the directory preserving its relative paths and internal aliases.
Independently deliver the assembler's `kit_sha256`, `receiver_sha256`, expected
signer, namespace and current minimum sequence. Do not derive these pins from
an untrusted transferred kit. Use the assembler's `receiver_sha256` entries to
prepare a trusted `receiver.sha256` file with lines in `sha256sum` format. Before
executing **any** transferred Python code, check all three receiver scripts:

```sh
cd /media/unrelated/offline-kit
sha256sum --check /trusted/receiver.sha256
# Continue only if all three script checks pass.
mkdir -m 700 /work/receiver-state
python -I -B scripts/release/offline_kit.py inspect \
  --kit /media/unrelated/offline-kit \
  --kit-sha256 INDEPENDENTLY_RECEIVED_KIT_JSON_SHA256 \
  --namespace dev.example --signer FULL_UPPERCASE_PRIMARY_FINGERPRINT \
  --minimum-sequence 42 --state-dir /work/receiver-state
```

Alternatively run an already trusted receiver installation to inspect the kit.
The fresh-state example is for a fresh disposable receiver. Existing receivers
must retain their existing checkpoint and independently current sequence floor;
replacing state would discard rollback history. Inspection locks state read-only
and never updates its checkpoint. It verifies the complete transport inventory,
then calls the existing development client with `apply=False`: external pins,
sequence/checkpoint, issue/expiry and signature expiry remain mandatory. It
rechecks the transferred files after verification. It reports local relocated
paths and the signed lock digest; it does not emit or execute a transaction.

Declared source bundles, notices, recipe/source maps and existing review records
are carried only as signed release evidence and revalidated by the existing
source-delivery helper. Without that declaration the kit remains inspectable but
reports `source_delivery_gap: true` and `source_delivery: NOT_DECLARED`. The
existing client's `sources` command still refuses absent source delivery. Even
with declared associations, source completeness and legal acceptance remain
false. A project-license file alone is not a source-complete delivery.

Actual payload installation remains behind the existing explicit disposable-root
transaction mechanism in `scripts/install/local_transaction.py` and its current
profile/contract gates. This bridge neither creates a contract nor authorizes
real candidate packages. Native ARM, VM, installed-system, M2 hardware and release
acceptance are separate; host fixture inspection grants none of them.

Run the meaningful host integration checks after integration:

```sh
python -B scripts/release/test_offline_kit.py
```

They use fresh TEST-only signatures and original synthetic fixture packages.
The relocation check launches the transferred receiver from an unrelated CWD
after removing producer inputs; refusal checks cover transport/payload tamper,
missing signatures/lock, expiry, external pins, checkpoint rollback, secret keys,
foreign nodes and unsafe output. Available source material is also exercised.
