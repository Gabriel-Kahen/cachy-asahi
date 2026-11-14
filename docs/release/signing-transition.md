# Planned release signing-key transitions

`scripts/release/signing_transition.py` creates a finite handoff between two
retained releases signed by different primary identities. Both identities sign
the same transition record. Independent verification checks both signatures,
both complete release bundles, exact public certificate bytes and an explicit
overlap window. `compare` then runs the normal package/base/dependency comparison
with the respective pinned signers.

The transition imports `compare_releases_v2.py`, a separate versioned comparison
API. The legacy `compare_releases.py` remains byte-identical to the previously
pinned implementation; no historical native consumer or source-map pin is
retargeted to enable this operation.

This implements an offline planned-rotation artifact and rehearsal. It does not
change pacman trust, deploy metadata or grant stable eligibility. The existing
[`scripts/repository/rotate.py`](../../scripts/repository/rotate.py) handles
operator-selected local enrollment changes separately; it does not consume this
artifact. Public distribution, client convergence, production custody and
exact-machine signing-rotation acceptance remain **NOT RUN**. A compromised old
key requires an independently authenticated replacement route under the
[recovery policy](recovery.md), not reliance on its transition signature.

Use independently authenticated **primary** fingerprints for both identities.
The old signature establishes continuity only while that identity remains
trustworthy; the new signature demonstrates possession of a signing key under
the replacement identity. Neither signature establishes organizational approval
or release compatibility. The supplied certificate exports cannot establish
current revocation; reports retain `current_revocation=UNKNOWN_OFFLINE_EXPORT`.

## Create and independently exercise the handoff

Stage and verify each release using its intended signer through the normal
release process. Export only public certificates. Supply explicit external
signing homes, outside the checkout and release bundles; private keys remain in
their existing homes. Both signing operations require the selected signer to be
available through that home. There is no default-key fallback or passphrase
argument.

```bash
python3 scripts/release/signing_transition.py create \
  --before /srv/cachy-asahi/staging/release-1 \
  --after /srv/cachy-asahi/staging/release-2 \
  --old-key OLD_PRIMARY_FINGERPRINT --new-key NEW_PRIMARY_FINGERPRINT \
  --old-certificate /secure/old-public.asc \
  --new-certificate /secure/new-public.asc \
  --old-gpg-home /secure/old-signing-home \
  --new-gpg-home /secure/new-signing-home \
  --not-before 2026-11-14T00:00:00Z \
  --not-after 2026-12-14T00:00:00Z \
  --as-of 2026-11-14T12:00:00Z \
  --output /srv/cachy-asahi/transitions/release-1-to-2

python3 scripts/release/signing_transition.py compare \
  --bundle /srv/cachy-asahi/transitions/release-1-to-2 \
  --before /srv/cachy-asahi/staging/release-1 \
  --after /srv/cachy-asahi/staging/release-2 \
  --old-key OLD_PRIMARY_FINGERPRINT --new-key NEW_PRIMARY_FINGERPRINT \
  --as-of 2026-11-14T12:00:00Z
```

`verify` accepts the same arguments as `compare` and omits package-difference
reporting. Verification requires no signing homes and uses new disposable
public-only keyrings. It does not import into a caller's keyring, launch a signing
agent or retrieve keys. Certificate validity and signatures are checked by GPG
at its current clock. `--as-of` evaluates only the transition's declared overlap;
it does not fake GPG time or prove historical certificate state, trustworthy time,
metadata freshness or replay protection. Change the example dates to the actual
reviewed overlap and observation time.

The output directory must not exist; its parent must exist. Creation verifies
both releases before requesting signatures, then verifies the resulting handoff
and comparison before returning JSON. Signing or final-verification failure
removes the newly created directory. An abrupt process/host loss may leave an
incomplete directory; verification refuses it, and an operator must inspect and
remove it before retrying. Existing output is never replaced. Use immutable
retained inputs: rechecks detect observed changes without providing a filesystem
snapshot or blocking concurrent writers.

The five-file bundle contains `transition.json`, `old-public.asc`,
`new-public.asc`, `old.sig` and `new.sig`. The signed schema binds:

- Distinct explicitly selected old and new primary fingerprints.
- Each exact release ID and manifest SHA-256 in the same named aarch64 repository.
- Each exact public certificate SHA-256, including any signing-subkey bindings.
- UTC overlap boundaries, at most 366 days, with an inclusive start and exclusive end.

Each signature must have one valid matching primary identity and a SHA-2 digest;
missing, wrong, appended duplicate, expired or revoked signatures are refused.
Secret or multiple-primary certificate exports, symlinked input paths/ancestors,
hardlinked or special files, extra/missing bundle files, duplicate JSON fields,
certificate substitution and release substitution are refused. Both complete
release verifications retain the normal package, database, provenance and
dependency checks. A handoff covers only this exact release pair; it is not
blanket authorization for future releases or a replacement for incident review.

Successful JSON reports `VERIFIED_FINITE_PLANNED_KEY_TRANSITION_ONLY`, exact
bindings, `stable_eligibility_checked=false`, `client_trust_changed=false` and
`freshness_established=false`. The nested comparison reports separate `signers`
for `before` and `after`, with its legacy singular `signer` set to null. The
standalone comparison CLI still requires one signer. Failures exit nonzero
without partial JSON. No supported release, native build, installation, M2,
performance, boot recovery or public trust acceptance follows from this tool.

## Verification

The focused suite uses two real disposable TEST identities, real signed
synthetic package/repository bundles and real ALPM ordering. It exercises
creation and independent verification, cross-key comparison, wrong/missing or
duplicate signatures, certificate/secret-material rejection, release replay and
substitution, overlap/schema checks, payload and mid-report tampering, unsafe
paths, interrupted signing, existing-output preservation and CLI failures:

```bash
python3 -B -m unittest discover -s scripts/release -p test_signing_transition.py -v
python3 -B -m unittest discover -s scripts/release -p test_compare_releases.py -v
```
