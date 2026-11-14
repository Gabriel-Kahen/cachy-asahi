# Apply an authenticated release signing-key handoff locally

`scripts/repository/transition.py` connects a [dual-signed release
transition](release/signing-transition.md) to the existing
[`rotate.py`](../scripts/repository/rotate.py) local trust operation. The default
previews the handoff; `--apply` imports/local-signs the verified successor public
certificate and changes the managed signing fingerprint. The existing snapshot
URL, strict required/trusted-only signature policy, old certificate/trust and
unrelated pacman configuration remain in place.

This is a **local trust rotation**, not acceptance or selection of the successor
release snapshot. It does not install packages, perform an upgrade, deploy an
endpoint, distribute trust, revoke/remove old keys or establish incident
recovery. The report always retains `snapshot_upgrade_accepted=false`,
`stable_eligibility_checked=false` and `production_accepted=false`. Both release
bundles must verify, but their signatures are not compatibility or hardware
acceptance. Production distribution/client convergence and supported-M2 rotation
remain **NOT RUN**.

## Preview, then apply

An enabled repository managed by the existing enrollment tool and a currently
trusted usable old certificate are prerequisites. Independently authenticate
both full uppercase primary fingerprints. Retain both complete signed release
bundles and the five-file transition bundle. Their repository name must be
`cachy-asahi`, with the existing aarch64 transition contract.

```bash
python3 scripts/repository/transition.py \
  --bundle /srv/cachy-asahi/transitions/release-1-to-2 \
  --before /srv/cachy-asahi/staging/release-1 \
  --after /srv/cachy-asahi/staging/release-2 \
  --expected-current-fingerprint OLD_PRIMARY_FINGERPRINT \
  --fingerprint NEW_PRIMARY_FINGERPRINT

sudo python3 scripts/repository/transition.py --apply \
  --bundle /srv/cachy-asahi/transitions/release-1-to-2 \
  --before /srv/cachy-asahi/staging/release-1 \
  --after /srv/cachy-asahi/staging/release-2 \
  --expected-current-fingerprint OLD_PRIMARY_FINGERPRINT \
  --fingerprint NEW_PRIMARY_FINGERPRINT
```

Run from the source checkout with the release-verifier dependencies, including
GPG, bsdtar, repo-add tooling and ALPM vercmp. This new bridge is not part of a
frozen two-file enrollment/rotation source bundle or its installed launcher.
`--root /` is the normal root. Alternate roots are disposable test fixtures and
do not make installed-machine or hardware acceptance claims.

The existing managed include must name **both** the old fingerprint and the
exact SHA-256 of `old-public.asc` in the signed transition. An equivalent public
export with different bytes does not satisfy that binding. The successor comes
only from the exact signed `new-public.asc` bytes; there is no separate public-key
path that could select a different certificate.

Preview may take `--as-of UTC_TIMESTAMP` for diagnostic overlap review. Apply
forbids that option and always evaluates the actual current UTC clock, including
after locked verification and immediately before each trust-changing command.
Historical diagnostic success cannot authorize apply after the overlap expires.
Current GPG signature/certificate validity is checked independently of the
diagnostic time. An offline export cannot establish current external revocation;
revocations already present in the managed keyring still cause the unchanged
rotation checks to refuse unsafe trust.

## Input ownership and mutation boundary

For apply, the selected root and all three retained input trees must be root
owned. Require canonical, disjoint absolute input directories with no alias or
symlink ancestors. Retained directories/files must not be writable by group or
others; regular files must be single-link. Signed repository symlinks may point
only to ordinary sibling files, under the release verifier's exact signed map.
Unsafe or special entries are refused. Each tree is bounded to 65,536 entries.
Ancestors must be owned by root and not writable by group/others, except a trusted
sticky temporary directory protecting its owned children. Mapped-root test
namespaces also allow the unmapped host-root owner for ancestors; retained input
entries themselves must belong to the selected root owner.

Do not hand privileged apply a certificate or bundle under a user-owned home or
writable intermediate directory. Place reviewed retained inputs into a safe
operator-controlled location before invoking apply. Metadata/identity snapshots
and repeated cryptographic verification detect observed concurrent edits; these
are not filesystem snapshots or protection against a hostile privileged writer.

Apply creates its own mode-0700 scratch directory under the existing safe
`/var/lib/pacman` directory of the selected root, containing only a mode-0400
copy of the verified successor public certificate. It never passes a mutable
user-owned export to privileged rotation. Preview can use the retained
certificate directly when it is inside the selected root; an external
alternate-root fixture uses equivalent temporary scratch. Neither preview path
changes configuration or keyring bytes. Scratch is removed on normal success
and caught failures. An abrupt host/process loss may leave a scratch directory;
inspect it before operator cleanup. The tool never removes retained inputs.

The bridge loads a private instance of the unchanged rotation/enrollment code.
Its guarded lock first acquires the original exclusive pacman transaction lock,
then compares the originally observed inputs, reruns the full dual-signed
release verifier and confirms the exact current managed selection. Only then
can the unchanged rotation execute its import/local-sign and atomic include
replacement. Every trust-changing command requires this locked authorization
and rechecks overlap, original input identities, private certificate bytes and
configuration state. Existing observed-current checks, signature-policy checks,
foreign-lock preservation and include replacement remain active.

Failure reports retain `config_changed`, `config_may_have_changed` and
`keyring_may_have_changed` from the underlying operation. Import or local signing
may have happened before a later failure; scratch cleanup is **not** trust
rollback. Inspect the actual include and keyring before retrying. A completed
rotation makes the old expected-current fingerprint stale; repeating this exact
handoff refuses instead of becoming an implicit no-op. No old trust or public
certificate is deleted automatically.

## Tests

```bash
python3 -B -m unittest discover -s scripts/repository -p test_transition.py -v
python3 -B -m unittest discover -s scripts/repository -p test_rotate.py -v
```

The bridge tests build real synthetic signed release repositories, create real
dual signatures, enroll a disposable base keyring and exercise mapped-root
preview/apply. They check actual successor signature trust and effective pacman
policy, retained old/base trust and snapshot URL, exact old certificate/CAS,
unsafe/tampered retained inputs, complete re-verification under the original
lock, valid same-primary certificate-body substitution, historical/expired
overlap refusal, foreign locks, and actual import followed by local-sign failure.
All writes are confined to owned disposable fixtures; no host trust or package
installation is changed.
