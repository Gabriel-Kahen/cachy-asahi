# Compare signed releases

`compare_releases.py` previews differences between two local release bundles before a maintainer considers promotion or recovery. Both bundles must pass the existing release verifier with one explicitly pinned full signing fingerprint: manifest, package and repository signatures, payload hashes, provenance, dependency consistency and any declared source-delivery associations. Unsigned, tampered or incomplete inputs fail; there is no verification bypass.

```bash
python3 scripts/release/compare_releases.py \
  --before /srv/cachy-asahi/staging/release-1 \
  --after /srv/cachy-asahi/staging/release-2 \
  --gpg-home /secure/external-verification-home \
  --key FULL_SIGNING_FINGERPRINT
```

The existing externally managed GnuPG home must contain the verification key and stay outside the checkout and both bundles. Required system tools are those of `release.py verify`, including `gpg`, `bsdtar` and ALPM `vercmp`. The comparison neither imports keys nor changes either bundle, release storage, a current-selection symlink, packages or system trust. GnuPG may maintain its own state inside the explicitly supplied external home. Symlinked bundle paths or ancestors are refused; address the concrete release directory rather than `stable/current`.

The JSON report contains:

- Signed release identities: release ID, exact manifest SHA-256, source commit and synthetic-fixture flag.
- Overlay package additions/removals, upgrades/downgrades, ALPM-equivalent version-label changes, same-version archive-byte changes, artifact renames and metadata differences. The version classification uses real `vercmp`, including epochs and package releases; tool failure refuses comparison. Changed metadata remains visible even when the version is unchanged.
- Complete base/dependency inventory differences and snapshot IDs from the signed `base.json` payloads. Dependencies, provides, conflicts, architecture and owned-file changes are retained. Overlay and base inventories are shown separately, following the existing schemas.
- Package-version changes within named coordinated sets, plus selected/protected package and supported-model policy changes. These are declared compatibility-set differences, not proof of hardware compatibility.
- Added, removed or changed signed payload paths/hashes and repository symlink targets. This includes provenance, evidence and repository metadata; normal differences between signed bundles may therefore be numerous.

No changes means empty difference lists; comparing one bundle with itself is supported. List ordering is deterministic. A successful comparison exits 0 even when it reports removals, downgrades or same-version byte changes: these require maintainer review, not automatic acceptance. Verification or version-tool failures exit nonzero without printing a partial JSON report.

This command compares authenticated retained bundles, including synthetic staging bundles and historical bundles useful for incident investigation. It does **not** check promotion gates, current selection, withdrawal status, freshness, key rotation, public endpoint state or the target machine. `stable_eligibility_checked` is always false. It grants no stable eligibility, update authorization, installation, recovery, native-build or M2 acceptance. Both bundles currently require the same pinned signer; cross-key transition review remains separate.

The verifier is rerun before returning and reported spec/base bytes join the signed payload map. This detects observed input changes; it does not provide a filesystem snapshot or lock out another process changing the bundles. Use immutable retained directories under the normal release operator's custody. The utility creates no storage lock files or selection pointers.

Focused tests use real, disposable TEST signatures and local synthetic packages/repository databases; no packages are installed:

```bash
python3 -B -m unittest discover -s scripts/release -p test_compare_releases.py -v
```
