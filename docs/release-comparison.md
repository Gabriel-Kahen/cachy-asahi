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
- `dependency_impact`: unchanged packages that may consume changed or removed packages through declared runtime dependencies. Each affected package lists the changed identity and one shortest dependency path in each release where it matches. Every hop records the consumer `package`, literal `dependency` and actual `provider` package name. Cycles terminate; equal-length paths use deterministic package/relation ordering.
- Package-version changes within named coordinated sets, plus selected/protected package and supported-model policy changes. These are declared compatibility-set differences, not proof of hardware compatibility.
- Added, removed or changed signed payload paths/hashes and repository symlink targets. This includes provenance, evidence and repository metadata; normal differences between signed bundles may therefore be numerous.

No changes means empty difference lists; comparing one bundle with itself is supported. List ordering is deterministic. A successful comparison exits 0 even when it reports removals, downgrades or same-version byte changes: these require maintainer review, not automatic acceptance. Verification or version-tool failures exit nonzero without printing a partial JSON report.

Dependency impact uses each verified release's effective inventory: overlay packages shadow same-name base packages, as in the existing release dependency verifier. A changed identity means its origin, normalized declared package metadata or recorded artifact name/hash differs; release provenance-only changes do not seed runtime impact. Unchanged dependents retain that same identity in both releases. Added-only identities are not seeds in this changed/removed report. Both old and new graphs are searched, so a removed provider can remain visible in a `before` path even when another provider keeps the new release's dependencies satisfied.

All packages satisfying a dependency are considered, using `release.py`'s ALPM relation/provides handling and real `vercmp`, including versioned virtual provides. The report does not choose which alternative provider an application uses. It marks **possible runtime-consumer review**, not a broken dependency, ABI failure or mandatory rebuild. It has no recipe/build-dependency edges: `build_dependencies_checked` is false and `rebuild_requirement` is `NOT_ESTABLISHED`. The existing schema1 report fields keep their meanings; `dependency_impact` is an additive field.

Provider names are indexed before matching; unrelated packages do not trigger version comparisons. Exact dependency/provider-version/provides matches are cached across both graphs. The report retains one path per cause and dependent rather than enumerating all cyclic/alternative routes. It refuses more than 65,536 distinct matching probes, 65,536 matching edges across both graphs or 65,536 reported path steps. One shared traversal budget also allows at most 262,144 work units across all roots and both releases: each queue pop costs one, plus one for every adjacent edge, charged before visiting those edges. This bounds repeated searches even when no unchanged dependent is reachable and no output path is produced. These limits fail the command without partial JSON; they never silently truncate the review list.

This command compares authenticated retained bundles, including synthetic staging bundles and historical bundles useful for incident investigation. It does **not** check promotion gates, current selection, withdrawal status, freshness, key rotation, public endpoint state or the target machine. `stable_eligibility_checked` is always false. It grants no stable eligibility, update authorization, installation, recovery, native-build or M2 acceptance. Both bundles currently require the same pinned signer; cross-key transition review remains separate.

The verifier is rerun before returning and reported spec/base bytes join the signed payload map. This detects observed input changes; it does not provide a filesystem snapshot or lock out another process changing the bundles. Use immutable retained directories under the normal release operator's custody. The utility creates no storage lock files or selection pointers.

Focused tests use real, disposable TEST signatures and local synthetic packages/repository databases; no packages are installed:

```bash
python3 -B -m unittest discover -s scripts/release -p test_compare_releases.py -v
```
