# cachy-asahi-apps 0.1.0

Offline application list/search/show and explicit install/remove **plans** over a finite signed ARM development catalog. Every successful output says `NOT_APPLIED`; there is no apply, download, cache deletion, orphan cleanup or host package transaction. Plans are not installer authority. No supported production application set is selected by this package.

The runtime requires an explicit `--repository-source` tree containing the three exact helpers in helper-pins.json: scripts/client/client.py, scripts/release/release.py and scripts/release/source_delivery.py. These MIT helpers are reused as source integration dependencies, not bundled. A different helper snapshot refuses before source execution. An installed interpreter, GPG, bsdtar and ALPM vercmp are required. This pure Python package is architecture independent; catalog/release/inventory inputs must be aarch64/any.

Supply a local development release created by scripts/release/release.py, an external public keyring and full externally pinned primary fingerprint. Both release.json and the separate catalog need valid signatures from that same fingerprint. The client helper rejects missing/bad/expired/revoked/weak signatures in an isolated temporary public verification home, without importing into user/system trust. The release helper checks package archives, provenance, repository metadata, source delivery when declared and full signed release dependency consistency. Semantic readers consume a private snapshot of the exact signed payload. Unsigned files outside that map are never consumed. No previous verification JSON is accepted. Freshness/withdrawal status is NOT_ESTABLISHED; production/stable acceptance and hardware compatibility are not inferred.

A caller prepares and signs this finite catalog, replacing every placeholder with real release values:

```json
{"schema_version":1,"kind":"development-application-catalog","target_arch":"aarch64",
 "release_sha256":"EXACT_SHA256_OF_RELEASE_JSON","repository":"EXACT_SIGNED_REPO_NAME",
 "applications":[{"id":"example-editor","title":"Example editor","description":"Caller selected application",
                   "packages":["EXACT_RELEASE_PACKAGE_NAME"]}]}
```

Catalog package names must exist in the authenticated release. The catalog cannot add repositories, packages, x86/multilib/AUR fallbacks or relax signed base protection. All release application packages must have signed native aarch64 provenance unless the release explicitly declares synthetic test inputs; synthetic remains visible in output. An architecture/provenance declaration alone does not establish an independent native build or M2 compatibility.

Use common options on every invocation:

```sh
cachy-asahi-apps --repository-source /absolute/repository-source \
  --release /absolute/signed-development-release --release-sha256 RELEASE_SHA256 \
  --catalog /absolute/catalog.json --catalog-sha256 CATALOG_SHA256 \
  --catalog-signature /absolute/catalog.json.sig \
  --keyring /absolute/external-public.gpg --signer FULL_PRIMARY_FINGERPRINT list
```

Replace `list` with `search editor` or `show example-editor`. No installed inventory is needed for browsing. JSON output includes application versions and release archive hashes. For a plan, add `--installed /absolute/inventory.json --installed-sha256 INVENTORY_SHA256` before `plan install example-editor` or `plan remove example-editor`.

The complete caller-supplied inventory has schema_version1, kind `complete-installed-inventory`, target_arch `aarch64`, a snapshot_id and a packages array. Each package has name, version, arch, depend, provides, conflict, files and optional replaces (defaults empty). Optional sha256 is the caller's declared installed archive hash, not a measured payload hash. Every package from the signed base must be present with identical normalized metadata. Package paths are relative regular-file ownership records, like release.py's base inventory. No host database is scanned: supplied inventory and any archive digests are explicitly labelled CALLER_DECLARED_METADATA_NOT_HOST_ATTESTED.

Install plans add/upgrade only authenticated release packages. Dependencies use ALPM relations and vercmp, including epochs, pkgrel and versioned provides. A missing dependency must have exactly one available provider; ambiguity refuses until the caller explicitly selects an application containing the desired provider. Cycles terminate, bounded work refuses rather than truncating, downgrades and equivalent-version metadata replacements refuse. Existing broken inventories, missing base members, protected base replacements, unsupported replaces, package/file conflicts and reverse-dependency breakage refuse. Same-version declared archive mismatch does not silently become reinstall. Remove plans remove only explicitly named catalog package groups; shared/reverse dependencies are checked, and unused dependencies stay installed.

Plans bind exact release/catalog/signature/keyring/source-helper/installed-input hashes, before/after normalized inventory hashes and package versions/metadata hashes. Additions/upgrades also bind signed release archive hashes; removals retain caller-declared archive hashes when provided. Output reports additions, upgrades, removals, dependency causes and conflicts/refusal issues. Applying would require a separate installer that re-authenticates all inputs, observes the actual target, isolates the transaction and proves cleanup/recovery. This CLI provides no such authority or endpoint.

Run source checks and focused tests with an exact repository snapshot:

```sh
python3 -I -B check_source.py --repository-source /absolute/repository-source
python3 -I -B test_apps.py --repository-source /absolute/repository-source
```

Tests use real isolated GPG/repo-add synthetic fixtures plus dependency/selection failure cases; they never install packages. They need gpg-agent's private local socket for test-only signing, and retire the owned signing agent afterward. For makepkg check, set `CACHY_ASAHI_REPOSITORY_SOURCE` explicitly; absence fails. No build/native pair/installed lifecycle/hardware acceptance is claimed by this proposal.
