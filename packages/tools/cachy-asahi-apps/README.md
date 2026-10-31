# cachy-asahi-apps 0.1.0

Offline application list/search/show and explicit install/remove/reinstall **plans** over a finite signed ARM development catalog. Every successful output says `NOT_APPLIED`; there is no apply, download, cache deletion, orphan cleanup or host package transaction. Plans are not installer authority. No supported production application set is selected by this package.

The exact `cachy-asahi-repository-runtime=0.1.0-1` dependency installs the three unchanged MIT helpers identified by helper-pins.json: scripts/client/client.py, scripts/release/release.py and scripts/release/source_delivery.py. The default helper root is `/usr/share/cachy-asahi/repository-runtime`, resolved relative to the installed app prefix. No Git checkout is required. An explicit `--repository-source /absolute/development-source` override remains available. A different helper snapshot refuses before source execution. An installed interpreter, GPG, bsdtar and ALPM vercmp are required. This pure Python package is architecture independent; catalog/release/inventory inputs must be aarch64/any.

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
cachy-asahi-apps --release /absolute/signed-development-release --release-sha256 RELEASE_SHA256 \
  --catalog /absolute/catalog.json --catalog-sha256 CATALOG_SHA256 \
  --catalog-signature /absolute/catalog.json.sig \
  --keyring /absolute/external-public.gpg --signer FULL_PRIMARY_FINGERPRINT list
```

Replace `list` with `search editor` or `show example-editor`. No installed inventory is needed for browsing. JSON output includes application versions and release archive hashes. For a plan, add `--installed /absolute/inventory.json --installed-sha256 INVENTORY_SHA256` before `plan install example-editor` or `plan remove example-editor`.

Create an observed inventory without release/catalog/key credentials:

```sh
cachy-asahi-apps inventory --dbpath /var/lib/pacman --output /absolute/private-parent/inventory.json
```

The output must be fresh, outside the database and under an ordinary caller-owned parent without group/world write access. It is created0600; the receipt prints its exact SHA256 for --installed-sha256. No live database is read unless explicitly selected. The command uses no package-manager or other subprocess and writes no DB lock or metadata. Any existing db.lck, including stale/uncertain/aliased locks, refuses; this does not authorize deleting it.

Only ALPM local format9, complete nonempty aarch64/any package metadata and bounded canonical file ownership are accepted. Desc/files are mandatory; a present zero-byte files record is ALPM's fileless format and remains hashed. Empty FILES sections are also explicit empty ownership. Missing files, other missing identity/architecture fields, malformed/duplicate metadata, unsafe paths, aliases/hardlinks/special records, ownership collisions, unknown record members and detected drift refuse. Known optional install/mtree records are hashed as opaque metadata and never executed. Limits are4096 packages,4MiB per record,64MiB total raw bytes,30 seconds and16MiB inventory output/input (separate from unchanged4MiB signed release/catalog bounds). Exceeding a bound refuses, never truncates.

Two matching no-follow descriptor scans check raw bytes, node identities, directory membership and db.lck absence before/after each scan. No exclusive ALPM lock is acquired: a snapshot can become stale immediately afterward. Output adds an observation object with raw per-record input hashes, a database snapshot hash and normalized metadata hash, qualified OBSERVED_LOCAL_DB_METADATA_NOT_PAYLOAD_OR_HARDWARE_ATTESTATION. Architecture is read from DB metadata, not inferred from the host. No installed archive hashes, payload hashes, signed-base fields or hardware assertions are invented. The planner accepts both observed and original declared schemas, checks observation hash consistency and still requires exact signed base normalization, protected package preservation and reverse dependency checks. It binds the full input file hash and explicitly does not re-observe or attest its source.

The complete caller-supplied inventory has schema_version1, kind `complete-installed-inventory`, target_arch `aarch64`, a snapshot_id and a packages array. Each package has name, version, arch, depend, provides, conflict, files and optional replaces (defaults empty). Optional sha256 is the caller's declared installed archive hash, not a measured payload hash. Every package from the signed base must be present with identical normalized metadata. Package paths are relative regular-file ownership records, like release.py's base inventory. No host database is scanned: supplied inventory and any archive digests are explicitly labelled CALLER_DECLARED_METADATA_NOT_HOST_ATTESTED.

Install plans add/upgrade only authenticated release packages. Dependencies use ALPM relations and vercmp, including epochs, pkgrel and versioned provides. A missing dependency must have exactly one available provider; ambiguity refuses until the caller explicitly selects an application containing the desired provider. Cycles terminate, bounded work refuses rather than truncating, downgrades and equivalent-version metadata replacements refuse. Existing broken inventories, missing base members, protected base replacements, unsupported replaces, package/file conflicts and reverse-dependency breakage refuse. Same-version declared archive mismatch does not silently become reinstall. Remove plans remove only explicitly named catalog package groups; shared/reverse dependencies are checked, and unused dependencies stay installed.

Plans bind exact release/catalog/signature/keyring/source-helper/installed-input hashes, before/after normalized inventory hashes and package versions/metadata hashes. Additions/upgrades also bind signed release archive hashes; removals retain caller-declared archive hashes when provided. Output reports additions, upgrades, removals, dependency causes and conflicts/refusal issues. Applying would require a separate installer that re-authenticates all inputs, observes the actual target, isolates the transaction and proves cleanup/recovery. This CLI provides no such authority or endpoint.

Run source checks and focused tests with an exact repository snapshot:

```sh
python3 -I -B check_source.py --repository-source /absolute/repository-source
python3 -I -B test_apps.py --repository-source /absolute/repository-source
```

Tests use real isolated GPG/repo-add synthetic fixtures plus dependency/selection failure cases; they never install packages. They need gpg-agent's private local socket for test-only signing, and retire the owned signing agent afterward. For standard makepkg check, all inputs are local pinned recipe sources: check-inputs.tar.gz contains exactly16 bounded MIT data files (the release fixture,3 helpers, license and complete companion recipe). noextract prevents automatic extraction; prepare-check-inputs.py verifies the closed archive/member hashes and writes a fresh private check tree before tests. No checkout, forwarded variable or undeclared sibling recipe is required. Optional CACHY_ASAHI_REPOSITORY_SOURCE and CACHY_ASAHI_RUNTIME_RECIPE development overrides remain available. check-only inputs and fixtures are not installed. The focused suite stages both package recipes, executes the staged app using default lookup without a checkout argument, and refuses a missing/tampered companion. No build/native pair/installed lifecycle/hardware acceptance is claimed by this proposal.

Native aarch64 packages may declare foreign-named provides/conflict/replaces aliases; these remain relation metadata, not selectable foreign package identities. Actual package identities, architectures and dependency names retain the ARM policy. Identical repeated ALPM relation values normalize once; duplicate identity, ownership and malformed fields still refuse. Literal backslashes in ALPM ownership are ordinary POSIX filename characters (including systemd unit escapes); they are never decoded or treated as path separators.

Explicit repair uses `plan reinstall APPLICATION...`. Every selected package must already have exactly the signed release version and normalized metadata; missing packages, upgrades/downgrades, protected targets and broken dependencies refuse. Only explicit catalog groups are reinstalled: no dependency expansion or automatic repair. The plan records both installed metadata/optional caller archive hash and exact authenticated replacement archive hashes in `reinstalls`. Before/after metadata inventory hashes can be equal while damaged payload bytes need repair; this planner does not observe or diagnose payload integrity. Every CLI result still says NOT_APPLIED.

The separate repository development backend `scripts/apps/transaction.py apply --operation reinstall` can apply that exact plan only in its existing explicitly owned offline disposable copy, with fresh actual inventory/root pins, source provenance, exact plan SHA and confirmation. It reauthenticates/replans, prepares only the signed selected same-version additions through ordinary libalpm, and verifies all replacement payload bytes plus unselected/base/user/trust preservation. The installed Apps CLI does not invoke this backend or gain host installer authority. Interrupted or uncertain work stays failed/retained under the original pending/cleanup rules. Native build/lifecycle and real-machine repair need separate evidence.

The existing leased-original574 adapter deliberately refuses any corrupted current candidate payload in its observation/selection/old-payload guards. It is unchanged: this new damaged-payload repair is implemented and host-tested only through the generic owned copied-root backend. No full574/native Apps6 repair or hardware/lifecycle acceptance follows, and existing Apps5/604 historical packets keep their own source/version bindings.
