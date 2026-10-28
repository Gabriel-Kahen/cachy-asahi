# Package cache maintenance

`package_cache.py` previews an explicitly chosen package cache. Apply deletes only individually selected entries from an exact reviewed preview. It never removes installed packages, orphans or a preexisting ALPM lock; it does not fetch archives, change repositories/trust, select a release or install anything. Run it with the identity that owns the cache and database directories. There is no automatic privilege escalation or scheduled cleanup.

This implements the cache-cleanup portion of the tools functionality matrix. The cache remains an additional convenience, **not** the immutable release retention archive. The [release recovery contract](release/recovery.md) still requires current, preceding accepted, upgrade-starting-point and incident releases, with compatible base inputs and signatures. An operator must include every cache archive/version needed for their rollback policy; newest cached versions are not automatically accepted releases.

## Explicit policy

Provide a local JSON policy. The following is a shape example; substitute real archive names, versions and SHA-256 hashes from operator-reviewed rollback records. The example is not usable recovery evidence.

```json
{
  "schema_version": 1,
  "retain_versions": 3,
  "known_packages": [
    {"name": "example", "arch": "aarch64"}
  ],
  "protected": [
    {
      "filename": "example-1.0-1-aarch64.pkg.tar.zst",
      "name": "example",
      "version": "1.0-1",
      "arch": "aarch64",
      "sha256": "REPLACE_WITH_ACTUAL_64_LOWERCASE_HEX"
    }
  ]
}
```

The known-package/architecture list is an explicit cleanup scope; unlisted packages remain unknown and cannot be selected. `any` and `aarch64` are supported. At least one exact protected archive identity is required; a missing, changed, corrupt or mismatched protected archive refuses the entire operation. Every readable duplicate of a protected version is kept, including ALPM-equivalent version labels.

`retain_versions` must be at least three. For each listed package/architecture, keep all copies of the newest N ALPM-distinct version groups, plus all protected versions. Real `vercmp` orders versions, including epochs and package releases. A missing/failing version tool refuses the operation; no lexical fallback is used. Raising this number retains more versions. It does not replace explicit known-good rollback pins or prove a compatible recovery set.

Archive names, regular-file ownership/modes/link count, complete compression/tar readability and `.PKGINFO` are checked without extraction or script execution. Unknown filenames, detached signatures, symlinks, hardlinked/writable/foreign-owned files, unsupported compression/architecture, malformed/corrupt archives and unlisted packages remain untouched. This is metadata/integrity inspection, **not** signature, safety or installation eligibility verification. Detached signatures are deliberately retained even when their associated obsolete archive is explicitly deleted.

Python 3.11+ and ALPM `vercmp` are required. gzip/xz use the standard library; zstd inspection additionally requires Python's `compression.zstd` module (Python 3.14+). Without that reader, zstd archives remain unknown, including refusal if one is a required rollback pin. Bounds are 4096 direct cache members, 2 GiB per archive, 65536 tar members, 8 GiB uncompressed data and a checked 30-second inspection deadline per archive. Bounds/unsupported inputs do not grant deletion permission.

## Preview and select

Both directories must already exist, be owned by the effective user, be disjoint, have no symlink path components, and deny group/other writes. Choose the **actual database directory used by the installation's ALPM transactions**; the tool does not guess it from the cache or discover host configuration. Preview also refuses an existing `db.lck`, whether active or stale. Stale-lock diagnosis is a separate procedure.

```bash
python3 -B scripts/maintenance/package_cache.py \
  --cache /absolute/chosen/cache --db-path /absolute/chosen/database \
  --policy /absolute/operator/policy.json > /absolute/operator/preview.json
sha256sum /absolute/operator/preview.json
```

Keep the policy and preview outside the cache/database directories. Review each entry's `action`: `protected`, `retained`, `candidate` or `unknown`. No candidates means nothing should be selected; an empty apply selection refuses. Preview creates no files or locks in either chosen directory.

Apply consumes the exact preview bytes/hash and one or more explicit candidate basenames; no wildcard, arbitrary path or automatic “all” selection exists:

```bash
python3 -B scripts/maintenance/package_cache.py \
  --cache /absolute/chosen/cache --db-path /absolute/chosen/database \
  --policy /absolute/operator/policy.json \
  --apply --plan /absolute/operator/preview.json \
  --plan-sha256 ACTUAL_REVIEWED_PREVIEW_SHA256 \
  --select example-OBSOLETE_VERSION-aarch64.pkg.tar.zst
```

The preview binds directory identities, canonical policy values, every observed cache entry and each readable archive's inode/metadata/hash. Any observed change requires a new preview. Apply exclusively creates the chosen database's `db.lck`, cooperating with ALPM's transaction exclusion, and removes only that exact owned lock. A preexisting or replaced lock is never removed. If acquiring the lock’s descriptor identity fails, the identity-unknown lock is retained without unlinking. Descriptor-close faults still restore the caller’s signal mask; cleanup faults are reported as notes without replacing the first error. The caller needs permission to create that lock; no ALPM transaction is run and no installed-package database contents are modified.

Each selected file is rechecked, moved into a private directory beneath the held cache directory descriptor, then rechecked before unlink. If replacement or cancellation is observed, restoration uses a no-overwrite hardlink operation. A collision or uncertain restoration preserves the bytes in the reported private quarantine. Do not remove that directory blindly: inspect its files and the current cache entries first. This covers the tested replacement/collision cases; directories must stay under operator custody and unrelated same-user writers must cooperate with ALPM exclusion. It is not protection against a malicious process with the same user privileges or root access.

## Cancellation and partial results

Deletion is incremental. A failure or SIGINT/SIGTERM stops further work and reports already completed deletions, any retained quarantine and cleanup uncertainty on stderr; exit 130 denotes cancellation, other failures exit 1. Success prints the exact deleted names and exits 0. There is no whole-batch atomic rollback or power-loss durability claim. A hard kill/crash may leave the owned ALPM lock/quarantine for explicit diagnosis; the utility never auto-clears them. Signals are deferred around unlink/progress recording and owned lock cleanup so a completed deletion is not reported as untouched in the exercised cancellation case.

All development tests operate exclusively on temporary caches/databases and real synthetic gzip/xz/zstd archives. They cover retention, protected duplicates, corrupt/unknown objects, source replacement, restoration collision, partial cancellation including a real SIGTERM, foreign-lock preservation and CLI selection. No live `/var/cache`, system database or host package is touched:

```bash
python3 -B -m unittest discover -s scripts/maintenance -p test_package_cache.py -v
```

Production cache maintenance, package lifecycle/recovery, compatible base/overlay rollback and M2 acceptance remain untested. Native builder/updater/client/P0/setup/KSM lanes, shared manifests and release policies are unchanged.
