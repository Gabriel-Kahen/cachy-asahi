# Signed initial587 producer candidate

Source-only implementation. The inert controls pass; native preparation, VM boot,
installer transactions, target installation and hardware validation have not run.
The failed container P0 boundary remains failed. This producer never starts the
composition container, copied-root upgrade, volume actor or installer.

## Callable contract

`producer.prepare(args)` returns the absolute path to `args.output/private/ready`.
`args` is a namespace with absolute directory paths `code`,
`preparation_source`, `product`, `updater`, `desktop`, `updater_v2_source`,
`native`, `fdk`, `cache`, `setup4_pair`, plus a fresh absolute `/tmp/NAME`
`output` and a full 40-character `code_revision`. The source checkout HEAD must
equal that revision. The existing held caller checks the original native/FDK
pair provenance and exact package bytes; the producer checks the original
product/updater/desktop/updater-v2 revisions and preparation revision
`93bc9bfac7343ee3b443ae3332c0942ed1ba5b55` before preparing anything.

The future native caller uses:

```python
ready = None
try:
    ready = producer.prepare(args)
    # run.host builds profile.build(ready, args.code, fresh_candidate_copy).
    # Build/boot the owned generic image; keep preparation resources alive.
    # Mount/copy ready package cache read-only into the owned guest image.
finally:
    # VM/image owner must first retire every VM/image actor using this cache.
    # Call even on prepare failure once producer-owner.json exists.
    if (args.output / 'producer-owner.json').is_file():
        producer.cleanup(args.output)
```

CLI forms mirror the callables:

```text
python -B producer.py prepare --code ABS --code-revision FULL_SHA \
  --preparation-source ABS --product ABS --updater ABS --desktop ABS \
  --updater-v2-source ABS --native ABS --fdk ABS --cache ABS \
  --setup4-pair ABS --output /tmp/FRESH_OWNED_NAME
python -B producer.py cleanup --output /tmp/SAME_OWNED_NAME
```

`prepare` refuses a non-aarch64 host or root process before any actors. Its
future build/package/GPG commands reuse the current composition functions and
their finite deadlines. No producer command was executed during implementation.

## Reused preparation and exact membership

The module loads `code/scripts/ci/full-root-upgrade-caller/run.py` and compiles
its existing `compose` function prefix, ending immediately before its unique
literal `footprint = module('composition_volume_owner', HERE / 'footprint.py')`
statement. It retains the actual caller SHA and extracted AST SHA in the
manifest. A missing/duplicated boundary refuses. The removed tail contains
volume creation, composition-container invocation, upgrade execution and
composition PASS assertions; none is replaced with synthetic success.

This reuses existing small-recipe native builds, updater native pairs,
authenticated desktop574 construction, dependency acquisition, retained setup4
input verification and ephemeral TEST signing. Setup4 is retained input only.
The initial selected setup stays **0.1.0-3**, updater **4.4.2-2**. No new artifact
pins are manufactured. The producer also does not claim a package-only cache
was installed as a full composition.

Cache membership is exactly 573 held desktop574 archives excluding
`libfdk-aac`, plus all 14 actual composition additions. The sorted name/version
set must equal the exact 587-row lock with SHA256
`2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7`.
Every archive and detached signature is copied from its actual preparation
location and checked for exact size/hash before and after copy. Each archive
has a 256 MiB compressed limit; aggregate compressed archives have a 4 GiB
limit. Overflow fails; no packages are silently skipped. Signature files have
a separate 1 MiB limit each.

A separate public-only GPG verifier imports the pinned ALARM keyring and actual
ephemeral TEST public key. Every exported signature must return one complete
VALIDSIG matching its expected primary signer (including signing-subkey primary
binding). All ten project packages use the actual TEST fingerprint; upstream
base and four dependency additions use the pinned ALARM fingerprint. Bad,
revoked, expired, duplicate or missing validation statuses fail. The verifier
home is retired before export completion; secret keys and agent sockets never
enter `ready`.

## Manifest and ownership

`ready/manifest.json` schema version 1 has status
`READY_SIGNED_INITIAL587`, `expected_lock:{path,sha256}`,
`builder_lock:{path,sha256,size}`, `packages`, `keyrings`, `projects` and
`preparation`. Every package row has `name`, `version`, relative `archive` and
`signature` paths, archive/signature SHA256 and size, and actual `signer`.
`keyrings` contains relative public key paths with SHA256 and size. `projects`
preserves the held payload/metadata maps. Preparation includes original source
revisions, actual native authentication receipts, signer roles, image ID and
absolute `image_id_path` from `private/desktop574/image-id`.

`builder-packages.lock` is copied from the actual
`private/desktop574/installed-packages.lock`; it must also equal the held574
inventory and SHA256
`cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`.
This is the existing generic image builder's inventory input, distinct from
the new install target's expected587 inventory.

The producer owns its fresh 0700 output, all private preparation subtrees,
ephemeral TEST signing home, verifier home and selected newly created builder
images. It snapshots preexisting image IDs before preparation and never removes
them; the borrowed original core image is independently protected. Inputs,
source checkouts, retained native/FDK/setup4 pair trees and shared cache are
borrowed and not removed. Existing preparation helpers retain their declared
cache behavior; this is not an atomic preservation claim for a writable shared
cache.

Exported archives/signatures/keys/locks/manifest are ordinary 0444 files; archive
and key directories are 0555, inside the private owned parent. The ready root remains owned by the producer. The VM controller writes the
bounded profile and payload map into its separate fresh candidate copy; VM
staging consumes the ready cache read-only. It must not mount the private preparation parent or signing home.
The VM owner owns all generic-image and guest lifecycle cleanup. Only after
that cleanup may `producer.cleanup(output)` retire producer resources. It
observes image absence after each removal and retains private state on any
cleanup failure. Public producer/cleanup receipts remain after successful
retirement. Preparation/export failure records a bounded error and preserves
the current phase; the caller must still run scoped cleanup.

## Validation and acceptance limits

`python -B test_producer.py` passes 16 inert tests: exact actual declared set,
mutation/omission/duplicate rejection, exact pre-actor prefix boundary, native
guard, signer/subkey/revocation controls, full 587-row synthetic export/signature
iteration and sealing, file/hash/size/bound failures, borrowed-image/core
protection and failed image-absence retention. Synthetic bytes exist only in
temporary tests and provide no native package/transaction credit.

No actual producer preparation, new signed587 installation, installer contract
run, proc/mount execution, boot/platform acceptance, physical target behavior or
performance gain is established by these controls. Native integration must run
the actual producer, profile builder and generic ARM VM route with their exact
source freeze and retain their real receipts and cleanup results.
