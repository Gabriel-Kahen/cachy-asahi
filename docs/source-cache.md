# Pinned source-input cache

`scripts/maintenance/source_cache.py` is an opt-in Linux CLI for caller-selected
HTTPS source archives read as opaque data. It acquires exact bytes, retains their
source/license provenance descriptors, and verifies/reuses them offline. It does
not extract archives, execute source, install packages, approve a license, verify
upstream signatures, or select release inputs.

This fills the retrievable-input storage gap for M5/R1; it does not establish
reproducible builds, native ARM execution, M2 behavior, release or maintenance
acceptance. The caller must obtain and review expected checksums, sizes, revisions
and license evidence independently. A checksum supplied alongside an untrusted
download does not authenticate its publisher.

## Inputs

Supply a JSON catalog and its independently held SHA256. The cache reuses
`scripts/release/source_delivery.py` material descriptors exactly:
`id`, `path`, `sha256`, `bytes`. Its bound is 512 MiB per archive and 2 GiB per
selected operation; callers may lower the total with `--max-bytes`. Catalogs are
at most 4 MiB and 128 sources. JSON duplicate keys, floats and unknown fields are
refused. `path` identifies the original material; it never selects a cache write
destination. Each requested `--id` must be unique and present.

Illustrative catalog (replace all example pins/size/revision with reviewed values):

```json
{
  "schema_version": 1,
  "purpose": "source-cache-inputs",
  "sources": [
    {
      "material": {
        "id": "upstream-archive",
        "path": "sources/upstream.tar.gz",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "bytes": 1234
      },
      "url": "https://example.invalid/project/archive/EXACT-REVISION.tar.gz",
      "revision": "EXACT-REVISION",
      "license": "MIT (caller record; pending review)",
      "license_evidence": [
        {
          "id": "upstream-license",
          "path": "notices/LICENSE",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "bytes": 456
        }
      ]
    }
  ]
}
```

License evidence paths are relative to the catalog's directory and must exist as
ordinary single-link files without symlink ancestors. Their exact sizes and hashes
are checked before acquiring or verifying selected sources. Each source requires
1–16 evidence descriptors, each at most 4 MiB. `license` and `revision` retain the
caller's bounded text without interpreting its legal or upstream meaning. Preserve
the catalog and its notice files as build inputs: the cache receipt records their
descriptors/checksums, while the original notice contents remain in that input set.

HTTPS URLs must contain no credentials, query, fragment, backslash or control
characters. Only the standard HTTPS port is supported. TLS verification uses
Python's standard HTTPS validation. Redirects are refused: supply the final URL
explicitly and pin its bytes. Environment proxy configuration is ignored. Nothing
loads credentials, authenticates, executes a shell or requests upstream trust.

## CLI

Create a fresh absolute directory beneath an existing nonsymlink parent:

```sh
python -B scripts/maintenance/source_cache.py init --cache /absolute/private/source-cache
```

Acquire only named sources; additional `--id` options select additional records:

```sh
python -B scripts/maintenance/source_cache.py acquire \
  --cache /absolute/private/source-cache \
  --inputs /absolute/reviewed/source-inputs.json \
  --inputs-sha256 REVIEWED_CATALOG_SHA256 \
  --id upstream-archive --timeout 120 --max-bytes 268435456
```

`--timeout` is a finite aggregate download wall-time budget in seconds, default
120 and maximum 600. Transfers run in a disposable child; the parent enforces the
deadline even during a blocked HTTPS open/read. Child termination and cleanup have
a bounded grace interval. Expected size is enforced while streaming, then both
size and SHA256 are independently rechecked before publication. Responses with
an unexpected status, URL, length or content encoding fail closed. No live HTTPS
request is needed when every selected object already matches its pin.

Use the same arguments with `verify` for strictly offline, read-only verification:

```sh
python -B scripts/maintenance/source_cache.py verify \
  --cache /absolute/private/source-cache \
  --inputs /absolute/reviewed/source-inputs.json \
  --inputs-sha256 REVIEWED_CATALOG_SHA256 --id upstream-archive
```

Successful commands emit JSON with each object's absolute `path`, `sha256`,
`bytes`, and `acquired`/`verified` status. Exit 0 indicates that selected cache
operation succeeded; exit 1 indicates refusal. `verify` requires both the object
and its exact provenance receipt and never repairs either. `acquire` can add a
missing provenance receipt for an already verified object without networking.

Current build/source helpers can consume the reported object paths as local data
inputs. A caller that requires the original archive filename must explicitly copy
the verified object into its reviewed input staging directory and recheck that
input snapshot as usual. No recipe, container command, source pin or build network
policy changes automatically. `check_source_pins.py` remains the release drift
checker; `source_delivery.py` remains the source-association authority.

## Storage and failures

The cache root and its `objects`, `receipts`, `.partial` directories must be owned
by the current UID with mode 0700. Cache files must be single-link regular files
owned by that UID with mode 0600. Symlinks, unsafe ancestors, FIFOs, hardlinks and
group/world-accessible entries are refused. `init` never adopts an existing path.

Objects are stored as `objects/<sha256>`. Provenance receipts are stored as
`receipts/<catalog-sha256>-<source-id>.json`; they include the complete selected
source record, catalog checksum and object path. Both acceptance booleans remain
false. Identical content from different recorded origins shares one object and
retains separate receipts. Byte reuse does not merge or approve provenance.

Random exclusive files in `.partial` isolate incomplete transfers. After fsync and
verification, atomic no-replace link publication makes the complete object
visible. Existing mismatching objects or receipts are retained and cause refusal;
there is no automatic overwrite, deletion or repair. Ordinary failures remove
only that invocation's partial file. Abrupt process/host termination may leave a
partial file; it is never considered an object. There is no scavenger command.
An object successfully published before a later receipt/source failure remains
available for a subsequent explicit `acquire`; an unsuccessful multi-source run
does not roll back earlier successful selections. A failure while initializing
can leave a fresh incomplete directory, which is never adopted as a valid cache.

The directory is private caller-owned storage, not a security boundary against
another process with the same UID, root or a compromised host. Preserve verified
objects as immutable inputs while a build consumes them; later `verify` detects
observed corruption but cannot prevent mutation after verification.

## Focused checks

After integration:

```sh
python -B scripts/maintenance/test_source_cache.py
```

Before integration, run the proposed script with the existing release helper on
the import path from the repository root:

```sh
PYTHONPATH="$PWD/scripts/release" python -B \
  artifacts/development/source-cache-implementation-20261027/proposed/scripts/maintenance/test_source_cache.py
```

The suite uses real temporary directories, subprocess CLI calls, real forked
workers and a real stalled-worker deadline. Only HTTPS response/error behavior is
mocked. Live upstream HTTPS, a native ARM build, package installation, physical
M2 testing, performance, release and maintenance acceptance remain NOT RUN.
