# Bankstown Qt3 passive profile seam v1

This opt-in sibling consumes the `BANKSTOWN_QT3_IMAGE_DATA_V1` receipt from
`scripts/ci/bankstown-qt3-native-source/` and the
unchanged `scripts/port/bankstown-qt3-native-v1/` consumer. It creates no image,
executor, Root trial, grant, dispatch, installation, or publication. There is no
automatic import or executable success route.

The caller must independently review and pin this family and supply external
whole-file SHA256 selections through trusted custody. A matching checksum or a
JSON `issuer` field does not authenticate a document.

## Interface

Import `profile.py` only after reviewing its bytes. Call:

```python
inputs = dict(image_receipt_path=actual_image_receipt,
              image_receipt_sha256=externally_selected_image_receipt_sha256,
              admission_path=externally_selected_root_trial,
              admission_sha256=externally_selected_root_trial_sha256,
              catalog_path=externally_selected_catalog,
              source_root=actual_source_root,
              executor=same_live_owned_executor)
result = profile.export(profile_path=fresh_profile,
                        output_receipt_path=fresh_profile_receipt, **inputs)
```

The image receipt must come from the actual image operation. Its IID, observed
inventory, filesystem archive/root, source/binding, nonce, executor identities,
and monotonic lifetime are mandatory. Templates with NULL actual selectors
refuse. The same externally reviewed owned executor must expose its maintained
`facts`, `deadline`, and `live()` API. This module calls `live()` before and after
inspection, joins its owner/daemon PIDs, engine, endpoint, code pin, binding,
nonce, deadline and custody flags, and never calls `run()` or creates an executor.
The caller must retain that original executor and daemon for the whole operation;
serialized receipts cannot replace their live custody.

The separate externally selected Root trial is required by the maintained public
`export_profile` API. This sibling never constructs or approves that trial. Trial
source, catalog, IID, observed inventory and executor selection must exactly join
the image receipt. Catalog/inventory bodies must also equal their uniquely
admitted source materials. Source commit strings are joined declarations; the
maintained closed material map checks actual source bodies.

`inventory.py` enforces canonical exact 477 inventory bytes, the whole pinned
protected 349 baseline, all catalog 333 package versions, and exactly 128 additions.
It forbids protected replacements and unselected additions. The maintained
consumer additionally verifies the frozen Qt3 lock/parent/recipes, full 333
metadata/signature observations, Rust137 descriptors, actual selected native
file bytes and modes, logical links, ELF facts and provider joins. The image
export archive is streamed against its whole pin without decoding/extraction;
its identity must remain stable. The materialized root is supplied by the image producer's
externally selected actual image receipt, and its selected tool files are read
again by the maintained consumer. This seam does not independently reconstruct
the entire image filesystem from that archive.

The output profile retains the exact existing consumer schema. A separate
`BANKSTOWN_QT3_PROFILE_DATA_V1` receipt binds its path/bytes/SHA256 to the original
image receipt, archive/root, actual IID/inventory, executor lifetime, trial,
consumer pins and inventory joins. Both outputs must be fresh and mode 0600.
A failure may leave a partial profile; without the successful bound receipt it
is not a completed export. Time bounds are at most 300 seconds, the remaining
Root trial validity, and the existing executor work deadline.

Only after export may Root separately select the whole profile and profile
receipt hashes. Verify those external selections through:

```python
profile.verify(profile_path=exported_profile,
               profile_sha256=externally_selected_profile_sha256,
               output_receipt_path=exported_profile_receipt,
               output_receipt_sha256=externally_selected_profile_receipt_sha256,
               **inputs)
```

This passive verifier rederives the maintained projection against the same
materialized root and requires byte-identical profile and receipt. It does not
change the runtime consumer: maintained `verify_profile()` still requires `/`,
and the unchanged `build_guard.native_tools()` remains the runtime guard.
No native compiler, payload, Docker/GPG process, network operation, or key is
selected by this family. `legal` and `key_freshness` remain HELD; Root final,
component, hardware and release acceptance remain unset or false.

## Evidence and portable controls

On 2026-11-16 the Root-supplied genuine 333 catalog was read at 27829517 bytes,
SHA256 `aa612232f6bf711b9d1137ec8e10c8aaca99d026f26fce2b1954f64c9973b673`.
The finite 349/333 union and actual maintained `_catalog` API passed DATA checks,
including 74,428 catalog entries. The prospective 477 inventory is 9102 bytes,
SHA256 `64f9c67795bd16f4cf3704dc0a050d2d17d1baa6e42b4e4fa254507b15183c49`.
That inventory was derived from catalog and baseline DATA. It was **not observed
in an actual image**. Actual IID, image filesystem, native profile, native build,
installation and M2 results have **not been produced** by this work.

All 35 portable controls pass on Python 3.12.14 and 3.14.7.
Portable controls use explicit MODEL metadata and inert ELF bytes. They test the
actual frozen consumer APIs, relocation/link/provider behavior and guard API
through explicitly mocked logical-root reads; no host native tools execute.
The orchestration controls separately mock the admitted export boundary and
the fixed inventory pin for their explicit MODEL data. They cannot establish
genuine admission or image provenance.

Run each test independently with Python 3.12 or 3.14:

```sh
python3 -I -B -Werror scripts/ci/bankstown-qt3-native-profile-v1/test_passive.py
python3 -I -B -Werror scripts/ci/bankstown-qt3-native-profile-v1/test_inventory.py
python3 -I -B -Werror scripts/ci/bankstown-qt3-native-profile-v1/test_profile.py
python3 -I -B -Werror scripts/ci/bankstown-qt3-native-profile-v1/test_consumers.py
```

`test_consumers.py` requires the exact frozen maintained adapter to exist in the
source checkout. For an isolated checkout based before that adapter, explicitly
set `BANKSTOWN_QT3_TEST_SOURCE` to a local export of committed
`4a7c58886917880d9a15124384ecaa70401a1032`, preserving its source-relative paths.
The loader verifies every imported consumer's whole pin; a missing/changed
consumer is an error rather than a skip. No retained archive acquisition or
actor run is part of these controls.
