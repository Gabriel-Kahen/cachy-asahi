# Unselected glibc auxiliary-cache semantic projection

This is strict pure DATA code for the exact glibc8362e8ce10b24068bacc19552c128dd10e082fd9 ARM64LP64 little-endian auxiliary2.0 format. It does not modify Source389,501, a guest guard, package state or Root authority. Actualr94's exact failed predicate remains unproven. The r96 observer recovered only the genuine baseline body before its later seam failure; a restored body is still missing. No baseline/after semantic equality or lifecycle acceptance is claimed.

## Primary layout, not a guessed struct

`primary.DATA.json` retains complete URLs, exact source revisions/byte hashes and line references. Exact glibc cache.c declares four uint64 stat fields followed by int32 flags, uint32 SONAME offset and uint32 ISA level. AAPCS64 release2025Q1, revisionc51addc3dc03e73a016a1e4edf25440bcac76431, specifies4-byte word and8-byte double-word alignment, aggregate maximum-member alignment and rounded aggregate size. Thus the32-byte header and48-byte entry are derived:44 defined bytes plus4 trailing ABI padding bytes. The installed glibc suffix corresponds to the exact upstream revision; binary reproduction is not claimed.

The writer clears the header, assigns every defined entry field and writes from xmalloc memory without assigning trailing entry padding. It serializes used entries in hash-bucket/list order, writes a separate terminated SONAME segment per non-NULL record and uses offset0 as a NULL sentinel. Loader hash size is nextprime(nlibs), while initial construction uses8191 buckets; insertion is at bucket heads. Primary readlib/ldconfig sources show only successfully processed libraries enter the auxiliary cache. These facts justify projecting defined fields independently of padding, bucket ordering and string-segment placement. They do not identify the actualr94 failure.

## Exact behavior

`decode(bytes)` refuses unknown magic/version/ABI, unsupported ARM64 library/ISA flags, excess counts/bytes/names, wrong48-byte geometry, trailing bytes, duplicate full stat identities, overlapping/interior/reused string pointers, missing NULs and unreferenced string segments. Policy bounds are1MiB,4096 entries and4096 bytes per SONAME; these are finite implementation limits, not claims that glibc imposes those limits. It supports a legitimate empty cache. It preserves all64 bits of inode, ctime, file size and device; all supported flag/ISA bits; complete binary-safe SONAME bytes; and library membership/multiplicity. NULL differs from non-NULL empty SONAME. No version/name shortening, timestamp/device/inode remapping or membership deduplication occurs. SONAME data is never opened as a filesystem path. Unsupported profiles HOLD instead of being silently normalized.

`normalize` produces a versioned, length-framed canonical binary sequence. It sorts by the full stat identity, replaces each string offset with exact SONAME bytes and omits only the documented4-byte padding. Raw body and opaque-padding hashes remain recorded. `compare` reports every added/removed identity and every changed defined field. It returns DATA-only equality/difference with selection UNSELECTED and explicit provider/metadata/predicate/Root-selection holds. Equal normalized data is not a Root certificate, proof of package correspondence or permission to change an existing guard.

The actual independently pinned baseline12313/SHA bf57218ea22ca530decf18bf8ec548c22ec96afb0afc423088a97fbb148149ed decodes190 entries, all flags0xa03, one NULL SONAME. Its canonical11373-byte digest is101a81b8720aeb3f5994f133226c19f06a3b9073d51cee7d419c2ceb96184f1d. This is an ACTUAL baseline fact only. No restored body exists in this family. The other layout/ordering/padding/flag/offset controls are explicitly MODEL DATA assembled from primary field offsets; none is a substituted actual observation.

## Future adapter remains unselected

A possible later cache_snapshot change would replace ONLY the auxiliary-file payload hash with this canonical defined-field digest after Root proves the actual failing predicate and independently qualifies both public bodies/providers/stat identities. Main cache equality, fixed path/type/mode/owner metadata, complete xattr streams, initialized/private/user/payload/dependency/retirement checks must stay required. No such runtime adapter or transformation is included or selected here. Auxiliary files contain no complete target paths; provider/path/hash/alias correspondence and live device/stat facts cannot be invented from SONAMEs. Missing after/provider/typed facts therefore remain explicit holds. Actual padding/order variations cannot justify dropping a changed defined field.

`inspect_public.py` reads only explicitly supplied ordinary single-link1MiB public DATA files with externally supplied whole SHA pins. It does not open an image, enumerate a namespace, query QMP, invoke an actor, acquire a lease, install a package, sign or issue a Root role. Example for the selected baseline:

```
python3 -I -B inspect_public.py --before /absolute/selected/baseline-aux.bin --before-sha256 bf57218ea22ca530decf18bf8ec548c22ec96afb0afc423088a97fbb148149ed
```

Add an exact Root-selected public after path and SHA only when separately recovered. Source/namespace/material/runtime acceptance and any future guest trial remain Root-owned.
