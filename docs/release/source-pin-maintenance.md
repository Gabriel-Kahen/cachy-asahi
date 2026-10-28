# Offline source-pin maintenance preview

`scripts/release/check_source_pins.py` compares one authenticated local release
bundle with an explicit proposed package/source snapshot. It identifies missing
or extra project-built packages and changes to package identity, recipe SHA-256,
or upstream source descriptors before another release has been built. This is
an M5 maintenance review aid; it establishes no upstream freshness, security
assessment, rebuild requirement, installation authority or stable eligibility.

The baseline is exactly the signed release's selected project-built packages,
using their hash-bound provenance. Base transaction packages have no equivalent
source provenance in this contract and are explicitly excluded. Same-name base
entries do not add a second baseline package. The development TOML inventory is
not a release selection. Use `compare_releases.py` for two built releases and
possible runtime dependency impacts, and `source_delivery.py` for recipient
source-material associations.

Provide the existing verification keyring and an independently authenticated
full signing fingerprint. The tool reuses `release.verify_release`, including
archive/repository signatures, provenance and transaction checks. It does not
fetch or import a key. The candidate SHA-256 only binds the caller's exact bytes;
it does **not** authenticate the candidate or its upstream sources.

```sh
python3 -B scripts/release/check_source_pins.py \
  --release /absolute/retained/release \
  --gpg-home /absolute/existing/verification-home \
  --key AUTHENTICATED_FULL_FINGERPRINT \
  --candidate /absolute/reviewed/candidate.json \
  --candidate-sha256 ACTUAL_CANDIDATE_SHA256 > /absolute/reviewed/preview.json
```

The explicit candidate format copies the `package`, `recipe_sha256` and
`sources` subtrees of the existing release provenance contract. The following
is a shape example, not an actual release or usable pin:

```json
{
  "schema_version": 1,
  "packages": [
    {
      "package": {"name": "example", "version": "1.0-1", "arch": "aarch64"},
      "recipe_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
      "sources": [
        {"url": "https://invalid.example/source", "commit": "REPLACE_WITH_40_LOWERCASE_HEX"}
      ]
    }
  ]
}
```

Every package needs a nonempty source list. Source descriptors use the same
inclusive rule as `release.provenance_check`: a nonempty URL and either a full
Git commit or SHA-256 archive pin. Both fields and other recorded descriptor
metadata are preserved. This tool treats source URLs as data; it neither parses
them into commands nor contacts them. Source descriptor order, duplicates and
additional metadata are compared using compact sorted-key JSON encodings of decoded
subtrees. Boolean, integer and floating-point values remain distinct, including
inside nested metadata. Object key order and raw JSON formatting are ignored;
different numeric spellings that decode to the same floating-point value are
equal. This is decoded-content comparison, not raw JSON formatting equality.
A reported source change may be ordering or metadata rather than a different
upstream revision. No ALPM version ordering or architecture compatibility
inference is made.

The snapshot's outer fields and package-row fields are exact. Duplicate JSON
keys or package names, nonfinite numbers, malformed pins and unsupported input
shapes refuse. Package names use the release name grammar with a 128-character
resource bound; versions are at most 256 characters without whitespace/NUL;
architectures are `any` or `aarch64`. Empty candidate package lists are valid:
they report all baseline packages missing. Extra packages are observations,
never automatic changes to the release policy.

Output is deterministic JSON with the signed release manifest digest, baseline
provenance digests, candidate digest, explicit coverage, changed before/after
subtrees and unchanged names. Arrays of package results are sorted by name.
Exit 0 means the preview was computed, including when changes or coverage gaps
exist. Authentication, malformed input, observed changes or resource failures
exit 1 without a report. No automatic acceptance or reject-on-drift policy is
chosen for an operator.

Inputs are bounded to 4 MiB per JSON file; candidate plus all baseline provenance
is at most 8 MiB. Each side has at most 4096 packages, 128 sources per package,
and 16384 total source descriptors. Report bytes, including the final newline,
are at most 32 MiB. Encoding uses `iterencode` with a checked byte budget before
each UTF-8 piece is appended (at most 4096 characters per piece), and stops on
refusal before consuming the remaining output. Compact typed subtree comparisons
use the same bounded encoder; pretty report indentation cannot amplify those
comparisons. The complete report is buffered and printed only after all release
verification/rereads succeed; no partial report is emitted on refusal. This is
an encoded-output bound, not a whole-process memory/RSS limit. Package-name
lookup avoids a cross-product comparison; descriptor work is bounded by input
bytes. The inherited full release verifier still inspects all bundle payloads;
these bounds do not add a subprocess deadline or whole-bundle archive-size cap.

Candidate, manifest, specification and provenance reads reuse the existing
descriptor-relative no-follow reader. It rejects symlink components, special
files, hardlinks, oversize files and changes observed while reading. Provenance
bytes are joined to the signed manifest, then the release is verified again and
all used raw JSON is reread before returning. Keep bundles and snapshots under
operator custody and immutable while checking. This detects exercised changes;
it is not a filesystem snapshot or protection against a hostile same-user/root
writer that repeatedly swaps bytes between observations. Only verification
subprocesses run; no recipe or source code from a bundle is executed. GnuPG may
use its existing verification-home machinery; no package, selection pointer,
repository lock or host trust setting is modified by this tool.

Tests use pure snapshots and signed synthetic package bundles with disposable
TEST keys. Dependencies are the existing release-test tools: Python 3.11+,
`gpg`, `gpgconf`, `repo-add`, `bsdtar` and `vercmp`. Missing tools are reported as
skips by the inherited fixture; an acceptance run must fail on any skip. No
production key, target hardware, native package build, upstream monitoring or
second stable release is established by these tests.

```sh
python3 -B -m unittest discover -s scripts/release -p test_check_source_pins.py -v
```
