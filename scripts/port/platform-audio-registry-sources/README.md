# Raw registry sources for the delivered audio vendor set

This bounded offline join supplies the missing raw-crate comparison for the
[vendor audit](../platform-audio-vendor-audit/README.md). It first verifies the
unchanged five-package handoff through the pinned intake/auditor APIs, recomputes
the vendor file maps, then joins independently captured official registry index
rows, raw archive SHA256 values and the actual vendored member bytes. It invokes
no Cargo, compiler, build script, procedural macro, package payload or subprocess.

The existing source-cache interface handles already described materials; it
does not perform registry-index identity joins or raw-to-vendor member
comparison. `join.py` adds only that DATA operation. Acquisition remains a
retained finite invocation rather than a general fetch/build framework. Existing
source exports, vendor/metadata reports, frozen profiles and recipes are unchanged.

## Inputs and replay

`registry-inputs.json` is 84574 bytes, SHA256
`fc8d9e9bb5c2696dce29bdddfc58e39d8cb568a5434dac47eb8ace3afc9adc94`.
It records all 117 exact names/versions, raw archive sizes/hashes, official URLs,
108 sparse-index snapshot references, acquisition provenance receipt and the
separate pinned host-metadata report. It contains no operator paths or source
code. Communicate its hash through the trusted checkout/channel; a hash supplied
only by the same untrusted packet does not authenticate a registry observation.

Supply the actual handoff and the private acquired packet, preserving its
relative `indexes/`, `crates/`, `metadata-replay.json` and `acquisition.json` files:

```sh
python3 -I -B scripts/port/platform-audio-registry-sources/join.py \
  --trusted-checkout /trusted/cachy-asahi \
  --handoff /private/relocated/handoff \
  --inputs scripts/port/platform-audio-registry-sources/registry-inputs.json \
  --inputs-sha256 fc8d9e9bb5c2696dce29bdddfc58e39d8cb568a5434dac47eb8ace3afc9adc94 \
  --materials /private/acquired-registry-packet \
  --output /private/new-registry-join
```

The trusted checkout defaults to this repository. Its vendor auditor must match
SHA256 `94b1c5c9196326354ec84d11b81c3cd114a3e0b9ba4fa914802db309cdb37d37`;
that auditor independently pins the intake API, which pins its source-delivery
APIs. No code is imported from the handoff or registry packet. The handoff index
`70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c`
and native input profile remain independently selected, unchanged inputs.

Fresh output is mode0700 with a mode0600 `registry-source-join.json`. Existing
outputs are preserved. Exit 0 means the finite source DATA joins have no detected
errors, with acceptance holds. Exit 1 means a refused critical input or recorded
per-crate registry/member errors. Neither exit accepts a binary, build,
transaction, source/legal completeness, registry security state or hardware.

## Exact comparison and bounds

Names and full version strings are validated before constructing the fixed
`index.crates.io` and `static.crates.io` URLs. Sparse paths and the registry
checksum field follow the [Cargo registry index specification](https://doc.rust-lang.org/cargo/reference/registry-index.html).
Each exact name/version must select one index row; its complete row, raw-line
pin, schema and yanked state remain in the report. A row's checksum must equal
both the verified vendor/lock package checksum and the raw `.crate` SHA256.
No newer version, mirror or same-name source is substituted.

The existing bounded tar parser reads regular member bytes without extracting a
tree or following links. Unsafe paths, foreign roots, duplicates, links, special
files and sparse representations refuse. The tool independently verifies the
vendor checksum map against actual delivered files, then compares raw files to
those actual bytes. Every missing, extra or different relevant file remains a
named observation with available hashes/sizes; Cargo.toml differences are not
silently normalized away. The vendor-generated `.cargo-checksum.json` is the
comparison map, not an expected raw archive member.

Inputs are limited to 16 MiB/object and 256 MiB aggregate. Each raw archive retains
the existing 8192-member/8 MiB-member/64 MiB-expanded limit; raw expanded bytes also
have a 256 MiB aggregate budget charged before reading member bodies. Source
manifests remain bounded to 1 MiB. Registry row parsing rejects duplicate JSON
keys, duplicate selected versions, unsupported selected schemas and invalid
checksum/yanked types. No network operation occurs during replay.

## Actual retained-source result, November 14, 2026

The real handoff verified first, and its recomputed vendor report exactly
matched `ce9e9077b961c60dfcb890914256235ae6376bdb689376a9471b8ce3eb08ad80`.
A read-only Cargo-cache scan found 57 exact raw archives. Their provenance paths
are retained in the private acquisition receipt; their hashes were subsequently
joined to the same independent official index rows as every downloaded crate.
Only 60 missing raw archives and 108 index responses were fetched: 168 exact HTTPS
requests, all 200, totaling 11859347 response-body bytes. Requests used four
workers, 30-second socket/60-second object deadlines, 16 MiB/object and 256 MiB total
caps, identity content encoding, fixed official endpoints and no redirects,
credentials, version substitution, installation or source execution.

| Actual observation | Result |
| --- | --- |
| Raw crate archives | 117 /9317118 bytes |
| Distinct sparse-index responses | 108 /5741544 bytes |
| Independent selected registry checksum joins | 117 /117 |
| Selected rows yanked in captured snapshots | 0 |
| Exact raw/vendor file sets and bytes | 117 crates /4292 files |
| Raw regular expanded bytes | 57154652 |
| Missing /extra /different files | 0 /0 /0 |
| Nonempty UTF8 license-text candidate present | 116 crates |

wmidi 3.1.0 still declares MIT without a nonempty license-text candidate in its
raw crate. The raw archive does not repair the separately retained limited
notice association. License declarations, candidate filenames/text presence,
terms authentication and legal applicability remain distinct. All original
source-publication blockers, including the wmidi/nalgebra association limits,
remain in the new report. No legal acceptance is inferred from file identity.

The pinned metadata replay remains SHA256
`bbdb8c033a859050d188ae1e573b91fd14d77092cd24ee6e8c5159bd5c02c210`.
Its 88 root-reachable registry identities are a labeled subset of these 117,
from the separate new host default-feature/target metadata query. This operation
does not replay Cargo or establish the original native build's active graph.

Eight synthetic DATA controls pass: index/checksum/version/yanked handling,
exact URL construction, every file-difference category, altered vendor bytes,
unsafe/duplicate/link/foreign members and byte/expanded budgets. The actual
117-crate join also passes while sockets and subprocess creation are fenced.
A copied real alsa 0.11.0 archive was corrupted: its row retained
`MATERIAL_BYTES_DIFFER`, 116 other exact crates remained visible, and the original
packet/handoff were preserved. The test copy was restored.

## Retained local evidence and remaining limits

Ignored evidence is under `work/platform-audio-registry-sources-20261114/` in the
implementation worktree. The finite acquisition invocation is 4555 bytes,
SHA256 `8faed62ca4496aa4145694ee560814c9d74afabd40b5d6befece834fe9831469`;
its exact command was `python3 -B work/platform-audio-registry-sources-20261114/acquire.py`.
It requires the already verified vendor report/cache preflight and an absent
`acquired/` output; its script, log, receipt and all received bytes are retained.
Network reacquisition can see changed index snapshots and must be separately
reviewed rather than silently replacing these pinned responses.

The final `join-final-r3/registry-source-join.json` is 472911 bytes, SHA256
`f6644393de2fa40a9a82cd3447df3d8efbcc2c8f0a1bb7849d4f66ce54bf9212`.
It binds the checker, prior handoff/audit/metadata, selected index rows,
raw archives, acquisition receipt and source/publication holds. The checker is
15559 bytes/SHA256
`5eb6279bf5ad495d53e46771471aba0d345c7839f4354e0d2366a145ec0812eb`.
The receipt is 80260 bytes/SHA256
`46d69ea623edfb62a9b457262334d2ba3f1fd2f38db5b2e1c40fe32b8884f210`.
No private packet or third-party archive is committed or published.

These independently captured official HTTPS index snapshots and raw digests
close this finite registry/vendor byte-correspondence gap. They are not signed
registry attestations or current security/revocation acceptance. Original
compiler/standard-library/linker/runtime source closure, original flags and
binary correspondence, relinking, grants/legal completeness, native execution,
audio/speaker safety, performance, both M2 models and release admission remain
held. No existing profile or acceptance field is relaxed.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/port/platform-audio-registry-sources/test_join.py \
  --trusted-checkout /trusted/cachy-asahi
```
