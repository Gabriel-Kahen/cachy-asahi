# Successor H: route exact missing inputs for all 90 cases

**Zero new closures; 90 remain unresolved.** Twelve high-evidence targets,
disjoint from G's twelve, were selected. Seven already have exact package/
revision/ancestor-grant joins but still lack an actual scoped named project
notice. Three others need primary package/source joins; two Servo revision
checks returned HTTP 404. Fortanix's acquired root MPL text and README establish
no new named package notice. No weaker evidence receives closure credit.

[`requirements.json`](requirements.json) is the requested machine-readable
fallback. Every remaining component appears exactly once with:

- frozen original manifest/VCS pins, prefix/full-body recovery checks, and
  declared registry checksum explicitly distinguished from archive authenticity;
- retained current proof references and overlapping unresolved requirements;
- one next-action route, plus every other blocking route;
- exact candidate metadata URLs, expected full hashes/Git blobs, or reusable
  offline metadata paths where available;
- a shared required-input/closure-gate catalog and zero package-closure credit.

The next-action queues partition all 90 cases:

| Next route | Cases |
| --- | ---: |
| Dirty published-source correspondence | 2 |
| Exact publisher transformation | 11 |
| Missing/failed source lineage | 16 |
| Complete original-manifest recovery | 3 |
| Framework SDK/source license scope | 10 |
| Governing workspace metadata | 19 |
| Exact primary manifest-to-Git proof | 18 |
| Actual complete scoped grant | 1 |
| Actual scoped project/package notice | 10 |

Requirements overlap: 27 need lineage input, 5 lack complete original
manifests, 13 retain framework SDK scope uncertainty, and 31 need some inherited
workspace values proved. These are not additional case counts.

Concrete routing examples:

- The seven selected compiler/jaq cases need an actual version/revision-scoped
  notice input, not another copy of an already-retained grant or an author list.
- CloudKit/Core Data/UIKit manifest requests name the exact pinned source path
  and expected 9,909/11,766/63,556-byte full hashes. Their 8,192-byte prefixes
  must also match. Metadata recovery does not clear SDK or licensing holds.
- ANES, ui_test and two core objc cases have retained manifest-blob candidates
  to validate offline; the ledger avoids recommending another fetch for them.
- The eleven RA descriptions already name Rust source commit `ce89c898...`.
  Missing publisher revision/transformation and VCS proof remain unresolved;
  current head/tag/common version is not a substitute.
- Dirty source flags remain true. A clean replacement is a different candidate,
  not a rewrite of the historical dirty artifact.
- Failed identity endpoints require authoritative matching-source input; the
  ledger does not guess Gecko/Stylo, alternate revisions or repository owners.

Status fields are narrow. For example, `source_lineage: SATISFIED` means the
retained VCS declaration is available and has no unresolved failed primary
route; canonical repository and manifest/workspace correspondence remain
separate gates. URLs are acquisition specifications, **not an executor** or
permission/acceptance flow. Publisher metadata is a checksum/provenance lookup,
not a license grant.

The three previously established wasm workspace-version proofs stay satisfied.
The two retained wasm file-only notice proofs stay file-only. The object
normalized-manifest mismatch is retained with both differing pins. All
package-notice, full-projection, source-cleanliness, activation, all-file/legal,
native/M2/release and other original holds remain intact. No external contact
was made.

A factual correction is recorded without editing frozen predecessors:
Hifijson's retained VCS revision is **40 lowercase hex characters**, not the
39-character label in the earlier compiler-notices README. The revision bytes,
HTTP 422 evidence, source-identity hold and closure counts are unchanged.

New acquisition is closed at **5 requests / 24,084 response-body bytes /
98.284 seconds**, including the two Servo 404 responses. Limits remain
50 requests / 2 MiB / 15 minutes, 128 KiB per body, 20-second network timeout
and a 60-second transfer check, with verified TLS. No retries occurred.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-h/requirements.py \
  --candidate-packet /tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json \
  --output /tmp/new-notice-requirements.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-h/test_requirements.py -v
```

Regeneration and all **nine controls passed** under 256 MiB/30s, with zero
replay requests. The full regeneration control skips when its deliberately
private source packet is unavailable. Output must be new below `/tmp`.
This depends on G (`89d9d35d`) and the retained earlier evidence chain. No
archives, checkout, builds, package activation, source/native actors, leases,
trust, daemons, shared manifests or workflows changed. Only this new subtree
changed; Root owns integration and publication.
