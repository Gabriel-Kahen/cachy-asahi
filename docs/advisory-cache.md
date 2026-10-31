# Explicit official advisory snapshots

`scripts/maintenance/advisory_cache.py` supplies the online acquisition side of
the existing [offline advisory monitor](security-advisory-monitor.md) and security
campaign adapter. It downloads advisory **DATA** only. It never discovers
installed packages, executes downloaded code, builds, installs, changes trust,
updates campaigns, schedules work or grants security acceptance.

## Acquire and retain the returned pin

Run from the integrated repository with an existing ordinary output parent:

```bash
python3 -B scripts/maintenance/advisory_cache.py acquire \
  --url https://security.archlinux.org/issues/all.json \
  --output /absolute/operator-cache/snapshot-001 \
  --timeout 60 --max-bytes 8388608
```

The URL must exactly match the current offline monitor's official source URL.
There is no arbitrary URL mode, mirror fallback, automatic retry, conditional
304 reuse or overwrite. A refresh uses a new output directory, preserving prior
bytes and retrieval times. Existing output nodes fail before any request.

The fresh private directory contains three ordinary single-link files:

| File | Meaning |
| --- | --- |
| `advisories.json` | Byte-exact original HTTP JSON body, validated with the existing planner's schema |
| `provenance.json` | URL, real request/retrieval UTC times, body size/SHA256, bounded transport metadata, implementation pins and explicit UNKNOWNs |
| `snapshot.json` | Size/SHA256 descriptors binding body and provenance, plus validated group count |

The CLI returns `snapshot_sha256`. Retain that digest independently from the
snapshot; offline verification requires it. These hashes bind bytes to the
operator's selection; they do not create a signed advisory attestation. Directory
mode is 0700 and files are 0600. Publication uses Linux
`renameat2(RENAME_NOREPLACE)` after validation and fsync, with no weaker fallback.
An interrupted acquisition may leave a hidden `.advisory-*` directory, which is
not a published snapshot. A failure after rename can leave the complete published
snapshot with uncertain durability; preserve and inspect it before use.

## Verify offline, then use the existing monitor or campaign

```bash
python3 -B scripts/maintenance/advisory_cache.py verify \
  --snapshot /absolute/operator-cache/snapshot-001 \
  --snapshot-sha256 RETURNED_SNAPSHOT_SHA256

python3 -B scripts/maintenance/security_advisories.py \
  --inventory /absolute/selected-arm-inventory.json \
  --advisories /absolute/operator-cache/snapshot-001/advisories.json \
  --provenance /absolute/operator-cache/snapshot-001/provenance.json \
  --output /absolute/fresh-advisory-review
```

`verify` performs read-only local checks. It never refreshes, repairs or relabels
data, requires exactly the three recorded entries, rejects unsafe paths/nodes,
checks the external snapshot pin and file descriptors, and reuses the existing
advisory schema/provenance validation. `--max-age-hours` defaults to 24;
`--as-of ...Z` supports explicit replay. A stale snapshot verifies as retained
DATA with a refresh action; future retrieval times refuse verification. The
monitor independently validates body/provenance and compares Arch references
using real `/usr/bin/vercmp`.

For `security_campaign.py`, select these two files using the existing selection's
`inputs.advisories` and `inputs.provenance` `{path, sha256}` references. Use the
digests from `snapshot.json`. Inventory and old/candidate graphs remain separately
selected inputs. The acquisition CLI does not prepare a campaign; the current
adapter requires no schema change. Preserve the snapshot pin with the selection.

Exit 0 means acquisition or offline verification succeeded; exit 2 means a check
failed. Neither code is a security verdict. Transport failures suppress remote
exception text. No retry is automatic.

## Transport and runtime requirements

There is one credential-free direct GET to the exact HTTPS URL, with JSON Accept
and identity encoding. Environment proxies, cookies, netrc, authorization and
client certificates are not configured or copied. TLS explicitly loads OpenSSL's
compiled-in system CA file with hostname validation; environment
`SSL_CERT_FILE`/`SSL_CERT_DIR` overrides are ignored. System CA configuration is
read, never changed. No certificate or advisory-signature pin is claimed.

All redirects are refused, including same-origin redirects. If the service moves,
review the source URL and offline consumer contract together. Non-200 responses,
HTML challenges, encoded bodies, duplicate selected headers, ambiguous framing,
empty/truncated bodies and unsupported JSON fail. The 8 MiB maximum cannot be
raised above the existing monitor's bound. Smaller explicit caps are supported.
Retained HTTP Date, Last-Modified and ETag are bounded untrusted metadata; they
do not establish feed freshness or completeness.

Linux, Python 3.11+, system CA certificates and existing project helpers are
required. Imports are `security_advisories.py`, `source_cache.py`,
`source_delivery.py`, `owned_process.py` and the standard library. The child has
a file-size resource limit and the exclusive WNOWAIT supervisor enforces a
1–120 second wall budget including retirement; default 60 seconds. DNS, TLS and
slow body reads occur inside that child. Direct-child mode is used; this transport
creates no descendants. No numeric signal/probe follows reap or lost custody.
Receipt durations use integer milliseconds for the strict existing JSON decoder.
Filesystem latency and process creation are not hard real-time bounded.

This is original MIT project code using MIT project helpers. The feed is retained
as attributed official Arch tracker DATA; independent data-license clearance and
redistribution permission are not asserted. Publication review remains separate.

## Semantics and official sources

The [official tracker](https://security.archlinux.org/) supplies Arch package
references. The [tracker source project](https://github.com/archlinux/arch-security-tracker)
describes its group/advisory tracking role. The official
[arch-audit manual](https://man.archlinux.org/man/arch-audit.1.en) documents this
tracker as its data source, currently using the distinct `/all.json` URL by
default. This CLI preserves the current cachy-asahi consumer's
[`/issues/all.json` contract](https://security.archlinux.org/issues/all.json),
without silently aliasing endpoints.

Acquisition time is not tracker update time. Completeness, ARM/ALARM applicability,
ARM fixed versions and ARM security status remain UNKNOWN. Null fixes, Unknown
statuses and repeated ASA references are preserved. Arch versions remain
references. Missing matches or newly retrieved old data never mean unaffectedness.
Additional feeds, maintainer response, authenticated ARM fixes, scheduling,
native/16K/M2 behavior and maintained release acceptance require separate evidence.

Focused controls:

```bash
python3 -B -Werror::ResourceWarning -m unittest discover \
  -s scripts/maintenance -p test_advisory_cache.py -v
```
