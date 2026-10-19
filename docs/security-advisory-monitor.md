# Offline ARM advisory monitoring

`security_advisories.py` compares an explicitly supplied supported ARM package
inventory with a cached official Arch Security Tracker JSON response. It writes
package/version/CVE review actions and preserves all three original input files
with their SHA-256 hashes. Processing performs no network requests, package
discovery, installation, repository changes, notifications or publication. Its
only child process is the existing `/usr/bin/vercmp` version comparator.

Python 3.11+ and Arch `vercmp` are required. Run as an ordinary user. The script
does not read the host package database or infer the supported system from the
development package manifest. Dependency resolution remains the separate
`scripts/checks/dependencies.py` workflow.

## Explicit inventory

Reuse that dependency checker's JSON list shape: each row contains the binary
package `name`, complete `version` and `arch` (`aarch64` or `any`). `provides` may
be retained from the same inventory; it is never used as an advisory alias.
Optional `pkgbase` and `origin` strings record operator context. Other inventory
metadata remains in the preserved original file.

```json
[
  {"name": "example-package", "version": "1:2.0-3", "arch": "aarch64",
   "pkgbase": "example-source", "origin": "operator-selected ARM repository snapshot"}
]
```

This is a shape example, not an installed package or supported release claim.
Use the exact binary package names from the selected ARM repository/inventory.
Matching uses those names, case sensitively, against the official tracker's
`packages` list. A source `pkgbase`, virtual `provides`, fork, rename or split
package is not silently mapped to another binary. Unsupported mappings remain
`UNKNOWN_NO_TRACKER_MATCH`; investigate their selected upstream source manually.
Keep an operator record linking the inventory to the actual supported snapshot.

## Cache acquisition is a separate operator action

The supported official source is
[all tracker groups JSON](https://security.archlinux.org/issues/all.json), including
resolved groups. It is an array of AVG groups with package names, status,
severity/type, affected/fixed Arch package references, CVEs and ASA references.
Null fixed versions and Unknown statuses are retained. Duplicate ASA references
occur in the official response and are preserved. An empty, malformed or
unsupported group response is refused rather than interpreted as a clean system.

Obtain and retain a response explicitly outside the monitor. For example, in a
fresh operator-owned cache directory:

```bash
curl --fail --show-error --silent --proto '=https' --max-time 60 \
  --max-filesize 8388608 --output all.json \
  https://security.archlinux.org/issues/all.json
python3 - <<'PYPROVENANCE'
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json
raw = Path('all.json').read_bytes()
value = {'url': 'https://security.archlinux.org/issues/all.json',
         'retrieved_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
         'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
with Path('provenance.json').open('x') as stream:
    json.dump(value, stream, sort_keys=True, indent=2)
    stream.write('\n')
PYPROVENANCE
```

Record the real retrieval time, preserve prior caches, and do not relabel an old
file with a new download time. The provenance file binds the supplied bytes, URL
and operator-recorded retrieval time; it is not a signed attestation of origin.
Keep the actual download/transport records if independently authenticated origin
matters. The monitor makes no online verification request.

Cache age is reported against current UTC by default, with a 24-hour default
budget. `--max-age-hours N` changes that recorded review budget. A stale cache
produces an explicit refresh action; future retrieval times or hash/URL mismatch
refuse the report. The feed contains no authoritative last-update timestamp or
complete ARM coverage assertion. Recent retrieval therefore never establishes
current or comprehensive security coverage.

## Generate and review

```bash
python3 -B scripts/maintenance/security_advisories.py \
  --inventory /absolute/selected-arm-inventory.json \
  --advisories /absolute/cache/all.json \
  --provenance /absolute/cache/provenance.json \
  --output /absolute/fresh-review-directory
```

The fresh directory contains byte-exact `inventory.json`, `advisories.json`,
`provenance.json`, plus `report.json` and readable `report.txt`. Existing output
paths are refused. Inputs must be bounded ordinary single-link files without
symlink path components. There is no automatic cleanup; a write failure can leave
a partial output directory for inspection. Use a new output path after correcting
a failure. `--as-of YYYY-MM-DDTHH:MM:SSZ` records an explicit report time for
reproducible offline replay; do not present a backdated report as current.

Exit 0 means the report was generated, regardless of review findings. Exit 2 means
input/comparison/output processing failed. Neither code grants security acceptance.

- `REVIEW_REQUIRED`: at least one Arch fixed reference is newer, a fixed version
  is missing, or the full package tuple cannot be compared. Review the linked
  CVEs against selected ARM source/patches; obtain or build an authenticated ARM
  package containing the fixes, then validate its provenance and behavior.
- `ARCH_REFERENCES_MET_ARM_UNVERIFIED`: supplied versions meet all matching Arch
  fixed references. Confirm the selected ARM source/build actually contains the
  fixes; this is not an ALARM/Asahi fixed-version assertion.
- `UNKNOWN_NO_TRACKER_MATCH`: check upstream/security sources and package naming.
  Missing data never means unaffected.

Each finding labels the Arch tracker status, affected reference and fixed
reference separately from `arm_applicability` and `arm_fixed_version`, which
remain UNKNOWN. The tracker's affected version is preserved as a reference, not
invented into a lower bound or complete affected interval. Architecture, patches,
configuration, backports and version schemes can differ. This monitor does not
certify exploitability or mitigation, and does not invent ALARM fixed versions.

Version ordering uses the official
[`vercmp` semantics](https://man.archlinux.org/man/vercmp.8.en), including epochs
and package releases. Because pkgrel is compared only when both operands include
it, incomplete versions are reported UNKNOWN rather than treated as fixed. A
missing or failing comparator refuses processing; no lexical fallback exists.

Local tests use inert inventories and advisory fixtures with real `vercmp`:

```bash
python3 -B -Werror::ResourceWarning -m unittest discover \
  -s scripts/maintenance -p test_security_advisories.py -v
```

This implements an offline advisory review component for R1/M5. An accountable
monitoring schedule, additional upstream/ARM feeds, incident response, complete
supported-set coverage, authenticated ARM fixes and subsequent maintained release
validation remain separate unfinished work.
