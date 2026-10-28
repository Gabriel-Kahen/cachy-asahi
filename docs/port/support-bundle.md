# Offline support bundle

`scripts/support/support_bundle.py` makes a small, deterministic local archive
from explicitly reviewed, SHA-256-selected JSON reports. It composes existing
session diagnostics, Doctor reports/comparisons and maintenance health reports.
It collects no live observations and invokes no subprocess, network, service,
package manager, session API or upload. Python's standard library is sufficient.

Creation needs the current repository's Doctor2 validator/comparison API and
session parser/constants. Verification and extraction need only this script and
the archive, so they work after relocation outside the checkout.

## Create

Review each report privately before selecting its exact digest. At least one
report is required. The release ID is an explicitly supplied public label, up to
96 ASCII letters/digits/`._+-`; do not put a username or secret in that label.
The release manifest SHA-256 and full Git source object ID are also explicit.
These inputs label the bundle; they do not authenticate a release.

```sh
python -B scripts/support/support_bundle.py create \
  --release-id reviewed-candidate \
  --release-sha256 RELEASE_JSON_SHA256 \
  --source-commit FULL_SOURCE_COMMIT \
  --reviewed-session ./reviewed/session.json SESSION_JSON_SHA256 \
  --reviewed-doctor ./reviewed/doctor.json DOCTOR_JSON_SHA256 \
  --reviewed-health ./reviewed/health.json HEALTH_JSON_SHA256 \
  --output-dir ./support-case
```

Each `--reviewed-*` option takes exactly a path and its SHA-256. Supported
formats are session-observations schema 1, complete Doctor schema 1 reports from
versions 0.1.0/0.2.0, and maintenance-health schema 1 output including its CLI
implementation receipts. No file discovery or automatic input collection occurs.

To include a before/after comparison, supply `--reviewed-doctor-before PATH SHA`
and `--reviewed-doctor-after PATH SHA` together. The command uses Doctor2's
existing offline validator and comparison function. Optional
`--reviewed-doctor-comparison PATH SHA` must match the recomputed existing
comparison format exactly, including its timestamps and limitations. A comparison
without its originals is refused. Known different Apple model labels refuse.
The comparison preserves change names/kinds and counts, including changes in
values omitted for privacy; it makes no causal or health verdict.

Creation checks the session's declared source revision, when present, against
`--source-commit`. Health's release ID, manifest hash and source commit must match
the supplied identity exactly. Doctor has no release binding and is explicitly
labeled as such. Report times are normalized UTC; no freshness is inferred from
the date of bundling. Supplied timestamps and execution contexts remain claims.

The new output directory has mode 0700 and contains only mode-0600
`support-bundle.tar` and `SHA256SUMS`. Existing directories are refused. Input
paths and their ancestors must have no symlinks or parent traversal; files must
be ordinary, have a single hard link and contain 1 byte to 1 MiB. Changed bytes,
wrong pins, malformed schemas, duplicate JSON keys and nonfinite numbers refuse.
Selected inputs and implementation bytes are rechecked before publication.
Errors return 2 without echoing input content. Success returns 0 and prints the
archive byte count and SHA-256; evidence failures inside valid reports still
return 0 and remain visible.

## Contents and privacy

The uncompressed USTAR archive has sorted fixed member names, zero timestamps,
zero owner/group IDs, empty owner names and mode-0600 members. The same selected
input and implementation bytes produce the same archive across output paths.
`inventory.json` records every other member's byte count/SHA-256, selected original
input byte counts/hashes and current implementation receipts. Its own integrity
is covered by the external archive SHA-256, avoiding a recursive self-hash.
The summary is readable text; projections live under `reports/`.

Only finite names, enums, booleans, bounded numeric observations, timestamps and
hashes are retained. Service `failed`/`inactive`, package absence, graph errors,
unknown/unavailable checks, health review requirements and physical `NOT RUN`
remain explicit. Kernel/package/compositor version text and architecture strings
are omitted; page size, exact known model labels, display scalars, the software
renderer hint, finite audio counts and volume/mute observations remain useful.

Original JSON is never embedded. Arguments, notes, full environment, kernel and
renderer free text, home paths, usernames, SSIDs, IPs, tokens, private keys,
owners/references and health finding text/codes are omitted. Hashes and times can
still correlate reports. Review the extracted summary and JSON before manually
sharing any archive. There is no sending or upload operation.

Health checking validates the public report envelope, binding, category/status
shape, finite counts and summary consistency. It does not rerun release signature
verification, reconstruct maintenance inputs, authenticate staffing/capacity or
validate every omitted nested finding payload. Output retains category statuses,
finding counts by category, selected numeric counts, synthetic labeling and
`UNKNOWN` ARM security. Its authentication field explicitly says the supplied
report's claim was not reverified. Use the existing health CLI with its original
digest-selected inputs for that independent replay. The bundle's exit status
cannot establish acceptance or upgrade safety.

## Verify, extract and relocate

Keep the expected archive SHA-256 independently. `SHA256SUMS` in the output
directory is convenient transport metadata, not an independent trust anchor.

```sh
python -B support_bundle.py verify \
  --archive ./support-bundle.tar --sha256 EXPECTED_ARCHIVE_SHA256
python -B support_bundle.py verify \
  --archive ./support-bundle.tar --sha256 EXPECTED_ARCHIVE_SHA256 \
  --extract-to ./reviewed-case
```

Verification checks the mandatory external hash, fixed member allowlist,
inventory, sizes and exact deterministic tar serialization. Links, traversal,
duplicates, altered inventory/member bytes, unexpected metadata and trailing
data refuse. Extraction occurs only after complete verification, into a new
mode-0700 directory with mode-0600 files. It never uses `extractall`. No absolute
path or sibling original report is needed after creation. The archive limit is
2 MiB; verification reads no original reports or repository APIs.

The file guards detect observed changes and aliases; they do not authenticate an
input producer or defend against a hostile process running as the same user.
No native ARM build, installed lifecycle, physical M2 compatibility, recovery,
performance, production trust or release acceptance follows from this tool.

Run the focused host checks after integration:

```sh
python -B -Werror::ResourceWarning tests/support/test_support_bundle.py
```

The tests use original synthetic JSON and injected current producer APIs, plus
real local CLI/archive operations. They include privacy markers, failed states,
every session value format, relocation outside the checkout, tamper/malformed
refusals, file aliases, private modes and output cleanup. No live target session
is used. This addition introduces no package recipe, hook or manifest selection.
