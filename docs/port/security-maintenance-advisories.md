# Installed advisory snapshots and offline security campaigns

`cachy-asahi-security-maintenance` **0.1.0-2** packages the finished advisory cache
helper with two explicit installed commands, alongside prepare/status/plan-builds
and the existing finite batch CLI. The package remains opt-in with
`selected_for_release=false`. The sealed 0.1.0-1 recipe, source bundle, exporter,
profile and retained results remain byte-identical.

## Select a retained snapshot and verify offline

```sh
cachy-asahi-security-maintenance verify-advisories \
  --snapshot /absolute/operator-cache/snapshot-001 \
  --snapshot-sha256 INDEPENDENTLY_SELECTED_SNAPSHOT_SHA256
```

Verification is read-only and offline. It checks the externally selected
snapshot.json, its exact body/provenance descriptors, private ordinary files,
existing advisory schema and recorded retrieval time. A stale snapshot reports a
refresh action without contacting the tracker, changing timestamps or replacing
bytes. Use `--as-of UTC_TIMESTAMP --max-age-hours HOURS` for explicit replay.
Neither successful verification nor recent acquisition establishes tracker
coverage, ARM applicability, fixed versions or mitigation; those remain UNKNOWN.
The receipt's implementation hashes describe acquisition at that historical time
and are preserved, rather than rewritten to the current package's implementation.

## Acquire only when explicitly requested

```sh
cachy-asahi-security-maintenance acquire-advisories \
  --url https://security.archlinux.org/issues/all.json \
  --output /absolute/fresh-snapshot --timeout 60 --max-bytes 8388608
```

The URL must exactly match that official HTTPS endpoint. The unchanged helper
makes one credential-free GET with no proxies, cookies, retries, redirects,
compression or arbitrary-URL mode. TLS loads the compiled-in system OpenSSL CA
file and verifies the hostname while ignoring SSL environment overrides. No
trust store is changed and no certificate or advisory-signature pin is asserted.
The supported 1–120-second wall budget includes owned-child retirement; the body
cap cannot exceed 8 MiB. The exact existing supervisor retains exclusive wait
custody and performs no numeric operation after reap/lost custody.

Output must be a fresh absolute directory beneath an existing ordinary parent.
Preexisting files/directories/dangling links refuse before any GET. After source
and schema checks, atomic RENAME_NOREPLACE publication retains advisories.json,
provenance.json and snapshot.json together: directory mode 0700, ordinary single-link
files mode 0600. Retain the returned snapshot SHA256 independently. A failed/interrupted
acquisition can leave unpublished private staging data or complete published data
with uncertain durability; preserve and inspect it before use. No overwrite,
repair, refresh or scheduled background request happens automatically.

Installed real-network acquisition is **NOT RUN** in this package work. A new
installed-CLI control uses a labelled mocked HTTP response; it is TEST DATA. The
separate acquisition packet's original 22 transport controls and one original
public snapshot acquisition are retained evidence, not rerun package/network or
native results.

## Continue an offline campaign

Use the existing schemas in [security-campaign.md](security-campaign.md). Select
advisories.json and provenance.json by the exact descriptors in the retained
snapshot, alongside independently reviewed inventory and pre-change/candidate
graphs. The acquisition helper does not discover inventory or prepare campaigns.

```sh
cachy-asahi-security-maintenance prepare --operation /absolute/fresh-operation \
  --selection /absolute/security-selection.json --selection-sha256 SELECTED_SHA256
cachy-asahi-security-maintenance status --operation /absolute/fresh-operation
cachy-asahi-security-maintenance plan-builds --operation /absolute/fresh-operation \
  --selection /absolute/batches.json --selection-sha256 SELECTED_SHA256
cachy-asahi-security-maintenance batch --help
```

Pair planning admits exactly two existing finite offline-build-v2 batches and
returns their actual plan/execute argv arrays. Prepare/status/plan-builds never
fetch advisories, build, sign, publish, install or change the Asahi stack.
Explicit `batch execute` may run reviewed Docker build containers; it is a
separate operation with pinned images and source-cache admission. Re-admit
external inputs before using old commands; status keeps its recorded-only scope.
Original emitted commands use Python -B, so use a clean environment or insert -I.

The public executable keeps its name across upgrade. Runtime identity changes
to `/usr/lib/cachy-asahi/security-maintenance-v2`, with twenty predecessor files
unchanged and two newly pinned helpers. Move the prefix before preparing a fresh
operation. Upgrades, moved runtimes or changed absolute recipe/cache paths need
new operations; do not rewrite prior admissions/receipts to fit a successor.

## Recipe and portable source delivery

The local MIT recipe is
`packages/tools/cachy-asahi-security-maintenance/PKGBUILD`, with matching .SRCINFO,
exact source checksums, source-provenance.json, LICENSE and NOTICE.
installed-files.txt lists 29 ordinary package-owned files/modes. Dependencies:
Python>=3.11, libarchive, pacman/vercmp, zstd and ca-certificates; optional Docker
for explicit reviewed batch execution. Linux fork/waitid/renameat2 support and
existing system CA certificates are required for acquisition. No hooks, services,
autostart, /etc defaults or installation-time network actions exist. Removal
preserves user-owned operation stores and caches.

In an already provisioned disposable ordinary-user builder:

```sh
makepkg --verifysource --noconfirm
makepkg --cleanbuild --force --log --noconfirm
```

No --syncdeps/--install is used. check() validates the exact 22-file runtime closure
and seven new successor-only staged CLI controls. Historical 8 package/10 exporter
controls remain separate evidence for unchanged mechanics. The host validation
assembled an `any` archive with --nodeps, inspected all 29 payload bytes/modes and
exact .BUILDINFO recipe identity, then extracted only its reviewed /usr payload
into a temporary prefix without ALPM, hooks or tar extractall.

The additive v2 exporter binds this exact 34-file recipe:

```sh
python3 -I -B scripts/release/security_maintenance_source_delivery_v2.py pack \
  --recipe /absolute/clean/recipe --output /absolute/fresh-source.tar
python3 -I -B scripts/release/security_maintenance_source_delivery_v2.py verify \
  --bundle /absolute/fresh-source.tar --sha256 SELECTED_BUNDLE_SHA256
python3 -I -B scripts/release/security_maintenance_source_delivery_v2.py unpack \
  --bundle /absolute/fresh-source.tar --sha256 SELECTED_BUNDLE_SHA256 \
  --output /absolute/fresh-private-directory
```

The extracted delivery/ carries the exact v2 exporter/profile and recipe/ carries
all reviewed recipe files. A moved extraction repacks byte-identically. V1 keeps
its original recipe/profile and refuses the successor; neither adapter runs
bundled source. Private fresh outputs, strict USTAR/finite member coverage and
checksum/path/type bounds retain the existing exporter mechanics. The live feed
DATA is excluded from the package and source kit; independent data licensing and
redistribution clearance is unasserted. Dependency/toolchain sources and legal or
source-completeness acceptance are outside this kit.

## Actual evidence and open gates

Seven new package controls and two new exporter controls pass. The original
897176-byte snapshot and provenance passed actual relocated archive-extracted
launcher verification offline, retaining 2444 groups and ARM UNKNOWN. Recorded
UTC replay time was 2026-10-28T01:42:00Z. A separate Python audit-hook replay
refused network events, recorded zero attempts and confirmed imports from the
relocated private runtime; this is not a kernel network sandbox. Original DATA
and every sealed predecessor source/archive hash remained unchanged.

Native ARM pairs, genuine ALPM lifecycle, native16K, physical M2 Air sizes,
installed real-network acquisition, production signatures/trust, performance,
maintenance coverage, ARM mitigation and release acceptance remain unrun or
unestablished. Root owns canonical adoption, manifests, Git, native work and
publication.
