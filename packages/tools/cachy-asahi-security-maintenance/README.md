# Security maintenance 0.1.0-2 candidate

This opt-in successor adds `acquire-advisories` and `verify-advisories` to the
installed prepare/status/plan-builds/batch CLI. It preserves the predecessor's
twenty exact integrated helper bytes and adds the finished original MIT
advisory_cache.py and exact owned_process.py supervisor. The sealed 0.1.0-1
recipe, package, source kit, exporter and profile remain unchanged. Source hashes,
lengths, licenses and predecessor evidence are in source-provenance.json.

Package name: cachy-asahi-security-maintenance, version 0.1.0-2, arch any.
Sources: local-original MIT project code; no third-party program or advisory feed
is bundled. See complete MIT LICENSE and NOTICE. Runtime dependencies:
python>=3.11, libarchive, pacman/vercmp, zstd and ca-certificates. Explicit batch
execution additionally needs Docker and reviewed preexisting pinned images.
Linux fork/waitid and renameat2 are required for explicit acquisition. Standard
Python/OpenSSL reads the compiled-in system CA file without changing trust.
Build/check requires existing makepkg/base-devel, Python, bash and coreutils.
No dependency provisioning is automated.

Installed files: /usr/bin/cachy-asahi-security-maintenance, twenty-two exact
helpers and payload-pins.json under
/usr/lib/cachy-asahi/security-maintenance-v2, docs/provenance/file list under
/usr/share/doc/cachy-asahi-security-maintenance, and LICENSE/NOTICE under
/usr/share/licenses/cachy-asahi-security-maintenance. installed-files.txt lists all
29 ordinary files/modes. The public command keeps its name across upgrade; the
private v2 runtime has its own identity. No hooks, services, autostart, /etc defaults,
install-time network or trust changes exist. Removal leaves user-owned operation
stores and advisory/source caches intact.

After reviewing sources in a separately provisioned ordinary-user builder:

    makepkg --verifysource --noconfirm
    makepkg --cleanbuild --force --log --noconfirm

No --syncdeps or --install. check() validates the exact source closure and runs
seven new successor-only staged CLI controls. Historical eight package controls,
ten exporter controls and twenty-two transport controls remain separate retained
evidence for unchanged mechanics; they are not rerun or promoted to new native
acceptance. Tests copy declared inputs, never makepkg logs, pipes or outputs.
The launcher uses isolated Python and verifies the complete runtime payload.

## Explicit acquisition; offline default

    cachy-asahi-security-maintenance --help
    cachy-asahi-security-maintenance acquire-advisories \
      --url https://security.archlinux.org/issues/all.json \
      --output /absolute/fresh-snapshot --timeout 60 --max-bytes 8388608
    cachy-asahi-security-maintenance verify-advisories \
      --snapshot /absolute/retained-snapshot --snapshot-sha256 SELECTED_SHA256

Only acquire-advisories makes a public request: one direct official HTTPS GET,
no redirects/retries/proxies/credentials/cookies/compression. Exact official URL,
1–120-second timeout including owned-child retirement and <=8 MiB bound are
mandatory. Existing output fails before any GET. System CA/hostname verification
ignores SSL environment overrides; no certificate pin or signed attestation is
invented. Atomic no-replace publication preserves the original JSON body,
provenance and snapshot receipt in a 0700 directory with single-link 0600 files.
Keep the returned snapshot SHA256 independently. A failed/interrupted acquisition
may retain a private unpublished staging directory or already published data;
inspect it before reuse, never overwrite the prior snapshot.

verify-advisories is read-only/offline and does not refresh stale data. It checks
selected snapshot/file bytes, existing schemas and provenance. --as-of UTC and
--max-age-hours support explicit replay. Stale data returns a refresh action.
Provenance records the implementation at acquisition time; verifying historical
DATA does not require replacing those recorded hashes with this package's hashes.
The installed real-network acquisition path is NOT RUN by this package work.
One CLI control uses an explicit in-process mocked HTTP response and is labelled
TEST DATA; the real retained897176-byte snapshot is verified offline separately.
Python audit-hook controls reject network attempts; they are not a kernel sandbox.

## Existing campaign and finite batch commands

    cachy-asahi-security-maintenance prepare --operation /absolute/new-operation \
      --selection /absolute/selection.json --selection-sha256 SELECTED_SHA256
    cachy-asahi-security-maintenance status --operation /absolute/new-operation
    cachy-asahi-security-maintenance plan-builds --operation /absolute/new-operation \
      --selection /absolute/batches.json --selection-sha256 SELECTED_SHA256
    cachy-asahi-security-maintenance batch --help

Select advisory/provenance files in the existing security selection via their
snapshot descriptors, alongside separately reviewed inventory and old/candidate
graphs. Acquisition never auto-prepares campaigns. Prepare/status/plan-builds and
verify-advisories never acquire a snapshot automatically. Pair planning returns
existing plan/execute argv; explicit execute can run Docker build containers.
No public command installs, signs, publishes or changes Asahi components.

Move a private prefix before preparing a fresh operation. Implementation identity
changes at upgrade, and planned admissions additionally bind absolute runtime,
recipe/cache/input paths. Prepare a fresh operation after moving or upgrading;
never rewrite old receipts. Original emitted commands use Python -B; use a clean
Python environment or insert -I after their interpreter. Status retains its
recorded-only external-input scope, requiring admission revalidation before use.

The additive security_maintenance_source_delivery_v2.py exporter/profile binds
this exact recipe and includes its own portable delivery files. V1 remains
byte-identical and accepts only its original recipe. Neither exporter runs
bundled code or proves binary/native correspondence or dependency-source
completeness. This source bundle excludes the live advisory DATA: independent
feed-data licensing/redistribution clearance is not claimed.

ARM applicability/security/fixed versions remain UNKNOWN. Recent retrieval,
version references, no match and successful builds do not establish mitigation,
coverage or recovery. Native ARM, ALPM installation, native16K, both physical M2
Air sizes, production trust, performance and release acceptance remain NOT RUN or
NOT ESTABLISHED; selected_for_release=false.
