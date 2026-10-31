# Offline maintenance health review

`scripts/maintenance/health.py` joins one explicitly selected signed ARM release
with retained observations from the existing finite release/maintenance tools.
It reports signing expiry, advisory and package coverage, source drift, release
transitions, missing owners/capacity, stale evidence and unavailable inputs, with
next actions. It supports M5/M9 maintenance work; it does not accept either gate.

The command uses only local files. It authenticates release signatures against an
**independently selected full fingerprint** and checks the supplied `release.json`
SHA-256. Release/base package identities, source commit, snapshot ID, signed
project recipe/source provenance and manifest hash form its observation binding.
The signed release packages override same-name base packages when constructing
the effective inventory. Inventory omissions, wrong versions/architectures,
changed source descriptors and generation mismatches refuse without a report.

Observation digests bind operator-selected bytes. An observation binding and
`observed_at` timestamp are operator records, not signed attestations. Replaying a
report establishes correspondence to the original inputs, not the truth of an
owner/capacity claim or ARM affectedness. Cached Arch advisory versions never
establish ARM mitigation, including when the installed reference is newer.
Missing advisory matches stay unknown. A finite case without source drift,
ownership gaps or advisory matches still requires coverage review.

## Invocation

Use an existing, operator-prepared public GPG home outside the checkout. The tool
reads its `pubring.kbx` (preferred) or `pubring.gpg`, then copies those public bytes
to a disposable verifier home with fixed offline options and a sanitized
environment. It does not copy configuration, ownertrust/trustdb, private keys or
agent settings, or import anything into the supplied home. There is no signing,
trust-change, installation, network, maintainer-contact or scheduler action.

```sh
python -B scripts/maintenance/health.py \
  --release /data/releases/candidate \
  --release-sha256 SELECTED_RELEASE_JSON_SHA256 \
  --key INDEPENDENTLY_SELECTED_FULL_FINGERPRINT \
  --gpg-home /data/offline-public-verifier \
  --as-of 2026-10-27T05:00:00Z --context-only
```

This prints the exact `binding` object to use when preparing observations. It
performs authentication; it is not a health report. Copy the whole binding into
each entry. Normal review takes a digest-selected index:

```sh
python -B scripts/maintenance/health.py \
  --release /data/releases/candidate \
  --release-sha256 SELECTED_RELEASE_JSON_SHA256 \
  --key INDEPENDENTLY_SELECTED_FULL_FINGERPRINT \
  --gpg-home /data/offline-public-verifier \
  --as-of 2026-10-27T05:00:00Z --max-age-hours 24 \
  --observations /data/observations/index.json \
  --observations-sha256 SELECTED_INDEX_SHA256 --format text
```

Use `--format json` for structured identities, key epochs, complete findings and
held rebuild actions. The default is JSON. Omitting the index produces five
explicit unavailable observations. A missing category, explicit null category,
or missing retained file is unavailable; wrong digests, malformed inputs, future
times, generation mismatches and reports that do not replay exit **2** with empty
stdout. A valid report exits **0**, including a held report. Inspect `status`,
`checks`, `findings`, `summary` and the concrete actions. Exit 0 is never a health,
security or maintenance acceptance signal.

## Observation index, schema 1

The index has exactly `schema_version: 1` and `observations: { ... }`. Supported
keys are `signing`, `maintenance`, `sources`, `comparison` and `operations`. Each
present entry has exactly:

```json
{
  "binding": "COPY_THE_ENTIRE_CONTEXT_OBJECT_HERE",
  "observed_at": "2026-10-27T05:00:00Z",
  "inputs": { "INPUT_NAME": { "path": "original.json", "sha256": "EXACT_SHA256" } }
}
```

The binding placeholder above must be replaced with the object, not a string.
Every file reference has exactly `path` and `sha256`. Paths are absolute or
relative to the index directory. Parent traversal, symlinks, special files,
multiple hard links and observed changes are refused. Each original file is
bounded to 8 MiB; aggregate reads to 32 MiB; source candidates additionally use
the source tool's 4 MiB bound. Use a finite reviewed release scope. JSON duplicate
keys, floating/nonfinite numbers and unknown index/category fields refuse.

The input names for each category are:

| Category | Required inputs | Producer / correspondence check |
| --- | --- | --- |
| `signing` | `certificate`, `report` | `signing_expiry.py`; replay GPG public-certificate inspection at original report epoch, then evaluate again at `--as-of` |
| `maintenance` | `inventory`, `advisories`, `provenance`, `advisory_report`, `graph`, `report` | `update_plan.py` plus the originals selected by its CLI; replay original plan, then reevaluate freshness at `--as-of` |
| `sources` | `candidate`, `report` | `release/check_source_pins.py`; verify release again and replay against the exact proposed snapshot |
| `comparison` | `predecessor`, `report` | `release/compare_releases.py`; authenticate the selected earlier bundle and recompute comparison |
| `operations` | `record` | Explicit operator ownership/capacity record below |

`comparison.predecessor` references a **directory**, with the SHA-256 of that
directory's `release.json`. It must differ from the selected generation and have
an earlier or equal creation time. The report must compare that predecessor to
the selected release, in that order. Downgrades, removals, equivalent-version
changes and changed bytes at the same version require explicit review. Runtime
consumer impacts and coordinated version/policy changes retain review actions.
No stable selector, promotion record or withdrawal policy is checked: the command
can inspect staged, withdrawn or synthetic DATA and does not authorize its use.

The signing report can be the CLI report with its `certificate` pin, or the
existing rehearsal's direct-helper report without that optional CLI field. Both
must replay exactly. Current revocation and custody remain unavailable offline.
Release signature verification runs at the actual GPG clock; `--as-of` controls
observation age and certificate-window evaluation. It does not authenticate a
release historically or establish future validity. An expired key can cause
release authentication to refuse even for an earlier supplied `--as-of`.

The maintenance graph must have the same release and base snapshot IDs and exact
binary package set as the signed effective inventory. Known runtime dependencies
and provides must equal signed metadata; absent fields create explicit holds,
including on packages with no rebuild roots. Project source-unit mappings must
match signed recipe hashes and full source descriptors. Missing mappings are
held; supplied conflicting mappings refuse. External base sources and build
relations are not authenticated by this join. All existing planner holds remain
visible; no build is scheduled or executed. Optional producer CLI implementation
receipts are excluded only from the deterministic plan projection; the originals
remain digest-bound, and the health report records its current helper hashes.

Source reports cover only proposed project recipe/source changes. Candidate
source origin/authenticity, current upstream freshness and base source pins remain
unknown. A matching candidate is not proof that upstream has not changed.

## Ownership and capacity record

The `operations.record` contains exactly `roles`, `package_owners`, `capacity`:

```json
{
  "roles": {
    "platform": null, "release": null, "support": null,
    "signing": null, "security": null, "incident": null
  },
  "package_owners": { "EXACT_BINARY_NAME": null },
  "capacity": {
    "native_aarch64_slots": null,
    "builder_owner": null, "builder_reference": null,
    "repository_owner": null, "repository_reference": null
  }
}
```

Supply every effective package name exactly once, including external packages
with an accountable upstream or integration owner. Null means missing and creates
an action. Owners and references are nonempty printable text, at most 512
characters. Native slots are null or an integer from 0 to 1024; zero is
unavailable. Named staffing and capacity are retained operator claims, not proof
of ongoing staffing, capacity or successful release operations.

All observation bindings must be recorded at or after the selected release's
creation time. Signing/maintenance report times must not postdate their enclosing
observation. Evidence older than `--max-age-hours` produces fresh-evidence actions;
exactly the age limit is allowed. Advisory report and cache age are independently
reevaluated, so relabeling an old wrapper does not refresh old reports or caches.
Source/comparison tools do not emit timestamps: their wrapper time is explicitly
an operator assertion of when the replay was observed.

## Verification and retained replay

Run `python -B scripts/maintenance/test_health.py` after integration. The suite
covers identity/generation refusal, stale and absent inputs, unknown ARM
applicability, held and unaffected packages, missing owners/capacity, signing
expiry, source drift, package transition review, unchanged inputs and isolated
verification configuration.

The implementation packet also contains `fixtures/replay_retained.py` and its
outputs in `fixtures/final-retained-replay/`. It reuses the actual signed DATA from the
2026-10-26 release-maintenance rehearsal, including its public certificate,
predecessor and retained comparison/expiry reports. The original successor was
deliberately corrupted and withdrawn. The replay restores **only a private copy**
using retained pre-corruption archive bytes matching the original signed hash.
The original withdrawal and DATA remain unchanged. This demonstrates byte-bound
reporting; it does not reverse a withdrawal or accept the successor for use.
Advisories and graph/ownership records for this replay are explicitly synthetic
or unknown, with no security allegation or fabricated infrastructure owner.

JSON and text outputs repeat byte-for-byte. The replay records original input
hashes and confirms that its supplied GPG home is unchanged. It requires the
retained TEST key to be usable at the actual verification clock; after its expiry,
refusal is expected rather than a reason to bypass release authentication.
Native builds, installed updates/recovery, physical M2, performance, staffing,
production publication and M5/M9 acceptance remain **NOT RUN / NOT ESTABLISHED**.
