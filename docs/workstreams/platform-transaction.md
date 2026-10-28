# Observed Asahi desktop/audio transaction

October 12, 2026 UTC. The complete 55-target proposal **fails** because it
requests Python `3.14.8-1` while the proposed protected image tuple retains
`3.14.7-1`. Actual private libalpm preparation of the other targets succeeds.
The resulting 624-package inventory is diagnostic and is not a release selection.

Ownership: the new transaction, ownership and archive-coverage helpers/tests in
`scripts/platform/`, their [public observation](../../scripts/platform/transaction-observation.json),
this report, and private ignored evidence. The previous eight platform files and
two installation-route documents remain unchanged against
`artifacts/platform/checkpoint-77-tests.json`. Shared manifests, CI, Git state,
installation and host system state are outside this workstream's edits.

## Inputs and actual preparation

Read the roadmap and development package inventory. Reused the observed minimal
image's 261 package descriptors, its 201-package proposed protected dependency
graph, and the existing refreshed desktop proposal without changing that
proposal's 45 roots or four provider constraints. Added six explicit roots:
`asahi-desktop-meta 4-10`, `asahi-audio 4.1-1`, `speakersafetyd 2.0.1-1`,
`bankstown 1.1.0-2`, `triforce-lv2 0.3.2-1`, and `vulkan-asahi 1:26.2.4-1`.

Bankstown and Triforce archives and detached signatures were retained and
cryptographically checked against the pinned community certificate, including a
second check. Their hashes and the receipt are in the public observation. This
establishes signature validity under that certificate; independent key-owner
trust, complete source/license grants and installation remain unaccepted.

Fresh core/extra `.db` and `.files` observations were retained separately from
the signed community metadata. The core and extra DB bytes match the earlier
refreshed proposal observations. Their DB signature endpoints returned HTTP 404;
these catalog observations are not authenticated repository or image evidence.

[`transaction.py`](../../scripts/platform/transaction.py) hashes every referenced
input and prepares with installed libalpm `16.0.1` in a disposable private root,
local/sync DB, cache, GPG directory, hook directory and log. It loads all 261
observed local file lists. Dependencies and conflicts remain enabled; flags are
`NOLOCK | NEEDED | NOSCRIPTLET | NOHOOKS`. Its exposed API has no commit,
download, repository-update or system-upgrade operation. Protected updates and
`mesa-dummy` are filtered from candidate catalogs. Unsupported unselected
metadata remains visible in diagnostics, including uppercase FEX, sparse
`findnewest`, and entries outside the helper's relation/field bounds.

| Actual result | Observation |
| --- | --- |
| Requested targets | 55; 54 satisfied, Python refused |
| Private prepare | Return 0, errno 0; no questions or callback errors |
| Proposed new packages | 363 |
| Proposed version replacements | Perl `5.42.2-2` → `5.42.3-1`; NetworkManager `1.58.1-1` → `1.58.1-2` |
| Proposed removals | 0 |
| Tentative final inventory | 624 packages |
| Protected versions retained | 201 of 201 |
| Final dependency relations | 3,197 with libalpm metadata witnesses |
| Final package conflicts | 0 |

Explicit providers remain native ALARM Mesa `1:26.2.4-1`, PipeWire JACK
`1:1.6.9-1`, D-Bus broker units `37-3`, and Perl `5.42.3-1`. No `mesa-dummy`
appears in the proposed final inventory. The retained raw `alpm_strerror(0)`
string is literally `unexpected error`; return 0/errno 0 establish successful
preparation of the remaining targets. The separately recorded Python policy
refusal makes the complete candidate fail.

## File ownership, hooks and archive evidence

Read all image local file-list metadata through read-only `debugfs`, without
mounting the image. Six empty metapackage file lists are legitimate and retained.
Read 23 existing local install scriptlets and 32 existing ALPM hooks as private
data; none was executed.

[`ownership.py`](../../scripts/platform/ownership.py) pairs selected `.db` and
`.files` identities, filenames and archive hashes, and uses observed image lists
for unchanged installed packages. The final rerun found all 624 selected lists
available across 136,407 declared paths, no non-directory overlap candidates,
and 41 hook-path candidates. NetworkManager relinquishes nine declared old
paths, including its versioned plugin directory and `nm-pppd-plugin.so`.
This describes package ownership changes, not actual deletion or filesystem
collision checks. Link resolution, payload identity and complete hook/scriptlet
behavior remain unchecked. The report correctly remains partial because the
full transaction failed.

[`archive_coverage.py`](../../scripts/platform/archive_coverage.py) binds each
candidate individually to retained authentication receipts, rehashes cached
archive/signature bytes and reinspects archives as data. It records prior
signature observations explicitly; it performs no fresh signature verification.
The generic desktop receipt does not become acceptance of this Asahi transaction.

| Archive evidence for the 624 entries | Count |
| --- | ---: |
| Exact candidate-pinned authenticated-cache archives inspected | 215: 211 generic, 4 community |
| Matching baseline name/version/architecture archives inspected; image payload unverified | 25: 20 generic, 5 community |
| Candidate archives lacking exact retained authentication | 150 |
| Baseline entries without archive identity evidence | 234 |

The 150 missing archives total 350,862,932 compressed bytes: 127 extra, 20 core,
and three community packages (`asahi-desktop-meta`, `startup-disk`, `widevine`).
All 150 archive and signature endpoints returned HTTP 200 in 300 bounded HEAD
requests; advertised archive sizes matched metadata. No archive/signature bodies
were fetched by that check, so authentication remains missing. HEAD observations
are mutable availability evidence. Their predecessor report's candidate pins
were checked equal to the final repaired coverage report.

Current catalogs retain exact versions for 185 of the 201 protected packages.
Sixteen have been superseded: ca-certificates-mozilla, device-mapper, expat,
gdk-pixbuf2, glib2, glycin, harfbuzz, hwdata, leancrypto, libevdev, librsvg,
libsysprof-capture, libx11, mkinitcpio, python and xorgproto. Their old archive
URLs and hashes were not guessed. Exact authenticated recovery inputs remain
unestablished even where current metadata contains the desired version.

## Checks and retained evidence

Executed 26 transaction, 27 ownership and 17 archive-coverage tests: **70 passed,
no skips**. Syntax checks passed. Independent review reproduced and verified
fixes for physical `desc`/`files` member provenance, sparse-folder resurrection,
and duplicate/excess archive fallback rehashes. Identical fallback bindings are
deduplicated; all distinct possible rehashes are budgeted before reading. The
actual rehash upper bound is 316,673,537 bytes against 1 GiB. Archive inspection
has separate existing bounds. The previous 77-test checkpoint was not repeated;
all ten frozen file hashes were verified unchanged.

Private mode-0700 directory `artifacts/platform/target-metadata-20261012/`
contains mode-0600 input contracts, fresh catalog observations, image metadata,
and actual reports. The public observation records each evidence file's size
and SHA256. Primary final reports are:

- `transaction-report.json`: complete failure, actual prepare and exact tentative inventory.
- `ownership-report-b.json`: repaired ownership validator, physical-member provenance and actual findings.
- `archive-coverage-report-b.json`: repaired fallback budget and archive inspections.
- `missing-archive-head-observations.json`: each of the 300 endpoint results.
- `protected-archive-availability.json`: all 201 protected-version catalog comparisons.

Earlier reports remain retained as predecessors. CLI exit 1 for these actual
runs preserves the complete candidate's failure/partial status; it does not
mean the recorded metadata preparation or file-list reads failed. Reproduction
uses checksum-bound absolute contracts and fresh private output filenames:

```sh
python3 -B scripts/platform/transaction.py --contract /ABS/transaction-inputs.json --contract-sha256 HEX --output /ABS/REPO/artifacts/platform/PRIVATE/new-transaction.json
python3 -B scripts/platform/ownership.py --contract /ABS/ownership-inputs.json --contract-sha256 HEX --output /ABS/REPO/artifacts/platform/PRIVATE/new-ownership.json
python3 -B scripts/platform/archive_coverage.py --contract /ABS/archive-coverage-inputs.json --contract-sha256 HEX --output /ABS/REPO/artifacts/platform/PRIVATE/new-coverage.json
```

The coordinator must explicitly reconcile the Python root and protected-tuple
policy before selecting a complete transaction. Exact archive retention and
authentication, complete hook/payload/source review, recovery inputs, actual
package lifecycle and both M2 Air hardware validations remain required. No
installer, package payload, scriptlet or hook was executed; no host package DB,
boot policy, service or keyring was changed. This checkpoint establishes no
native package build, installation, performance gain or full-port acceptance.
