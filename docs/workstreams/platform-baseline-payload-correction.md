# Baseline archive filename and payload budget correction

This is a bounded source correction for the next inert platform audit. **GRUB acquisition/authentication and the merged 617-archive payload audit have not run under this correction.** No package payload, scriptlet, hook, installer or bootloader was executed. Platform installation, dependency/runtime ABI acceptance, boot/runtime behavior, firmware conversions and M2/performance acceptance remain unestablished.

Read the current roadmap and package inventory. Only `scripts/platform/{authenticate_missing.py,test_authenticate_missing.py,payload_audit.py,test_payload_audit.py}` and this new guide were edited. The original accepted platform source/236-test history, old source pins and retained observations were not rewritten; root owns shared maps, Git integration and later acquisition/audits.

## Exact catalog filename

The initial task assumption described an epoch-omitted `grub-2.16-3-aarch64.pkg.tar.xz`. Reading the actual retained catalog corrected that assumption: the declared filename is **`grub-2.2.16-3-aarch64.pkg.tar.xz`**, while VERSION remains **`2:2.16-3`**. No database metadata, version, filename, hash, URL or receipt was edited to fit the helper.

The actual catalog is `artifacts/platform/m8-minimal-20261012-b/asahi-alarm.db`, SHA256 `bb500d9a8293142332189946b6fce5cf927ed677f73f749d35f4f3eff0a5d217`. Its exact `grub-2:2.16-3` record declares aarch64, CSIZE 9,800,024 and archive SHA256 `e43b968d72cde70752ca82450a72fb65644c1a324c03eaee820446c9ba5827da`. The original gap-map, SHA256 `e94464870fb86b502433c5d1369967d8eed1b523e9bbd613a03eff9b4037ecd4`, still retains `GAP-helper-contract` / `exact xz archive filename required`; its source/refusal history was preserved and rehashed unchanged after this edit.

For a VERSION containing a colon, `archive_spec` now requires exactly one ASCII decimal epoch prefix and a nonempty noncolon version suffix. Only the **declared** FILENAME may select a closed form:

- Full version, including the colon, or the epoch-omitted suffix, with the exact metadata name/architecture and `.pkg.tar.xz` extension.
- For `asahi-alarm` only, the declared epoch-colon-to-dot form demonstrated by the retained GRUB record. Core/extra reject that dotted form.

No alternate filename is fetched or guessed. URL construction uses the accepted declared FILENAME unchanged. Full VERSION, name, architecture, archive digest/size, metadata and any embedded signature pins remain intact; full `.PKGINFO` identity/dependency observations and signature verification are unchanged. Malformed epochs, extra colons, wrong names/architectures, traversal, arbitrary separator replacement and nonstring/archive-field type substitutions are refused. Non-epoch packages retain their original single canonical filename behavior.

The exact retained GRUB catalog row passes a local metadata-only `archive_spec` control. Its catalog has no embedded PGPSIG, so this control does not fabricate a signature pin or authenticate the archive. Actual detached signature acquisition and pinned public-key verification remain coordinator-authorized future work. Accepting this filename representation establishes no semantic dependency, architecture/runtime or bootloader compatibility.

## Finite compressed aggregate policy

The coordinator's merged 617 archive references account for 1,298,106,720 compressed bytes, above the previous 1GiB aggregate. The sole resource-policy increase is an explicit **2GiB compressed aggregate maximum**. Existing per-archive 300,000,000-byte, per-archive decoded 1GiB, aggregate decoded 8GiB, per-file 512MiB, per-archive100,000-node, aggregate 500,000-node, per-archive 300-second and finite 4096-reference limits remain unchanged. Link resolution, scriptlet/hook inertness, exact full metadata, captured-byte checks and filesystem guards remain unchanged.

The prior aggregate sum ran before per-reference size validation. A malformed final reference could therefore cause TypeError or use a negative size to offset a large positive array before earlier payload inspection. This pre-existing accounting gap is now closed: every row/reference has its exact schema, selected unique name, absolute string path, fixed checksum, nonboolean positive integer size within 300,000,000 bytes and matching final metadata pins validated before summation or any archive inspection. The existing per-row checks remain in place as well. Source metadata reports are still read through their existing bound references; the no-read guarantee refers to package payload inspection.

Only then may the compressed sum reach 2GiB. A sum above 2GiB or a malformed reference refuses the complete input before payload capture. No additional cap is raised to accommodate any later inspection failure. A future real audit must retain such a failure and its actual diagnostics rather than silently trim its inventory.

## Held source and validation

| Current source | SHA256 |
| --- | --- |
| `authenticate_missing.py` | `6af079cf10f8ebcc9416bf64bca4336ea03dbbf13f99ebd98a83808365f2fe59` |
| `test_authenticate_missing.py` | `8b717a1e9b9a2063909f86c444034b2ea8d7ee4b3248763938b2cd88bec1cad0` |
| `payload_audit.py` | `a7cb3a1c469f88fdb37d17e2414eb283bc53e0ef7211d0723af2b9037fa7689c` |
| `test_payload_audit.py` | `160182be1f0c581e14ee7904f04965e946d8f0e0ae453ba3cbbf50cac1db74f4` |

Historical committed source hashes, retained as history rather than new acceptance pins: authentication helper `28d7d4e007b9d856733eb64e250f8c24ecfedf409ce4c0b0221329e443e1f1fa`, its tests `af98c580bbb6f9554ef3ddbc6ef601cf7c68b273837c2a0c0dfa39b875e60301`, payload helper `07dbd012913490e3a7e1360a50adb115ee6e01cb7d356501e5c9c67c82bb540c`, its tests `22ba84ced4daeade722c8d6a5084b60700c1ffc7080eaac9e7fbb12b169a4778`.

Focused suites passed 25 authentication and 28 payload tests. Complete platform suite: **249 tests PASS, zero skips**, 1.574 seconds, preserving the prior 236 checks and adding 13 new tests. Scoped whitespace checks passed. Tests use tiny source/archive/database fixtures and mocked HTTPS/GPG/inspection delegates; the broader existing suite includes tiny local bounded process fixtures. There was no real network, GPG archive authentication, package execution, system installation or Docker workload.

New controls cover canonical/omitted/dotted epoch forms, repository restriction, malformed epochs/types/paths, unchanged metadata/URL/digest/size, full `.PKGINFO` name/version/arch mismatch, exact embedded signature pin and signature/digest refusal. Synthetic declared-size accounting controls admit 1GiB, 1GiB+1, 1,298,106,720 bytes and exactly 2GiB; reject 2GiB+1 before inspection; and reject negative/zero/float/bool/missing/wrong-type/oversized references before inspection. A negative offset against a positive array already above 2GiB is refused before any delegate call. Duplicate/foreign names and hash/size drift remain refused. These controls allocate only small metadata and mock inspection; they do not allocate or read gigabytes or claim actual payload acceptance.

Root must independently review/adopt these exact source bytes before the one-archive GRUB acquisition and full 617-archive inert audit. Future receipts must bind the new source pins while retaining all earlier observations and failures. A completed metadata/payload audit would still not establish a successful platform transaction, runtime ABI/import behavior, hooks on target, boot recovery or hardware compatibility.
