# Complete the one finite public selection after conversion

The retained actual common DATA is exactly 4822 bytes / SHA256
`d76d2f5cfa66ef7f8d2f18a4ce8651061f466cb47133ebcfa6f974ed5e530ea6`.
The complete original 111-package identity is exactly 18370 bytes / SHA256
`ae69ebe75e2b17011ac6bd063f825f9993242e63b7a293799a5bcd1fa6fb4d79`.
Both public DATA files are retained here and checked against those whole pins.
No descriptor-referenced image, prepared file or private input is opened.

`selection.ACTUAL.INCOMPLETE.DATA.json` (3525 bytes / SHA256
`52600c78395cb976274b711e6d658c7642cd5867cd910f953018a9a0f0004ef1`)
contains the actual fixed common facts. It is incomplete and intentionally
refuses source construction. `selection.TEMPLATE.json` has the same contents.
The original actual control establishes finite observation and cleanup only.

After separately admitted conversion, Root must select these fields in a new
canonical public selection file:

- `warmed_baseline.raw`: exact new raw `{ "bytes": N, "sha256": "HEX64" }`.
- `warmed_baseline.prepared`: exact new prepared descriptor of that shape.
- `warmed_baseline.certificate`: exact separately Root-selected certificate
  descriptor of that shape. The constructor never creates this certificate.
- `conversion`: exactly `{ "report": PIN, "raw": RAW_PIN, "prepared": PREPARED_PIN,
  "opaque_only": true, "original_unchanged": true }`, with the report pin selected
  from actual conversion evidence and the raw/prepared pins equal to the new
  warmed-baseline descriptors above.
- `packages.warmed_inventory`: the same complete original identity pin above,
  only after Root establishes that the selected prepared/certificate lineage
  retains that exact 111-package identity. Count111 alone cannot substitute.

Every other fixed field must remain exactly as supplied. In particular,
`Root_warm_baseline_acceptance` and `next_boot_stability` remain NULL in source
selection DATA; neither conversion nor source construction supplies those
outcomes. A future packet's separately reviewed Root baseline declaration and
fresh execution grants remain unissued by this constructor.

Root supplies the new selection's exact SHA256 to `construct_source.py` through
`--selection-sha256`, its canonical path through `--selection`, and a fresh
ordinary disjoint public output through `--output`. The source output remains
unissued. No source ref, execution nonce/resources/output grants, runtime result,
restoration result, package-lifecycle result or hardware acceptance is created.
