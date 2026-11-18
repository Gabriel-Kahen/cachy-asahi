# Stage signed operands for supported composition

Run `assemble_signed_additions.py` against a reviewed, SHA-256-pinned contract and a new private output directory. The command consumes the exact add set from the selected `compose.py` report, checks its archive pins, copies detached signatures and package bodies, then verifies signatures and signed package metadata. It works offline and uses existing files, a fresh temporary GPG home, and public certificates. It needs Python, GnuPG and bsdtar for zstd package metadata. The original composition report and its policy verdict remain visible in the receipt. Authenticated archives can be staged even when original policy blockers keep the composition on hold or cause it to fail. The assembly receipt grants no transaction, production-trust, or install authority.

The JSON contract has the following fields.

| Field | Value |
| --- | --- |
| `kind`, `schema_version` | `supported-Asahi-signed-additions-DATA`, `1` |
| `original`, `composition` | Whole-file references to the original and selected reports. Use the same report twice when there are no alternatives. |
| `alternatives` | Zero or more records with `name`, `before`, `after`, and `evidence`. The two archive identities each contain `repo`, `version`, `filename`, `size`, and `sha256`. Evidence is a whole-file reference to the separately reviewed alternate custody proof. |
| `keys` | Records with `id`, `role`, `fingerprint`, and a `certificate` whole-file reference. Core and extra use `alarm`, Asahi community uses `community`, and each project package uses its own name and role `project-test`. The vendor role is `vendor` and its public certificate pin comes from the existing acquisition verifier. |
| `operands` | One record per selected ALPM add with `name`, `version`, `repo`, `key`, `archive`, and `signature`. Archive and signature references must have their exact package and detached-signature filenames. |
| `byte_limit` | Total archive and signature budget in bytes, capped at 1 GiB. |

Whole-file references have exactly `path`, `size`, and `sha256`. Use absolute paths, positive sizes, and lowercase SHA-256. The input files must remain ordinary, single-link files throughout the read. Assembly keeps the original membership, protected versions, provider choices, dependency graph, and policy results. An alternate may change an unprotected selected archive's exact identity and defined build metadata. It needs the same runtime package metadata and a pinned evidence artifact. The operator reviews the evidence separately.

```bash
python -I -B scripts/port/supported-composition/assemble_signed_additions.py assemble \
  --contract /absolute/path/contract.json --contract-sha256 "$contract_sha256" \
  --output /absolute/path/new-stage
```

On success the new directory contains `cache/`, `public-keys/`, and `receipt.json`. Each staged file is a separate read-only copy. A failed assembly may leave partial files in its exclusive directory and produces no success receipt. Use a fresh destination for any retry.

```bash
python -I -B scripts/port/supported-composition/assemble_signed_additions.py verify \
  --contract /absolute/path/contract.json --contract-sha256 "$contract_sha256" \
  --output /absolute/path/new-stage --receipt-sha256 "$receipt_sha256"
```

Readback takes the externally retained receipt digest, rechecks the two reports and alternate evidence, and rehashes the exact staged file set. It does not need the original archive or signature bodies to remain available. Signature freshness is recorded at assembly time.
