# B08/B09 local signed staging and recovery checkpoint

On 2026-11-25, Linux x86_64 with 4,096-byte pages, pacman 7.1.0 and
GnuPG 2.4.9 ran the following cases from source
`565e10bfe7ef00b0528881dfba08e0f0fe50721c`. Each used private directories
and disposable TEST-only keys. The public Preview 1 download remains an
unsigned GitHub prerelease. [Preview 1](https://github.com/Gabriel-Kahen/cachy-asahi/releases/tag/overlay-preview-1)

## Preview archives in a local signed staging pair

All seven locally retained public downloads matched the prerelease API's byte
counts and SHA-256 digests. The checksum file matched the bytes at the remote
`overlay-preview-1` tag, and all six listed assets matched it. The successor
used the existing local Preview staging spec and all five published package
archives. The predecessor used the same four other archives and the retained
5,400-byte Fish `0.1.0-1` native-build archive from run `38259350917` (SHA-256
`22e6e3ca4f23b73434c4aed284016914652900c33e845516621c0eb8b176d64e`). Its
digest matched both the native build record and the documented archive pin.
The predecessor spec named the old Fish build/source and pinned its version in
the compatibility set. Both specs are synthetic staging inputs over the
same historical 574-row dependency inventory (SHA-256
`da2f06cd7f79cd47c5146cc8e9a60923b00fc09dcca9350be51f7423042c177a`).
[Preview checksums](../release/overlay-preview-1/SHA256SUMS) · [Historical archive pin](../workstreams/native-arm-install-transaction-proposal.md)

| Signed staging bundle | `release.json` SHA-256 |
| --- | --- |
| `overlay-preview-test-retained-fish` | `1f9f5528856b7fbfe98754b67d022ef245f31f3da474dd85d80ccdfd96ea9b5b` |
| `overlay-preview-1-local-test` | `93dee7097cd6edfe52780d62f84c69511f06af50dbd380090506fcc97bad1b38` |

- `release.py stage` and public-only `verify` exited 0 for both bundles.
  `compare_releases.py` found only Fish `0.1.0-1` → `0.1.0-2` with changed
  archive bytes and one corresponding compatibility-set row change. The base
  inventory, other four package archives and selected/protected package lists
  matched. The two compatibility sets differ, so the pair does not meet the
  retained stable recovery contract's identical-policy prerequisite.
- Both real `release.py promote` calls exited 1 with `synthetic fixtures cannot
  enter stable`. `export_repository_v2.py --apply` exited 1 with `no stable
  selection or signed withdrawals to export` and left the endpoint empty.
  `release.py verify` exited 1 on a deliberately corrupted copy of the
  successor archive. The retained original bytes were intact.
- `release.py withdraw` signed the TEST incident for the local successor.
  Subsequent channel verification exited 1 with `release withdrawn; retained
  files are recovery evidence only`. Endpoint preview and apply agreed on
  withdrawal-only generation
  `0c095b8c238a2eaa46a88a3d159a2a9f35cc281ee50eb469434488a4d9fdb52a`.
  `client/endpoint.py` verified its separately copied generation and reported
  the withdrawal with a null repository route. `recover_repository.py plan`
  refused the incident-only current generation with exit 1, `invalid name:
  None`. The endpoint selection held and the predecessor still verified.
- After the TEST signing home was removed and the evidence directory moved,
  a new public-only home reproduced the comparison byte for byte and the
  recipient verified the withdrawal again. Comparing retained raw bundle
  signatures does not clear the signed withdrawal.

The Preview pair receipt and comparison have SHA-256
`0dddb54e8f77dc15e78c6128c11cac41966fcc5ce3b7fc7dc850ff531f24d566` and
`03574b37137d24b83b0ae827a5b5ff532710aad4c8660d5f96b8af5e55ed4816`.
[Release CLI](../release/interface.md) · [Endpoint verifier](../release/endpoint-client.md)

## Rollback and transition fixtures

`rehearse_lifecycle.py --output <new-directory>` passed all 19 checks for the
inert `rehearsal-fixture` package, versions `1.0-1` and `1.1-1`. The private
selector refused a partial successor, selected the complete successor, and
returned to the byte-identical retained predecessor after corruption and a
signed withdrawal. Both fixture promotions were refused by the real gate.
Public-only reverification after relocation authenticated the predecessor and
both signed recovery and withdrawal receipts. The rehearsal report SHA-256 is
`2608ab4d6d9fb9e8fbac6f613a3a063b271048fe04f4d07bd3d72b862615cafa`.
[Offline rehearsal](../release/offline-rehearsal.md)

The retained-stable recovery suite exercised successful old-generation
selection, signed withdrawal retention, refusal of stale/altered inputs,
copy and pointer-commit faults, and retry. Positive stable fixture cases model
hardware gate admission. The real CLI separately refused the stable fixture.
The transition suite verified dual TEST signatures from independent public
material and rejected wrong, expired and revoked authority cases.
[Recovery contract](../release/retained-selection-recovery.md) · [Signing transition](../release/signing-transition.md)

In a separate fixture integration, recovery selected `previous` and retained
the real TEST-signed `recovery-plan.json` and detached signature. The endpoint
recipient CLI then exited 1 with `unrecognized endpoint member` before stable
gate evaluation. The ordinary exporter and recipient suite verifies only the
original generation layout. Recipient support for the recovery authorization
pair requires coordinated validation of its schema, signer, and bindings.

All 128 focused tests passed with no skips. Commands were run individually
with `python3 -I -B` and `-v`.

| Test file | Passed |
| --- | ---: |
| `scripts/release/test_release.py` | 31 |
| `scripts/release/test_export_repository_v2.py` | 5 |
| `scripts/client/test_endpoint.py` | 20 |
| `scripts/release/test_recover_repository.py` | 26 |
| `scripts/release/test_recovery_bundle.py` | 23 |
| `scripts/release/test_rehearse_lifecycle.py` | 9 |
| `scripts/release/test_signing_transition.py` | 14 |

## Production gates

B08 has additional local staging, incident and rollback evidence. B09
production remains open. The release operator needs a reviewed complete Asahi
baseline and exact old/new stable candidates with native build, provenance and
promotion evidence, named permanent primary and alternate signing custodians,
production trust bootstrap and exercised key transition/revocation, and a
supported published signed package endpoint. Both physical M2 Air sizes still
need the exact signed install/upgrade, induced failure, package and platform
restoration, and boot/session recovery. These runs did not execute a package
transaction. [Roadmap](../roadmap.md) · [Backlog](../backlog.md) · [Acceptance matrix](../acceptance.md)
