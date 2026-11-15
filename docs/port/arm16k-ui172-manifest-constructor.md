# UI172 unissued manifest constructor

The [constructor](../../scripts/port/arm16k-first-login-ui-inputs/retained_archive_audit/ui172_successor/manifest_constructor/)
joins existing pinned DATA. It does not open package archives, signatures,
public keyrings or rootfs payloads, copy materials, invoke GPG, acquire inputs,
or run a daemon, lease, guest or installer.

Inputs are the accepted UI172 authenticated ledger, the actual 172-addition
proposal, Root's baseline namespace v2, and Root's actual lower155 additions
manifest. The latter supplies corroborating baseline/44-package DATA only;
its Root issuer, review, timestamp and approval are never inherited.
`contract.json` records the observed UI consumer schema and fixed complete
PAM/seat-rule/typelib/policy payload expectations from the pinned inputs.
The consumer source snapshot is read as DATA, not imported or executed.

The generated `ARM16K_FIRST_LOGIN_UI_ADDITIONS_V1` template contains:

- Exactly 172 archive/signature references and full PKGINFO multimaps, keeping
  list order; 169 official and three distinct project TEST signing roles.
- The unchanged actual ALPM preparation and all 1,319 selected provider edges.
- All 111 baseline package ownership/provides associations, their provenance,
  the exact prepared pin, and seven original file pins.
- Twelve addition namespace records plus original GLib/Gio typelib records.
  All seven fixed baseline leaves are also retained with exact numeric payload
  metadata, including the four PAM files and stock 71-seat rule.
- The actual original NetworkManager policy payload, current Xvfb 21.1.26-1,
  exact fish/zsh template references and two distinct public-keyring roles.

The baseline normalized association is
`bb7deff9b41610e454244b4b6c87529a8007795703417a788d2dfbcad7d1683b`.
The original policy remains SHA256
`6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446`.
Baseline v2 and lower155 baseline metadata, provenance and file pins match
exactly. Each of the lower44 archive/signature/PKGINFO rows also matches the
UI172 ledger. Missing or mismatched exact DATA refuses construction.

All Root issuance fields, TEST trust issuance and `trust.valid_until_utc`,
actual runtime qualification and runtime authority remain **null**. Status
remains HOLD. `refuse_unissued()` confirms that these outputs cannot pass the
missing-Root gate; it is not a runtime trust verifier or actor entry point.
No command-line option accepts an approval, trust horizon or qualification.
Current signature/trust qualification, full archive namespace/link-target and
ownership checks, full ABI/runtime/seat, native builds, M2, legal and release
acceptance remain external.

Run `construct.py --output /tmp/NEW_DIRECTORY` with Python 3.12 or newer.
It writes `additions-manifest.UNISSUED.json`, `materials-plan.DATA.json` and
`receipt.json`. The materials plan is 348 source-path/pin records: 172 archive
pairs, two templates and two public rings. Nothing in the plan is opened or
copied. Each invocation is fenced to 256MiB address space, 30s, 16MiB total metadata
input, 8MiB per input and 8MiB per output. Paths must be ordinary pinned files;
duplicate JSON keys, nonfinite values, symlinks, mismatches and caps refuse.

The committed control fixture is a bounded metadata snapshot, not package
payloads. Eleven mutation/isolation controls run without private input paths
or material reads, including a pure-function test with all file-opening APIs
blocked. They check full joins, fixed metadata, signer separation, exact pins,
tampering, preserved inputs and null Root/trust/runtime fields.

Actual validation: all eleven controls passed on Python 3.12.13 and 3.14.7.
Both actual CLI joins also completed under their 256MiB/30s fences, reading
5,519,187 bytes of metadata each in 0.099s/0.088s. Manifest and materials-plan
bytes are identical across both runtimes. The resulting template and receipts
are retained under `manifest_constructor/results/`; the missing Root fields
remain null, and no structural DATA input is missing.
