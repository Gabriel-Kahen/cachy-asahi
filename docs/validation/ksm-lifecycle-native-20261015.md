# KSM native build and package lifecycle: 2026-10-15

[GitHub run 38760405710](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38760405710), attempt 1, succeeded on the generic `ubuntu-24.04-arm` runner. Its retained terminal report and curated artifact record two accepted native ARM builds, byte comparison, the disposable signing/install/remove lifecycle, and owned-resource cleanup as **PASS**. This is development evidence for the current read-only diagnostic package, not an Asahi/M2 installation or KSM management result.

## Tested source and retained bytes

- Source: `2db02a279cf7dcee90167858f96a543689e45198`.
- Workflow: [native-arm-ksm.yml](../../.github/workflows/native-arm-ksm.yml).
- Packet SHA-256: `4d8fef2e5256cf08bcd88ffab5760aae0617823d881ff842d91164eed93baf31`, independently recomputed from that committed Source.
- Package: `cachy-asahi-ksmctl 0.1.0-1`, architecture `any`, GPL-2.0-or-later, dependency `python>=3.11`.
- Accepted builder image: `sha256:f69bd43c1f2f54b68aad01bf7c17ce48fbbbbef4fa14e74e9377f8ea99e7bd89`.
- [Uploaded development artifact 11988100732](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38760405710/artifacts/11988100732): `ksm-development-38760405710-1`, three files, 33,665 ZIP bytes, SHA-256 `1108fec62fd43cdf1778c068fe1ddcc537b04738a1331d954f2a9e1269707fa0`. The workflow requested one-day retention; the ZIP was also retained locally.

The existing downloads are [logs.zip](../../artifacts/development/ksm-run38760405710/logs.zip) and [evidence.zip](../../artifacts/development/ksm-run38760405710/evidence.zip). Both ZIPs passed CRC checks; read member lengths matched their ZIP declarations. The aggregate and native-step logs contain identical terminal JSON bytes. The artifact ZIP's actual size and SHA-256 match the uploader's declarations. Its original `evidence.json` is 2,225 bytes and hashes to `65d836954906e2276af16c57ffc7a1fa7de8d4f20c5fe24a1b1113c1d2c3d479`, matching the terminal report.

Both package members, under `build-1/` and `build-2/`, are named `cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz`. Each is 15,460 bytes and hashes to `00757d41be50b18e3cd46988b13308f7e05f8d4df8f16fbd61909e944122bfdf`. Their declared sizes and hashes were recomputed, and their complete compressed bytes compare equal. The artifact also reports metadata, payload and build-information equality; complete archive equality was independently confirmed locally.

All 15 approved recipe inputs in [packages/tools/cachy-asahi-ksmctl](../../packages/tools/cachy-asahi-ksmctl/) and [the reviewed source map](../../manifests/reviewed/ksmctl.json) match the tested Source and current canonical files at this audit. The package's five installed payload files also match their current source bytes: the CLI, README, source provenance, license and notice. This result therefore applies to the current recipe and diagnostic payload, rather than only the older native-build commit in the inventory. It does not extend to subsequent edits without comparison.

## Actual results and their scope

| Check | Result | Evidence and limit |
| --- | --- | --- |
| Native producer and two fresh package builds | PASS | Terminal report accepts the producer and both builds. Both actual resulting archives are retained; this Python package declares `arch=any`, so this is not a compiled ARM/M2 binary result. |
| Archive, metadata, payload and build-information comparison | PASS | Curated evidence records all four comparison booleans true; retained archive bytes are identical. |
| Disposable signing and signature verification | PASS, accepted lifecycle | SIGN and LIFECYCLE attach returned 0. The accepted source contract requires a disposable signing key and trusted local package verification. This is not release-key custody or signed repository publication. |
| First installation and installed payload/ownership checks | PASS, accepted lifecycle | The accepted worker uses signed local `pacman -U --noscriptlet`, verifies inventory, package-owned paths, modes and content, and leaves image hooks unchanged. No target Asahi transaction is established. |
| Installed CLI and unprivileged probes | PASS, accepted lifecycle | The contract requires help/version success, refusal of enable/disable, and read-only status with exit 0 or 3. The exact status exit is not present in the retained aggregate, so KSM availability on the runner is not established. |
| Page-size counter conversion and user fixture preservation | PASS, software fixtures | The installed CLI is checked against synthetic 4,096- and 16,384-byte page inputs, without fixture mutation. User fixture state is preserved across package transactions. These are not tests on an actual 16K-page kernel. |
| Remove, reinstall and final removal | PASS, accepted lifecycle | Both install/probe/remove cycles are required for lifecycle PASS, including package absence and baseline inventory afterward. Reinstall follows removal; in-place upgrade, failed upgrade and rollback were not tested. |
| Lifecycle process/tmpfs and container cleanup | PASS, accepted lifecycle | Curated lifecycle cleanup is PASS; signer and lifecycle child return codes are 0, and no controller failure or cancellation is reported. |
| Global owned-resource cleanup | PASS | Curated evidence has `absence_verified=true`; producer diagnostics report owned containers and owned image absent, with `owner_failed=false`. `ownership_uncertain=false`. |
| Existing daemon baseline preservation | PASS within recorded scope | Inventory/reference observations preserve six protected image IDs through `after_cleanup` over 34 observations. Nine unowned image IDs are explicitly NOT VERIFIED; legacy build-cache absence is NOT ESTABLISHED. |
| Curated export and artifact upload | PASS | The retained three-file artifact matches its reported ZIP digest and the evidence/package declarations. `published=false`: this is a development artifact, not a maintained package repository release. |
| Interrupted lifecycle or boot/session recovery | NOT RUN | This successful normal path does not establish interruption recovery, failed transaction recovery, or boot rollback. |
| KSM activation, policy execution and performance | NOT RUN | The shipped CLI remains read-only. No enabled service, privileged management implementation, sysfs mutation, memory saving, latency, power or thermal result is established. |
| Asahi target installation and both M2 Air sizes | NOT RUN | Generic ARM CI does not establish Apple boot, graphics, audio, suspend, actual 16K-page behavior, or compatibility on either supported Air size. |

The retained terminal report and public evidence are available as readable derivatives in [terminal-summary.json](../../artifacts/development/ksm-run38760405710/terminal-summary.json) and [public-evidence.json](../../artifacts/development/ksm-run38760405710/public-evidence.json); [local-validation.json](../../artifacts/development/ksm-run38760405710/local-validation.json) records the byte checks. Original artifact bytes remain in `evidence.zip`. The verbose private build provenance, signing material, per-worker receipts and individual probe output are not retained here. The detailed lifecycle credits above follow the exact Source's enforced acceptance checks and its observed PASS, rather than a new independent replay of those private actors.

## Remaining work

The [management policy contract](../../packages/tools/cachy-asahi-ksmctl/management-policy.md) still describes an unimplemented management executor. This successful run closes the normal disposable native package lifecycle check for the audited payload; target installation/removal, interruption recovery, safe management, both M2 Air validations and measured performance remain open. Curated evidence preserves license and notice files but explicitly sets `source_grants_complete=false`; broader distribution grants are not established by this run.

Earlier run 38753691479 failed at `LIFECYCLE / INSPECT_BEFORE / sandbox-isolation-cap-add-drift`. Its actual capability operands were not exported. The normalized capability predicate is exercised successfully by this later Source, but the later success does not reveal the earlier operands or prove the earlier underlying cause.
