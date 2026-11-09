# Client v3 and Runtime1: finite native ARM fresh component

Root qualifies Source [`a28b081836f11c4867ec1104f29e1e91ebee68da`](https://github.com/Gabriel-Kahen/cachy-asahi/commit/a28b081836f11c4867ec1104f29e1e91ebee68da), tree `ae67a466868fdaf9270d36164ce46d3e127245dd`, ref `codex/client-v3-closed-entry-fixed-source-v1-20261108`, [run 42537753458](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/42537753458), attempt 1, job `128905741960`. The native ARM4096 component and matching passive reader pass. This does not qualify the supported target system or a release.

## Packages and installed behavior

Both packages are version **0.1.0-1**. Four distinct clean build containers on one hosted runner produce two byte-identical pairs. The reader independently compares complete original XZ archives, payloads, PKGINFO and BUILDINFO; mandatory makepkg checks pass without skips. Independent-machine rebuilding is **NOT ATTESTED**.

| Product | Archive bytes | SHA256 | Payload files |
| --- | ---: | --- | ---: |
| Runtime1 (`cachy-asahi-repository-runtime`) | 28888 | `1c8a9149da02e60a4c14598cdf7007d6dbffcd6150757fcf6711977aa00cf8aa` | 8 |
| Client v3 (`cachy-asahi-repository-client-v3`) | 16936 | `c07c9441bf6ab9b1f6d942868ffc0bb762c89ec99e7702563355bf8435399f0a` | 7 |

The disposable TEST-signed lifecycle records fresh install (576 packages), same-version reinstall (576), remove (574), reinstall after removal (576), and final removal (574). Both a fresh and an existing ordinary home are exercised in each installed phase. Installed CLI checks cover real GPG verification and signed apply, idempotence, and state-directory replacement after verification: the replaced directory is refused before checkpoint writing. Each observation retains five raw real GPG signature statuses; cryptographic success is not mocked. Changed-version upgrade was **NOT EXERCISED**.

All 43 current trusted reader inputs and all 82 published Source DATA leaves are joined. Complete actual runner bytes are joined in both contexts. Preservation maps are private and unexported: preservation and retirement are **source-enforced recorded evidence**, not independently retained raw maps or live retirement re-observation. TEST signatures establish no production trust. Image-build daemon policy is not inferred from consumer-container restrictions.

## Reader history and public retention

Root acquired the original artifact body once. Reader call 1 refused the private caller's compile fence during maintained `adapter.text` AST parsing, before a strict result. The first raw result is preserved privately; the archive contains a labeled projection with its raw pin and trace function/line references. A fresh caller permitted only the exact trusted-adapter plaintext AST operand (12102 bytes, SHA256 `cd297fa822cabb44b651e80eb34f508ee1b7822c0e62006e343211c90f8d1440`); execution remained denied. Call 2 returned the unchanged matching strict result, with zero actor calls, network GETs, collected-code imports or denied operations. This was a local caller correction, not a product/native failure. Cumulative reader calls: **2**. No native or artifact-body replay occurred.

The strict result is `VALIDATED_CLIENT_V3_RUNTIME_NATIVE_FRESH_COMPONENT_DATA_ONLY`; its `Root_acceptance` is null, `native_admission` and `Doc315_qualification` are false. Root's separate decision is `ROOT_QUALIFIED_FINITE_NATIVE_ARM4K_CLIENT_V3_RUNTIME_FRESH_COMPONENT`. Public projections retain every strict flag and original raw result/decision hash.

[Public retention archive](records/client-v3-runtime-native-20261108.tar.gz): **402306 bytes**, SHA256 `c8ee24727cf4cb054800c8f41f89c2344e43aa1c7fd44247813f9534a61c4fc6`. It contains the unchanged original artifact ZIP (522293 bytes, SHA256 `b37bcad8dd78d5b42bfa2fea3c297bb2bfb24ac4276b5d73344f936bdba81188`), public source identity/raw commit/full 82-file hash-and-mode map, strict/history/Root decision fact projections, and a member inventory. The archive is passive DATA; no collected code is executed. Private custody paths, caller/operator packets, authority/lease/process details, HTTP headers, authentication and signed URLs are excluded from the projections. The first raw refusal remains private. The original ZIP is retained byte-for-byte rather than rewritten.

## Open work

Native16K and emulated16K integration, supported Asahi/M2 installation and both Air sizes remain **NOT RUN** for this component. Performance is **NOT MEASURED**. Production signing/trust, complete selected composition, hardware acceptance and release admission remain open. Development/release selection stays false. Historical Runtime/v1/v2/Apps/native records and earlier failures are unchanged and are not requalified by this result.
