# Independent review of native run 38221511121

The actual run at commit `a03c0719893afe582a6e6364ff70f0e3e5b33fb2` remains **FAIL**. The first ten repository cases passed; the final positive B upgrade was correctly refused despite exit zero. This is independent data-only inspection of the retained hosted ARM evidence, not execution of another workload or approval of a proposed correction.

Read the current roadmap/inventory and inspected `artifacts/ci/38221511121/decoded`. `/tmp/native-repository-run-review.py` independently checked all **12** encoded workflow-log frames: strict base64, declared compressed length/SHA-256, saved tar equality, finite unique regular relative members, and equality with every decoded file. It also checked **15 exporter manifests / 606 accepted rows**, with matching sizes/hashes, no rejected rows and no inventory overflow. All **187 repository command records** match their retained stdout/stderr or deliberately renamed public logs. No source, Git, system, network or native workload was mutated; only this review document was written in the repository.

| Evidence | SHA-256 |
| --- | --- |
| `repository.tar.gz`, 113,527 bytes | `4b15c935803b83e5d0de9048b9829222638efad241d5e56776a5fe497d7911ba` |
| `summary.tar.gz`, 1,020 bytes | `0101a166f065703aea2dec15fdc42e9e2da4ca5b697933e5d1a576e49640e64b` |
| `native-evidence.tar.gz`, 1,256,125 bytes | `815cba9dcbd4ca84ac36731cf3a2ec598b785846ca16fe4a6de0e3eadc1980fe` |
| `repository/result.json` | `3e019780ebd721737e09c11cb817bb93247c6bd8d18f06e364532ccf926a66e8` |
| Final `185-unrevoked-B-final-full-upgrade.txt` | `735c2ff3a4895736c10ceb83d3e919d3e2f1fe12e2e3a6ef81405b47e18e460c` |

The actual runner receipt reports Linux aarch64, native aarch64 Docker, ordinary UID/GID 1001, Neoverse N2 and 4096-byte pages. Source-suite receipts sum to **603 tests PASS, zero skips**, with their command/cleanup gates passed. All four original packages have distinct clean native build IDs, identical actual archive bytes and matching archive/provenance hashes; recorded byte, installed-content, PKGINFO and BUILDINFO comparisons are all true. Signer, fixtures, lifecycle, onboarding, desktop and source-suite stage receipts passed. These are bounded generic hosted-native results, not M2 hardware or supported target installation evidence.

The repository observed exact effective/permitted/bounding capability mask **`0x400cb`**, zero inheritable/ambient sets and NNP=1. Command 112 (trusted A install), 126 (trusted B upgrade) and 134 (retained A rollback) each exited zero, recorded `positive_diagnostics=PASS`, and contain no error/chroot/helper-failure diagnostic. The completed cases are:

| Actual case | Result |
| --- | --- |
| Untrusted A rejection | PASS |
| Trusted baseline full install | PASS |
| Untrusted B rotation rejection | PASS |
| Trusted B full upgrade | PASS |
| Full rollback to retained A | PASS |
| Tampered package signature rejection | PASS |
| Tampered database signature rejection | PASS |
| Missing package signature rejection | PASS |
| Missing database signature rejection | PASS |
| Revoked A repository rejection | PASS |

Every negative case preserves its complete before/after inventory and tracked payload-state snapshot exactly. Every completed snapshot retains all 341 accepted base-package versions; additions are confined to the four original packages and one synthetic test fixture. The missing-database case reaches the exact selected local required-signature retrieval failure. Revocation evidence includes both `REVKEYSIG` and `KEYREVOKED`, followed by nonzero pacman rejection of A. The earlier cached B diagnostic in that negative command does not erase the subsequent explicit revoked-A rejection evidence.

Final command **185** exits zero and upgrades all five development/fixture packages to their B versions. Its after snapshot records those versions and preserves the full base. Its first log diagnostic, however, is `error: integration: signature from ... signer-A ... is invalid`, before database synchronization. The ordering supports the coordinator's cached revoked-A sync-database diagnosis; it is not a failure of the eventual healthy-B package signatures. The positive gate therefore records no diagnostic PASS, emits `unrevoked-B-final-full-upgrade: positive command has error/ancillary execution diagnostic`, and leaves that eleventh case unaccepted. Repository, integration summary and outer native result consistently retain FAIL. Exit zero and updated versions do not override that gate.

Repository private-state removal and owned container absence are recorded PASS. The summary also confirms absence of its exact owned lifecycle-derived image `sha256:3dd3cf99eb6936bc43752403ead35c0374df380397bf0757b130e2a61429235e`; this does not claim complete daemon cleanup. The proposed narrow reset of private cached sync state before selecting a fresh repository requires separate source/fixture/native verification. This review grants no diagnostic waiver and does not convert the failed run to PASS. Production trust, stable promotion, release selection, Asahi/M2/16K hardware and performance remain **NOT RUN**.
