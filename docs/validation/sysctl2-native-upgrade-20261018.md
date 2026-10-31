# Native sysctl discovery upgrade

[Run 39100389988](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39100389988) passed at exact source `e2b0f5d6cde885936369949c6b0fcab2e4f66d12`. Root's strict replay accepted the retained original evidence. The hosted machine reported aarch64 and 4096-byte pages.

Four distinct clean native builders produced two complete byte-identical pairs: the same actual package `cachy-asahi-sysctl`, versions 0.1.0-1 and 0.1.0-2. Baseline recipe source was `8daeb115740ffb494e8fa91f0749c2edd6dd4284`; candidate source was `eac600bd4f256068a78eb793dd464277eed6ce23`. The candidate program SHA256 is `70e3e35d1bf517b21c84f5ecbe608da551e6f8577c68bbfbbd2412b8dd3ed4f0`.

Required TEST-signed install → actual upgrade → remove → reinstall → final remove passed, with exact 575 → 575 → 574 → 575 → 574 package transitions. Two ordinary user homes each ran the original 19 controls on v1 and all 28 controls on v2. Original v1 PLANNED and APPLIED private model records survived upgrade and reinstall and were discovered without mutation. Exact package ownership and payload checks passed at every installed stage. All six consumers retired before the original producer.

The original 574-package payload, raw database, user configuration and system trust preservation checks are source-enforced; their private maps are unexported. Installed test text is unexported, with stream identities retained. TEST signatures establish this disposable lane's required trust path, not release signing or independent machine attestation. No actual `/proc/sys` values changed. Full604 integration, generic16K execution, M2 hardware, physical recovery, performance and release selection remain open.

Original artifact ZIP: 264042 bytes, SHA256 `0426b2e01449a7f0076f2f26f37af98e7f1cd40d94dd573de2b6d711229cad18`. Original logs: 90151 bytes, SHA256 `3ad20beba17e19fa3ef9fabb952ead005c53d039dd57f5b04866a476546c9b15`. Root retains the original transport and scoped decision privately. The default canonical upgrade lane keeps actual source/ref/run authorization NULL until explicitly selected; this result credits only the source above.
