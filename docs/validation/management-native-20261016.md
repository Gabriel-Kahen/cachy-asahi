# Native Apps, Runtime and Cache candidates

Root accepts run [38970264456](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38970264456), source `87b7418375b5334bad7e92faf68f6d11df50d533`, as `ROOT_ACCEPTED_APPS_RUNTIME_CACHE_NATIVE_PAIRS_AND_INSTALLED_LIFECYCLE`.

| Candidate | Archive bytes | SHA256 |
| --- | ---: | --- |
| Apps0.1.0-5 | 22088 | `9ec47f6cf506c5d2b6da3ac6f4f42e00ce98b8d1985b1b9eca065c38058c1580` |
| Cache0.2.0-1 | 18304 | `450706e2899f57b44ca2f446560c8aeab710a4726a13561d09a2cb4a8bf1da40` |
| Runtime0.1.0-1 | 28888 | `1c8a9149da02e60a4c14598cdf7007d6dbffcd6150757fcf6711977aa00cf8aa` |

Six distinct recorded clean native aarch64 builds produce three byte-identical pairs, including exact BUILDINFO, metadata and installed source/license payloads. All mandatory checks execute without skips:39 Apps tests,27 Cache tests and Runtime's exact three-helper contract. Runtime is first signed-installed into the575-package dependency image; Apps builds against that declared dependency. Cache builds independently on the original574 image.

The signed combined lifecycle performs574→577→repeat577→remove574→reinstall577→final574. Existing574 payload/database records and user files stay preserved by the frozen-source checks. At each installed checkpoint, two ordinary-user profiles invoke the default installed CLIs without a checkout. Apps authenticates a signed synthetic catalog and produces read-only install/removal plans; a separate real577 metadata collection checks the complete package map and raw record hashes. These observations remain metadata evidence, not independent payload attestation. Application plans remain NOT_APPLIED.

Cache verifies explicit plans and actually removes only selected synthetic archive/signature pairs from private disposable fixtures. Real libalpm16 holds its empty transaction during cleanup; the journal records its own lock release, protected/nonselected inputs remain intact, and a real counterpart-held lock is refused. Logical selected deletion is measured; reclaimed physical disk space is NOT_MEASURED. Host system caches and installed packages are untouched.

Root replays all156 closed public files,65 frozen Git inputs, all recipe source files, the six original build validators and three original comparisons, exact payload checks and the original installed-lifecycle validator. Ten owned consumers, derived dependency image, original producer and TEST authority have successful ordered retirement; borrowed images remain preserved. Original collection and Root receipt: `artifacts/development/apps5-cache-native-run38970264456`.

Full original574 payload maps and complete577 local database observations were not exported, so preservation/collector coverage remains source-bound retained runtime evidence. Signatures and catalog use disposable TEST authority. This generic ARM/4096 result establishes no16K execution, M2 compatibility, production application apply, physical recovery, performance gains or release admission.
