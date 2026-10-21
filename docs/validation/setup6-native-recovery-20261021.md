# Setup6 native recovery-preview qualification

Setup0.1.0-6 shows each interrupted component/path as pending or already applied, uses the same read-only preparation as replay, and reports edited target/template conflicts before apply. Apply rechecks the inputs before writing.

[Native ARM run39595642635](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39595642635), exact source `141ba835bb632483342c6a7f0246c7fe0f2bc5c3`, passes complete original API/artifact/source/build/lifecycle and ordered-cleanup verification. Two `cachy-asahi-setup-0.1.0-6-any.pkg.tar.xz` archives are byte-identical:27,188 bytes, SHA256 `a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8`. The two builds use one native host. The source closure is73 files, including70 manifest bodies.

The disposable native aarch64 root uses4096-byte pages. Eight Setup4/6 install, upgrade, reinstall, rollback and removal transitions pass; six direct acceptedSetup5/6 transitions pass. Each checks the full574-package baseline, unrelated user state and database consistency, restoring574 at completion. The original five legacy profiles plus grouped journal provide24 ordinary observations and60 inert module cases.

Six additional tests execute the installed Setup6 helper as UID1000 with private user fixtures: interrupted activate and remove; already-committed state; edited-target refusal; required-template refusal; and identical preview/apply preparation with apply-time rechecks. Every case passes and the private fixtures retire. The tests make no system configuration changes.

This qualifies namespaced inert module and private recovery fixtures only. Actual six-module configuration integration, expanded desktop lifecycle,16K execution, abrupt power-loss durability, Asahi/M2 onboarding, performance and release trust remain NOT RUN. The isolated lifecycle masks41 existing ALPM hooks; this is not normal-hook or service-start acceptance. Packaged README status text is the frozen pre-build snapshot; this record supplies the subsequent finite qualification without changing the accepted package bytes.

All74 source recovery/setup tests and packaged synchronization checks also pass on Python3.12/3.14. Root independently matched every proposed implementation/package leaf to the qualified native source. Local acceptance: `artifacts/development/setup6-isolated-producer-native-actual-20261021/Root-component-acceptance.json`. Original failed checkout/import trials remain retained and unaccepted.
