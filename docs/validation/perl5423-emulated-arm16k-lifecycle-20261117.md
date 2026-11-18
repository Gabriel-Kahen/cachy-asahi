# Perl 5.42.3-1.3 emulated AArch64 16 KiB lifecycle, 2026-11-17

Root independently closed r118 as
`CLOSED_LOCAL_R118_EMULATED_ARM16K_PERL_LIFECYCLE_PASS`. The controller
recorded `PASS_EMULATED_ARM16K_PERL5423_DATA_ONLY` in a disposable QEMU
AArch64 guest with 16,384-byte pages. Installation, functional probes,
removal, normal PAM logout, baseline and user preservation, and persistent
journal preservation passed. The journal comparison excludes only access
time on the journal mountpoint. Host readback checked 54 ELF objects for
16 KiB load geometry.

The verified manifest covers 135 retained files (68 results and 67
receipts) totaling 56,812,305 bytes. The `before.cache` and `after.cache`
receipts match in size and SHA256.

| Evidence | Bytes | SHA256 |
| --- | ---: | --- |
| Operational Source391 lock | 70,012 | `64ecce647475769f47d70aef06eb17c902f6bccdad17a0bd67420c890733c467` |
| Retained manifest | 21,996 | `477306e49018a8289c695c10624565a0e70b55cf546d4a1b93841d20032728f6` |
| Independent r118 closure | 2,961 | `2c28818147a91875412ea10a88d0080f3096e08a989df9e95fdc6acebfecce45` |

This runtime result applies to the exact operational Source391. PR517
covers the separate [Source339 successor and its source controls](../../scripts/integration/arm16k_perl_serial_journal_vm/README.md).
Native 16 KiB, M2, performance, and release gates remain open.
