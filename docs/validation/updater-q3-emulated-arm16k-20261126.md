# Updater 4.4.2-3 signed transaction on emulated AArch64 with 16 KiB pages

On November 26, 2026, the installed `cachy-asahi-update` 4.4.2-3 completed
one TEST-signed upgrade and refused a bad package signature in separate
offline AArch64 QEMU guests. Both measured 16,384-byte runtime pages.

The native rebuild produced two matching archives and retired its owned
inputs. The privately retrieved 3,084,316-byte archive matched the original
native and installed Check SHA-256
`44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc`.
[Original native Check qualification](updater-native-45715088356.md)

Each case used a fresh writable child of the same read-only Q3 scratch and a
separate boot derivative and media image. The measured PL031 clock advanced
before TEST trust was loaded. The original 356-package Q3 inventory gained
four vendor packages, the exact updater and the inert fixture. Both guests
checked the resulting 362-package inventory. The scratch mount retained
`nosuid`, with setuid enabled only on a read-only bind of the pinned guest
`sudo` binary.

| Case | Installed updater exit | ALPM and state evidence |
| --- | ---: | --- |
| Unconfigured policy | 21 | Preserved the package inventory, local database, original fixture and pending records |
| Protected transition | 22 | Preserved the same checkpoint and made no elevation request |
| Configured update | 0 | One real `sudo` upgrade, exact fixture `0.1.0-1 → 0.1.1-1`, cleared pending records, unchanged nonfixture database and consistent ALPM state |
| Separate bad-signature guest | 5 | Signed database accepted, package signature refused, zero commits and exact original local database, payload, inventory and pending records preserved |

The refusal trial used the unchanged new fixture archive with the valid
detached signature of the old fixture. The repository database itself had a
valid TEST signature. The case allows a refresh of the synchronization database.

Both guests powered off naturally. The host owner verified each container's
absence twice, rehashed the unchanged input media and retired its writable
child and input clones. Independent readback joined serial, launch,
admission, owner and retirement receipts to the correct case.

| Evidence | SHA-256 |
| --- | --- |
| Q3 scratch | `70ca6c345fcf5e5d29d0bb90993d54c17a54164f23b2a6fe839e061b51edca45` |
| 362-package inventory | `7a5779caafed704a109debcf207b040e32565b5102c889809eb33d9bbbe8680b` |
| Update independent readback | `e98ac77a642d25e6f038331a2ce05bcc2869716719660aff499ca761cda72ef8` |
| Bad-signature independent readback | `ef9401c2b709dc5c98f9f0f34e4931769ba526780e5765bf103cf80ce4003cf6` |

The run qualifies the finite generic installed updater transaction. The
supported Asahi composition, coordinated platform updates, boot recovery,
physical M2 and production trust remain open.
[Guest owner and verification commands](../../scripts/ci/updater-full-update/README.md#separate-signed-cases)
