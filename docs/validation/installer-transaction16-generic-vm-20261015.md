# Generic ARM VM: sixteen installer fixture methods

[Actual run38822044432](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38822044432) passes all sixteen selected original methods and twenty-one worker calls, with zero failures, errors or skips. This extends the [earlier three-case result](installer-transaction-generic-vm-20261015.md). It is a disposable generic ARM fixture result; native-container P0 and physical target installation remain separate.

| Binding | Actual selection |
| --- | --- |
| Fixture Source | `dbd783d4b8535ebd23d319e2d9ab90b9f1ce4c2e` |
| Workflow | `6b074af508e4bdfe7f01f4d02f34401f0de46fb0` |
| Fixed retained-input Source | `88a88bc5f3be3998e992881bf090137df16f1aae` |
| Worker SHA256 | `757841a9af84cd2fe84c292711c93745f5985738c4186d219c34783891319ba8` |
| Original test SHA256 | `1987ed23821da917215e9e3366545810d565ece08406fafd429a8c3c772eb2cd` |
| Proof | `47396ea72ef25e0809ba0583f70e07c2a64c3fc7d9316bc575ba8fd7bb4375ed` |
| Retained log ZIP | 4,428,294 bytes; `edc8d9979c129c7e833b6b3601bd9b4220964fa817be290d27e477821835792a` |

The first attempt38820921623 failed acquisition before VM launch. The corrected workflow only adds the exact twelve-file cache seed; package versions, locks, signatures, selected fixture Source and assertions stay held. Native source preparation and the generic 4KiB ARM VM now execute. Boot reports aarch64, kernel7.2.10-1-aarch64-ARCH and4096-byte pages; the ordinary test child runs as UID/GID23001.

The closed per-method result retains the following outcomes. A negative FAIL/REFUSED outcome is the expected test behavior, not a failed test.

| Original selected case | Retained worker outcome(s) |
| --- | --- |
| SIGNED_PAIR | committed / complete |
| MISSING_DEPENDENCY | FAIL / prepare |
| WRONG_SIGNER | FAIL / isolated |
| INVALID_SIGNATURE | FAIL / isolated |
| SECRET_CERTIFICATE | FAIL / isolated |
| SIGNATURE_SUBKEY | committed / complete |
| INPUT_HARDLINK | FAIL / snapshot |
| ESCAPING_ARCHIVE | FAIL / isolated |
| EXTERNAL_ROOT_HARDLINK | FAIL / snapshot |
| FILE_CONFLICT | FAIL / commit |
| PROTECTED_UPGRADE | committed / complete → REFUSED / NOT_REPORTED |
| PROTECTED_REMOVAL | committed / complete → REFUSED / NOT_REPORTED |
| SIGNED_SEED_REMOVAL | committed / complete → committed / complete |
| UPGRADE | committed / complete → committed / complete |
| PROTECTED_UNRELATED_ADD | committed / complete → committed / complete |
| WRONG_BEFORE_INVENTORY | FAIL / prepare |

There are ten successful committed calls, nine expected FAIL calls and two expected REFUSED calls. Both calls in each seed-plus-operation method are validated independently. The real TestSuite reports class cleanup returned, first_failure=null and cancelled=false; the ordinary child returns naturally with exit0.

Source/nonce/proof/prepare/image/inventory joins match. The native handoff includes166 lifecycle checks,361 commit checks and a345-package installed inventory; the tooling guest contains366 packages. The held tool profile has136 files/85,445,048 bytes, and its47,593-byte descriptor SHA256 is `b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8`.

Detailed signature verification, before/after maps, payload/lock preservation, tool rehashes, all five zero outer capability sets, NNP1 and inner isolation checks are mandatory checks in the exact selected source. Their private raw bodies were not separately exported or replayed in this review. In particular, the secret-certificate case proves an isolated no-commit refusal, without separately identifying import versus key-policy cause; protected minimal refusals do not export a specific predicate. Removal uses its installed signed seed, with no new signed removal request.

Scoped cleanup records four virtual-container absences, private tooling-image absence, private workspace cleanup and outer installed-image absence. QEMU ownership retirement passes with cleanup_uncertain=false; natural QEMU exit0 and UART EOF are source-enforced PASS preconditions, without a separate exported exit/EOF field. Individual GPG-agent absence and daemon-wide cleanup were not independently established.

Observed durations are318.611 seconds for the VM,55.569 for preparation and383.739 for its owner. Per-method timings are not exported. These are execution durations, not comparative performance measurements. The900-second child/completion,950-second unit and1200-second whole-VM limits remain held.

Only the bounded selected metadata frames were decoded for review. Native/package/tool/archive/certificate bodies were excluded; no fresh package/signature/VM execution or duplicate log collection occurred. The retained review is under `artifacts/development/installer-transaction16-virtual-run38822044432/review/`.

The original seventeenth declared-after control was not selected in this actual. A separately reviewed seventeen-method successor must execute before claiming full class coverage. Full installer/recovery coverage, native-container P0, production trust, actual Asahi/M2 installation, physical16KiB behavior and release acceptance remain unfinished. Release-selection flags stay false.
