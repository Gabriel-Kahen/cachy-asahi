# Repository chroot correction: independent source review

Reviewed 2026-10-12. **PASS for the bounded source correction; corrected native repository execution remains NOT RUN.** No actionable defect reproduced. This closes the focused review of the held candidate, not a native transaction or hardware acceptance gate.

## Exact reviewed source

Read the current roadmap, package inventory, and `docs/workstreams/virtual-repository.md`. Independently compared the workspace and isolated copied source against `/tmp/cachy-repository-chroot-copied-atuj7npt/regression.json`. All four files match the following SHA256 values and mode `0644`:

| File | SHA256 |
| --- | --- |
| `scripts/ci/integration.py` | `cb6145d94e1b384d2fedc459fbc4b94fe6a53bcb0834d0e90c2ab5a56dd61eb1` |
| `scripts/ci/test_integration.py` | `62fa9a3843721ccd63fa7b9a4a577cefc1df8db80984255ed4d57b0b2ab046de` |
| `scripts/integration/repository.py` | `e58468fe9ec8158dc082580e400bc63cde374376a50a4be71382fc7c305e228d` |
| `scripts/integration/test_repository.py` | `0c6f936c2dd62dcb703c6bfc45b1cf1a4593ad19db87d8f67bdaa1e5dff6fdb5` |

The copied receipt identifies the initial candidate as `9cfbd847bd2969aadf700b1ebb9943680b064b0ec6570726cdd9389aa31db0bb`, with 159 source files and 125 unchanged generated fixture files. Its historical initial lock is `be5363dfb9f11b39f42fc419bebaa9cbaa11780fce1aa5cde2cedc25629766bb`. This review checks the four changed files; the coordinator owns complete candidate adoption, Git proof, and broader development packet rebinding. No shared lock was changed by this reviewer.

## Capability and launcher scope

`repository_ldconfig=True` is accepted only for the root repository role with a fresh exact `cachy-asahi-repository-<32 lowercase hex>` name and no custom capability override. That launcher adds only `SYS_CHROOT` to the existing five capabilities. Generic explicit capability selection does not allow `SYS_CHROOT`. The actual repository call keeps a read-only container root, network isolation, private cgroup namespace, `cap-drop=ALL`, no-new-privileges, resource bounds, read-only inputs and runner, private scratch/home, and its dedicated output mount.

The repository guard requires exactly `0x400cb` in **each** of `CapEff`, `CapPrm`, and `CapBnd`, zero `CapInh`/`CapAmb`, and `NoNewPrivs: 1`. The previous five-capability mask is refused. Default other launchers retain their five-capability policy; the previously reviewed lifecycle-specific `KILL` override remains separate. Existing filesystem, device, socket, source, nonce, native-machine, and copied-root guards remain present.

The pinned [official ALARM pacman recipe](https://github.com/archlinuxarm/PKGBUILDs/blob/fd636a0077db0efe900d67d4de910c0d270fc8c4/core/pacman/PKGBUILD) selects `/usr/bin/ldconfig` and pacman revision `54d94116164b0b2202c6061c4a59c6f3e70820d8`. The actual chroot/helper behavior still requires the next disposable native run.

## Result and diagnostic authority

Positive pacman commands now require both their expected zero exit status and clean diagnostics. The gate examines raw transaction output and, for local queries, separately retained stderr. It rejects `error:` and the retained native `could not change the root directory` failure. It records a positive diagnostic PASS only after that check. Query inventories remain separate from stderr and transactions retain their strict private configuration and inventory/payload checks.

The missing database signature exception is narrowly typed: only the exact named negative case, nonzero exit, and `-Syyu --noscriptlet` invocation may use it. Its private repository must equal the signed reference byte and alias map except for the two explicitly absent database signature names. Strict Required/TrustedOnly configuration, selected endpoint, and the exact proof fields are checked before and after the command. The entire four-line local signature retrieval diagnostic must match the selected `/scratch/repos/active/integration.db.sig` path; generic download failures cannot substitute. Other rejection cases retain their generic signature/trust diagnostic requirement.

Failed transactions still capture an after snapshot and must preserve both installed inventory and owned filesystem state. A diagnostic classification failure does not bypass that invariant. Raw logs and their hashes remain available for review.

## Independent validation

Ran **26 focused copied-source tests: PASS, zero skips**. They cover actual launcher/owner guard agreement, scoped capability additions, all capability fields and NNP, positive ancillary errors including query stderr, exact typed diagnostics, repository byte/config/endpoint binding before and after failure, nonzero-exit enforcement, unchanged inventory/payload invariants, and raw stdout/stderr receipt retention. These tests used bounded temporary fixtures and mocks; subprocess tripwires prohibit host Docker execution.

Additional independent checks passed:

- Accepted the exact six-capability status, then rejected all **320** single-bit changes across the five capability fields and rejected NNP zero.
- Replayed retained actual native logs `112`, `126`, and `134` from run `38214941784` through the positive pacman path with mocked exit status zero. All three were refused; their bytes and SHA256 receipts remained exact and no positive diagnostic PASS was emitted.
- Accepted the exact retained log `175` only at the typed diagnostic parser. Changed endpoint, extra error line, and changed filename were refused. The focused suite separately verifies the full typed input proof and transaction invariants.

Independently verified the copied full-suite log hashes and PASS/count endings recorded in the receipt: CI **334**, integration **137**, zero skips. Log SHA256 values are respectively `855d203384b927313e54635072a0e638cdee23e784406fe8bcf92c0be655b723` and `77f2e2a990f3ebd4d0f3a18a86c7a1fe5e0e2021010d8c16ede612d2d5e8aaef`. The reviewer did not repeat those entire unchanged suites; the coordinator separately reports independent full-suite execution.

No Docker, chroot, host pacman transaction, key generation, host account/service change, workflow dispatch, or Git mutation was performed. The retained run's ancillary chroot failures remain historical failures. The new source must pass actual six-capability native repository execution before that runtime stage can be accepted. This review provides no M2, boot, desktop, stable promotion, or performance evidence.
