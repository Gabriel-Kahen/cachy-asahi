# Updater private-directory failure observation

October 12, 2026. Held source implementation with independent source review PASS, awaiting coordinator adoption. The stage test suite passes 87 tests with zero skips; all 78 original test methods and their original bodies remain. No native updater, compiler, Docker, GPG, package transaction, installation or hardware trial is performed here. Actual updater9 (`38319260369`) remains FAIL with its directory branch, component and race UNKNOWN. Actual updater8 (`38314402583`) retains its separate ELF UNKNOWN result. These source controls cannot identify either historical private leaf.

## Selected authority and owned files

The coordinator selected `artifacts/reviews/native-updater-38319260369-root-peer/private-scan/leaf-proposal.json`, SHA256 `db0b9b5c1ce9541e05eab7cabde44ca3166814ec3f6a399a1659d177531941b9`. Its exact path, size, mode and hash are authenticated by final receipt `1bb0930c8fea47b5d1e57e63a7fe3339ecd5960b38d9fa1793925935b02e1912` and its owned-artifact row. This implementation changes only the following two production/test files, this new guide, and the new review namespace.

| File | Held SHA256 | Bytes | Mode |
| --- | --- | ---: | --- |
| `scripts/port/updater-native-stage/stage.py` | `de7f19f58c2773896879a1997a7ea707619d47644ce0f3b4f0a7b11ce3feb3a5` | 68,423 | 0644 |
| `scripts/port/updater-native-stage/test_stage.py` | `77c09c71a0503ab7228b0f5cb2357be53cb3a967f221583a3f9919571b9caf9d` | 107,636 | 0644 |

`artifacts/reviews/updater-private-directory-leaf-20261012/held-source.json` holds the data-only 86-file closure and exact copies: 4,248,868 bytes, the same 86 paths as updater9, with the other 84 files unchanged in bytes and modes. This is a source hold, not a committed Git collect/verify or native freeze. `source.py`, ready/input maps, workflow, shared manifests, package recipes and actor entry points are not edited by this lane. READY_SHA remains `6dc5515b411bcaa9cff7caa844fcc623a7a0dba39cb0c28e1c6859db457438e2`.

## Closed diagnostic group

The only new public field is optional `directory_leaf`, with exactly four plain string fields: `availability`, `check`, `scope`, `component`. It can accompany only `runtime_reason=tick-failed`, `tick_operation=private-scan`, `tick_reason=private-directory-identity`. Observed rows are limited to these 19 tuples:

| Check | Scope | Component |
| --- | --- | --- |
| `OPEN_FD_IDENTITY` | ROOT or DESCENDANT | DEVICE, INODE or MODE |
| `ROOT_PATH_MISSING` | ROOT | NONE |
| `LINKED_CHILD_PATH_MISSING` | DESCENDANT | NONE |
| `PATH_IDENTITY` | ROOT or DESCENDANT | DEVICE, INODE, OWNER or MODE |
| `PATH_NOT_DIRECTORY` | ROOT or DESCENDANT | TYPE |
| `CHILD_OPEN_REAPPEARED` | DESCENDANT | NONE |

Every observed row has `availability=OBSERVED`. The sole unobserved row is `NOT_OBSERVED/UNKNOWN/UNKNOWN/UNKNOWN`. Canonical compact JSON is bounded to 256 bytes; the largest admitted group currently encodes to 103 bytes. Extra keys, subclasses, non-string values, partial rows, wrong combinations and groups outside the matching failure context are rejected. No paths, numeric identities, ownership, permissions, mount records, logs, exception text or traces are exported in this group.

The original failing predicate constructs the same exact `ValueError('private-directory-identity')` before attempting optional observation. A private plain tuple carries a source-local issuer object and the three finite labels on that exact exception. Plain caller dictionaries, exception strings and exception subclasses cannot seed an observed row. This is provenance within authenticated source, not an isolation boundary against code already able to inspect or mutate that module's process memory. Public receipt validation checks the finite schema; authentication of the actual receipt remains the existing controller/export authority.

Identity components select the first unequal member in the original DEVICE, INODE, OWNER, permission-MODE order. Opened-FD owner, type and unsafe-permission checks retain their earlier separate reasons, so OWNER and TYPE are not admitted for `OPEN_FD_IDENTITY`. The path type check retains the original identity-first short circuit. A vanished descendant with zero links remains benign; a missing linked child and missing root retain their refusal. Child-open reappearance is recorded only after the original parent validation and second successful child stat. File metadata changes already permitted by the scanner remain permitted.

## Failure and acceptance behavior

Tick metadata latches on the first failed callback and later callbacks cannot replace it. Capsule acquisition is separately contained so acquisition faults retain the original operation/reason and yield UNKNOWN. Optional issuance, property/subclass reading, projection, control-flow and diagnostic-storage faults cannot replace the original refusal. The original scanner `finally` blocks still close child, lock and root-chain FDs. No observer fault grants success or skips disposal.

`failure_diagnostics` still requires the authenticated runtime's exact typed lifecycle receipt and FAIL/CANCELLED status. All optional acquisition and storage is best effort and contains `BaseException`; source control failures still propagate through their original error path. Legacy receipts with the original three/five diagnostic keys remain readable. A missing source capsule is UNKNOWN; an absent optional public field is legacy UNKNOWN. There is no retrospective path or branch inference.

The header, successful schema, resource limits, cleanup behavior, runtime codes and PASS acceptance gates retain their original bodies/constants. Of the 37 original top-level functions, 33 are AST-identical; the only modified functions are `disk_check`, `tick_observation`, `failure_diagnostics`, and `diagnostic_projection`. No function is removed. Four small projection/capsule helpers are added. The sole changed original constant is `DIAGNOSTIC_FIELDS`, which adds the optional key. This metadata never supplies compilation, publication or hardware acceptance.

## Validation and adoption

Nine added stage tests cover all six sites and all 19 tuples, mismatch ordering, benign vanished-child/metadata behavior, all-FD disposal, issuance/reader/storage faults including KeyboardInterrupt and SystemExit, caller/subclass UNKNOWN, finite/privacy rejection, first-failure retention, cancellation cleanup, legacy FAIL readability and refusal of false PASS. Against the old stage source, the same nine produce three failures and 29 subtest errors, principally absent observation/projection behavior; the benign metadata control passes both sources. Against the held source, all nine and all 87 stage tests pass with zero skips. The original 103 methods, including all 78 original test methods, are AST-identical. Original runtime tests use controlled harmless Python fixtures; fake native commands remain inert. Their results are source/fixture evidence, not native-package actors.

The coordinator-facing fresh-copy run independently repeats all 87 tests, zero skips, against the exact held 86-file copy. The actual updater9 terminal FAIL and recovery terminal PASS both project byte-for-byte equivalently under the new public schema, retaining absent leaf/UNKNOWN; recovery PASS does not attest compilation.

Independent source review reports PASS with no unresolved actionable finding: 11 separate causal-control methods and 84 guarded fixture methods pass, zero skips/errors/failures, with actor-launch tripwires untouched. Its guarded selection explicitly leaves three existing Python subprocess fixture methods NOT RUN: public-worker CLI, repeated runtime cancellation, and runtime receipt replacement. Those three run and pass in the separate full 87-test source suite. These counts overlap and are not added together. The review also reconstructs the original `disk_check` AST after removing only the selected refusal annotations and verifies the other 84 source rows against updater9.

The review namespace retains old/new logs, exact original source captures, source-preservation proof, a fresh 86-file copy, independent controls and receipts. Pre-existing unowned bytecode caches are excluded from the closed source copy and are not deleted.

The coordinator owns adoption and future runtime validation. The current workflow `.github/workflows/native-arm-updater.yml` at SHA256 `0b28670a11ac7cde76a7d248f2a1b13b15df477e581dfb7ecc9a6500cb61f799` still has the old five-key `diagnostic_fields` set in inline `terminal()` at lines 338–339. Proposed delta: add `directory_leaf` to that explicit set while retaining the updated stage projection equality and existing `public_summary` equality. Keep schema version 1, source/controller/ready bindings, legacy omission, and all strict PASS/cleanup checks. Rebind the workflow stage source literal through coordinator review. This lane makes neither edit and performs no 86-file registration, Git mutation, dispatch or actual trial.
