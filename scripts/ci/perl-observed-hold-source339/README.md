# Frozen observed-HOLD Source339 hosted controls

This actor-free CI slice reconstructs the genuine unissued Source145, Source310
and Source339 entirely from this repository's authored Git history. It reads no
developer artifact directory, raw image, credential, private key or collection
lease. It grants no Root input, nonce, runtime/profile, VM, native/M2 or release
acceptance. The current actual diagnostic run is separate and is not represented
by passing source controls.

The integration preserves the original authored commits as actual ancestors:

| Role | Original revision |
| --- | --- |
| Guard and post-metadata diagnostics | a3350c985b1602f64e2d7ee4755b9f93bf39ba16 |
| QMP observations | 79f1c6e0fed8da4835722cdad62bdaf930a3201c |
| Source339 constructor | 9df629f6e0ca5fa769b41774caf41f7802a57f59 |
| Required Source310 constructor | aebd81802046e025d8bf1a62cf8904ce9236d61a |
| Required Source310 cleanup proposal | c3289ac12770251f24aa6a6ccdb8ef3cd606953c |
| Required metadata proposal, inherited through guard ancestry | 3f9b140e545d5a6fd5ac168d9d449167522e3102 |

dependencies.json pins every original family member's bytes, SHA256 and mode,
including Source65's existing executable test leaf. The runner verifies original
Git objects, their actual ancestry and the complete working family namespaces
before using them. No original family body/mode, source seal, manifest, prior CI
workflow or actual execution packet is modified.

The Source145 lifecycle constructor uses unchanged Main Source65 and the exact
frozen f51 family from published ancestor ead107b0f904d72e61b262f77444e46abd80cd7f.
The current portable qualification family is not substituted for that frozen
dependency. Then the original Source310 and Source339 constructors run unchanged.

| Physical Source | Leaves | Closed bytes | Whole Source lock SHA256 |
| --- | ---: | ---: | --- |
| 145 | 145 | 1546678 | 9dd3695b4892a740c3f1e9b878e41fe009e9fa66494be2db012275b71dd2f946 |
| 310 | 310 | 3239759 | 42d666e54ec0d45e97ed12f584425013d2a42cbba73a602deeb6372a15fd3637 |
| 339 | 339 | 3512147 | 7beb4deb63cbd03b34738b41463380b388e67c2a8015b81f7124866e80b17b13 |

Each physical lock/count/byte total, complete constructor inverse and unchanged
adapter acceptance must pass. Source339 retains its unchanged4MiB cap. All
actual authority/ref/nonce/profile fields stay NULL.

Run from a full-history checkout, with Bash, GNU coreutils/findutils and attr:

```
python3 -I -B -Werror::ResourceWarning scripts/ci/perl-observed-hold-source339/check.py
```

The65 original controls are:

- 18 Source310 constructor/inverse/corruption controls.
- 14 initialized-guard and post-metadata ordinary temporary-tree controls.
- 12 QMP observation controls using real local socketpairs and temporary DATA.
- 21 Source339 constructor/efficient310-inverse/corruption/default-authority controls.

The guard tests' single ACTUAL operand is rebound to the constructed genuine
Source310 in memory; no test or implementation file is patched. Existing CLI
tests receive their explicit temporary Source operands. The parent audit fence
rejects local artifact/raw/private/lease reads, external socket activity, runtime
admission and non-control process entry; constructor tests also retain their
original actor/process/network fences. Local socketpair trials test transport
primitives, not QEMU, guest behavior or real actor retirement.

The dedicated workflow uses Python3.12/3.14, pinned actions, contents:read,
credential-free full-history checkout, explicit family path filters and finite
process/job limits. The16MiB file ceiling matches the original user_snapshot
control; the1GiB address-space ceiling also covers Git through16MiB mapping
windows and a64MiB pack mapping limit. Hosted results remain pending until Root publishes this
integration and the actual jobs finish. Source145/310/339 code and actual Root
records remain frozen; a future cache policy successor requires its own review.
