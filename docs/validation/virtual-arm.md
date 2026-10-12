# Native software integration execution

The connected V01–V09 batch validates development software in disposable native
ARM environments. It cannot accept either M2 Air, the Asahi target transaction,
16K runtime, platform recovery, performance, production trust or R1–R5 completion.

## First actual attempt: source preflight failure

- Source: `4128b22233d7c47da7e8aeb90e2ef87afcb97569`.
- [Native run 38198364798](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38198364798): **FAIL**.
- Reviewed integration lock:
  `d01fbf28be171f838e6bd92d6a89127875d5b1d701c0881f1c8f2826e2840670`.
- Signed input lock: `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41`;
  original recipe lock: `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.

The native ARM host executed all 211 bootstrap boundary tests successfully and
passed the runner probe. The full-source preflight then correctly refused the
checkout before input acquisition or package builds. Its local freeze included
two ignored host package archives under `packages/desktop/evidence/`; neither
was in the committed tree. Coordinator comparison found every other frozen
file's Git bytes and executable mode matched. This is a source-selection error,
not evidence of package installation or hardware failure.

The corrective task excludes generated package evidence directories from the
executable snapshot while preserving their historical records. Before rerunning,
the coordinator must compare every frozen file with the committed Git tree and
repeat preflight against a clean checkout. Hash checks remain mandatory.

Raw workflow logs and decoded bundles are retained locally under
`artifacts/ci/38198364798/`. Verified compressed bundle receipts:

| Bundle | SHA-256 | Bytes |
| --- | --- | --- |
| Native probe | `160dddcfeb3304230e03a0595e0d3683f2f93086e97d869916e98e96a371f525` | 1780 |
| Failed preflight evidence | `3cdd0541aee178dc05c61ff54c91bd36b059974957d52949fa0408c0d196bca4` | 56036 |

New original/fixture builds, signing, installed lifecycle, repository transactions,
onboarding, desktop checks and locked-userspace source suites are **NOT RUN in
this attempt**. The earlier successful four native package build pairs retain
their separate evidence in `native-arm.md`.

## Source-selection correction

Generated evidence directories beneath `packages/` are now excluded from the
executable snapshot; their files remain preserved. Two regressions check that
such evidence cannot alter a source freeze and that drift diagnostics identify
missing/extra/changed source paths without dumping content. The revised local
CI suite passes **213 tests**, with no skips.

Corrected integration lock:
`ac1fe1a05a8841da66824af496b81200376d32aa67320e6c48485b9373761408`.
It binds 100 source files and the same 125 deterministic fixture files. Local
preflight passes. The original signed input and recipe locks remain unchanged.
Clean committed-tree verification and a new actual native run are required;
this correction alone grants no executed integration acceptance.

## Second actual attempt: upstream input unavailable

- Source: `1c2d97bc9d2c82ac984b1297a808aba21d89745e`.
- [Native run 38199269315](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38199269315): **FAIL**.
- Corrected integration lock: `ac1fe1a05a8841da66824af496b81200376d32aa67320e6c48485b9373761408`.
- Original signed input and recipe locks remain the identities recorded above.

All 213 bootstrap boundary tests passed on the native ARM host. The runner probe
and full-source preflight passed. Before dispatch, the coordinator independently
checked every frozen file's bytes and executable mode against the committed Git
tree and repeated fixture/source preflight in a fresh detached checkout.

Input acquisition then failed with HTTP 404 before signature authentication,
image construction or package builds. The retained result only identifies the
HTTP error; it does not identify a filename. A subsequent bounded availability
audit identifies `perl-5.42.2-2-aarch64.pkg.tar.xz` and its detached signature as
the only two unavailable original URLs. The other 499 URLs return the expected
HTTP lengths; this HEAD result does not authenticate their bodies. All 501
retained local files still match their original pinned hashes. Current upstream
metadata advertises a newer Perl version; adopting it requires explicit
authentication, transaction review, a new coordinated snapshot and complete
native rerun. Original evidence must remain linked to its original snapshot.

Raw logs and independently decoded bundles are retained under
`artifacts/ci/38199269315/`:

| Bundle | SHA-256 | Bytes |
| --- | --- | --- |
| Native probe | `e5865947cd7f2d6738b564a4dc3850e87415f67f5fae176e3b9b5fd05edccda2` | 1781 |
| Failed acquisition evidence | `273df3994f55dfbab1235ca024425ab007d3142d437e07dd67a243878c2135e5` | 56043 |

Builds, signing, installed lifecycle, repository transactions, onboarding,
desktop checks and locked-userspace suites remain **NOT RUN in this attempt**.
The source-preflight correction has actual native evidence; the connected
integration batch still has no passing execution.

## Explicit builder snapshot refresh

The coordinator adopted authenticated Perl `5.42.3-1` after independently
rehashing the archive/signature, repeating exact-primary GPG verification in a
temporary public-only context, and comparing the complete signed `.PKGINFO`.
The migration proposal records 341 generic metadata entries and 1,582 satisfied
dependency relations with no missing relation, conflict or removal. All other
original rootfs, key and package bytes are retained. This is an explicit retained
transaction refresh, not a claim that every package came from today's sync DB.

- New signed input lock: `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`.
- Migration proposal: `d39c1b744ea54e282663e99932d58976336496426f7c3c6fd12b94526ff09a8f`.
- New integration lock: `b27a30d06aaa0870017adb1e37fe38c78384eea23234c6b8290d1b7536c785e2`.
- Original recipe lock remains `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.

The complete original input lock is preserved in `input-snapshots/` under its
original digest. Both earlier execution records remain bound to that old lock.
The acquisition adapter now atomically retains every input's outcome before GPG
and reports bounded filenames/HTTP statuses without response bodies or URL
credentials. The coordinator reran all **217 local CI tests**, with no skips.
All eight original package builds and the connected integration batch must run
against the new snapshot before any new execution acceptance.
