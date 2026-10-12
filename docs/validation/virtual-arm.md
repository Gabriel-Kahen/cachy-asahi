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
