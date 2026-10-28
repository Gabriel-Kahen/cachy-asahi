# Corrected updater native trial 38251407975

Actual hosted ARM execution completed **FAIL** at 12:52:54 UTC on
2026-10-12. Checkout/source commit was
`90d8a242b7759631b6fe0c454bb473289ff5f815`, workflow
`9f6a6a9b0acb9acbfdab560f32b671ebf7d14726f01bbb8b91c9b5bb58636fd5`,
stage `3b548467b2ff775e1bb5a6422e2ce1678c0a9e7ef9c6283926bb6395f2b7646a`,
and unchanged ready map `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2`.
The actual committed-source/native-host controller freeze passed.

Materialization and all527 acquisitions pass. The actual builder bootstrap
reaches the exact354-package inventory, SHA256
`d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271`,
with image `sha256:c82d89b7c381c5247beb6026f69f2ee327c0458aa0bb823e753dac50253ae83f`.
The first worker is attempted, then reports ValueError at `worker-inspection`;
its container removal and absence checks pass. The native pair fails at
worker1. The outer receipt records `native-pair`, `process-failed`, returncode1,
226 seconds, and cancellation false. No package pair is accepted.

The stage label does not identify the exact underlying error. The held native
helper sets `worker-inspection` after the worker command returns, then inspects
the container and checks the worker returncode, inventory and output symlinks.
Therefore the label alone neither proves inspection failed nor establishes
whether Rust compilation was invoked. The private worker output/returncode and
original exception message are not exported. Source diagnosis remains open;
the failure is not promoted to successful compilation or a proven root cause.

The revised shared storage policy remains unlatched: baseline available bytes
115,212,570,624; final sample102,425,341,952; recorded peak available-byte loss
12,787,228,672 (about11.91GiB), below the16GiB cap, with the2GiB reserve intact.
These are bounded filesystem-wide observations, not owned Docker byte counts
or a measurement that a complete build will fit. No storage tick failure is
reported in this trial.

Scoped process, Docker, GPG and private cleanup all report **PASS**, with empty
cleanup reasons and private-data removal true. Recovery also reports PASS,
while explicitly retaining `NOT ATTESTED BY RECOVERY` for native compilation.
Daemon disposal is NOT ATTESTED. Recovery and resource removal do not accept the
failed native pair or establish release/hardware behavior.

Strict decoding recovers three bundles:

| Bundle | Bytes | SHA256 |
| --- | ---: | --- |
| guarded | 34002 | `36ba810dc3ac336d5701b682fde6a57b2ae06ed36ab7d909645dd9d84a116df5` |
| terminal-public | 1217 | `d75ce719ea257d652d097eb3770cb1f849d7632af1e598a262c80263dde6eab4` |
| recovery-terminal-public | 843 | `1a73fa4fb65ea6655516fe3c0a3ea621402004992253d7e256047c092a3eb140` |

All14 regular files pass independent revalidation using the exact reviewed
workflow consumer functions, authenticated fresh85-file helper snapshot,
closed selector/storage/cleanup schemas, projection metadata, export manifests
and source/controller/ready bindings. Actual records and
`root-public-verification.json` are retained in `artifacts/ci/38251407975/`.
The private controller and original private bundle are not recovered evidence;
their public hashes are cross-bound only. No signature-verification receipt,
installation, M2/16K execution, production publication or performance is accepted.
