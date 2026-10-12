# Native client fixture correction

The native release-client stage in run `38218102399` recorded **FAIL**: 37 tests executed, 36 PASS, one failure, zero errors and zero skips. Its actual owner receipt is `artifacts/ci/38218102399/development-decoded/development-client-owner-public/owner-public/receipt.json`. The sole failure was `client_stage_tests.PortableTests.test_checkpoint_private_mode_symlink_and_malformed`; the native worker ran as UID 1001 on aarch64. Container and private-directory cleanup both passed. This historical result remains a failure; corrected native execution is **NOT RUN**.

The fixture assumed `Path.write_bytes` would create a checkpoint with unsafe mode 0644. The stage worker explicitly sets umask 077 before executing the suite, so that operation creates mode 0600. The implementation correctly accepts a caller-owned private 0600 checkpoint; the test therefore fails its expected refusal assertion. Independently reproduced the exact assertion failure locally as ordinary UID/EUID 1000 under umask 077: one failure, zero errors, `Error not raised` at the initial private-mode assertion. No implementation defect was found.

The narrow correction explicitly changes the fixture checkpoint to mode 0644 before asserting refusal. Its subsequent 0600 acceptance, malformed boolean-sequence refusal and symlink refusal remain intact. The original 37 test methods and selected test IDs are unchanged. No test is skipped or removed. Under the coordinator's separate authorization, `stage.py` changes only its `FROZEN` checksum for the corrected test file; stage implementation is unchanged.

| File | Corrected SHA-256 | Mode |
| --- | --- | --- |
| `scripts/client/test_client.py` | `11d475979806af12a514c9e860f614f22b6b4517078f97fceacc18c13563afd8` | 0644 |
| `scripts/client/stage.py` | `dc0c75969ed79548c3eb0ab1692f57ebffe7464d9192e591cdcf61aeaeb77154` | 0644 |

`scripts/client/client.py` remains unchanged at `3025aa0e167c836e31c949e0915d4ee82a1007dc0fada598b4895240c82f5f97`. Historical test and stage hashes were respectively `a1a6a844ad4c0fd394a407529c5c7039f2a9e2bb43b63ee90a4e1e925701e144` and `00d4f5fb14158c22da1575f0527e59791d60536bff4f365b6b60995942c6c73d`.

Independently loaded the corrected test source as `client_stage_tests` and compared its AST-derived method IDs to `stage.TEST_IDS`: exact set equality, 37 IDs. `/tmp/client-native-umask-check.py` ran the complete actual source suite as ordinary UID/EUID 1000 with real GPG fixtures in disposable TEST-only homes:

| Local environment | Executed | PASS | Skips | Failures | Errors | Time |
| --- | --- | --- | --- | --- | --- | --- |
| umask 077 | 37 | 37 | 0 | 0 | 0 | 1.336 s |
| umask 022 | 37 | 37 | 0 | 0 | 0 | 1.358 s |

After updating the stage's single checksum pin, all 39 stage adapter tests passed locally, zero skips, in 0.176 seconds. These are portable/local fixture checks, not another native stage execution. No Docker, installation, network, host default keyring or default trust mutation was performed. The coordinator owns dependent source-pin/lock refreshes, source-packet closure, Git and native dispatch; those refreshes must precede the corrected native trial. Only the two explicitly authorized source changes and this review document were edited by this reviewer.
