# FDK producer failure audit and diagnostic correction

The coordinator's actual public ARM trial
[38223759349](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38223759349)
ended FAIL before FDK acceptance on source commit
`b939ebff3faaa8f3ffa68d5faf2d77e30b87de5b`. Checkout, the committed 128-file
packet and host prerequisites passed; all 501 acquisitions passed. The retained
[public job receipt](../../artifacts/ci/38223759349/decoded/public/status.json)
reports producer FAIL, FDK `NOT RUN`, no cancellation and verified owned-image
absence. The [producer summary](../../artifacts/ci/38223759349/decoded/public/producer/producer-summary.json)
is the fixed invalid/incomplete failure shape. No original native build PASS or
codec build result is inferred.

Missing **public** `producer/signatures.json` does not locate a GPG failure.
The unchanged helper persists private signatures during authentication, but the
public exporter copies signature evidence only when the complete producer has
recorded native build PASS. Failure during authentication, signed metadata,
bootstrap, original builds/comparisons or evidence projection can all leave the
public signature record absent. The hosted failure's exact cause remains unknown.

A separate real local check used the unchanged helper's import/verification
shapes through `ProducerCommands` and the actual bounded job runner, with
GPG 2.4.9, a fresh owned home, clean environment and `--no-autostart`. It verified
the frozen 3098-byte public-key file and the exact rootfs/signature size/hash pins,
then passed import (exit 0), first rootfs signature verification (exit 0), and the
full pinned primary-fingerprint check. Private home and logs were removed; no
raw diagnostic was published. This checks the local delegate path. Ubuntu's
GPG 2.4.4, complete 249-payload authentication and actual ARM compilation were
not tested by that check. No service guard was removed and no host package,
agent command or Docker build was run. The coordinator retained separate local
[import](../../artifacts/reviews/fdk-noagent-public-import-20261012.json) and
[delegate-import](../../artifacts/reviews/fdk-real-delegate-gpg-import-20261012.json)
observations; they likewise do not establish the hosted cause.

The source audit reproduced one concrete compatibility gap. The original helper
sends import child bytes directly to a log file descriptor; the adapter instead
strictly decoded those bytes as UTF-8. A successful mocked import containing
`0xff` in its diagnostic therefore raised only in the adapter. The corrected
import path writes exact bytes through a real log's `.buffer`, preserving the
original behavior. A synthetic text-only fixture uses `backslashreplace`.
Verification still returns separate strictly decoded stdout/status and stderr,
matching the helper's `text=True` call. This is a reproduced source correction,
not an identified cause of trial 38223759349.

The producer now durably records an exact private `{phase, outcome}` before and
after recognized operations. It wraps the unchanged acquisition function with
the same arguments and return behavior, and records bootstrap entry without
altering the original helper file. Phases are preflight, base/host probe,
acquisition, GPG import/verify, bootstrap, original build and original comparison.
Outcomes are not-run, started, pass, command-failed, delegate-refused,
runner-failed and cancelled. `pass` describes the delegated call; a successful
GPG command is not substituted for the helper's full signature authentication.
`runner-failed` identifies a raised delegated bounded call, not a proven tool
exit or a specific underlying failure.

The parent re-reads the last durable worker diagnostic even if the outer worker
call raises, then accepts only the exact fixed fields and enum values. Public
status keeps its existing 14 fields and projects only a finite `error_code`:
`producer-before-PHASE-failed`, `producer-during-PHASE-failed`,
`producer-after-PHASE-failed`, or `producer-PHASE-OUTCOME` for the four failure
outcomes. Before/during/after distinguish a recorded not-run/started/pass state;
these codes do not fabricate a more precise cause. Unknown/malformed diagnostics
fall back to `fdk-native-job-failed`. Source, FDK and unrelated failures retain
that generic code; an accepted job retains `error_code: null`. Raw messages,
commands, filenames, logs, responses, environment and binaries never enter this
projection. Original native result bytes, acceptance conditions, cleanup,
cancellation and public producer schemas remain intact.

The failed trial's historical packet SHA256 remains
`2e190f75594fe5550770aa567b7729637853a99d6c2ce3b137248ed3954cbe32`; its old
90-test checkpoint is historical. **The modified six source/test files require
a newly reviewed packet and committed Git binding before execution.** The
coordinator owns that refresh. The held workflow SHA256
`c7b90461edfbc079768a189d0930c0249b1d430174590b9dc3342413796afbbf` also needs a
separately reviewed finite error-code allowlist update before it can publish the
new diagnostic codes. This task edits neither the packet nor workflow. The
accepted 39-file adapter, 22-file template and original helper are unchanged.
Lifecycle implementation is paused; no lifecycle files were created.

Validation checkpoint: **104 wrapper tests PASS, no skips**, 16.656 seconds;
independent scoped review and 60 producer/evidence/controller tests passed.
Four additional original/delegate byte-logging comparisons pass after the fix.
The real local import/first-rootfs-signature check also passes after correction.
These checks exercise source/mock behavior and local public cryptography, not a
successful hosted producer, native FDK build or target lifecycle. The 39 adapter
byte/mode pins remain unchanged; precisely six owned source/test entries differ
from the historical 128-file packet.

| Modified input | SHA256 |
| --- | --- |
| `producer.py` | `4cf0c56e7aade2289aefb21936928f89f97dd6d79e2a31551ee80021be67c41f` |
| `job.py` | `1b6c95b1cf8c428671fa2c4636def9e41a494bc600b4a24f7d9de455dee64ef4` |
| `evidence.py` | `8a70c467fc54862f8863fc0d24bdef18138ddffeb38ee80a84c8f0aba6fe7e3d` |
| `test_producer.py` | `0104f899289498361dea62433351f08f34d1744a0b909f9c3e9aaf7dcce696d3` |
| `test_job.py` | `107ae574dbbc5f4337b01680260a417101ba7cad4498add8dca8cef5c1bf0ec3` |
| `test_evidence.py` | `76862744a19422e5137a883de7558e4b91a4faae296facddf021c5e3eaca085f` |
