# FDK producer failure audits and bounded diagnostics

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

The first failed trial's packet SHA256
`2e190f75594fe5550770aa567b7729637853a99d6c2ce3b137248ed3954cbe32` and 90-test
checkpoint are historical. The coordinator subsequently accepted the six
correction inputs below, refroze packet
`76e475f63332c66de123481b77c904254c8f0c988bdf73b0787c732d3ae70449` at
`e3c450cc342e9f5e1f24f195c342d8d9c67e7c72`, and accepted the finite 70-code
workflow correction `6eecc3235b91dfeb326f497f6fe0984ce7525db860739b2c0083b0f8271e37b1`.
The next trial used commit `ee9797812cb454e413b5900d8262f1015fe863f1`.
This producer audit edits neither packet nor workflow. The accepted 39-file
adapter, 22-file template and original helper are unchanged. Lifecycle
implementation is paused; no lifecycle files were created.

Historical first-correction validation checkpoint: **104 wrapper tests PASS, no skips**, 16.656 seconds;
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


## Second actual trial and narrower probe diagnostics

The coordinator's actual run
[38230760444](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38230760444)
on commit `ee9797812cb454e413b5900d8262f1015fe863f1` and corrected packet
`76e475f63332c66de123481b77c904254c8f0c988bdf73b0787c732d3ae70449` ended FAIL.
Its retained [public status](../../artifacts/ci/38230760444/decoded/public/status.json)
reports `producer-base-probe-runner-failed`, all 501 acquisitions passed, FDK
`NOT RUN`, no cancellation and verified owned-image absence. The bounded public
bundle was encoded successfully. A raised delegated call can represent broker
policy, HTTP framing, local CLI/socket/daemon pinning, image/container inspection,
owned cleanup or a subprocess failure. The code does not establish a timeout,
GPG failure or a particular predicate.

The source-ordered helper initially probes Docker architecture, version, lscpu
and context before acquisition. After authentication/bootstrap it also captures
the image inspection and exact builder-inventory probe. A fixture executed all
four initial call shapes and both post-bootstrap call shapes through the actual
`ProducerCommands`, unchanged `native.run`, and owned fake CLI plus bounded Unix
HTTP daemon. Calls, output and owned cleanup passed. The fake socket was in an
owned temporary directory, so this exercised delegated call contracts rather
than waiving the helper's real deployment endpoint guard. No simple argument or
stream mismatch was reproduced. The exact hosted predicate remains unknown;
this checkpoint introduces diagnostics, not a claimed causal fix or blind rerun.

For `base-probe` only, the durable private diagnostic now permits exactly
`{phase, outcome, call, refusal_code}`. Other phases and historical receipts
retain the exact two-field shape. The fixed call identities are `docker-info`,
`docker-version`, `docker-context`, `image-inspect`, `inventory-probe` and
`unclassified`; recognized identities require the literal allowed argument shape
and current immutable image. Before-call persistence records the identity without
an argument list, filename, socket value, image hash or response body.

Refusals accept only 108 explicit predicate labels taken from the already reviewed
broker/runtime sources, or eight fixed exception categories: `os-error`,
`unicode-error`, `key-error`, `type-error`, `value-error`, `subprocess-error`,
`unknown-error`, `cancelled`. Exact known ValueError arguments are matched against
that closed set; exception messages are never converted into public text.
`none` is required for not-run/started/pass states. Unknown labels, arbitrary
strings, missing/extra keys, wrong types and detailed probe fields attached to
another phase fail sanitization. Cancellation keeps failure acceptance intact.

Public status still has exactly 14 fields. It exposes only a closed error code:
`producer-base-probe-CALL-REFUSAL`, or before/during/after probe-call failure when
only that boundary was recorded. The finite source set contains 802 codes:
the existing 70 and 732 probe-detail codes. The existing capture, source, cleanup,
GPG service/stream, original result and package acceptance boundaries are unchanged.
The accepted workflow and packet were not edited. The coordinator must review a
new packet and separately update the publisher's exact code allowlist before a
future diagnostic trial; the held 70-code workflow will reject the new codes.
The prior trial remains actual FAIL, and no new native/compiler/FDK/installation
or hardware result is asserted here.


Current next-diagnostic checkpoint: **110 wrapper tests PASS, no skips**,
17.010 seconds. Independent scoped review passed 66 producer/evidence/controller
fixtures. The owned fake CLI/Unix-daemon control also passed all exact initial
probe and post-bootstrap delegated call forms after the diagnostic change
(1 test, 0.910 seconds). Refusal checks cover all 108 established policy labels,
fixed exception categories, private/appended/newline/nonstring arguments,
Unicode-before-ValueError precedence, before-call persistence, cancellation,
missing/extra/malformed detail fields and unchanged two-field states elsewhere.
Original helper, accepted adapter, BaseBroker, packet and workflow remain held.
Five owned source/test entries changed at this checkpoint; `job.py` already
supports recovery through the updated fixed sanitizer and was not edited.

| Current changed input | SHA256 |
| --- | --- |
| `producer.py` | `e01ea63606b044e71cfb159d156c3a92fb6f31004f23923557bee8fa745b65a1` |
| `evidence.py` | `03f803aede7367c22199468961a0463b2fe688f637271fd2760692967796a75c` |
| `test_producer.py` | `b546eb3bb040923a0c18f7feec5f6c020f22d371cbe9d94bec96001ed0f5dcaa` |
| `test_job.py` | `d4f7af33449048427d4fe2801910459dcdf746926ece7812dcba18d7c9ecb640` |
| `test_evidence.py` | `00a99d62faaca4541485b2e2cafa768c0afb4cbeefb2d71e609d932aad77bd3a` |
