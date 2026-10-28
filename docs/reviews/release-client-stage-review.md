# Native release-client stage independent review

October 12, 2026. Source/local portable review only. Roadmap and package inventory
were read first. This reviewer owns only this document. No source/shared
manifest/CI/workflow/Git edit, Docker/native stage, network, host package/trust
operation or native client test execution occurred.

## Final disposition

**Ready for source integration into the controlled same-job native trial. Both
reproduced findings are closed at the final frozen adapter hash below.** This
review establishes local/source readiness only. Actual ARM execution of the
unchanged 37 tests, native process/container cleanup, production acceptance and
M2 behavior remain **NOT RUN**.

Final independent checks: **39 adapter tests PASS**, zero skips, 0.176 seconds.
`/tmp/client-stage-final-review.py` separately authenticated the frozen test bytes
and derived all method identifiers with AST parsing: exact **17 PortableTests +
20 GPGTests** matches the adapter's pinned set. Both the original invented37
receipt and a 37-unique receipt replacing one real GPG case now refuse with
`incomplete-client-suite`.

The independent complete mocked-controller check switched the default context
after its first inspection. All subsequent image/daemon/create/start/inspect/
remove and both name/ID absence queries retained `--host=` for the accepted local
socket, and private controller scratch was removed. Mocked PASS is a regression
result; it is not native execution evidence. Frozen client source/test hashes
remain unchanged. Final hashes were rechecked after these local checks.

## Resolved review findings

### Bind the inspected local Docker endpoint for every later operation

`stage.py:480-491` inspects the default context and requires a local Unix socket,
then invokes later Docker operations with only PATH/HOME/LC_ALL in the command
environment. It supplies neither `--host` nor `DOCKER_HOST`. A concurrent change
to the user's default context can therefore change the daemon used for image
inspection, create/start, stopped inspection or cleanup after the local-endpoint
check. The intended same-job local daemon is not pinned for those operations.

The passing full mocked controller regression exercises these unbound commands;
the missing binding is visible directly in the actual environment and argv
construction. No real context or daemon was changed. An additional independent
fixture invocation overlapped owner edits and was not accepted as a coherent
reproduction; final correction review must use the owner's next frozen hashes.

Required correction: bind all subsequent commands and cleanup queries to the
exact validated local endpoint using an explicit host argument or controlled
DOCKER_HOST. Add a regression changing the mock default context after the first
inspection and verify every later command remains bound to the accepted daemon.

Closed: the final `docker_command()` helper permits only the two accepted local
Unix sockets and constructs an explicit `--host=` prefix. Controller operations,
container creation and teardown all use that same validated endpoint; the final
receipt records it. Remote/unreviewed endpoints refuse.

### PASS receipts must identify the exact frozen 37 tests

`validate_receipt():386-418` requires 37 unique regex-matching identifiers and zero
skips/failures/errors, but does not require the identifiers in the frozen test
suite. A receipt with `PortableTests.test_case_0` through `test_case_36` passes;
none is an actual frozen method and there are zero GPGTests outcomes. The real
unchanged suite has **17 PortableTests and 20 GPGTests**.

This was independently reproduced with the current portable receipt fixture.
It demonstrates a retained receipt validation gap; it is not evidence that any
test ran or that a malicious native worker was observed. The worker's frozen
source still loads the real suite, but its consumer should enforce the stated
exact-test contract as well.

Required correction: pin or derive the exact expected identifiers from the
hash-authenticated frozen test source and require that exact set for PASS.
Keep incomplete/failed/aborted receipts conservative and sanitized. Add a
regression with 37 invented valid-looking identifiers and one replacing a real
GPG test with a PortableTests identity.

Closed: final PASS validation requires `set(ids) == TEST_IDS` in addition to exact
count, uniqueness, successful statuses and zero skip/error/failure counts. That
set was independently verified against checksum-pinned source as described
above. Failed/aborted sanitized receipt behavior is preserved.

## Verified source behavior and actual local checks

`python3 -B scripts/client/test_stage.py`: initial **34 PASS**, no skips, 0.173
seconds; final corrected freeze **39 PASS**, no skips, 0.176 seconds.
These are portable fixtures, mocked Docker replies and bounded own-Python/signal
helpers. They do not execute the native stage or establish the 37 client tests
on ARM. The previously independently reviewed frozen client source/test hashes
remain unchanged.

The six-input source snapshot binds the adapter, unchanged client/test pair,
release/test pair and fixed `source_suites.py` guard. Builder/bootstrap checks
require the exact refreshed `3c16c37d...` input lock, immutable image and canonical
341 inventory with package-lock SHA256
`89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`.
The worker also compares the image lock and actual `pacman -Q`. Old hosted
images, completed-job JSON receipts and mocked output are not native evidence.

The controller checks Linux ARM, effective nonroot identity, actual ARM daemon/
image and a new private output. Container creation requests a read-only root
and minimal read-only source snapshot, private PID/IPC namespaces, loopback-only
network, dropped capabilities, no-new-privileges, no devices/host sessions and
finite CPU/RAM/swap/PID/FD/tmpfs limits. Before fixture keys, PID1 worker identity,
actual guard observations and all protected proc mounts are required. Creation
and stopped inspection reject unexpected binds, isolation drift, OOM, nonzero
exit and runtime errors. Subsequent daemon operations now remain explicitly
bound to the validated local endpoint.

Inside, source/input hashes and tool availability are checked before the suite.
The environment is cleared; private tmpfs HOME/TMPDIR/GNUPGHOME/XDG paths and
isolated Python startup are used. The suite loads the unchanged 37-test module,
requires zero skips/errors/failures, and exports only bounded structured counts/
outcomes/pins. Raw test logs, attach bytes, traceback details and TEST key data
are discarded. No package installation, fetch, image build or publication action
exists in this stage.

TERM/INT handlers and spawn masking preserve tracked children. PID1 cleanup
terminates/reaps private namespace processes including daemonized TEST agents;
private tmpfs/controller scratch are removed. The controller removes the fresh
named container and requires successful daemon name/ID absence queries. Final
mode-0600 public receipts follow cleanup; cancellation during receipt sync
rewrites FAIL before return. Existing complete-controller cancellation/removal/
OOM/malformed-receipt and real signal-at-final-sync regressions passed. Actual
native cleanup remains unexecuted here.

## Source snapshot and disposition

| File | SHA256 |
| --- | --- |
| `scripts/client/stage.py` | `00d4f5fb14158c22da1575f0527e59791d60536bff4f365b6b60995942c6c73d` |
| `scripts/client/test_stage.py` | `796822f78c16a172c5202e719c4dad875f868c5e823f38e312fcc93c55933378` |
| `scripts/client/client.py` | `3025aa0e167c836e31c949e0915d4ee82a1007dc0fada598b4895240c82f5f97` |
| `scripts/client/test_client.py` | `a1a6a844ad4c0fd394a407529c5c7039f2a9e2bb43b63ee90a4e1e925701e144` |
| `scripts/ci/source_suites.py` | `4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100` |

Status: **source review complete; no open blocker within this bounded native
source-test stage; ready for controlled native integration at this freeze**.
Native 37-test execution, actual native process/container cleanup, production
client/key/transport/release acceptance, physical M2 behavior and R1–R5 full-port
completion remain **NOT RUN/unaccepted**. A later native PASS must bind the live
same-job image/bootstrap and actual unchanged 37 outcomes with zero skips/errors;
source/local review cannot supply it.
