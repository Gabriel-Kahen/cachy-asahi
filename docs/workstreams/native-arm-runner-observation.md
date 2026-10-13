# Private hosted ARM runner observation proposal

The new helper observes fixed tool bytes and host/path metadata before checkout
or project execution. It supplies data for Root to select real Git/Docker pins
and review hosted-runner constraints. This worker has not dispatched or observed
an Ubuntu runner: there are **no actual hosted Git, Docker or interpreter hashes
in this packet**. Test digests are explicitly synthetic. Root owns primary
workflow adoption, Git publication, dispatch and final bootstrap selection.

The proposal is in
[`artifacts/reviews/native-arm-runner-observation-proposal-20261013`](../../artifacts/reviews/native-arm-runner-observation-proposal-20261013/).
`observer.py` is the isolated standard-library helper. The proposed
body is 11,740 bytes, SHA256
`ad6d7908ef1dca36356cc5c8450f655c323021ec1ab89b4569708d4297989b4b`.
The proposed
`workflow-excerpt.yml` embeds its exact bytes as the first and sole inline step:

```
/usr/bin/python3 -I -B -S
```

The specimen selects `ubuntu-24.04-arm`, concurrency group `native-arm-build`
with cancellation disabled, and a five-minute scheduler cap. It has no checkout
action, project imports, caller-supplied path/command, shell input interpolation,
package installation or external upload action. Its literal trusted workflow
body and selected code/workflow SHA must be reviewed by Root before dispatch.
The specimen was compiled and authenticated as data, not executed.

## Exact observation

The helper records a monotonic entry immediately after importing `time`, before
the remaining imports. Inspection, serialization, descriptor retirement and
checked stdout writes share the original entry plus 60 seconds. This is an
observation bound, not the development issuer's clock, grant or allowance. A
trusted supplied earlier entry can only shorten it. An existing timer is
refused; INT/TERM/ALRM handlers are scoped and restored. Scheduler timeout and
Python deadline checks do not prove that every OS syscall finishes within the
interval.

It reads only the fixed executable paths `/usr/bin/git` and `/usr/bin/docker`,
requiring regular files, UID 0, mode 0755, one link, positive size and a 128-MiB
cap per file. It hashes them incrementally with remaining-time checks. Named
and opened identity must match before reading; after reading, descriptor and
named identities must still match, including size and modification/change
timestamps. Byte count must match the original size. Tool ancestry uses held
no-follow directory descriptors and requires root ownership with no group or
other write permission. Nothing invokes either executable.

Interpreter observation starts at `/usr/bin/python3`. It accepts a direct
regular binary or at most eight root-owned, single-link symlinks. Each link is
held using Linux `O_PATH | O_NOFOLLOW` and read through that descriptor; targets
are restricted to `/usr/bin/python3` or a Python 3 basename with one or two
numeric version components. Escapes, cycles and a ninth link are refused. The
final regular target uses the same root/mode/link/stability checks with a
64-MiB byte cap. The observation describes the on-disk trusted path; it does
not attest the running interpreter's entire dependency chain or memory image.

Architecture comes from `os.uname().machine`, and page size from
`os.sysconf('SC_PAGE_SIZE')`. The report includes the runner UID and an explicit
ARM-name flag; metadata capture alone does not qualify a host for production or
prove M2 page-size compatibility.

The helper opens only `/run` directory ancestry and performs two no-follow
stats of `/run/docker.sock`. It requires a root-owned socket and stable identity,
and records its mode/GID. It never opens or connects to the socket. The report
does not establish Docker daemon isolation, successful CLI/socket use, trusted
images or the private-runner assumptions of the development execution grant.

Original `GITHUB_WORKSPACE` and `RUNNER_TEMP` are inspected through canonical
absolute, no-follow directory traversal, with at most 4,096 path characters and
64 components. They must be disjoint. Their ancestor ownership/modes are
reported along with three explicit flags: whether the fresh-sibling parent has
the runner UID, whether that parent excludes group/other writes, and whether
original/temp ownership matches the runner. A false flag remains useful
observation data and gives Root a constraint to resolve. No sibling is created,
no workspace is moved or deleted, and no project file is read.

All opened FDs are registered while controls are deferred and retained until
inspection completes. Final verification checks held/named identities again.
Retirement attempts every owned descriptor once, using device/inode custody;
mutable content changes may invalidate observation without preventing closure
of the still-owned inode. Foreign/reused identity and ambiguous close faults
refuse healthy completion. The first failure survives later cleanup faults.
Directory content timestamps/link counts are excluded from directory identity
because unrelated entries may legitimately change.

## Report and Root handoff

The single JSON report is capped at 64 KiB. Environment-derived fields are
limited to run ID, run attempt, source SHA, workflow SHA, the fixed canonical
repository, optional `ImageOS`/`ImageVersion`, and the two required path inputs.
Run/attempt and SHA values use closed patterns; source/workflow SHA must match.
Optional image strings are bounded. There is no environment dump, credential
field, hostname or raw exception text. Expected section failures use fixed
refusal codes or numeric errno; fatal failures exit without a traceback.
Partial stdout writes require progress and deadline checks. A write failure
can leave an incomplete report, which Root must reject.

`OBSERVED` means the byte/metadata comparison completed; it is not an approval
or private-runner guarantee. A fully inspected report may still contain false
workspace/ARM suitability flags. A refused section makes the helper exit
nonzero after emitting the bounded partial observation when possible. A fatal
deadline/identity/cleanup failure cannot establish healthy completion. Complete
JSON may already have been emitted before a late write or handler-restoration
failure. Root must require step success and job provenance as well as the
complete report before
selecting pins; a status string alone grants no Source authority.

The proposed hosted ARM label differs from the prior unexecuted private-runner
label specimens. Root must review the actual observed ownership, Docker socket,
interpreter and fresh-workspace constraints. A checksum cannot turn a hosted
runner into a private runner or guarantee that a later job has the same image.
Actual bootstrap preparation must check the selected hashes again; drift
requires a new observation and Root selection rather than silent pin renewal.

The test-author and independent peer lanes use finite synthetic OS fixtures;
they never inspect this machine's fixed binaries/socket or invoke Git, Docker,
subprocesses, network, project Source, real issuer/grant or package mutation.
Counts and exact source pins are retained in the parent receipt. Any fixture
diagnostics remain distinguished from actual hosted evidence. Real dispatch
and the host report are still pending. ARM builds, supported-system delivery,
Asahi hardware and measured performance retain the current roadmap gates.
