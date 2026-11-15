# Retained archive reader: Python 3.12 and 3.14

PR449's Python 3.12 static check failed because `tarfile.open(stream=True)`
requires Python 3.13 or newer. The reader now opens a narrowly scoped
`CurrentMemberTarFile` in forward-only `r|` mode without that keyword.
Its `next()` clears the unused TarInfo member cache after every call, including
constructor first-member parsing. Iteration calls `next()` directly.
`extractfile()` accepts only the exact current regular TarInfo; filename lookup,
previous members and link extraction are refused. Package links remain catalog
DATA and are never followed on the host.

The actual installed stdlibs were inspected: Python 3.12 calls public
`TarInfo.fromtarfile/frombuf`, while 3.14 also uses private
`_fromtarfile/_frombuf` helpers with `dircheck`. Both entry points now reach
the same physical-header counter, deadline and end-marker check. The 3.12
fallback uses its native public buffer parser; 3.14 retains the extension
readers' `dircheck` argument. Existing PAX/GNU extension-body caps, sparse
refusals, namespace checks, per-object limits, decoded-byte accounting and
process limits remain in place.

Actual synthetic validation on 2026-11-15:

| Runtime | Executable | Result |
| --- | --- | --- |
| CPython 3.12.13 | `/home/gabe/.local/share/uv/python/cpython-3.12.13-linux-x86_64-gnu/bin/python3.12` | 21 controls PASS, 0.571s |
| CPython 3.14.7 | `/usr/bin/python3.14` | 21 controls PASS, 0.586s |

Both used `-I -B -W error::ResourceWarning` with
`scripts/port/arm16k-first-login-ui-inputs/retained_archive_audit/test_audit.py`.
The additional regression runs the real audit reader over 2048 extended-name
regular files in each of PAX and GNU formats, plus PKGINFO/BUILDINFO. Each case
observes 2050 members and 4098 physical headers, verifies the final file's hash,
and observes zero cached TarInfo entries after every `next()`. All previous 20
controls also pass, including caps, traversal, metadata, signer-status DATA,
ELF geometry and baseline-symbol holds.

Only source, synthetic controls and this compatibility note changed. No retained
archives, acquisition, gpgv, rootfs payloads or actors were run. Historical
UI145/seat44/UI172 reports, their source pins, budgets and acceptance boundaries
remain unchanged; this is compatibility verification of the new reader source.
