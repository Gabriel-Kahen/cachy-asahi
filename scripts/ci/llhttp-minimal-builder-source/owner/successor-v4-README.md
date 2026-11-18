# Filesystem observation successor v4

Source implementation/proposal only. The retained actual87 result remains HOLD;
its native package pair remains NOT RUN. These DATA controls do not run a native
actor, Root role, systemd unit, cgroup mutation, network operation, publication,
Original GET, or private material access. Signing, installation, M2 hardware,
performance and release acceptance remain open.

The actual87 owner log identifies phase `readonly-filesystem`, exception
`ValueError`, message length 64 and the nontruncated SHA256
`fb486df27f93098ca0869bbefefdfc5eebd0260b10abfcc4fb1b8c1dfb3286bb`.
That digest matches the literal guard
`actual owner writable filesystem restricted to quota work domain`. The exact
guard tests the aggregate of `os.access('/tmp', W_OK)`,
`os.access('/var/tmp', W_OK)` and `os.access(root, W_OK)` with short circuiting.
This establishes which aggregate guard refused; it does not identify which
path was writable or the underlying mount mismatch.

The retained command012 requested `ProtectSystem=strict`,
`ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup` and only the quota work directory in
`ReadWritePaths`. The actual Source directory is a separate runner checkout.
The public result did not retain mountinfo, statvfs flags or the three individual
access results. No path, mount flag or scope waiver can be inferred from that
missing observation. This proposal adds bounded observations for a future run;
it does not claim to have fixed filesystem confinement.

The owner exited 2. Actual cleanup independently verified the original owner
identity, its exited PIDFD and two empty cgroup observations, then recorded
`STOPPED_EMPTY_FAILED_OWNER`, `payload_success=false` and `unit_reset=false`.
Daemon retirement and exact owned-storage removal succeeded. The cleanup report
has no errors and `owned_storage_absent=true`; successful retirement does not
make the payload or native pair successful. All original evidence remains
unchanged.

The helper observes the three fixed guard labels, the filesystem root and the
quota work label with their covering mount classes. It parses at most 1 MiB,
1024 rows and 16384 bytes per mountinfo line, resolves
covering mounts by longest path-component prefix, and leaves an ambiguous
stacked covering mount explicitly unknown. It emits only fixed labels, allowlisted filesystem
classes, mount flag booleans, bounded counts and access/statvfs outcomes. Mount
sources, arbitrary mount paths, environment and exception text are never
published. Unknown, malformed, truncated or inaccessible observations remain
unknown rather than supplying a guessed mount class; unavailable read-write
counts remain null rather than zero. The read-write
mount summary is diagnostic and does not authorize any writable scope.

The original aggregate guard and service launch properties remain unchanged.
Diagnostic observations cannot approve the guard, expand `ReadWritePaths` or
turn a failed observation into payload success. The source constructor requires
the exact retained 76-file public parent and reconstructs all 76 original bodies,
modes, Source map and Git tree through its complete inverse. Only the payload,
the explicit diagnostic policy, Source namespace metadata bound and program/source
bookkeeping change. The finite Source-file cap changes from less than 80 to less
than 96 to fit the 85-file successor and retained complete before-bodies.
Runtime, kernel resource,
deadline, quota, retirement, ordinary-success and final HOLD/PASS
predicates remain unchanged. All actual selectors remain NULL.

Eight actor-fenced controls exercise bounded parser resolution and ambiguity,
read/parse refusal, individual fixed-path observations and errors, privacy and
output bounds, complete source inverse and preserved service scope, the
unchanged refusing guard, and the retained public failure/cleanup distinction.
Model observations are labeled DATA and provide no native confinement credit.
Missing retained external fixtures produce an explicit SKIP.
All eight controls pass on Python 3.12.13 and 3.14.7 with the retained public
Source76 and actual87 inputs. With the external parent absent, six controls pass and the
two dependent controls explicitly skip. No mount or service actor ran.

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/llhttp-minimal-builder-source/successor_v4/test_data.py
python3 -I -B scripts/ci/llhttp-minimal-builder-source/successor_v4/prepare.py \
  --parent /absolute/exact-Source76 --output /absolute/fresh-successor
```
