# Bounded nested namespace preflight: source controls

The deferred local implementation commit
`0530803aaa06f23d739ec985aa75b3cde9eeeb5c` was integrated on Main baseline
`a1c8e00fb3c8de8e94a8641b9e38ade6e2a71468`, with two concrete observation fixes.
This is source/control evidence. Docker, Engine, namespace operations, native
builds, a Root execution grant and hardware qualification were **NOT RUN**.

The preflight is useful as an explicitly admitted diagnostic before a future
build: it separately records the selected bubblewrap sandbox and subsequent
mapped-root operation, namespace identities/maps, loopback-only networking,
hidden/read-only fixture effects, bounded raw command output and retirement.
A completed diagnostic grants no package, namespace or runtime qualification.
The exact Engine28.0.4/Linux/arm64, immutable image and whole seccomp-profile
requirements remain mandatory. Builder defaults and policy bytes are unchanged.

The original 16 modeled controls passed, but a separate DATA reproduction
showed that a signalled child (`exit=-9`) with permission text was incorrectly
classified `DENIED`. Signalled, out-of-range and inconsistent success/exit
records now remain `UNKNOWN`; ordinary permission-denial observations retain
`DENIED` without inferring a kernel/seccomp/LSM cause.

The complete-controller model also accepted an empty binary-observation map.
The controller now requires all three Python/bubblewrap/unshare observations,
with finite positive lengths, whole-file digests and requested/resolved paths.
Missing or malformed records hold and still exercise owned cleanup. The same
complete model covers both useful observations and denials; its missing-binary
variant refuses. Binary/context qualification remains null. These checks do not
authenticate image binaries or establish their version/dependency closure.

Actual local commands:

```sh
python3 -I -B -Werror::ResourceWarning scripts/build/nested_userns_v1/test_probe.py -v
python3 -I -B -Werror::ResourceWarning scripts/build/nested_userns_v1/test_policy.py -v
```

Result: **18 probe + 17 unchanged policy controls passed**. Their audit fences
forbid actual process, socket, ctypes and lease operations. Coverage includes
namespace/map effects, exact constrained argv/loaded profile, denial versus
unknown, complete byte retention, helper-refusal retirement, foreign-container
refusal, missing binary records and normal modeled cleanup.

One command was added to the existing Native adapter DATA controls job, using
its existing Python3.12/3.14 matrix and isolated flags. That CI execution remains
separate from these local results. No new workflow or automatic preflight,
Docker/Engine query, namespace actor, package build, lease or dispatch was run.
The source-only selectors remain null and no native/M2/release credit is claimed.
