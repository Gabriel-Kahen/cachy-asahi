# Owned GNU trial AppArmor policy (source proposal)

This CI owner gives only the conventional GNU lifecycle/interruption trial its own enforcing AppArmor profile. It tests a security-layer hypothesis from run38989923613: utility mount exited32 and legacy mount(flags15) returned EACCES under docker-default. That evidence does not identify the unique cause. A new native counterfactual is required; source controls give no build, installation, hardware, security or release credit.

The inherited policy is [Moby profiles](https://github.com/moby/profiles/tree/4b8214fc4971e06172938a1f1554ccff6647ee80), revision4b8214fc4971e06172938a1f1554ccff6647ee80. Unchanged template.go, apparmor.go, Apache-2.0 LICENSE and source/hash metadata are retained under vendor/. The finite renderer follows that generator's host ABI/include choices and actual dockerd signal peer. Its only rule delta replaces the one blanket `deny mount,` with exactly:

```
mount fstype=proc options=(ro,nosuid,nodev,noexec) proc -> /work/.gnu-readonly-proc-probe/,
mount fstype=proc options=(ro,nosuid,nodev,noexec) proc -> /work/pristine/root/proc/,
mount fstype=proc options=(ro,nosuid,nodev,noexec) proc -> /work/modified/root/proc/,
mount options=(bind) /dev/null -> /work/pristine/root/dev/null,
mount options=(bind) /dev/null -> /work/modified/root/dev/null,
```

Every other mount stays implicitly denied. All inherited umount, file/network/proc/sys restrictions remain. Same-profile signal and ptrace peers use the unique name. The trial keeps its original nine capabilities, default seccomp, NNP, namespace/mount topology and resource/time/output limits. Producer, outer observers and scrub retain docker-default; no producer or daemon configuration changes. Container.main checks the expected enforcing profile only when the CI trial passes its environment marker. Shared lifecycle common/case functions and installed16K guests are untouched.

Only ordinary native aarch64 GitHub Actions jobs may manage the profile. Existing root-owned system apparmor_parser is required. The current local default Unix Docker context, root-owned docker.pid, Docker service MainPID before/after, root dockerd comm/cmdline/root-owned executable and process starttime must join; namespace links are recorded when readable. The fixed bounded sudo observer reads only the kernel profile registry and that verified numeric dockerd PID's attr/current. The registry remains in memory; command files contain only its byte length/hash. No raw host profile list is exported. Missing or ambiguous identity fails closed.

A fresh caller-owned0700 registration binds source SHA, consumer token, original producer token, actual image and profile bytes. The original producer's completed `--rm` probe is verified absent by recorded CID/name; no live profile claim is made for that removed probe. The fresh image's labels/architecture/ID are checked again. Fresh outer observers provide actual docker-default readback. After unprivileged bounded parser compilation, `sudo -n -- apparmor_parser --add --skip-cache --jobs=1` atomically adds only the new name. Collision or uncertain outcome never triggers replace/remove. Kernel readback must show exactly this enforcing addition. Docker inspect and /proc/self/attr/current independently join the trial's expected name.

The outer owner lock protects execution and cleanup. Cleanup first retires all inner/outer actors and disposable data; then verifies both owned role-label inventories empty and every bounded remaining Docker container free of the custom profile. Only a confirmed owned load is removed, using its unchanged private profile file. Kernel readback must show exactly that removal with docker-default still enforcing. Uncertain load/removal or any remaining consumer retains the profile and producer and reports FAIL. A never-added registration can only confirm absence. Ordered producer cleanup runs last.

State/profile receipts are individually capped128KiB (profile64KiB); registry observation1MiB, daemon context512B, each observer10s, parser operations30s, all-container inventory32. Existing owner command cap256 and aggregate export768MiB remain. Public retention joins the actual registration/profile hashes, owner and ordered cleanup. Full raw host registry data is excluded.

Run `python3 -I -B scripts/ci/glibc-gnu-trial-apparmor/test_profile.py` for23 inert controls. They model parser/kernel/Docker responses; they do not invoke those actors. CI must perform the real parser compile, enforcing load, trial and ordered teardown. Local parser compilation, kernel operations and native counterfactual are NOT_RUN.

Primary operating documentation: [Docker per-container AppArmor profiles](https://docs.docker.com/engine/security/apparmor/), [Ubuntu parser options](https://manpages.ubuntu.com/manpages/noble/man8/apparmor_parser.8.html), [Ubuntu mount rule grammar](https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html). No global docker-default edit, privileged container, unconfined container profile, seccomp override, daemon restart or policy replacement is used.
