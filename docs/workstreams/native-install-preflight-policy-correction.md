# Native installer P0 inspected policy correction

October 12, 2026. **SOURCE/DATA/MODELS ONLY.** This corrects NIP-POLICY1 in the new owner bridge. Actual native P0, ABI16.0.1, fixture26, Docker containers, namespace/mount/package actors, real-four installation, both M2 Air sizes and M8 remain **NOT RUN**. The original hold `f9f638d3c726ec1491fcc1be69c53f9225daa1f8f5fe019d6e6c55368f707b89`, its 72 controls, original BLOCKED peer receipt `f9409612f54d7a8dd8f64827608fd15ee01f10f0e0a1d346957d04971019a028` and earlier receiver87 remain historical and unchanged. Their captured original source remains available; live bridge/test files now contain this separately held correction.

Only `container_binding` changes in production. Before `start`, the daemon's inspected HostConfig must provide these complete facts:

| Field | Accepted value and exact type |
| --- | --- |
| PidMode | builtin string, empty |
| IpcMode | builtin string, `private` |
| UTSMode | builtin string, empty |
| UsernsMode | builtin string, empty |
| AutoRemove | builtin bool, false |
| RestartPolicy | builtin dict with exactly builtin-string keys Name and MaximumRetryCount; builtin-string Name `no`; builtin-int MaximumRetryCount zero |

HostConfig must be a builtin dict with builtin-string keys. Config must be a builtin dict. All six policy facts are required. No absent/null, truthiness, integer-as-boolean, subclass equality, unknown restart key, shared/host mode, retry or automatic removal supplies authority. Diagnostics contain only finite field names and type names or `missing`. Modes remain inspected facts; the correction adds no CLI flags or invented private-PID spelling. The receiver command constructor, strict twelve Config projection, live source/owner custody, first-failure behavior, immutable CID cleanup, original60-second cutoff, preflight-only phase and source/profile pins remain unchanged.

## Primary-source basis and actual uncertainty

The retained hash-checked Docker CLI source is Apache-2.0, tag v28.0.4, commit `b8034c0ed70494a90c133461d145cd072d920d7c`. `cli/command/container/opts.go` (SHA256 `5152629b6638c0a307da1c24a9758b443d8c66b1eee35d38ec77ed6265d29109`) declares empty PID/IPC/UTS/userns selectors, false auto-removal and disabled restart default; `opts/parse.go` (SHA256 `7a42eb6c02c6fa4dc4999c19727061ebbc195e2ef9ee5273216a6d8777c1fc34`) constructs the retry count with integer zero when no count is given. These bytes and the prior pin records are captured under this correction, not executed. [Pinned CLI options](https://github.com/docker/cli/blob/b8034c0ed70494a90c133461d145cd072d920d7c/cli/command/container/opts.go), [pinned restart parser](https://github.com/docker/cli/blob/b8034c0ed70494a90c133461d145cd072d920d7c/opts/parse.go).

Pinned Moby source at `6430e49a55babd9b8f4d08e70ecb2b68900770fe` distinguishes private, shareable, joined and host IPC, empty/default PID/UTS/userns selectors, and disabled restart with integer retry count. Its daemon resolves an empty incoming IPC selector using daemon configuration before runtime setup. The current Docker documentation confirms that unspecified IPC can resolve to private or shareable. Requiring inspected private IPC deliberately refuses a shareable, empty, missing or otherwise unknown actual result. The default userns selector preserves daemon policy; it does not prove remapping is enabled. [Pinned Moby type definitions](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/api/types/container/hostconfig.go), [pinned daemon IPC resolution](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/daemon_unix.go), [Docker namespace documentation](https://docs.docker.com/reference/cli/docker/container/run/#ipc-settings---ipc).

These primary sources justify the closed values; they do not identify the actual future native daemon/CLI version or prove namespace behavior. Primary official web documentation was read for this correction; the tests and source replays perform no network or external actor calls. There was no fresh Docker inspection. A differing actual default remains a finite refusal and requires a separately reviewed correction. No daemon setting, host policy, privilege, isolation profile or runtime retry is changed.

## Narrow scope and remaining limits

The existing exact three observed bind mounts continue to protect source/input/output destination, source paths, read-only flags and propagation; additional observed mounts or changed aliases refuse. This correction does not independently allowlist every HostConfig field: Binds/VolumesFrom aliases, custom runtime/init, sysctls, supplemental groups, device-cgroup rules, log-driver defaults, storage options, masked/readonly-path defaults and other daemon-selected metadata are not given a new validation predicate here. This is a remaining inspection-scope limit, not evidence that a generated command requests them or that a real daemon bypass occurred. The captured CLI constructs the restrictive command; actual daemon/runtime behavior still needs its independent native gate. No universal namespace/process/resource isolation claim follows from these pure inspectors.

The five peer counterexamples now refuse, plus the analogous userns host opt-out. Pipeline models show that every policy substitution refuses before the modeled native start while still removing the already source-owned CID and checking absence. Original owner/source/phase/cleanup/time controls remain. Missing facts, bad types, joined/shared modes, legacy empty restart names, retry counts, extra keys and foreign equality types are also tested. The valid complete default fixture remains accepted.

Root still owns new packet/source registration, final accepted issuer-pin rebind, callback/module-graph wiring, publication, enclosing failure cleanup and actual P0 admission. The bridge may run at the beginning of its actual native consumer callback, independently of SVG/Zsh/repository acceptance. This correction issues no live grant. A blocked original review is not rewritten; the same peer must review this exact corrected checkpoint before Root's composition or native dispatch.
