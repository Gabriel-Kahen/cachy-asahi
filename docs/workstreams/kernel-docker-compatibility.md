# Kernel Docker API and start compatibility

The kernel image client now uses fixed API 1.48 for commit and tag inspection.
The hosted job requires the actual local daemon range to contain 1.48; malformed
ranges, maximum versions below 1.48 and minimum versions above 1.48 are refused.
No automatic API negotiation occurs.

The retained ARM runner for run 38237127237 reports Docker 28.0.4, maximum API 1.48
and minimum 1.24. That recorded range satisfies this version check. Its memory
and free-disk metrics were not retained, so this is not a prediction that the
job's 15 GiB total memory, 14 GiB available memory or 30 GiB free-disk guards
will pass. Native Docker behavior and both kernel compilations remain NOT RUN.

Pinned [Moby v28.0.4 constants](https://github.com/moby/moby/blob/v28.0.4/api/common.go)
declare API 1.48. The
[commit handler](https://github.com/moby/moby/blob/v28.0.4/api/server/router/container/container_routes.go)
accepts the existing container/pause/repo/tag query and config body and returns
HTTP 201 with an image ID. Its configuration type contains the twelve held
projected fields. The existing configuration helper, sentinel handling,
effective-config verification, exact base-layer prefix plus one added layer,
size limit and ARM64/Linux identity checks remain in place. Source support for
this contract does not establish a successful daemon commit.

The broker now starts the journaled container with
`docker start --attach <exact-ID>`. The removed `--sig-proxy=false` option is
unsupported by start. Official Docker CLI
[v28.0.4 start](https://github.com/docker/cli/blob/v28.0.4/cli/command/container/start.go)
and [v29.0.0 start](https://github.com/docker/cli/blob/v29.0.0/cli/command/container/start.go)
sources register no such flag. For non-TTY attachment they forward signals,
wait for the container result and report its exit status. The separately
registered attach command has its own sig-proxy option.

Cancellation can therefore forward a supervisor signal to the owned container.
The runtime still terminates and reaps its owned CLI process group, and the
broker still verifies and removes the exact journaled container under its
cleanup budget. No signal policy or timeout was otherwise changed. A real local
CLI parser check and owned process fixtures do not test daemon-side signal
forwarding or cleanup.

The correction preserves nonce/container/image ownership, journal writes before
uncertain mutations, recovered immutable IDs, unknown-commit FAIL, private-tag
and image-ID absence checks, accepted base configuration, resource enforcement,
source/licensing/payload checks, five-hour stage budget and both 7,200-second
build budgets. Native Docker, native kernel compilation, installation, kernel
execution and exact-M2 validation remain NOT RUN; performance is NOT MEASURED.

Local test evidence includes real owned Unix sockets capturing exact versioned
GET and POST requests, the query/config body, all twelve fields, empty-entrypoint
sentinel behavior and strict HTTP 201/Id acceptance. Existing negative fixtures
retain unknown-POST and recovered-ID/removal failure coverage. Tests also bind
the job guard to the kernel request version and reject unavailable or malformed
daemon ranges. Final counts, exact source hashes, pinned upstream source hashes
and independent review are recorded in the ignored handoff artifacts.

The previous 24-file kernel lock and job packet pins are deliberately held. They do
not authenticate the changed implementation. The coordinator must independently
review and rebind those source maps transitively, prove committed Git bytes and
modes, and satisfy the unchanged prerequisites before a separate finite native
job. This worker has not generated locks, mutated Git, dispatched workflows,
installed host packages or changed the FDK broker owned by the tools workstream.
