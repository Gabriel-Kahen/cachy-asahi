# Separately admitted namespace preflight

Source implementation only: **Engine, Docker, namespace operations and native
execution NOT RUN**. Actual image, binary qualification, context qualification
and namespace qualification remain unset. The existing17 policy controls and
builder defaults are unchanged. This addition creates no workflow or authority.

`probe.run(image, profile, profile_sha256, output, runtime_root, allow=False)`
provides a finite preflight before a future admitted enrollment0.4 build. It
requires the exact reviewed profile described in README.md, a fresh observation
of Engine28.0.4/Linux/arm64, an immutable local image ID and ordinary caller UID.
An image must already contain `/usr/bin/python3`, `/usr/bin/bwrap` and
`/usr/bin/unshare`. Their actual resolved paths and whole-file hashes are
recorded when executed; their versions and dependencies need separate Root
review. No image is supplied or claimed qualified here. Local Engine29.8 is
outside this profile; a client version does not establish a daemon version.

After Root separately admits the resource use and execution context, the entry
point is:

```sh
python3 -I -B scripts/build/nested_userns_v1/probe.py \
  --allow-preflight \
  --image sha256:ROOT_SELECTED_IMMUTABLE_IMAGE_ID \
  --profile /absolute/reviewed/nested-seccomp.json \
  --profile-sha256 471a0bfd86586464226ac69cedf7104ab573d37c3be83771a3fb5f33e95f1e29 \
  --runtime-root /absolute/reviewed/arm16k_systemd_tcg_guest/frozen \
  --output /absolute/fresh/private/preflight-output
```

`--allow-preflight` is an explicit execution switch, not a resource grant or
lease. Root retains responsibility for admission and coordination with the
canonical build lane. No package build follows automatically.

The two commands use the selected V4 check's bubblewrap operations:
`--unshare-net`, read-only root, proc/dev/tmpfs, writable private work bind,
read-only fixture bind and hidden-path tmpfs. One runs a fixed diagnostic; the
other captures the immediate bwrap context and execs exactly
`unshare --user --map-root-user --` into that diagnostic. No package, repository
payload or artifact code is executed. The checks require distinct user/mount/net
namespace links, unchanged PID namespace, loopback-only networking, an empty
hidden fixture and an EROFS refusal to write an otherwise owner-writable fixture.
The second command additionally requires UID/GID0 with exact one-ID maps and
only its user namespace changed relative to the immediate bwrap context.

One fresh container has one CPU,512MiB memory and swap,64PIDs and a64MiB exec
tmpfs. It runs with an ordinary fixed UID/GID, cap-drop ALL, NNP, no network,
read-only root and only two read-only trusted-code mounts. Inspection rejoins
the full loaded seccomp JSON, identity, labels, mounts and resource settings.
Implicit image volumes are refused. Each operation has20seconds and16KiB per
stdout/stderr. The controller has90seconds for execution plus35seconds for
owned cleanup, at most24 commands and2MiB total retained output. CLI captures
have file-size limits and use the existing owned-process supervisor, including
natural reap and EMPTY_TWICE checks. Per-command virtual-address-space limit is
2GiB; the container's512MiB limit separately bounds its processes.

Existing whole-pinned helpers are reused unchanged:

| Helper | SHA256 |
| --- | --- |
| `owned_process.py` | `83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f` |
| `reference_controller.py` | `e7c8935f342d4b36bb6f8f24c0b48c3b8aa04be9807f62c3f8141aeaf26819fc` |

Ownership recovery uses the private CID, exact fresh name, image, labels and
confinement before cleanup. Cancellation and uncertain retirement retain HOLD.
Bounded owned-container removal may be forced after the normal wait; foreign or
ambiguous identity is never removed. Final absence must be observed. A failed
cleanup is HOLD even when both diagnostic commands returned useful data.

Private `preflight.json` retains command pins, full bounded operation bytes as
base64, retirement, actual observations and cleanup; numbered private files
retain controller stdout/stderr. A complete diagnostic reports
`OBSERVATIONS_RETAINED_NOT_QUALIFICATION`. Per-operation outcomes are
`OBSERVED_REQUIRED_EFFECTS`, `DENIED` for a naturally reaped request with an
explicit permission-denial diagnostic, or `UNKNOWN` for other failures,
timeouts, malformed output or uncertain retirement. None infers which
kernel/seccomp/LSM layer caused a denial. Exit0 requires both observed effects
and verified cleanup; all other outcomes exit2 or refuse before entry. Even
exit0 leaves qualification fields null and does not establish the Docker
build-RUN context, a full package check, native package acceptance or M2 support.

Portable verification uses only synthetic DATA and mocked command boundaries;
an audit fence refuses process, socket, ctypes and lease calls:

```sh
python3 -I -B -Werror::ResourceWarning scripts/build/nested_userns_v1/test_probe.py -v
```

The 18 controls cover exact argv and loaded-profile joins, namespace/map effects,
denied versus unknown results, complete output, owned-child retirement on helper
refusal, foreign-container refusal and complete modeled success/denial cleanup.
They do not observe namespace support.

Integration corrections require ordinary consistent exit statuses (0–255): a
signalled child, contradictory success flag or uncertain retirement stays
UNKNOWN even if stderr contains permission-denial text. DENIED does not identify
the kernel, seccomp or LSM cause.

Before diagnostic completion, the controller requires all three binary
observations, each with its exact requested path, canonical resolved absolute
path, bounded positive file length and whole-file SHA-256. Missing/malformed
observations refuse while retaining normal owned cleanup. Duplicate JSON keys
and invented qualification fields also refuse. These are complete observation
records, not binary authentication, supported versions or runtime closure.
The actual qualification fields remain null.

The existing actor-fenced Native adapter DATA controls job now runs this probe
suite alongside the unchanged 17 policy controls, under the same isolated
Python3.12/3.14 flags. No additional workflow or automatic preflight is enabled.
