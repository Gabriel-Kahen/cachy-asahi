# Real process authentication-agent/PAM gate

This separate bounded x86 actor tests whether a real ordinary-UID process can
advance the previous user-write HOLD using standard Polkit mechanisms. Earlier
61-command, 16-command and ordinary-user sources/results remain unchanged.
**Actual result remains HOLD:** the agent registers, but neither a direct
interactive authorization request nor NetworkManager's own-write request invokes
an authentication challenge. No successful PAM authentication or user write is
claimed, and this path ends at that genuine observed limitation.

```sh
python scripts/integration/networkmanager_auth_agent/run.py \
  --allow-owned-auth-agent \
  --archives work/networkmanager-source-candidate-20261114/archives \
  --output work/networkmanager-auth-agent-20261114/new-run
```

Ordinary host user, Python 3.11+, Docker, exact retained image and four actual
candidate archives are required. Output must not exist. The unchanged archive
intake, image-only installer, real UID102 Polkit wrapper, environment isolation,
D-Bus transport/authorization policy and existing owned-process retirement helpers
are reused. The actor remains **cap-drop ALL, no-new-privileges=1, read-only root,
network-none**, 2 CPUs/4 GiB/256 PIDs, owned tmpfs only, without caller mounts or
host bus/devices. No SYS_ADMIN, privilege, seccomp or host-session fallback exists.
Per-role/process budgets, fixed handshakes and whole-fixture deadlines bound it.

`probe.py` first ran real `/usr/bin/pkttyagent` as UID1000/account builder against
its real PID and kernel start time. A real private controlling PTY was established
using the existing onboarding terminal pattern; the standard `--notify-fd`
registration protocol completed while the agent remained alive. Polkit's real
log independently records that process-subject registration. No synthetic
logind/active session, custom allow rule or wheel/empower membership was added.

The installed Polkit128 helper is **0755, no file capabilities**, using the
stock `polkit-agent-helper.socket` and `polkit-agent-helper@.service` mechanism,
not a setuid executable. Accordingly no SETUID/SETGID grant or no-new-privileges
relaxation was justified or added. The new actor provides the same accepted
socket stdin/stdout arrangement with real `systemd-socket-activate --accept
--inetd`, the real helper `--socket-activated`, owned socket and stock socket
permissions. Original PAM service/system-auth and Polkit rules remain unchanged.
The helper listener was ready; **no helper connection or PAM verification occurred**.

A random private TEST builder credential is generated only in host memory and
handed through stdin, never arguments/environment. Only that account's password
field is provisioned in a root-owned 0600 shadow file in private `/run` tmpfs;
this new image's `/etc/shadow` points there. Other image account fields and groups
are retained. No host account/PAM/trust file changes, credential baked into the
image, policy edit or password publication occurs. An ordinary-owned 0600
credential handoff file is read then unlinked; terminal echo is disabled and
any captured credential bytes are redacted. Private shadow/tmpfs/container/image
tag were removed. The actual credential was **never sent to a prompt**.

The same real UID1000 process held the registered agent and made a direct
`CheckAuthorization` for its exact `unix-process` PID/start-time/UID with
`ALLOW_USER_INTERACTION=1`, under ordinary `settings.modify.own` policy. Polkit
returned `(authorized=false, challenge=true, auth_self_keep)`. NetworkManager's
real own-profile `AddConnection2` returned
`org.freedesktop.NetworkManager.Settings.PermissionDenied: Insufficient privileges`.
No profile was created; configuration bytes, complete package inventory and policy
hashes stayed unchanged. System/foreign actions after authenticated own-write
were **not reached**, rather than reported as successful authorization coverage.

The source contains that explicitly gated positive path, but only registration,
real authority/daemon denial, unchanged state and cleanup are credited here.
Missing login-monitor/systemd service observations are retained. The cause of
non-delivery to the registered agent is not independently established; do not
turn this into a claim that a real logged-in system fails. No further speculative
retry, capability grant, fake session, authentication rule or candidate patch was
used. PAM credential verification, authorized ordinary writes, normal sessions,
ARM/16K, Asahi/M2, real connectivity, suspend and release acceptance remain held.

Normal root/Polkit/bus cleanup passed. Agent and listener were stopped with normal
SIGTERM (their default exit is -15), reaped with `EMPTY_TWICE`, no timeout or
supervisor escalation. That expected controlled stop is recorded explicitly,
not mislabeled as exit-zero or authenticated success.

```sh
python -m unittest discover -s scripts/integration/networkmanager_auth_agent -p test_auth_agent.py -v
```

Two focused host-refusal controls cover credential and actor entry points.
`validation.json` preserves exact actual input/source/report pins and scope.
The command returns zero for a completed bounded observation even when its
reported authentication status is HOLD; it never represents user-write acceptance.
