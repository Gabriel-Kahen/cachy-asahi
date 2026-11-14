# Real ordinary-UID NetworkManager authorization observations

This distinct x86 fixture uses the actual `1.58.1-2.1` candidates, real
Polkit 128-1 and ordinary UID/GID 1000 on an owned private SYSTEM bus.
It preserves the earlier 61-command no-daemon and 16-command root/private-bus
results. It does not qualify native ARM/16K, M2, connectivity, normal user
sessions, authentication agents or release acceptance.

```sh
python scripts/integration/networkmanager_user_auth/run.py \
  --allow-owned-user-auth \
  --archives work/networkmanager-source-candidate-20261114/archives \
  --output work/networkmanager-user-auth-20261114/new-run
```

Use an ordinary host user, Python 3.11+ and Docker; the output must not exist.
The existing exact archive intake, pinned local prerequisite image, image-only
installer, private-bus environment/config and owned-process helper are reused
without modifying them. No image/dependency acquisition fallback or host
installation exists. The image-only unsigned local installation is hash-bound,
dependency-checked and has hooks/scriptlets contained, as documented by the
previous private-bus fixture; it is not new signature/trust acceptance.

The runtime is read-only, network-none and capability-free, with
no-new-privileges, 2 CPUs, 4 GiB, 256 PIDs, standard Docker runtime mounts and
bounded private tmpfs state only. There are no caller mounts, host bus/devices,
service activation directories, CAP/SYS_ADMIN/seccomp fallback or host interface
operations. Fixed role deadlines, per-command bounds and owned retirement
bounds limit execution; no new general process supervisor is introduced.

The root fixture starts its owned bus and daemon and seeds two explicitly
non-autoconnecting, IPv4/IPv6-disabled profiles for absent `cachy-test0`:

- A root-created system profile available to all users.
- A **root-seeded user-restricted profile**, with `user:builder` permissions.
  This is not credited as an ordinary-user-created profile.

Real `polkitd` runs directly as its installed UID/GID 102 through Docker exec,
with no SETUID/SETGID capability grant. A fixed UID102 wrapper holds its actual
child through normal shutdown using the existing owned-process helper.
Ordinary clients run directly as UID/GID 1000, account `builder`, group 1000;
they are not members of `wheel` or `empower`. Each client compares real D-Bus
`UnixUserID`/`ProcessID` against its own identity. NM is independently observed
as UID 0 and the authority as UID 102; the authority PID matches the held
polkitd child. All clients receive the exact owned Unix socket through the
existing clean-environment helper, overriding hostile caller bus addresses.

The private bus uses the **actual installed system.conf policy elements** and
exact installed NM/Polkit D-Bus transport fragments. Service-directory activation
is omitted. Original Polkit action XML and JS rules remain unchanged and are
hashed before/after every operation. The first diagnostic run lacked the
standard requested-reply transport permission, causing a rejected Polkit method
return; the adapter now derives that transport policy from the real installed
file. No custom Polkit allow rule, fake session/logind/authentication agent,
wheel bypass or authorization-default change was introduced.

Actual observed policy results without interaction:

| Action | Real Polkit result |
| --- | --- |
| `settings.modify.own` | Not authorized; challenge required; `auth_self_keep` |
| `settings.modify.system` | Not authorized; challenge required; `auth_admin_keep` |

Actual ordinary UID operations:

| Operation | Result |
| --- | --- |
| Modify root-created system profile | Denied: insufficient privileges |
| Modify root-seeded user-restricted profile | Denied: insufficient privileges |
| Create user-restricted profile as ordinary user | Denied: insufficient privileges |
| Read root-seeded user-restricted profile | Allowed; restriction and autoconnect=false returned |

Every denied request preserves exact config-file bytes, modes, UID/GID, complete
package inventory and policy hashes. Read-only access also leaves them unchanged.
No successful user write is claimed: **positive own-user write authorization stays
HOLD without a real logind/session/authentication-agent path**. Real Polkit logs
retain the missing login monitor and unavailable private systemd service.
The fixture never creates an active session or authenticates a password.

Root cleanup removes only the owned profiles. NM, bus and real Polkit retire
zero/reaped/`EMPTY_TWICE` without escalation; the owned socket, container/image
tag and private tmpfs state are removed. This root cleanup receives no ordinary
user authorization credit. CLI exit zero means these real observations and
cleanup checks passed; inspect `ordinary_write_scope`, which remains HOLD.

```sh
python -m unittest discover -s scripts/integration/networkmanager_user_auth -p test_user_auth.py -v
```

Two focused controls verify host-execution refusal before helper loading.
`validation.json` records actual source/report pins and observations. Raw logs
remain private; no native or production authorization conclusion follows from
this isolated fixture. No candidate recipe or earlier integration source changed.
