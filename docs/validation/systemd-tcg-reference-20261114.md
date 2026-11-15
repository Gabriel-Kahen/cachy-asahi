# Full-system x86 reference login

Root completed the first QEMU TCG reference boot on November 15 UTC (November
14 local time). The unchanged official Arch userspace and signed stock kernel
booted with systemd as PID 1. The private `builder` account authenticated through
the normal serial PAM login and received an active logind TTY session.

| Observed field | Result |
| --- | --- |
| User and UID | `builder`, `1000` |
| Session | `1`, class `user`, type `tty`, service `login` |
| Active / remote | `yes` / `no` |
| D-Bus and logind | active |
| Logout | normal PAM logout observed |
| Emulator retirement | QMP quit and owned-process retirement passed |
| Container removal | exact ownership and absence verified |

The host actor used rootless Docker, zero capabilities, no-new-privileges, a
read-only root, no network/devices/KVM and two explicitly owned input/output
binds. QEMU used q35 with TCG, two virtual CPUs and 1536 MiB guest RAM. The
container limit was two CPUs, 3 GiB and 256 PIDs. The immutable raw disk used a
fresh bounded qcow2 overlay. No OS bootloader or host service was installed.

The 1561-byte private Root report has SHA256
`d831499e4a46be86680809fe09dd46641809adf1beca68dc8a98c0702671e09d`.
Its status is `PASS_X86_REFERENCE_SERIAL_PAM_SESSION_ONLY`. The exact invocation,
prepared inputs and runtime image are recorded by the
[reference controller](../../scripts/integration/systemd_tcg_guest/README.md).
Private credentials and the consumed first-boot marker remain outside Git.

This proves the reference login substrate. Guest shutdown, NetworkManager
authorization, ARM/16K, Asahi/M2, performance and supported release acceptance
remain separate. The emulator was quit after logout; no clean guest shutdown
result is claimed.
