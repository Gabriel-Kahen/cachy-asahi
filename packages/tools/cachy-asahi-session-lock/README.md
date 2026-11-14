# Explicit session locking

`cachy-asahi-session-lock` is an original MIT development candidate for a
validated Wayland desktop with Swaylock and systemd/logind. It supplies two
explicit foreground commands:

```sh
cachy-asahi-session-lock lock
cachy-asahi-session-lock suspend
```

`lock` starts a black Swaylock screen and waits for normal authentication/unlock.
`suspend` first waits for Swaylock's readiness notification, then requests
`systemctl --no-ask-password --check-inhibitors=yes suspend`. Authorization and
inhibitor failures remain failures; the helper does not retry with elevated
privileges. The helper waits for the locker to exit, including after a failed
suspend request. Diagnostics go to stderr.

The readiness timeout defaults to ten seconds; `--ready-timeout 1` through `60`
changes it. No readiness, invalid readiness, an early locker exit or cancellation
prevents the helper from starting a suspend client. A successful client exit
means the request was queued, not that the machine slept or resumed.

The helper requires the current non-root user's ordinary private0700
`XDG_RUNTIME_DIR` and a user-owned Wayland socket named by `WAYLAND_DISPLAY`
inside it. Absolute display paths and inherited `WAYLAND_SOCKET` are not
supported. It uses fixed `/usr/bin` executables and a minimal child environment.
The installed shebang selects Python isolated mode; direct Python invocations
must also supply `-I` and otherwise fail before session inspection.
Swaylock receives `--config /dev/null --color 000000`; existing Swaylock configs,
images and daemonization settings are neither loaded nor edited. The base's
Swaylock PAM/authentication configuration is still used and must work.

One helper per display holds a0600 runtime guard file until its locker exits.
An empty leftover file is harmless and reused; it is deliberately not unlinked
while another process might have it open. Different existing lock programs are
not detected by process name or killed. The compositor must reject a second
session lock; that rejection must not produce a readiness notification, and
therefore must not cause a suspend request through this helper.

Ctrl+C, SIGTERM or SIGHUP cancel a pending request but **never kill the locker**.
A timed-out locker may already own the compositor lock, so the helper reports
the error immediately and continues waiting for normal unlock/locker exit.
Its readiness pipe remains open so a late acknowledgement cannot terminate
Swaylock with SIGPIPE. A hung locker can consequently keep the helper running;
the timeout bounds permission to request sleep, not the locker lifetime.
Use the base's tested TTY/session recovery if authentication is unavailable.
The helper never sends Swaylock's unlock signal.

If the suspend client hangs, the helper stops its own client group after ten
seconds and preserves the separate locker. Cancellation or locker exit during
the request also stops that client. An interrupted request may already have
reached logind; its outcome is reported as unknown and is never retried.
Readiness is checked before requesting sleep, but unlocking and an asynchronous
sleep request are not atomic. This helper does not guarantee lock retention
against user unlock, locker failure or compositor failure after readiness.

After installing and manually validating both commands on the supported base,
an optional change to **your separate Hyprland Lua configuration** is:

```lua
-- Replace your existing SUPER+L binding; do not add a duplicate binding.
hl.bind("SUPER + L", hl.dsp.exec_cmd("cachy-asahi-session-lock lock"))
hl.bind("SUPER + SHIFT + L", hl.dsp.exec_cmd("cachy-asahi-session-lock suspend"))
```

Review custom bindings first. No package template, default session launcher or
user configuration is changed automatically. This is an explicit command, not
an automatic idle/lid lock or a logind `PrepareForSleep` inhibitor integration.
Do not use it as a `swayidle before-sleep` hook: foreground completion waits for
unlock, and a failed hook would not by itself prevent an independent sleep.
Existing base lock, idle and lid policies must retain their established owner.

Installation owns only `/usr/bin/cachy-asahi-session-lock` and its documentation
and license files. There are no hooks, services, PAM/logind changes, setuid
files or configuration copies. Upgrades replace these package files. Before
removal, restore previous user bindings; removal preserves all user configs
and does not stop a running helper or locker. Runtime guard files disappear
with the base's normal runtime-directory lifecycle.

The ready-fd, config and existing-lock behavior was audited against
[Swaylock v1.8.6 source](https://github.com/swaywm/swaylock/blob/44b82de635c3bc66b0093abd1cf8cc1c8b1b9c0f/main.c)
and [its manual](https://github.com/swaywm/swaylock/blob/44b82de635c3bc66b0093abd1cf8cc1c8b1b9c0f/swaylock.1.scd)
at commit `44b82de635c3bc66b0093abd1cf8cc1c8b1b9c0f`.
Suspend request, authorization and inhibitor options follow the
[systemctl manual](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
Its `--check-inhibitors=` option requires systemd248 or newer, reflected in the
recipe dependency.
This package contains no copied upstream implementation. Local fixture tests
exercise subprocess ordering, failure and cancellation without starting a real
locker or touching logind. Clean native ARM builds, actual Swaylock/PAM behavior,
installed base integration, locked suspend/resume and both M2 Air sizes remain
**NOT RUN**. No release or hardware acceptance is implied.
