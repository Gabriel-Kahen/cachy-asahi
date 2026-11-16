# Explicit and idle session locking 0.1.1

This is a separate opt-in **same-name 0.1.1-1 successor**. Choose this recipe or
the existing 0.1.0 recipe. Its old evidence does not qualify this successor.
No default binding, startup, service, base idle/lid policy or configuration is
changed by installing this package.

## Optional automatic idle locking

M6 desktop coverage requires automatic locking in addition to explicit bindings.
After validating manual locking/PAM and ensuring the base session has no other
idle-lock owner, run as the ordinary user in the affected session:

```sh
cachy-asahi-session-lock idle --idle-seconds 300
```

Install `swayidle>=1.8.0` for this optional mode. The timeout is required and must
be an integer from 30 to 86400 seconds; there is no implicit timeout policy.
The helper starts fixed `/usr/bin/swayidle -C /dev/null -w timeout SECONDS`
with one fixed shell command, `/usr/bin/printf '\n'`. Only that newline reaches
a private pipe. No caller-supplied shell command, user swayidle config, resume,
sleep, unlock, display-power or idlehint hook is accepted. The minimal session
environment and socket checks are the same as for manual locking. Swayidle
provides compositor idle/inhibitor behavior; physical inactivity, inhibitor
handling and desktop protocol compatibility still require actual session tests.

On each fresh idle notification, Python invokes the existing ready-confirmed
manual lock path. The watcher never starts or owns a locker. One idle watcher
per display has a separate guard, so manual lock/suspend remain usable while
watching. If a manual helper already holds the lock guard, that event is skipped;
a held guard is not evidence that the desktop is securely locked. Invalid/unsafe
guards fail. Events accumulated while a locker is active are discarded after
normal unlock, preventing immediate locking from an old event. A later fresh
idle cycle can lock again. Readiness failure or a failed locker stops automatic
locking with status 1 after preserving normal authentication. Errors are visible
on stderr; they are not retried silently.

Ctrl+C, SIGTERM or SIGHUP stop watching with status 1. If a locker is active,
the helper first waits for normal authentication/exit; it never kills or unlocks
that locker. The separate watcher group receives SIGTERM and, after a one-second
wait, SIGKILL if needed, then is reaped. Its group contains only swayidle and the
fixed printf callback. A watcher exit, pipe closure or malformed/excessive event
stream also fails, without killing an active locker. Kernel-uninterruptible I/O
can still prevent prompt child retirement. A startup diagnostic only confirms
process creation; there is no claim of idle protocol readiness or automatic
lock coverage before a real event. Keep this foreground command supervised by
the existing session owner if explicitly integrating it after validation.

Activation is explicit and temporary. To roll back, stop the foreground watcher
and authenticate normally if already locked. Remove any launch line you chose
to add yourself, then return to the previous package recipe/version if needed.
No configuration migration, automatic startup or removal-time process stop is
performed. Removal while a watcher runs does not stop that process; stop it
first. The base's working automatic/lid/sleep policy must retain one owner.
This mode does not lock before an independent sleep request and does not delay
sleep. The supported manual suspend command remains separate.

The audited primary interface is
[swayidle 1.8.0 `f554943bec003c2f70306123bd8db18465fcc3e4`](https://github.com/swaywm/swayidle/tree/f554943bec003c2f70306123bd8db18465fcc3e4),
including its [manual](https://github.com/swaywm/swayidle/blob/f554943bec003c2f70306123bd8db18465fcc3e4/swayidle.1.scd)
and [implementation](https://github.com/swaywm/swayidle/blob/f554943bec003c2f70306123bd8db18465fcc3e4/main.c).
The source uses a shell for timeout commands. `-C /dev/null` disables ambient
config input, `-w` waits only for our short printf callback, and sleep listeners
are registered only when sleep/resume hooks are configured. No upstream source
is bundled. Source/reference hashes and parent identity are recorded in
`source-provenance.json`.

```sh
python -I -B -Werror::ResourceWarning test_session_lock.py
python -I -B -Werror::ResourceWarning test_idle.py
python -I -B -Werror::ResourceWarning test_package.py
```

The retained manual tests and new real disposable watcher/locker subprocess
fixtures check repeated cycles, callback/config isolation, invalid notification
refusal, duplicate/manual guard behavior, cancellation and independent locker
survival, including an actual SIGTERM and bounded watcher cleanup. They do not
start swayidle, Swaylock, logind, services or a compositor. The fixed printf
callback is checked in a real local shell. Package tests stage private files and
exercise only safe CLI help/refusals. Native ARM, installed ALPM lifecycle,
actual swayidle/compositor/PAM behavior, idle inhibitors, 16K, both M2 Air sizes,
performance and release qualification remain **NOT RUN** for 0.1.1.

## Manual commands retained from 0.1.0

`cachy-asahi-session-lock` is an original MIT development candidate for a
validated Wayland desktop with Swaylock and systemd/logind. It supplies explicit
foreground commands:

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
user configuration is changed automatically. The manual commands and optional
idle mode do not provide lid locking or a logind `PrepareForSleep` inhibitor integration.
Do not use it as a `swayidle before-sleep` hook: foreground completion waits for
unlock, and a failed hook would not by itself prevent an independent sleep.
Existing base lock, idle and lid policies must retain their established owner.

Installation owns only `/usr/bin/cachy-asahi-session-lock`, its documentation
and `source-provenance.json`, and license files. There are no hooks, services,
PAM/logind changes, setuid files or configuration copies. Upgrades replace these package files. Before
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
