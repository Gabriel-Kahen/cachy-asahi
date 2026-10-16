# Optional Fish completion notifications

This is a Linux adaptation of MIT-licensed [Done at the pinned revision](https://github.com/franciscolourenco/done/tree/b86292a52a2b8f646ef8d25daa3cc01ccab60b62),
with independent opt-in and background-watch integration. The project version
0.1.0 is not an upstream release tag. Fish >=4.9.3, libnotify's notify-send,
coreutils timeout, Linux /proc/uptime and an existing session bus address are
required. Host x86_64 Fish 4.9.3 was tested; held574's Fish is 4.9.3-1. No native
ARM or physical M2 execution is established by arch=any text metadata.

To enable, add this guarded, user-owned block to your existing config.fish:

```fish
if test -r /usr/share/cachy-asahi/fish-done/opt-in.fish
    source /usr/share/cachy-asahi/fish-done/opt-in.fish
end
```

Use this path only. done.upstream.fish is an unchanged source record, not the
supported activation path. Nothing is installed in Fish's automatic conf.d or
function directories. The wrapper is silent in noninteractive shells, without
a session bus address, or without notify-send/timeout. It does not connect to
the bus at source time, probe focus/desktop/windows, start a notification server,
select an audio output, download dependencies or modify configuration/history.
The presence of a bus variable does not prove a working notification service.

Once explicitly enabled, foreground commands lasting **more than 5000 ms**
request a notification, including when the terminal stays focused. Success uses
normal urgency; failure/cancellation uses critical urgency and the actual exit
status. This focus-independent policy is deliberate and differs from upstream.
Each named notify-send process is bounded to 2 seconds plus a 1-second kill grace; calls
run synchronously, so a failed or slow service can delay the prompt by that
bound. Transport errors are suppressed and do not change the command's status.
No automatic retries or sound fallback are performed.

Background jobs are explicitly selected in the current interactive Fish:

```fish
sleep 10 &
caa_done_watch $last_pid
```

Only a live single-process child job can be watched. Pipelines/multiple-process
jobs, another shell's children, invalid PIDs and jobs already reaped are refused.
The notification duration starts at watch registration; it is not the job's
whole runtime. Register immediately after launching a job. Repeated registration
keeps one handler and the original start time. A process-exit event reports the
actual child's status, including signal termination (e.g. 143 for SIGTERM).
A disowned job does not deliver the Fish exit event; its inert handler remains
until caa_done_disable or shell exit. The watcher never kills the watched job. The transport watchdog only terminates
a timed-out notification command.
Foreground `wait` is a separate command and may also qualify for notification.

Optional user settings, placed before or after the source block:

```fish
set -g caa_done_min_duration 5000   # decimal milliseconds, 0 through 999999999
set -g caa_done_exclude '^git (?!push|pull|fetch)'  # optional regex list
set -g caa_done_show_command 1     # opt-in command text in notification bodies
```

No settings are written automatically. Invalid duration values suppress
notification. Exclusions match the whole submitted foreground command; for
watched jobs they match Fish's base command name. Choose valid Fish regexes.
Default messages reveal neither command text nor the working directory.
If explicitly requested, command text is capped at 240 characters and XML
markup escaped; it is passed as a literal argument, never evaluated. It may
still contain private information. Titles contain duration and success/failure.
Below one second, duration is shown in milliseconds. Notifications expire after
3000 ms if the user's notification manager supports that request.

All preexisting `__done*` functions/variables or `caa_done_*` function names win,
including autoloadable helpers. An existing temporary `_caa_done_enable` function
also prevents activation. Legacy __done_* settings therefore keep their owning
plugin in charge; they are not silently migrated. Custom bindings and unrelated
event handlers are preserved. Repeated sourcing returns normally to its caller
without duplicate event hooks. The module writes no bindings or global options.

Run `caa_done_disable` to remove this shell's module functions/event hooks,
including pending watch handlers; user settings remain. Installation/removal
owns only ordinary files under /usr/share, with no hooks/scriptlets. Removal
does not edit the user source block. Loaded shells retain their functions until
disabled or restarted; the guarded block becomes inert in fresh shells after
removal, and reinstall restores the same opt-in path.

Validation covers real Fish PTY foreground/background events and a local
notify-send process shim, including its argv, error and timeout behavior.
Actual D-Bus delivery, notification-manager behavior, visual display,
package-manager lifecycle, native ARM builds, generic 16K operation, both M2 Air
models and performance remain NOT RUN. The unchanged upstream code and complete
MIT notices are provided for review; the adapted path is not a full upstream
feature-equivalence claim.


Pkgrel2 uses timeout --foreground so the timeout monitor survives its forced
kill and reaps the named notify-send child. The normal libnotify binary is a
single process; this bound does not cover arbitrary descendants launched by a
replacement command. A controlled isolated host subreaper probe confirmed that
the previous group-kill mode killed the monitor and left an adopted zombie,
whereas foreground mode reaped the child and removed its /proc entry in3seconds.
Real desktop delivery/physical validation remain NOT_RUN.
