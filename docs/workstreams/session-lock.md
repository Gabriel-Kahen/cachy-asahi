# Explicit desktop locking and suspend

The opt-in `cachy-asahi-session-lock`0.1.0-1 development candidate adds a manual
lock-before-suspend command. The existing accepted Hyprland template only calls
Swaylock directly and intentionally supplies no sleep policy. This new package
does not change that template, DesktopTools, Setup, the base launcher, user
configuration or accepted native evidence.

The [package README](../../packages/tools/cachy-asahi-session-lock/README.md)
documents commands, optional user-owned Lua bindings, recovery, installation
ownership and limits. The [implementation](../../packages/tools/cachy-asahi-session-lock/cachy-asahi-session-lock)
starts Swaylock independently, waits for its `--ready-fd` newline and checks the
locker is still alive before issuing an explicit noninteractive suspend request.
There is no shell command construction or automatic lid/idle activation.

Readiness timeout, malformed/closed notification, startup failure and
pre-readiness cancellation prevent a suspend client from being started. The
foreground supervisor never kills the locker: even a timed-out notification
can follow a compositor lock. It retains the read descriptor until normal
locker exit so late readiness cannot cause SIGPIPE. Existing lockers are not
adopted by process name. A duplicate helper is refused by a private per-display
runtime guard; an independently existing locker must be refused by the
compositor without a successful readiness notification.

The helper uses Python isolated mode and requires a non-root desktop user,
private runtime directory and ordinary user-owned Wayland socket. Swaylock's
own configuration is bypassed to keep foreground/readiness behavior explicit;
the base's authentication/PAM remains authoritative. The fixed suspend request
honors authorization/inhibitors and has no privilege or force fallback.
An interrupted in-flight request can already have reached logind and is
reported as unknown. Readiness and user unlock versus asynchronous sleep are
not atomic; this is not an unconditional guarantee of lock retention after
readiness. Automatic `PrepareForSleep` inhibitor integration remains separate.

Sources are original MIT implementation, tests and documentation. No upstream
code/assets are bundled. Interface audit used Swaylock v1.8.6 commit
`44b82de635c3bc66b0093abd1cf8cc1c8b1b9c0f`; source and manual links are in the
README. Dependencies are `python>=3.11`, `swaylock>=1.8.6`, and `systemd>=248`.
The systemctl manual explicitly records version248 for `--check-inhibitors=`.
The package owns only its executable, README, license and notice. It has no
hooks, services, setuid files or system/user configuration ownership.

## Actual local validation, 2026-11-14

On the existing x86_64 development host with Python3.14.7:

| Check | Actual result and limit |
| --- | --- |
| `python -I -B -Werror::ResourceWarning test_session_lock.py` | PASS,24 tests using real fixture subprocesses; never calls real Swaylock or systemctl |
| `python -I -B -Werror::ResourceWarning test_package.py` | PASS,2 tests: source checksums/actual SRCINFO and real unprivileged package-function staging with exact four files/modes/help/refusal |
| `bash -n PKGBUILD` | PASS |
| `makepkg --nodeps --noconfirm` in a new temporary recipe copy | PASS,exit0; actual `check()` executes24+2 tests; dependency checks deliberately skipped |
| `scripts/checks/package_checks_v2.py recipe .../PKGBUILD` | `static-pass`,no errors, after removing only this recipe's generated `src` directory |
| `scripts/checks/recipe_metadata_consistency.py .../PKGBUILD` | `MATCH_MODELED_LITERAL_DECLARATIONS`,no mismatches |
| `scripts/checks/package_checks_v2.py artifacts ...pkg.tar.zst` | `artifact-static-pass`,no errors; root-owned payload, no ELF or install hook |
| Independent coordinator source review | Readiness and preservation reviewed; requested isolated-mode guard added and controls/build rerun |

The final host archive is `cachy-asahi-session-lock-0.1.0-1-any.pkg.tar.zst`,
18552bytes, SHA256
`738f361830f0586dff28acd725b2865f3a95f0c1ab0d1cbc6517ede8d750a686`.
Its four payload hashes match source bytes exactly. Development-host logs,
archive and `host-result.json` were retained locally under
`/tmp/cachy-asahi-session-lock-final-host-3oqv04q_/`; they are temporary host
outputs, not published or durable release evidence. `SOURCE_DATE_EPOCH` was
`1794667200`; no repeated-build reproducibility is claimed. A preliminary
pre-guard build emitted a host libfakeroot warning despite exit0; the final
build did not repeat that warning. No host repair or installation was attempted.

Fixtures exercise successful ordering, early/preexisting-lock refusal,
invalid/closed notifications, delayed notification after timeout or cancellation,
SIGTERM, cancellation after readiness/during the request, request refusal/hang,
locker exit during the request, missing commands, guard concurrency and unsafe
paths, minimal environment, and direct non-isolated Python refusal.

Clean native ARM4K/16K builds, installed transaction/removal, real
Swaylock/compositor/PAM behavior, real lock/suspend/resume, hardware recovery and
both M2 Air sizes are **NOT RUN**. The new recipe is not selected in the shared
development/release manifests by this lane. M6/R4 acceptance remains incomplete.
