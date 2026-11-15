# First-login GTK in a genuine x86 real-seat session — 2026-11-15

**Actual Root r4 PASS:** `PASS_X86_REAL_SEAT_FIRST_LOGIN_UI_LIFECYCLE_ONLY`.
Root naturally completed the one admitted QEMU TCG experiment. Independent
read-only revalidation joined the original seat parser's redacted serial frame,
foundation report and UI acceptance result; no new guest or control-socket action
was performed. This is genuine x86 software execution, not ARM/M2 acceptance.

The guest used normal password/PAM login as UID/GID 1000 on active `tty1`/`seat0`.
Real login1/D-Bus PID/session checks and `sd_session_get_seat` returned seat0.
Original PAM, Polkit and udev seat policies were preserved. All 46 nonce-bound real
keyboard release acknowledgements were ordered; password entry waited for actual
TTY ECHO-off, followed by normal logout. No extra authentication or policy grant
was introduced for the per-user GTK actions.

The actual installed GTK4 window and callbacks ran as the ordinary user in a
private **real Xvfb X11 display with Cairo rendering**, within that genuine TTY
login session. The driver mapped the window, checked read-only inspection,
selected Fish/Zsh, invoked read-only Preview and explicit Apply, then repeated
Inspect/Preview/Apply after a user edit. Existing Zsh settings and that edit were
preserved. X11 returned 3,145,728 rendered pixel bytes, SHA256
`265474085c654bcd9a9ba8afa5af15ac38ba85ad284d83479cc7b886748f6223`;
no screenshot was exported. This was a controlled GUI action driver using the
installed implementation, not a display-manager/menu-launch or physical-display
trial. Hyprland was not selected or launched.

## Package and persistence result

- Normal `Required TrustedOnly` ALPM installed 128 exact signed inputs against 164
  baseline packages: **164→292→164** after removal. Strict dependency/ownership
  checks and all 24 installed project file hashes passed before login readiness.
- The root-owned nonce/input/inventory-bound installed receipt matched the
  independently returned result. Actual guest `syncfs` passed after installation,
  after removal and before terminal PASS publication.
- After removal, **17,619 package-owned non-directory paths were absent**, baseline
  inventory/dependencies were restored, unrelated user data and original policies
  were preserved, and all four private Fish/Zsh/profile-state files were unchanged
  from the post-edit snapshot.
- Normal hook effects remain explicit: `/etc/passwd`, `/etc/group`, `/etc/shadow`
  and `/etc/gshadow` differ from their pre-transaction snapshots. Exact account
  deltas were not captured in this result. **Full account/filesystem/cache
  restoration is not claimed**, and those changes were not erased to create PASS.

The three project inputs were UI 0.1.0-2, FirstLogin 0.1.0-2 and Setup 0.3.0-1;
125 official x86 dependencies came from the pinned frozen closure. Public-only
TEST-context trust stayed inside the guest; no private signing key was used.
This does not establish production trust/revocation freshness, source/legal
acceptance, architecture portability or hardware acceptance.

## Inputs and exact terminal evidence

Prepared path:
`/dev/shm/cachy-asahi-ui-seat-preparation-root-20261115-r4/prepared`.
Manifest 3,157 bytes, SHA256
`34019a0c68e2541cfc91bc2a6e9d81d3b190af26aaae33189408c14734fc6ae1`.
The 3GiB logical raw SHA256 is
`9f9a5aa97356af80333a65a0f546954144f8b4b7893c815d86e797cb43d950e0`.
Exact tool image `cachy-ui-real-seat:ce5f5c357ab9945f`, ID
`sha256:aee0497e5d1cd7773659faa9e81a2c633f88dfe3ef12f3bc730b9b120b254e20`.
The source includes the one-flag CLI correction `fb6d023e`; runtime/input pins are
recorded in the prepared manifest and the
[fixture documentation](../../scripts/integration/first_login_ui_session_vm/README.md).

Root terminal output:
`/dev/shm/cachy-asahi-ui-seat-first-boot-root-20261115-r4`.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `report.json` | 19147 | `9cfa7850361e1fd2fde5f98534179edd8f25fb30e72804b9d2c7fda67f40623a` |
| `journey.json` | 7086 | `20a8e9195d2862ba702fd1c7fa80d0646819c3aea2766ddf92620b3d7eed1083` |
| `serial.redacted.log` | 27656 | `c546f70a3af4c83b9717d2af9cadb2b2a40caa515eeaa066af4fba3d712925eb` |
| `qemu-retirement.json` | 251 | `529eb59fa5494516ce378da89275f0b3f08ea2b8511af95ae6f2cec3a18535d2` |

GUI/Xvfb/session-bus process retirement passed naturally with exit 0, reaped
ownership, `EMPTY_TWICE` and no signals/timeouts. Normal VT PAM logout and session
removal were observed, then QMP quit retired QEMU naturally with exit 0, reaped
ownership and `EMPTY_TWICE`, without cancellation. Exact admitted container
absence was independently rechecked; cleanup ownership/removal/absence were all
true with an empty cleanup-error list. These are scoped retirement observations;
normal guest poweroff was not qualified.

The earlier closed UI r1 PAM HOLD, r2 ownership-stage HOLD and r3 CLI option
refusal remain preserved with their original inputs/markers/results. The live r3
39-byte error hash identified invalid `--noprogressbar` on a query; the shared
argument list removed only that download-only flag. This does not retroactively
explain the earlier PAM failure or assert a package ownership defect.

No further source defect is evidenced by this passing run. ARM/native execution,
M2/Asahi hardware, physical graphics/input, actual desktop-session integration,
networking, suspend and release acceptance remain outside this result. The next
step is to use the retained implementation/evidence for those separately admitted
journeys; this success must not be promoted to a hardware or release PASS.
