# Managed user-session VM profile

Opt-in software-only profile for the accepted exact574 builder /591 runtime route.
Source and inert controls pass; native managed execution and visual review remain
NOT RUN. The accepted default launcher lane is unchanged. No new packages or Asahi
platform changes are selected.

The fixture adds Requires/After=systemd-user-sessions.service. Packaged tmpfiles
creates /run/nologin and user@ reaches pam_nologin through its account stack; the
previous custom target did not start the service that permits sessions. This is
a source-backed correction; the immediate historical denial lacks a journal.
PAM/account policy and nologin are preserved, with no manual deletion or bypass.

prepare.py stages a fresh runner from28 exact dependency/test hashes. The managed
API requires explicit VM markers, systemd PID1, Permit User Sessions readiness,
fresh selected user@/runtime-dir units, and systemd-created /run/user/23001. The
real user bus must report manager UID23001 and the user@ MainPID, then answer the
systemd Manager.GetUnit API. The user rechecks that identity before unchanged
minimal/overlay phases. There is no private-bus fallback. Start/readiness is
bounded; workload retirement precedes exact unit disposal and runtime absence.
A failure retains one capped journal without replacing the original error.

21 managed controls and the unchanged44 guest/13 runtime controls passed before
CI preparation. CI caller controls, source/derived manifest and actor budgets are
in ci/. Running code on hardware, managed startup, all user services, Waybar/Mako,
acceleration, audio, performance, complete R4/M6 and release acceptance remain
unestablished. Root owns exact Git/workflow freeze, native execution and visual
acceptance. No artifact cache, package archive, disk or diagnostic package tree
belongs in this source lane.

The separate workflow requires an explicit full source commit. It checks the
complete selected source closure, prepares the profile, uses only the existing
six private seed objects and exact retained14 public source, builds exact574,
executes one managed591 trial, then retires the owned base through the existing
builder API. Fixed public diagnostics and full minimal/overlay PPMs are retained
for3 days. A successful recorded-state CI gate still requires Root's pixel review.

From a pinned checkout, source preparation is:

    python -B scripts/ci/desktop-user-session/prepare.py --source "$PWD" --output /absolute/fresh/managed-runner

Use the workflow/caller in ci/ for the native trial; preparation runs no actors.
