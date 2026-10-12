# Supporting evidence draft for existing PR #1972

Status: **NOT SUBMITTED**. Proposed destination is [the existing package-retirement PR](https://github.com/CachyOS/CachyOS-PKGBUILDS/pull/1972), subject to refreshed status, coordinator review and separate submission authorization. If equivalent evidence is already present or the retirement has resolved the issue, hold this draft. No maintainer has been contacted.

Suggested comment body:

> Supporting compatibility evidence: settings 1.4.4 (`449635e3718f4f178503682b29b159b0a758e5e7`, archive SHA-256 `6329177a462392ae018e81572359aaf4c530e4ff4136ef6f170ab33eb043893b`) fails `Hyprland --verify-config` on v0.56.2 (`efb50993780079460b0cbed1363e2166a2de1d9f`): removed `dwindle:pseudotile`, unknown standalone `togglesplit`, and invalid legacy rule fields. A five-line no-import reduction reproduces exit 1. Full-tree verification rewrote only source paths in a temporary copy. This was x86 parser testing; no session or ARM/M2 compatibility claim. Existing user copies still need an explicit migration path.

Before posting, attach or link the reviewed minimal reproduction and diagnostics from [the detailed draft](hyprland-config-draft.md) through an authorized accessible destination. Local repository paths are not assumed public, and this task uploads nothing. Refresh PR state and check existing comments first. The text above is an original summary of this task's measurements, not a submitted review or copied upstream comment.
