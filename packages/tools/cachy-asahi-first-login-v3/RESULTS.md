# FirstLogin 0.1.0-3 isolation correction

This is an unselected successor to retained 0.1.0-2. The installed entry point
already used isolated Python, but the old helper subprocess inherited Python
variables/interpreter PATH and printed follow-ups omitted `-I`. Private actual
reproduction observed both failures before this correction. No configuration
ownership rules or selected package dependencies changed.

Focused checks on 2026-11-15:

- Maintained CLI: 14 passed; candidate CLI: 14 passed.
- Actual `package()`/relocated installed launcher: 6 passed. These include poisoned
  Python variables, interpreter PATH, helper-directory imports and an unsafe cwd;
  printed inspect → preview → explicit apply; custom roots and existing user
  lines; and removal of the six payload files while retaining user settings.
  Payload removal is a private filesystem check, not an ALPM uninstall.
- Retained02 rehearsal source-selection control: 1 passed. The finite rehearsal
  continues to select 0.1.0-2 with local pins; Setup8 still checks canonical sources.
  Its optional installed-payload assertion also points to that retained02 source.
  The full rehearsal was not rerun.
- New canonical/local source pins, generated `.SRCINFO`, Python syntax, and the
  focused static workflow shell/argv construction passed. The workflow's other
  blocks and all old02/UI02/Setup8 source bytes remain unchanged.
- Ordinary `makepkg --nobuild --noconfirm`: exit 8, missing only
  `cachy-asahi-setup>=0.3.0`. No host dependency installation was attempted.
- Private unsigned `makepkg --nodeps --force --noconfirm`: exit 0; `check()` ran
  all 20 candidate checks. This assembles the package without dependency credit.
  A host libfakeroot warning (`payload not recognized`) was retained. Independent
  archive inspection confirmed six expected regular payload files, root:root
  ownership and launcher 0755/other files 0644.

Retained host archive: `cachy-asahi-first-login-0.1.0-3-any.pkg.tar.zst`, 20,272
bytes, SHA-256 `c07583ae4af92d960a544249aa376cf89326508668165da9eb8a46d0be4cd6ed`.
Local logs/archive are under `work/first-login-v3-build-20261115-r1/` in the
implementation worktree. They are not claimed as publicly durable artifacts.

Ordinary dependency-closed build, signed ALPM install/remove, native ARM, M2,
graphical login and release admission remain unestablished. UI02 still requires
exact 0.1.0-2; this change does not select a new backend for it.
