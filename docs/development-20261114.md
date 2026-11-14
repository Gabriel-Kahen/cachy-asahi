# November 14 development push

This push connects installed user workflows and maintained release operations.
The additions are opt-in development candidates. Previously qualified package
recipes and their evidence remain available at their original versions.

| Capability | Entry point | Current verification |
| --- | --- | --- |
| First-login discovery, selected configuration activation and interrupted setup recovery | [`cachy-asahi-first-login`](first-login.md) | Real Setup8 temporary-home operations; extracted/moved host package execution |
| Explicit locking and readiness-ordered suspend request | [`cachy-asahi-session-lock`](workstreams/session-lock.md) | Real subprocess readiness, refusal and cancellation controls; unsigned host package assembly |
| Installed repository enrollment, disable and authenticated key transition | [`cachy-asahi-repository-enrollment 0.2.0-2`](../packages/tools/cachy-asahi-repository-enrollment-v2/README.md) | Public-certificate verification, source-hidden relocated signed transition preview and unchanged target state; existing disposable enrollment/rotation suite |
| Dual-signed planned release-key handoff and cross-key comparison | [`signing_transition.py`](release/signing-transition.md) | Real disposable GPG identities and signed synthetic release bundles, tampering/replay/expiry/refusal controls |
| Apply an authenticated handoff to local managed trust | [`transition.py`](repository-signing-transition.md) | Complete re-verification under the original pacman lock, exact certificate/current-state checks and real disposable mapped-root trust rotation |

The separate [Hyprland 0.1.1 candidate](workstreams/hyprland011-session-lock.md)
binds `Super+L` to the lock helper and `Super+Shift+L` to ordered suspend. Real
Lua evaluation and the host Hyprland configuration parser pass. The selected
0.1.0-3 recipe is unchanged; the successor remains unselected.

The [actual shell journey](validation/first-login-actual-shells-host-20261114.md)
uses extracted FirstLogin, Setup8, Fish and Zsh packages. Forty-one commands and
ten actual shell startups cover activation, user edits, removal and recovery
after process death. This is an x86 host journey in private temporary user state.
The [build-and-rehearse command](validation/first-login-build-rehearsal-host-20261114.md)
reproduces it from four checksum-verified local recipes with no package install
or source downloads. CI runs that path after its disposable-host prerequisites.

Configuration activation requires explicit components and an explicit apply.
Package installation supplies commands without activating templates, services,
repository configuration or public trust. The first-login helper preserves
effective HOME/XDG/ZDOTDIR roots in recovery commands. Known conflicts block the
complete selected activation before writes begin.

Lock readiness precedes an explicit suspend request. Cancellation and errors
preserve the locker until normal unlock. A queued request does not prove sleep,
resume or atomic exclusion of a later unlock. No automatic lid/idle policy is
installed.

The key-transition artifact binds both complete releases and both public
certificates. It establishes a finite planned handoff between explicitly pinned
identities. Production custody, remote revocation freshness and distribution
remain separate operational requirements.

New candidate packages remain outside development/release selections. Host
assembly uses `makepkg --nodeps`; successful assembly does not prove dependency
resolution, native ARM builds or ALPM lifecycle. Native ARM qualification for the
new packages, the complete supported Asahi dependency transaction, first graphical
login, lock/PAM and sleep/resume, macOS installation and recovery, production
trust, measured performance and both physical M2 Air sizes remain open. The
[roadmap](roadmap.md) and [acceptance contract](acceptance.md) remain in force.
