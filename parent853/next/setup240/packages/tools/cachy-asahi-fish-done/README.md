# Fish Done product candidate

Separate opt-in Linux adaptation of exact upstream
b86292a52a2b8f646ef8d25daa3cc01ccab60b62. See NOTICE, usage.md and
source-provenance.json. done.upstream.fish is byte-identical primary source;
the complete upstream archive/tree and original per-file grants are retained in
the handoff. done.fish retains the full upstream MIT header and unchanged
humanize_duration function, with explicit foreground and single-process job
completion behavior. The wrapper installs no automatic startup registration.

Run `python check-module.py --source . --output /new/private/path` with host Fish
4.9.3 and Python 3 available. Eighteen bounded controls run real private PTYs and
child jobs with an executable local notify-send recorder (no bus connection).
They cover foreground success/failure/short/excluded/invalid-setting behavior;
background completion/failure/SIGTERM and duplicate-watch cleanup; invalid,
foreign, reaped and pipeline watch rejection; disown and disable; caller
continuation, custom bindings and preexisting event handlers; opt-in command
text kept literal; transport failure and forced kill; namespace/autoload guards;
missing bus/dependency; and silent noninteractive behavior. Files, process exits,
notification arguments and handler identity are asserted rather than inferred
from terminal repaint output. Private config and history are preserved.

PKGBUILD check() runs syntax and all real controls. package() only copies files;
Python is check-time only. No build(), scriptlet, install hook, dependency
installer, desktop controller, startup download, eval override or compiler is
used. arch any describes the text payload; ARM/package-manager/16K/M2/performance
validation remains NOT RUN. This follow-up does not expand either prior frozen
three-tool or autopair native lane.


Pkgrel2 corrects notification-monitor lifetime with timeout --foreground. It
retains the2s+1s named-process bound and exact PID-absence assertion. A controlled
private host subreaper probe establishes prior monitorSIGKILL/adopted-zombie
behavior and foreground monitor reaping; all18 real host PTY controls are rerun.
The native0.1.0-1 actual failed its first installed transport-timeout control,
although both makepkg18case checks and the build pair passed. Its failed process
state was not retained, so the zombie relationship is source/host evidence,
not claimed direct native observation. Corrected native lifecycle remains open.
