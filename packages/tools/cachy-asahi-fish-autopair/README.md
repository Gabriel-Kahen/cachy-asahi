# Fish autopair product candidate

Independent opt-in integration of the exact MIT upstream pin
4d1752ff5b39819ab58d7337c69220342e9de0e2. Complete primary archive, original
startup file and source joins are retained in the handoff; only the five
unchanged editing helpers are runtime inputs. See usage.md and NOTICE.

Run `python check-module.py --source . --output /new/private/path` with Fish
4.9.3 and Python 3 available. The 14 bounded controls use real Fish PTYs in
private homes, including 19 editing snapshots in each of default/vi/hybrid,
repeat and caller continuation, user/preset/keymap/function/autoload/variable
preservation and noninteractive no-op. They perform no package installation.
The fixture answers terminal device/cursor queries and uses explicit file
barriers; no editing snapshots are inferred from terminal repaint output.

The PKGBUILD has no build(), hooks, scriptlet, global Fish registration or
network source. check() runs syntax and real host PTY controls; package() only
copies files. Python is a check-time build dependency, not a runtime dependency.
Native ARM pair, package-manager lifecycle, generic 16K and physical M2 checks
remain NOT RUN; arch=any describes text payload metadata only. This separate
follow-up candidate is not part of the existing three-package native lane.
