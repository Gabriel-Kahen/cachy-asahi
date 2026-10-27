# Setup status, offline diagnostics and rebuild planning

October 27, 2026. Development source and host validation; native package builds,
installed lifecycle and both physical M2 Air sizes remain untested for these revisions.

The setup candidate 0.1.0-7 adds `cachy-asahi-setup status`. It reports managed
configuration ownership, drift and pending recovery without writing, locking or
replaying a journal. Its package copy now carries the exact current repository
enrollment guide. The source helper and packaged helper are identical. The
93 setup tests pass; the guide successor additionally passes all three ordinary
synchronization modes, normal checkout preparation, five new controls, ten sync
regressions and six packaged regressions. These used disposable host fixtures.
Earlier native Setup5 results apply to that older version only.

Doctor 0.1.0-2 adds `cachy-asahi-doctor --compare before.json after.json`, with
optional `--json` and a new private output file. It reads bounded supplied reports
without running the collector, system commands or network clients. Its 16 existing
and 17 new controls pass. Changes in reported observations are separate from
health, update causation, hardware behavior and performance. The audio-enabled
Doctor2 0.2.0-2 successor is also implemented: 47 package controls pass on Python
3.12 and 3.14. Its separate 63-file maintained source constructor preserves
the historical 705/62-file context, default NULL selectors and native actor
guards; 89 source/package controls pass per interpreter, with 33 historical
controls passing separately. Its old native results do not cover either new
comparison implementation. New native builds remain unrun.

`scripts/maintenance/rebuild_plan.py` plans conservative reverse build impact
from explicit pre-change release, source and build-dependency inputs. It groups
same-source outputs and cycles, orders prerequisites, and retains missing metadata,
ambiguous providers, ownership and capacity as visible holds. Its 30 controls and
59 existing helper controls pass; two illustrative fixtures replay byte-for-byte.
A plan does not execute builds, solve a release transaction or establish a security
fix. Real release inputs and ongoing maintainers remain required.

The maintained Core source constructor also reconstructs the exact published
ad09 media-contract correction, preserving the original thirteen-command Source
block, 43 bridge controls and native actor/security/budget checks. Both Python
variants and known/NULL contexts pass locally. The privileged installer wrapper
remains mandatory in CI and was not run locally. Native trial 40423799398 is a
separate pending result; source reconstruction does not establish native media,
boot, cleanup or target-machine acceptance.
