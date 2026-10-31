# Maintenance and session-diagnostics native fixture corrections

The development package corrections are **maintenance 0.1.0-2** and
**session-diagnostics 0.1.0-3**. Their affected source/host controls pass; corrected
native build pairs and signed disposable installed lifecycles remain **NOT RUN**.
The retained failed runs establish the causes below, not acceptance of either
new package version. No release, physical M2, 16K or performance result follows.

## Native failures and bounded corrections

Maintenance [run 40499578636](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40499578636),
source `3d68ac1f5f29ebbe17fad6e9d20d6c39706cf22d`, passes all 18 source checksums
and its source checker. Package-control setup then recursively copies makepkg's
working directory and encounters the live `logpipe.*` FIFO: **zero tests run**.
The second build and installed lifecycle are not reached. Release 0.1.0-2 copies
only the complete declared 20-file recipe fixture, validates the 18 source pins
before/after, and refuses unsafe declared file types with nonblocking/no-follow
reads. Unlisted makepkg outputs are excluded; all controls still execute.
The nine private production modules remain byte-identical to their canonical
sources; launcher changes bind the new version and package pins.

Session-diagnostics [run 40499774542](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40499774542),
source `44c025a31c640fd96dda2b1efa2aa06c27c15d41`, completes bootstrap 574 and
reaches the first check(): 34 of 35 probe tests pass, while the socket fixture's
positive assertion fails below `/tmp/work/src`. The old test places its socket
under checkout ancestry that production deliberately rejects when writable.
The precise native `/tmp` mode was not retained; attributing that stat is an
inference supported by the author's controlled 1777→0755 host reproduction.
The second build and lifecycle are not reached. Release 0.1.0-3 changes only this
test among 35 methods: its first root descriptor maps to a private fixture;
subsequent descriptor operations remain real, including O_NOFOLLOW. Writable
ancestry and unsafe owner/type/link/replacement cases remain tested. Production
`session_probe.py`, launcher, remaining 34 probe methods and all seven package
controls are byte-held.

## Canonical-layout checks actually run

A fresh local `git archive` of parent
`e5814001fe64147eadbb7c69650a9771f53c976e`, overlaid with the exact proposed
packages, passes on the x86_64 host:

- Maintenance source/snapshot checker and all 18 package controls, including a
  real unlisted FIFO and refusal of unsafe declared inputs.
- Session source/snapshot checker, all 35 corrected packaged probe controls and
  seven package controls; the existing canonical 35 probe controls also pass.
- Explicit static inspection of both recipes, complete 20/12-file recipe
  membership, exact versions, `.SRCINFO`/source pins and recipe shell syntax.
- Canonical source correspondence for maintenance's nine private modules and
  session's production probe; cached actionlint 1.7.12 for the modified workflow.

The 60 affected controls have zero skips. Package controls create private staging
trees and exercise delivered launchers; this is neither ALPM installation nor a
fresh native build. Existing CI already runs maintenance's package suite and
session's seven package controls. One command adds the corrected packaged 35
probe suite; prior workflow steps and historical tool discovery remain intact.

The author's earlier host makepkg/package results remain separate from these
integration checks. New native trials must bind their complete 59/54-file
contexts to the newly published package commit; the old failed sources/readers
cannot admit changed releases. The incomplete maintenance native-harness
fragments are excluded from this canonical package adoption. Actual native
execution, signed installed lifecycle, 16K, both M2 Air sizes, measured performance,
maintained-system and release acceptance remain pending.
