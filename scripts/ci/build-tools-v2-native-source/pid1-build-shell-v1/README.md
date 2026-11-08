# BuildTools 0.2 explicit PID1 build-shell variant

This opt-in sibling changes the image-build `RUN` launcher, using the maintained
Release PID1 layout: exec-form `/usr/bin/bash --noprofile --norc -p -c`, a fixed
background Python lifecycle child, `wait` for that child and exact exit-status
propagation. Python must have PID greater than1 and PPID1 before source verification
or lifecycle work. The retained report records those observed IDs. The matching
reader independently requires typed PID/PPID observations for positive evidence
and validates any retained initialized failure report. Those observations alone
establish neither adopted-child reaping nor an empty process group.

Actual parent Source52 (`52a425ef08c5dc84ba1a7c5b53be8d21dc42f9dd`) built the archive
and passed all eleven makepkg checks, but `build-a` failed supervision because its
process group was `PRESENT_OR_REUSED` after exit0/reaping. There are no retained
census member rows or original build PID observations. Zombies and Python-as-PID1
are not attributed to that run. Its first failure, frozen reader and original
Source remain separate. This variant addresses the source-level absence of an
explicit image-build init owner; a genuine new native trial is still required.
Consumer `--init` does not replace an image-build `RUN` owner.

`prepare.py` is a Root-operated DATA emitter. It authenticates the complete actual
Source52 raw commit and 200 bodies/modes/tree, applies three pinned code bodies
and reseals the199-row nonrecursive map. Exactly four leaves change;196 remain
identical. It reuses externally pinned maintained descriptor-relative input and
atomic no-replace DATA-publication helpers. The physical publication parent is
Source52; its historical c5e/basis identities remain unchanged. A fresh output
outside the input/variant and externally reviewed profile hash are required.
No emitted Source import/execution, Git, network or Native action is implemented.
All new actual Source/ref/run selectors are NULL until Root acts.

The default factory/profile, original Source52 reader, package/contract, workflow,
349-package baseline, eleven package checks, six public commands, nine business
observations, default834 retirement runtime and resource/deadline/output limits
are held. Every lifecycle command still requires `EMPTY_TWICE`; unknown or present
members remain a refusal. No capability, privilege, policy or acceptance waiver
is added.

Nineteen actor-fenced DATA/AST controls cover the launcher and exact status path,
malformed map/suffix refusal, early direct-child guard, actual ID recording,
reader type/identity/retention refusals, whole actor/reader inverse, exact producer
pins, full200 raw-commit/tree/map closure and four-delta/196-held inverse. They run
on Python3.12 and3.14 without starting Bash or importing emitted Source/readers.
These controls grant no ARM/native, installed, M2 or release acceptance.
