# Repository original view independent source review

Disposition: **BLOCKED for source adoption** at the exact held candidate below.
The 92-test replays pass, but an independent receipt-shape control accepts
surplus and invalid directory rows. No execution grant or actor authority is
issued by this review.

Reviewed hold: `artifacts/reviews/repository-original-view-implementation-20261012/held-receipt.json`,
SHA256 `b340a6470c615914f76f02a83f44e4b71d61608c48298c93b91bfc9b1406c263`.
Its four implementation/test rows and implementation document authenticate by
exact bytes, modes and sizes. The implementation document authenticates to
`ee43141ee8c84c68e469c29d23e049cb12bdb69b534a1bce9fd4a4127505b63c`.
The capture's 255 rows authenticate against the held-source copy, including
5,128,890 bytes and no PYC files. This is a held source proposal, not Root's
registered whole current-root packet.

## Blocking finding

**P2: Close the receipt's directory set before accepting context.**
`Session.verify_view` checks each visited directory against its receipt row,
but permits surplus rows through the `<=` count check and final verification
without directory-set equality. Directory keys are only required to be strings.
The independently captured actual Session receipt, recanonicalized with either
`directories['ghost'] = directories['.']` or
`directories['../ghost'] = directories['.']`, is accepted by the actual
`session.original_context` when its private bytes and SHA are replaced together.
Both controls return a context dict despite contradicting the copied tree.

Require the exact ancestor set implied by the 160 selected files, including the
root `.` row; validate directory names and reject missing, surplus and invalid
rows. Retain causal controls for each case. This concerns cooperative state
validation and the promised refusal of contradictory receipt fields. It does
not establish an attack on hostile same-UID memory isolation. The unmodified
receipt and real directory replacement controls behave as intended.

The reproducer and results are
`artifacts/reviews/repository-original-view-root-peer-20261012/controls.py` and
`controls.json`. The source location at this hold is
`scripts/ci/development/repository_handoff.py:899`, with incomplete count/set
checks at lines 914 and 929. Primary source files were not edited in this review.

## Verified source and fixture evidence

- Fresh held-copy and working-tree authorized replays each run 92 tests with
  exit0 and no skips. Both use `-B` and `PYTHONDONTWRITEBYTECODE=1`; the copied
  source retains zero PYC files. Sandbox replays separately retain one EPERM
  at the harmless private AF_UNIX socket send; this is not reported as PASS.
- Prior 61 adapter and 17 authority test method AST bodies are unchanged against
  the prior graph correction's accepted capture. The adapter adds 14 tests;
  fixture setup changes are distinct from those preserved method bodies.
- The actual context accepts the closed five-field result: PosixPath root,
  immutable bytes receipt, str SHA and dict original/aliases. Actual namespaces
  number nine and projection aliases two. Readiness alone grants no Controller,
  compiler, build or PASS authority.
- The unchanged original scanner reads 159 source rows on the real 160-file
  view. The original lock remains
  `d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`.
  The source-only recipe freezer passes four recipes / 71 inputs in the suites.
  The unchanged scanner comparison causally refuses the held expanded source
  with Zsh12 and accepts the copied original view. The original module loader
  itself captures its selected rows without rejecting scan extras; no extra
  scanner protection is attributed to that loader.
- The full current-root scan is 175 = original159 + Zsh12 + installer4. It is
  neither filtered nor waived. The held minimum255 capture's scan is 171;
  installer4 is absent from that proposal. Eight unrelated virtual source rows
  differ in the live tree from the held255 capture; their names and held facts
  are recorded in `authorized-authentication.json`.
- Exclusive file creation, no-follow file/directory FDs, file modes, bounded
  writes/fsync, file inode/byte custody, directory replacement detection, partial
  copy registration and owned cleanup pass the held tests. Cleanup refuses a
  replaced root and preserves the foreign replacement.
- Schema2 closes the exact view descriptor, checks the invocation/output hash
  before copy, and requires explicit absolute view metadata flags and hashes.
  Old schema1 is refused. Status22 and callback live12 remain. Source graph
  custody distinguishes full-source and original-view compilation roots.
- Context controls refuse expired, boolean, NaN, infinite and renewed deadlines,
  same-class fabricated Controller/direct observer invocation, and equal code
  transplanted into foreign globals. Source review confirms the consumer wrapper
  checks its actual code/globals, actual Controller.run/native.main frames and
  controller/image/commit/lock facts. The separately observed native return is
  typed; callback `_live` still requires returned0 plus existing source, image,
  nonce, crypto, phase, custody, cleanup and PASS conditions.

## Bounds and next action

Correct and re-hold the adapter plus causal tests, then independently replay the
receipt controls and source checks before Root adoption. The historical hold,
its exact source copy, evidence and this blocked disposition remain unchanged.
Root alone reconciles maps, packets, workflow, Git, grants and dispatch. Generic
policy material under ignored artifacts is a future selection input, not proof
of an issued Root grant.

A legitimate actual Controller.run/native.main positive invocation and return
remain **NOT RUN**. No native/daemon, compiler/build, Docker, GPG/image/mount,
network/install or hardware actors were run. No hardware model is admitted.
R1–R5 and M5–M9 remain mandatory and incomplete; source fixture acceptance cannot
close those distribution, installation, performance or exact-model gates.

Evidence is sealed by
`artifacts/reviews/repository-original-view-root-peer-20261012/final-receipt.json`.
