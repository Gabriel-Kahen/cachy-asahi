# Controlled full587 postcommit interruption and owned-copy disposal

This is a separate, source-selected development test. It does not change or
select the precommit-exit86 case. Its exact purpose is
`actual587-postcommit-failure-disposal-test`, case `postcommit-exit87`.
Implementation and inert fixtures establish no actual transaction result.

The existing composition owner stages the complete initial587 persistent root,
quiesces its existing keyring, and owns its container/volume. The unchanged
full-root driver creates a byte-identical owned copy and performs the held
one-shot copied-root initialization before the baseline. The parent retains
that copy's lifetime and starts exactly one bounded child, with the private
Runner's exact128→8192 descriptor binding. Archive decoder/window bounds stay
16MiB. No existing/stale copy is resumed.

The child subclasses only the selected linked Runtime. Its original precommit
checks run before a small observer wraps the live ALPM commit function. That
observer calls the original function with unchanged arguments and returns its
unchanged result. It counts one call and records the integer return code; it
never substitutes a commit. The existing `observed_after` method runs immediately
after the real successful ALPM call and before checkpoint writing in bound_update.
It retains its inherited exact after587 inventory check, then requires that one
original commit returned0. A nonce/source/spec/root-bound fsynced witness precedes
`os._exit(87)`, deliberately skipping checkpoint writing and ALPM lock release.
No shared transaction seam, Runtime policy change or checkpoint writer patch is
needed. Failure to reach this exact boundary earns no controlled-case credit.

The parent waits for the held Runner to retire the direct child and its whole
reserved group. It then reads the fresh checkpoint directory. Only an exact
witness plus an independently observed unchanged empty checkpoint establishes
commit_started=True, packages_committed=True, checkpoint_changed=False. Missing
or unreadable evidence remains UNKNOWN. A known successful commit is retained
if later payload verification, checkpoint inspection or disposal fails.

Before starting the child, the parent constructs an independent verifier from
the original complete node map, actual setup3 ownership records and the pinned
setup4 archive. It uses the held linked Runtime's exact six-file projection,
selected links, hardlink preservation and auxiliary policies. After retirement
that verifier checks the real after tree, allowing only the declared stale empty
mode0000 UID/GID0 database lock in addition to the existing projected transition.
A local bounded descriptor reader checks all587 real desc/files records against
that complete observation, exact after inventory, unchanged nonselected records,
and selected package ownership including directories. This reader never opens
ALPM; the default unlocked database API is unchanged. No lock is removed or hidden.

The normal driver receives a FAIL update, then disposes its complete owned copy
through the existing copier lifetime. Case PASS requires the exact child boundary,
independent post-state proof, unchanged complete original source and confirmed
copy absence. It records one committed transaction and one verified interruption;
it grants no successful checkpoint or normal-upgrade acceptance. If the nested
supervisor raises without a terminal retirement receipt, the parent worker exits88
without unwinding the copy lifetime. The outer owner must stop its container and
dispose the volume before releasing backing sources. No retry occurs.

The launcher uses the held composition owner's existing explicit caller-directory
setting; temporary caller sources are removed only after its separate container
and volume cleanup receipts pass. Outer retirement is separate from inner copy
disposal. This test proves no hardware rollback, boot recovery, Asahi production
installation, M2/16K acceptance or performance.
