# Downstream opaque-handler source audit

Root extracted only the signal-scope definitions from the exact transport and
launch bytes in maintained Source `f93ac927c206fbe387e4caf03b289bfea0cab7ec`.
The existing 271-row Source proof authenticates their hashes. No full module,
signal API, process, package, library, network or native actor was executed.

Six independent inert controls cover each scope with a known-handler positive,
an opaque None-handler model, and that model combined with a body ValueError.
The known-handler cases restore the simulated original handlers and entry mask.
Both opaque cases raise TypeError at restoration and retain the installed
temporary handler in the simulation. With a body error, TypeError becomes the
primary exception and the body error survives only as its context. These checks
establish behavior of the extracted definitions under the declared model; they
do not prove actual kernel handler/pending behavior or the cause of trial07.

The finite evidence is under
`artifacts/reviews/maintained-downstream-opaque-signal-audit-20261013/`.
This audit supplies no runtime correction or native acceptance. After the common
service-context correction is sealed and reviewed, transport and launch need a
separate bounded correction preserving opaque originals, entry masks, originally
blocked pending signals, child mask inheritance, nested cancellation propagation
and first-error disposition. Their existing Source guards and packet pins must
be reviewed with the changed bytes before a fresh execution is admitted.

Historical run records remain unchanged. Full R1–R5/M5–M9, target installation,
both-Air behavior, 16K compatibility, performance and maintained releases remain
open.
