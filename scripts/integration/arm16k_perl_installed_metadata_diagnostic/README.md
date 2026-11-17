# Opt-in installed-metadata diagnostic successor

Root's r80 initialized lifecycle boot retained an explicit
`RESTORED/installed_metadata` HOLD with `EXIT_STATUS=2`. Its serial log does
not name the individual failed predicate. The public fixture's 3259 metadata
rows pass the static scope, mode, UID/GID, uniqueness and size checks. This
does not establish the actual runtime predicate that failed.

This sibling proposes a diagnostic-only replacement for the exact 8662-byte
Source65 `guest/installed-metadata.sh`, SHA256
`565b6373d9feb9d37db048ad175b3f986af9e3bcf6ede413131f1cb05c508c11`.
It does not modify Source65, the initialized constructor, the executed R2
Source, the CI integration or any Root input. Root must explicitly select the
generated helper into a fresh constructed Source and issue fresh bindings.
No actor or new lifecycle execution is authorized by this proposal.

`instrument.py` requires that whole predecessor pin, retains every original
predicate, and adds observations to its 55 explicit return sites and 14 fixed
stages. `guest/installed-metadata.sh` is the complete generated candidate;
`mapping.DATA.json` maps each return ordinal to its original source line,
category and unchanged exit behavior. Every bare command return saves its
original status before observing it. A full inverse control removes the
instrumentation and reproduces every predecessor byte.

The marker is one fixed line, outside all existing protocol frames:

```
PERL5423_INSTALLED_METADATA_DIAGNOSTIC_V1 CATEGORY=PREDICATE ORDINAL=8
```

The only categories are `PREDICATE`, `COMMAND`, and `STAGE`; their exact
category/ordinal pairs are whitelisted. Return ordinals are 1..55 and stage
ordinals 1..14. No argument, pathname, command text, file body, variable value,
nonce or other arbitrary text is printed. The marker writes directly to the
guest's fixed `/dev/ttyAMA0`, already selected for the actual serial capture,
before Root publishes the unchanged five-field HOLD frame. The controller
retains incoming serial bytes and redacts its selected password. Neither
controller nor protocol changes are needed. A missing/unwritable console is
best effort and cannot change a predicate's exit status.

A STAGE marker reports only progress. In particular, shell failure before an
instrumented return leaves the last fixed stage observation; it does not name
the failed predicate. A PREDICATE/COMMAND ordinal identifies the original
return site. Multiple COMMAND markers can report propagation of the same
nonzero status through nested batching functions. None grants acceptance.

Run the 12 actor-free controls with:

```
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_perl_installed_metadata_diagnostic/test_instrument.py
```

They use ordinary temporary trees and the original synthetic private ALPM
wrapper. They prove the complete inverse/map, generated-file pins, immutable
predecessor refusal, success/query parity, real global-record, metadata,
stat-stream, mode, ownership, hardlink and inventory refusals, preservation
of command status 37 and early shell status 2, unavailable-console behavior,
fixed marker grammar and unchanged five-field HOLD parsing. Fixture operands
and the console sink are adapted only in temporary test copies.

Actual failing-predicate diagnosis, generated helper execution in the VM,
Root Source selection, lifecycle acceptance, native/M2 and release remain
NOT RUN. The independent QMP retirement issue is outside this sibling.
