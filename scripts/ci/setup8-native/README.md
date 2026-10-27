# Setup8 configuration migration native candidate

This additive source context keeps the exact accepted Setup7 recipe, helper,
producer, legacy lifecycle and its status/recovery assertions. It builds fresh
Setup7 `0.1.0-7` and Setup8 `0.3.0-1` pairs, then requires both pair comparisons,
the held Setup7 installed baseline, and the Setup8 migration lifecycle.
Both recipe profiles produce the ALPM name `cachy-asahi-setup`; the candidate
recipe lives separately in `packages/tools/cachy-asahi-setup8`.

Six owned consumers are bounded: dependency probe, two independent builds for
each profile, and one installed lifecycle. They are retired before the unchanged
owned574 producer. The existing credentials, public input refs, signature checks,
action pins, host/Docker/architecture guards, source proof before secrets, and
95min/2300s/1500s/600s/330s budgets remain held. Public retained evidence is capped
at96MiB. No source preparation performs acquisition, build, installation or
native dispatch. Runtime manifests and receipts remain distinct from hardware
qualification.

`freeze.py --source ABSOLUTE_CONTEXT` seals the finite source closure and stamps
the registered workflow and byte-identical candidate workflow. It records both
recipe input identities, exact delivery case names and preserved dependency
bindings. It includes the original Setup7 manifest and source pins as immutable
inputs. Only the new manifest/pins and its two circular workflow bodies are
excluded from the new pin table. The whole context map also binds those bodies
and modes. Run freeze only after all coordinated source edits finish.

`job.py proof` requires the exact source/workflow commit before any credential
step. `producer.py` validates this source then executes the untouched Setup7
producer in a clean Python interpreter. `run.py` performs offline disposable
native builds and installation; `job.py cleanup` and `retain` enforce ordered
retirement and closed public evidence. This is an unselected, unsigned local
candidate. Generic ARM success would not establish physical M2, actual16K,
performance, recovery media, release signing, or full-project acceptance.
