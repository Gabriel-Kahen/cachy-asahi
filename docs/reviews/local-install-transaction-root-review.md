# Independent local transaction review

Read-only source/evidence review, October 12, 2026. **Two execution/receipt
binding gaps remain before strong source admission.** The cooperative x86
synthetic transaction works in the bounded trial described below. This review
does not authorize a release, ARM transaction, complete installation or M8.
Persistent review output is limited to this new document and
`artifacts/reviews/local-install-transaction-root-peer-20261012/`.
Installer/KSM sources, maps, workflows, Git and historical receipts were held.

The [roadmap](../roadmap.md), [development inventory](../../manifests/packages.toml),
[installation route](../port/installation-route.md), and
[software gap review](complete-install-software-gap-review.md) retain the full
installation, authenticated baseline/release selection, both-size M2, first
login, update and recovery requirements. This worker deliberately accepts only
tiny `synthetic-fixture` x86 inputs; real-candidate/selection authority is refused.

## Exact source and evidence authority

The author handoff was checked repeatedly before execution and after the review.
All three original files are mode `0644` and unchanged:

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `scripts/install/local_transaction.py` | 44,991 | `5ef418929ddbe6e387626ac824f292197fb59a73950ef9b0983e4e9e4af7ee53` |
| `scripts/install/test_local_transaction.py` | 38,263 | `9ace5f83d84fe37c5fce57563854e7fef8440ea01a8bb80e2d92430fe169ccb8` |
| `docs/workstreams/local-install-transaction.md` | 9,957 | `1e484601713b924a95038b5356522e2277913ac45a712e09359c1ccbb7aaa9ff` |

The supervisor source is `8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821`.
The existing `/usr/lib/libalpm.so.16.0.1` matches
`da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888`;
the local `alpm.h` matches the declared file/list ABI, required local signature
level and `NOHOOKS` bit 7 / `NOSCRIPTLET` bit 10. No library was installed.

The final checkpoint `438442cf2e775f0eee2cf31b07cdc4c87f8d322529008e2f9b65467973b68199`
is `artifacts/install-local-transaction-20261012/checkpoint.json`; the separate
`tests/checkpoint.json` is `e973a75964b6de7b9eeac3322cf92857b123e594645badbd0f20cc72ecf8921b`.
All seven checkpoint evidence references were independently hash-verified.

The original broad peer review binds historical worker `a0c5ea63...`, tests
`4928f151...` and an earlier guide. The GPG delta peer binds current worker
`5ef41892...`, historical tests `dca22cee...` and historical guide `d7c49771...`.
The supplied delta snapshot is byte-for-byte equal to the final worker. Its
current keyring/command functions match the reviewed correction: ordinary
trust/diagnostic records are allowed, secret/unknown records and private material
are refused, and the bounded merged output/zero exit are checked. Those old
receipts are preserved; they are not relabeled as a review of the final test and
guide bytes. This review independently inspected the final three files.

## Findings

1. **Bind child worker execution to captured source bytes.** At
   `local_transaction.py:652–655`, the parent runs Python against
   `Path(__file__).resolve()` without capturing that worker or supplying a
   worker-source pin. The engine specification digest binds inputs, not code.
   The supervisor is correctly hash-captured and compile-executed, and the
   explicit test/barrier loaders avoid repository bytecode fallback; the actual
   worker launch still reopens a pathname. Source hashes before/after a trial
   establish cooperative stability, not enforced execution of the expected
   bytes during replacement. Use an independently pinned, captured-source
   launcher and retain the correct runtime binding. No replaced-code or escape
   exploit was executed in this review.

2. **Retain evidence-directory identity through promotion and failure revocation.**
   `save():153–161` and `execute():662–677` open/replace/unlink through paths;
   `OWNED_OUTPUT` retains a path, not custody of the original directory. An owned
   model published the ordinary modeled PASS, renamed that directory, created
   an owned replacement, then raised a publication error. The parent returned
   FAIL and wrote FAIL to the replacement, while the renamed original retained
   its PASS and final installed lock. This is a modeled receipt-custody defect,
   not an actual package-manager escape or evidence of a successful failed CLI.
   The existing final-status/CLI-exit/lock rule still rejects the failed attempt.
   Retained directory descriptors, identity guards and revocation of the
   original authoritative nodes are needed to refuse replacement rather than
   redirect writes or leave stale authority elsewhere.

The child environments at lines 499 and 651 explicitly set `HOME` to workspace
and scratch. They do not change the host process environment or trust store,
but conflict with the current instruction to preserve `HOME`; reconcile this
separately using inherited `HOME` and explicit private GnuPG/temp/config paths.
No functional host-trust mutation was inferred from that assignment.

## Independent controls and actual execution

[Independent controls](../../artifacts/reviews/local-install-transaction-root-peer-20261012/independent-controls.json)
record **9 checks, zero failures/errors/skips**: eight modeled contract/keyring,
export/cancellation/deadline/custody controls and one actual captured-source
namespace barrier. Models mock child completion; they do not initialize libalpm
or interrupt a C commit. Their fresh TEST key generation/signing is setup,
not an installed transaction.

The actual barrier observed changed user/mount/PID/network namespaces, mapped
UID 0, `NoNewPrivs=1`, effective/permitted/bounding `0x400cb` with no inheritable
or ambient capabilities, and `EPERM` for the seven invalid-FD outgoing-IPC and
io_uring probes. Only the owned evidence marker persisted; an owned outside
sentinel write returned `EROFS`, host namespaces/sentinel bytes stayed unchanged,
and guest tmpfs data was absent after exit. It initialized no libalpm handle
and performed no package commit. This is the already-audited barrier control,
not an arbitrary escape attempt or complete adversarial sandbox proof.

[One independent signed-pair receipt](../../artifacts/reviews/local-install-transaction-root-peer-20261012/independent-signed-pair.json)
records **one actual x86 synthetic pipeline call and accepted commit**, zero
failures/errors/skips. An owned fresh `0400` capture of unchanged worker, tests
and supervisor bytes was used; this external cooperative capture does not fix
finding 1 in the worker interface. The unchanged namespace engine authenticated
the fresh public TEST key and signed dependency pair, prepared/committed through
the pinned existing libalpm, checked both installed payloads and the complete
two-package inventory, exported the copied root, and returned final parent PASS
with CLI exit 0 and the expected installed lock. The original fixture seed did
not acquire the installed payload. The original sources and captured copies
were hash-identical afterward. No host package database or live system was a
transaction target; no privilege bypass or additional libraries were used.

## Retained author evidence and remaining work

[Passive reconciliation](../../artifacts/reviews/local-install-transaction-root-peer-20261012/retained-evidence-audit.json)
verified the retained 38-check receipt and all 22 pipeline call records: 19
models, 17 actual synthetic pipeline cases, one actual barrier and one real
owned sleeping-child timeout. The calls include 11 entered commits, 10 accepted
commits, 9 expected FAIL and 3 expected REFUSED. All 19 retained non-preflight
result files match their recorded reports; all accepted locks match the exact
after maps, and failed/refused calls retain no accepted lock at their recorded
output paths. Protected refusal/removal cases have multiple setup/subject calls;
22 calls are not 22 separate test methods.

The source retains local-only package loads, DB locking/dependency/conflict
checks, actual before/prepared-add/remove/after comparisons, protected versions
and payload preservation, signature/primary-subkey/SHA-2 checks, finite decoded
archive/projected-link bounds and measured capacity. The child emits only a
provisional receipt/lock; parent export/database/ownership/payload checks and
clean returned exit are necessary for final promotion. Read-only inherited
mounts, exact safe devices, IPC restrictions and capability reduction precede
authentication and libalpm initialization. These positive checks do not close
the two identity-binding findings above.

Actual interruption inside libalpm C commit remains NOT RUN. Parent late
cancellation, plan/post-inventory poisoning and export corruption in the author
suite are modeled; the real timeout concerns a sleeping child. Production key
custody, adopted 624-package selection, ARM execution, hooks/scriptlets,
first boot, a deployed installer, M2 hardware and full installation/update/
recovery acceptance remain unestablished. Correct the bounded source/receipt
findings, then source-review the resulting delta before coordinator adoption.
