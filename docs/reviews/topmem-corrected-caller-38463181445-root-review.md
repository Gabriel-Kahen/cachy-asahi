# Independent retained Topmem03 review: run 38463181445

The retained schema3 caller result is FAIL with first cause `signing-failed`.
Its closed diagnostic is `io-failed / start`, errno 13, Source operation
`PROC_EXE_READLINK`. The authenticated Source maps this opcode to
`os.readlink(path / 'exe')` in the held signer's `process` function. This review
checks that static mapping and validates the exported diagnostic; it does not
replay the traceback probe or the operation. Underlying permission policy,
dumpability and a root-permission-policy explanation remain UNKNOWN. Root's
separate build chat owns the runtime-fix proposal.

Public metadata reports a fresh baseline ACCEPTED8/4/249, receipt
`945776ca5b14cf9b3a35096610d68558f06506293bc887899f8164525a12a438`.
Addon counters are all zero/NOT ACCEPTED, cancelled is false and owned-image
absence is true. These are Source-gated public observations without independent
package archive or individual baseline/signing-journal replay.

Before signer recovery the validated journal projection is OBSERVED/failed,
launch_attempted true, agent_bound false, sticky_uncertain false. After recovery
sticky_uncertain is true; the other fields are unchanged. The recovery result
is FAIL/refused, agent_absent false, keyhome_absent false and cancelled false.
Signer absence remains unproved. No unlaunched/exited-agent or VM-disposal
inference follows. Full raw signer journal is not exported; only the validated
closed projection is retained. Image absence supplies no independent proof of
all signer/process cleanup, and no live cleanup replay occurs here.

Completion SHA256
`c021bf5885066f4a59bccf5ef966c7d8bf09f5f0e1e532ed54d3d3e3b7bc97b6`
authenticates six files, 60,640 bytes. Unique raw-log markers reconstruct the
exact 864/551-byte gzip streams and 1,739/1,036-byte caller/prefetch JSON bodies
with bounded decompression. Retained source-proof and prefetch steps succeed;
prefetch records 501 PASS, zero failed/pending and signature authentication
NOT RUN. No archive contents are executed.

Source is `9710bcf31bf3b1fdeff683eeddc222c6d4d0cfac`, with retained proof
`dedf9e5e74c3827defc284a53f19a7ab524671242e29fb2a87858be32bd0f447`.
Independent checks authenticate all 125 blob Git SHA1, SHA256/bytes and
tree-declared modes: nested Source96/18/6 union123, policy124 and workflow125.
Profile is `topmem-v1`, caller manifest
`3086e42c74ec489105d37f41897b41f2cf49a86bd8b480906d70cb2c6bfdf092`,
caller
`478f6439b4847b514173e29ddb98b32fb157d7472ff2e63c73fa18c358f542b6`.
Signer a0d0 and producer8e27 remain unchanged. Three candidate-adoption rows
match, with declared author03d769/peer2cb2 pins; their raw receipts are not
independently authenticated in this task.

Clock SHA256
`4254232a1137700045fb44ff22255a4aedbcfffcad2f7729d1a8b215e5da0765`
matches caller, prefetch and log cross-pins; raw clock is absent. Raw commit
DAG/tree-object proof and fresh external Source-variable API authentication
are unavailable. This retained review selects no policy and grants no actor
authority.

Fifteen coordinator corruptions are refused by pure extracted schema3 public,
diagnostic, journal and recovery validators plus bounded framing and observed
state checks. Twelve independent binding corruptions are refused. No author
full suite, original tests, source module/providers, GPG/library/native actor,
raw archive execution, account mutation or live cleanup replay runs. Static
Source mapping does not prove a permission-policy cause. Keygen, library and
repository producer execution are not inferred from this parent start failure.

The frozen receipt/index are under
`artifacts/reviews/topmem-corrected-caller-38463181445-root-peer-20261013/`.
Review PASS authenticates an actual failed result with uncertain recovery;
native addon acceptance, both-Air hardware, measurements, trust/release and
full R1–R5 completion remain false. Prior313/392 seals and shared source, Git
and active Root goal are preserved.
