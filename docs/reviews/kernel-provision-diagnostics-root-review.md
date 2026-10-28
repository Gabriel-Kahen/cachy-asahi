# Kernel provisioning diagnostic-2 independent review

Disposition: **source-ready for committed bootstrap proof**, with no material
blocker reproduced in this bounded review. Corrected native execution is NOT RUN.
Actual kernel trial 38279898941 remains FAIL, its inner cause UNKNOWN, cleanup
FAIL and baseline preservation/owned absence UNVERIFIED. Compiler invocation,
kernel runtime, installation, M2/16K compatibility and performance are not proved.

The reviewed author hold is
`artifacts/reviews/kernel-provision-diagnostics-20261012/held-receipt.json`, SHA
`39ba7d93f0c249874e4bf1202374342328d21e2caf98feaa7dc9322e615690e5`.
All twelve source hashes, lengths and modes plus the guide match its held sibling
and current source. The guide was finalized after the author's earlier test
capture; the peer took its exact held bytes, rather than treating that earlier
guide snapshot as the hold. Source/tests were otherwise unchanged.

## Observed behavior and independent checks

A fresh private source capture passed **78 owned stage tests and 205 job tests,
zero failures/errors/skips**, with ResourceWarnings treated as errors. These
include private fake CLI processes and Unix HTTP fixture responses. They perform
no Docker, GPG, kernel compilation, network acquisition or system installation.
The initial peer job harness printed all 205 tests OK, then failed writing its
own output because the tests changed `sys.argv`; preserving the harness output
path before running tests produced the final exit-zero 205 record. Both logs are
retained. This was a peer harness error, not a source failure.

Independent probes check 900 HTTP/process return-slot and type combinations
against both child and parent validators. Booleans, wrong ranges and process
returns in the daemon slot are refused; the two validators agree. A separate
schedule retains returned create exit 125 through a failing post-query daemon
check, keeps that primary snapshot through a cleanup signal/error and a new
action, and removes an unknown private path from public observations. Failure
snapshots are deep copies. Returned CLI status, parsed daemon HTTP status,
syntactic CID observation and attached-start return remain distinct observations;
they establish no compiler invocation, accepted worker result or deletion authority.

Inspection confirms that actual CLI status is recorded before existing local
and daemon postchecks. HTTP status is recorded after the existing response
parser returns, before body/metadata acceptance. New action scopes reset only
current observation; the first primary and cleanup failures remain sticky.
Checkpoint, launch, journal, inspection and finalization errors use a closed
gate/label projection; unknown exception text becomes UNKNOWN. Private binding
and public projection retain their total 4 KiB limit. The parent uses the same
immutable captured child receipt for diagnostics and acceptance, and COMPLETE
refuses observed primary or cleanup errors. Existing cancellation, source
deadline, scoped cleanup and acceptance controls remain independently required.

Static comparison to the retained baseline preserves all 75 broker, 43 image and
31 original stage guards. The eight broker, nine image and three stage actor
call expressions remain exact and in source order. All seven broker, three image
and two stage clock/Runner call expressions are unchanged. Source inspection and
fixture schedules show no extra daemon operation, changed command/capability,
timer reset, pruning, borrowed ownership or cleanup waiver. This comparison
establishes source preservation, not actual daemon behavior.

The current receiver projects the actual historical schema4/diagnostic1 failure
to identical compact canonical bytes, SHA
`db71b7b81fb32f3fcd44e16242e467d3c4f4b6d70faa228b16602d7938eb6ed2`.
It does not reinterpret PROVISION_COMMAND/INVALID_DATA as an identified inner
cause. New diagnostic2 is a separate exact schema, not an optional arbitrary
dictionary or a replacement for old evidence.

## Coordinator rebind reviewed

The proposed stage 26 SHA is
`387e72fc836103b9654e65ee9e186369ebe34e240f9603f8b9779f6f317e2b63`;
packet 117 SHA is
`9ca9414c8461d2a134d68390381755811b0d61aa9097ef23b747ef91f138dbf0`,
with 2,012,976 selected bytes. All current row hashes, modes, lengths and nested
stage rows match. A second fresh 117-file copy reproduces the exact authenticated
closure with no bytecode. Comparison with committed historical
`bae171ea0dd6c4c5c492403dc112b2dcbdb79953` confirms the same source paths,
exactly 15 changed packet rows and nine changed stage rows, matching the
coordinator's adoption record. Workflow SHA
`1ff6d9c5711b527992499405e23130f10924d524514322942de199b3deabfba4`
is unchanged.

FDK evidence dependency SHA
`27d16ce1a89d949075b0fe85072575883de6e9021a4902747c4b8ed44ed71b27`
is selected under the coordinator's explicit prior independent seven-file FDK
review receipt `34e7ab164f95fa61dccc43b8940499245df1e32f9f920d45ee201bde62b7477a`.
This peer authored that FDK code and does not count its own review as independent
dependency authority. No FDK dependency or other implementation was edited here.

Evidence and exact reviewed source bindings are retained in
`artifacts/reviews/kernel-provision-diagnostics-root-peer-20261012/`.
A newly committed Git/bootstrap proof and subsequent actual native trial remain
pending. This review authorizes no native success, cleanup success or hardware claim.
