# KSM producer RPC observations independent review

Disposition: **source-ready for coordinator binding and committed proof**;
no material blocker was reproduced. This is an observation-only change.
Actual KSM3 run 38286983453 remains FAIL/BrokenPipeError, producer mutation
UNCERTAIN and cleanup FAIL. Its private journal/logs are unavailable and the
underlying cause is UNRESOLVED. No transport fix, native compilation, KSM
activation, installation, M2/16K or performance acceptance is established.

The exact reviewed checkpoint is
`artifacts/reviews/ksm-producer-rpc-diagnostics-20261012/checkpoint.json`, SHA
`43319e5f7cea149aa769d73f3eca0ef98598507d541095a9db95ee209139f353`.
The peer verified all 152 copied source rows by hash/size/mode, eight owned
source/guide rows against current bytes and twelve indexed artifact hashes.
There are seven changed packet rows and 145 unchanged against committed
`f7ee4a7e0cf1145e15970f13daa1ec76ef5f567e`; the new diagnostic guide is outside
the packet. Exact reviewed source identities are retained in the peer receipt.

## Actual bounded validation

A fresh source copy passed **279 tests, zero failures/errors/skips**, with
isolated Python, bytecode disabled and ResourceWarnings treated as errors.
The suite includes fake backend/RPC, owned temporary Unix sockets/Git, bounded
harmless Python children and signal controls. No Docker, native compiler, GPG,
package actor, download or host system mutation ran.

Additional independent controls use real closed local pipe writes across eight
completed/refused request and completed/closed/partial/cancelled reply schedules.
Exactly one request occurs with no retry. Returned request code 0 remains an
observation when the reply fails. Earlier request refusal survives a later broken
reply and cleanup error; first and last failures remain distinct. Partial reply
and cancellation preserve the original failure behavior. Raw private paths,
tokens, IDs, output and error messages do not appear in the projection.

Ten return-code cases confirm nonboolean bounded codes and exact output hashes;
oversized/unknown source fields remain unobserved or UNKNOWN. Counter saturation
stays bounded at 4096 and does not retain a request history. Cleanup controls
retain returned absence flags separately from sticky owner failure; those flags
cannot clear uncertainty or grant overall cleanup/PASS.

Three additional harmless-process schedules distinguish naturally observed 7,
a callback BrokenPipeError before natural poll, and an error after owned cleanup.
Natural return 7 retains natural poll, Runner return and reaped code separately.
Thrown paths retain Runner return as null even when cleanup reaps the child.
Cleanup failure retains the originally observed poll without inventing a Runner
return. Every owned child is reaped and its group is absent after the control.
These process observations are not compiler or actual producer acceptance.

## Preserved authority and source behavior

The schema is closed and bounded to 4 KiB. It contains request count/ordinal,
candidate command family and transition, last CLI begin/return, last request
return, first/last finite failure, producer observations and existing cleanup
return flags. Candidate family is an issued boundary label, not command-policy
validation. CLI begin and return ordinals may differ when a later call throws.
Unknown/unobserved codes are null, never guessed zero. Only bounded output
lengths and SHA256 are retained; raw argv, tokens, identifiers, paths, output
and exceptions remain private.

Independent ordered AST comparison with the exact committed baseline preserves
140 broker, 142 runtime and 105 executor selected original guard/actor/clock/poll/
cleanup/acceptance call expressions. Source inspection confirms instrumentation
around existing operation and return sites, with no added query, poll, callback,
retry, signal, deadline reset or removal action. The original source/baseline
guards, producer mutation states, exception propagation and acceptance/export
gates remain. The author's broader AST proof was also hash-verified. AST checks
support the causal fixtures; they do not prove actual daemon behavior.

The current production packet SHA
`0623a4d68b736c85128b55686347921ab50fc45c9105785c54f8b74206177435`,
required-paths SHA
`47e1f0eaa37ec4c9c90baa9742a56a51cc83c4f60ab26c19b65b2a8a55101e34`
and workflow SHA
`ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae`
remain unchanged. The external proposed 152-row packet SHA is
`68c1bb02ea10317cb6b65140fc133fab1c9e2e834de11a7bfd665ba4abbfd179`,
with 2,284,026 selected source bytes. Root must rebind those seven rows and verify
the committed source before production use. Diagnostics do not enter the
unchanged package-publication acceptance contract and cannot promote old FAIL.

Peer evidence is in
`artifacts/reviews/ksm-producer-rpc-diagnostics-root-peer-20261012/`.
No implementation, source map, Git or native dispatch changed in this review.
All ten updater held sources and the four kernel Labels sources/guide remain
untouched. Corrected native execution and explanation of actual KSM3 remain pending.
