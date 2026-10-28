# Common caller custody-descriptor finalizer correction

This separate Source-only proposal contains a close failure in the common
Topmem/Fish caller. The descriptor held in `held['fd']` belongs to
`caller-state.json` custody. The inherited bare close could raise after an
earlier business failure and escape before report return and publication.
The independent parent counterexample reproduced OSError, KeyboardInterrupt
and SystemExit; it did not exercise actual native teardown.

The correction wraps only the existing descriptor-finalization block in a
BaseException handler. The existing `fail` helper preserves the first failure
code and enforces FAIL. KeyboardInterrupt, named Cancelled and secondary
cancellation use the existing latch; SystemExit from this finalizer now also
latches cancellation. A private `recovery.owned_state_close` row records FAIL,
`absence_verified: false`, `retry_performed: false` and `disposition: UNKNOWN`.
The descriptor is popped before its one close attempt and is never retried.
The unchanged PASS gate cannot admit uncertain finalization.

The immutable inputs remain the Topmem receipt
`3331c024e60a7065bdabef241069b33ef14787bd157ffdca57ab598405fa28ea`
and common-caller integration receipt
`535edb90fab340ef32dcc046dd42904308afaa1f645c8152102603855d39d131`.
Their original findings and evidence remain intact. The corrected caller is
`bf795d8849e85e9549f0cfbd45451d1f4d336ac76d8e3e90400152b20655f0a6`.

| Profile | Source files / proof rows including future selected policy | Corrected caller manifest SHA256 |
| --- | --- | --- |
| topmem-v1 | 123 / 124 | `5080efc0b1924274875b78444d1859abe4812bf7952a069e1c3d4c83fa4b06b9` |
| fish-history-v1 | 129 / 130 | `0a49a45ff402d3f653f118c82d6543a7fa7e090d77bcc5beb44b2b3349788472` |

Only `caller/caller.py` and `caller/manifest.json` change in each rematerialized
job. The seven-file caller closure retains the same six Python sources plus
manifest. Source96, both addon manifests, profile constants, commands, clocks,
counter expectations, producer `8e27901c8bf395b0a9145fd5303bb8f35db2cd498ebc86b412a6916aa09fe5a7`
and all other helpers are unchanged.

The independent peer authenticated all 252 source rows and found the entire
caller AST changed solely in the outer close finalizer. Its 15 finite controls
reproduced four old escapes and passed eleven corrected cases, including
compound first-business/close faults, success followed by uncertain close,
sticky cancellation, no descriptor, successful close and one attempt without
retry. Four coordinator controls use the actual handler, finalizer, PASS gate,
publication tail and return AST with inert work and actors: three close faults
reach a saved/published FAIL with the original code, and successful close
reaches PASS. Both actual pure source verifiers pass, binding Source96,
Source18/24 and the six caller files. None of these controls dispatch the
caller or prove actual teardown, signatures, native execution or M2 behavior.

The sealed proposal is
`artifacts/reviews/fish-common-caller-finalizer-correction-proposal-20261013/`;
`final-receipt.json` binds its support index and this guide. The independent
peer receipt is
`60ae390533b020d11319eb2d06c878aea70a934eaaa3931cc02bd39e9140aa6d`.
The retained actual ARM observer candidate remains read-only and unselected.
No tool-policy grant, native Root adoption, workflow dispatch, Git operation,
package installation, hardware acceptance, performance claim or public
admission is supplied by this correction. Independent Root review of this
corrected Source is still required before native adoption.
