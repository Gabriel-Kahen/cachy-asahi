# Keyless early cancellation Source successor

This is a narrow Source correction to frozen author packet
`d473bd9801781c7c57df39fb0cee0e2e91ed0ae2e3c98563df73e4474398df0a`.
External Release receipt
`a84e08c55d0fc9ee4b6eb44c9b30f53f00b7cc650eebe7da28252e802e11c03b`
found one bounded defect: the first authenticated Source guard could raise the
exact selected `Cancelled` before the entry installed its cancellation sidecars.
The closed caller then reported `PROOF_REFUSED` with `cancelled=false`.

The new whole fifteen-file Source selection lives in
`artifacts/reviews/test-signer-runtime-early-cancel-successor-20261014/`.
Its `proposed-source-pins.json` retains fourteen exact bodies and replaces only
`keyless_entry.py`, target `scripts/ci/test-signer-runtime/keyless_entry.py`, with
14933-byte SHA256
`7792dc24dbbcab59181c4603aa54b6ae2e958a5689a3c2cd1b8d3540b22447d1`.
Root must authenticate the whole selection and perform canonical adoption and
registration separately. This packet makes no committed Source or runtime claim.

After the existing admission, module identity and original frame checks, the
entry binds the selected cancellation class. The first guard and pure custody
constructor share a small exception envelope. Exact selected cancellation and
`KeyboardInterrupt` install strict true cancellation sidecars; the same exception
is re-raised. Unrelated errors retain any existing sticky markers and first cause.
No allocation, actor, cleanup, or absence observation is invented on this path.
The complete post-constructor lifecycle and closed failure projector are unchanged.
Original work/cleanup endpoints remain entry+8/entry+13, clipped by their original
outer endpoints. Descriptor retirement in the inherited probe is unchanged.

Author validation authenticates the original 62 leaves and 119 inputs, the
external 252 leaves and 196 inputs, and the fifteen selected Source files, with
zero current drift. The 77 inert early controls reproduce the frozen defect,
check guard and pure constructor cancellation, preserve exception identity and
falsey errors, reject unrelated cancellation classes and bad module graphs,
preserve preexisting sticky markers, and prohibit actor calls. The original 29
inert regression checks also pass against the new whole Source selection.
Independent review and its exact seal are recorded in the successor receipt.
These are finite Source and synthetic-control results, not native execution.

P0 independently passed the external Source review. Its published three-file
Source92d00 and separate live SDK Session routing successor remain distinct from
this keyless correction. The full signer API bridge, 26-test native matrix,
ABI16.0.1 trial, M2/16K compatibility, installation and performance remain untested
or unfinished. R1-R5, M5-M9 and A01-A15 retain their existing acceptance requirements.

No keys, GPG commands, compiled outputs, native constructors, grants, Source
registration, Git operations, dispatch or system mutation were executed here.
