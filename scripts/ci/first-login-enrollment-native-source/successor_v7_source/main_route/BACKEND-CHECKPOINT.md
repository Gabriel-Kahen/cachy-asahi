# Source205 backend checkpoint

Use the registered workflow's `backend` stage for the first real Native248
transport checkpoint. Public14 precedes Native248, which has staging command
ordinal 2. A successful transport can be observed in the retained Complete517
receipt after staging scope retirement and assembler intake. The workflow can
continue into backend builds after this checkpoint. It has no transport-only
stage or stop condition.

## Prepare the unissued caller

```sh
python3 -I -B checkpoint.py --selection /absolute/selection.json --selection-sha256 SHA256
```

The canonical JSON selector has top-level fields `schema` (integer `1`),
`kind` (`SOURCE205_BACKEND_DATA_SELECTION_V1`),
`selection` and `files`. `selection` contains `source` (`cid`, `ref`), `main`
(`cid`, `tree`) and the positive integer `workflow_id`. `files` maps each role
to an absolute local `path`, byte count `bytes` and whole `sha256`:

- `publication` is Root's retained complete Source205 public readback.
- `source196_close` is Root's retained consumed Source196 HOLD closure.
- `registration` is the observed active workflow registration metadata.
- `profile` is the exact Source205 unissued profile.
- `launcher` and `provenance_operand` are the adopted Main launcher and
  matching frozen v7 body.
- `reader` and `workflow` are the selected Main Reader and workflow bodies.

Select the checkpoint and input pins independently of the files under review.
The result records the observed adoption and preserves the older request
generator's unissued template and status. The live registration, lease,
approval, nonce, grants, and run selectors are unresolved at preparation.

## Qualify the Root-issued inputs

Root supplies the seven independently pinned operands from the [Main route
contract](README.md) to `checkpoint.qualify_backend`, along with the unissued
checkpoint and its independent pin, the exact Core and profile bytes, and the
current epoch. The wrapper requires the static Source, Main, operation, group,
resources and workflow selection from the checkpoint. It preserves the issued
request bytes and requires backend assembler `products={}` and `retention=null`.

At the dispatch boundary Root needs a new case, held reservation with zero
active and pending work, canonical lease identity and FD/PIDFD custody, and two
converged complete live run and job sweeps. Registration, Source/Main readback
and exclusive ONCE guard observations must be current within 120 seconds. The
guard follows all other observations and requires a fresh output, no previous
intent or POST and no uncertainty. Root supplies both assembler trust records
and the exact 21 HTTPS redirect decisions. The hosted caller receives its 22
secret values through the workflow's existing secret bindings. Qualification
returns data for Root's existing ONCE operator. If a POST may have occurred,
reconcile that run before any further dispatch work on the case.

## Read the terminal checkpoint

After the one run reaches terminal state, Root selects and whole-pins the issued
case and request, the run metadata, complete attempt job and artifact
inventories, and the original `current-onboarding-control-<run>-1` ZIP. Capture
the original once under Root's bounded intake. Preserve the ZIP bytes for the
reader. If there is no Original, retain the metadata and leave the checkpoint
unverified.

```sh
python3 -I -B terminal.py --selection /absolute/selection.json --selection-sha256 SHA256
```

The canonical selector has integer `schema: 1`,
`kind: SOURCE205_BACKEND_TERMINAL_SELECTION_V1`, `ids` containing the positive
integer `run`, `job` and `artifact`, and `inputs` containing `case`, `request`,
`run`, `jobs`, `artifacts`, `archive`, `core`, `profile` and `reader`. Each input
has an absolute local `path` and a whole `pin` with `bytes` and `sha256`. The
terminal consumer reads the local ZIP in memory under member and expansion
bounds.

- `CHECKPOINT_NATIVE248_TRANSPORT_RETAINED` joins the Native248 command to the
  Complete517 receipt, staging retirement and input intake. The original
  Native248 transport bodies are retired by the hosted stager.
- `HOLD_NATIVE248_TRANSPORT_DIAGNOSTIC` retains the finite v2 diagnostic of an
  ordinal-2 Native248 command failure. A null nested transport packet leaves the
  child cause unknown.
- `HOLD_NATIVE248_CHECKPOINT_NOT_RETAINED` records a joined terminal failure
  whose evidence cannot establish either checkpoint result.
- `HOLD_TERMINAL_INPUT_REFUSED` covers inconsistent or unsafe input.

Backend, package, image and hardware acceptance still require their own evidence
and the maintained Reader.
