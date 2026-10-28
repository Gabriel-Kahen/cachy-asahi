# Maintained KSM16K sharing source factory

This explicit factory upgrades the complete pinned scalar605 runtime into the exact sharing608 runtime, then emits the existing sharing628 hosted source. The ordinary `ksm2-generic16k-vm-hosted/prepare.py` remains the scalar605 emitter.

```sh
python3 -B scripts/ci/ksm2-generic16k-sharing-hosted/prepare.py \
  --runtime /absolute/path/to/pinned-scalar605/runtime \
  --output /absolute/path/to/fresh/source-default
```

Defaults retain NULL native/kernel selectors and NULL actual source/ref/run. To reproduce the reviewed component-selected source, Root must explicitly provide its existing selection with `--binding /absolute/path/to/selection.json`. The profile accepts only that exact reviewed component selection; it grants no native/kernel/VM acceptance and never selects an actual run.

The emitter validates all605 input leaves, replaces19 and adds3 from its maintained `runtime/` payload, and preserves the other586. These deltas include the sharing experiment, required advice-capable kernel profile, advisor bracketed-enum format, and pinned run2/full_scans epoch fix. It consumes six changed hosted templates in `templates/` and ten byte-held templates from the scalar sibling. Every payload is referenced and pinned in `profile.json`. Changed profile/source inputs refuse before output creation.

The entire emitted default or selected628 map must equal its profile before output is written. This preserves every existing source, nonce, ownership, FD, process-retirement, network, ARM16K and restoration guard, all clocks, and original workflow stamps. The emitted source includes its original608 self-reproducing factory. No runtime or emission path references development artifacts.

Run the focused controls with an exact scalar605 fixture:

```sh
KSM_SHARING_SCALAR_RUNTIME=/absolute/path/to/pinned-scalar605/runtime \
  python3 -B scripts/ci/ksm2-generic16k-sharing-hosted/test_factory.py
```

Controls include exact default/selected628 emission, original608 and scalar605 self-reproduction, pre-output tamper/selection refusal, all14 original sharing/owned-FD controls, and the exact partial scan-epoch relation. They do not construct a passing VM receipt, access host KSM sysfs, or run a VM. Source emission carries no new performance, M2, native execution, hardware, interruption or release claim.

The optional `--controlled-interruption` flag selects the maintained sibling
`ksm2-generic16k-interrupted-sharing-hosted` factory and emits its fixed637 source.
It adds a controlled owned-controller SIGTERM case and immutable complete574
cache preparation. The ordinary command above continues to emit the exact628
source. Component binding is still explicit and actual source/ref/run stay NULL.
This source option grants no native interruption, scalar interruption, M2,
performance or release acceptance. See the sibling README for exact scope and
unchanged budgets.
