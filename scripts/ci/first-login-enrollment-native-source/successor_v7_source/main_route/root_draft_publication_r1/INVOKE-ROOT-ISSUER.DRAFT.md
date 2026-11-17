# Root-private issuer invocation DRAFT

The published Source selector is now fixed to
`9a311ae00576196fdfc14b3fdab6676b18429bf0`,
`refs/heads/codex/current-onboarding-staging-v7-20261117-r1`.
The independently supplied Root publication receipt is923bytes/SHA256
`87b12617ce5e7e55f1855cf5ba32a31afd833d44c1a82a1615236e4e64c9a150`.
It proves publication DATA only. It grants no runtime, Root case or lease.
Constructor9e26ce81 and Source205d7/a6/623/991 identity stay unchanged.

`Root-case.DRAFT.json` binds only that Source CID/ref. Its Main selector,
registration ID, case ID, nonce, issuer, approval and clocks remain null.
`admission.DRAFT.json` and `runtime.DRAFT.json` remain exactly unissued scaffolds.
No old Source196 case, admission, runtime, nonce, grant or request may be reused.

Root's private issuer must receive all following explicit operands, with no
Main/HEAD/default-proof lookup:

1. The pinned Source publication receipt and complete Source205 readback.
2. The actual published Main CID/tree AFTER canonical adoption, independently
   read back with canonical launcher68455B/d491..., finiteV2 Source205 Reader
   whole pin, unchanged workflow8949B/4aaa... and the trusted contract code.
3. Actual active workflow registration ID/readback for the frozen workflow.
4. A newly issued Root case, resource admission and current canonical runtime
   custody/live qualification, all bound to this exact Source/Main/group/op.
5. A fresh seven-operand pin set, an already Root-issued canonical request,
   current epoch and final ONCE guard after all qualification inputs.

Only that private issuer may supply issued Root fields. This repository draft
contains no issuer implementation, signing key, approval or live proof. The
existing `contract.qualify` does not issue or authenticate them. Root must use
its established private authority and canonical ONCE procedure.

Invocation contract after those operands actually exist:

```python
# Root-private code; every name below is a required explicit Root input.
assert case_source == "9a311ae00576196fdfc14b3fdab6676b18429bf0"
assert case_ref == "refs/heads/codex/current-onboarding-staging-v7-20261117-r1"
assert actual_adopted_Main_CID is not None
qualified = contract.qualify(
    actual_Root_operand_bytes, independently_selected_operand_pins,
    now=actual_current_epoch,
    core_raw=readback_verified_canonical_Main_launcher_bytes,
    profile_raw=exact_Source205_profile_bytes,
)
# DATA consistency only: Root_authentication=False; lease_observed_here=False.
# Root authenticates/rejoins actual custody and final freshness independently.
# Use unchanged request_raw and the exact two dispatch_inputs through the
# established canonical ONCE operator; this DRAFT invokes no POST or operator.
```

A missing Main adoption/readback, unissued case/admission/runtime, prior intent,
prior run, uncertain outcome or stale live gate remains HOLD. Reconciliation is
never a reason to repeat a possible POST. No native execution or acceptance is
inferred from the publication receipt or this draft.
