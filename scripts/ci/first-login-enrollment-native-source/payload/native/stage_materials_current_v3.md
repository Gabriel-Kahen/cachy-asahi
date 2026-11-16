# Complete517 hosted material staging — unissued capability

`stage_materials_current_v3.py` implements the missing acquisition/cache phase
before input assembly and the existing launcher. It is not wired into a workflow
or launcher. No Root grant, Source freeze, network, secret injection, privileged
actor, GPG, ALPM or native role was executed during implementation. The executable
launcher remains byte-identical at42857 bytes / SHA256
`bf25c8b7d4bc58e9899f122472175b9847e5f2784445b8796dbd959e0681ce8d`.
The separate TEST-only fixture update is `3af5e522`: exact input fixture7a1719be /
`ee72d05d380caa6c49e7b0601a3ac641d55c352478f35d7d251f14c6a0dd6b8e`,
actual committed image676528 and actual committed context efa5a268. No matching
validator replacement or private provisional image is used.

## Exact API and caller sequence

```python
S.stage_materials(
    source_root=source_root,
    delegation_raw=Root_selected_delegation_bytes,
    delegation_sha256=Root_external_delegation_sha,
    context=actual_poststart_context,
    grant_raw=Root_selected_staging_grant_bytes,
    grant_sha256=Root_external_staging_grant_sha,
    output=mounted_domain / ('cachy-current-materials-' + nonce),
    secret_provider=S.OneShotSecrets(explicit_owned_dict_of_exact22_values),
    base_lock=whole_ref_to_fixed_original_lock,
    bootstrap_profile=whole_ref_to_fixed_signed341_plus8_profile,
)
# returns {receipt, references, assembler_fields}; still no Root acceptance
```

The public `stage_materials` entry always closes its one-shot secret mapping,
including authorization failures. It validates both external hashes before
selected imports, then uses the whole descriptor-selected context's actual
`validate_delegation`, `source`, `validate_context`. The Source, context, policy,
nonce, grant and executing program must join. The external hashes must come from
the Root once operator; hashing a self-asserted grant is not Root authentication.

Before entry, the future caller must capture actual bounded public jobs context
(one fixed metadata query under the context policy), provision the explicitly
Root-selected finite filesystem, enter the exact finite physical scope with the
held process supervisor, apply rlimits and drop to the ordinary native ARM64
runner UID. The module never invokes sudo, formats/mounts storage or creates its
own scope. Missing actual scope/storage/helper/secret/grant facts HOLD before
acquisition. Returned DATA must not be handed to native consumers until the
caller observes natural controller retirement and actual scope absence.

After complete517 verification and scope retirement, pass `assembler_fields` to
the separately reviewed actual `inputs_current_v3` assembler. It still requires
actual Root official/TEST trust, current signed project materials and the other
stage-specific public proofs. Then compare the resulting actual outer wrapper
against the Root-selected launch request and invoke the existing launcher. No
unknown future image ID, producer observation or Root image acceptance is filled.
This caller/workflow wiring is deliberately not included in this change.

## Source/helper authorization

In addition to existing `context`, `image_executor`, `hosted_launcher`, policy,
Source map/lock, factory profile and baseline349 inventory, the constructor must
close these exact program roles. The new executing program is `materials_stager`.
No old frozen helper is edited. Relative paths are preserved because the held
helpers resolve their own reviewed dependencies there.

| Role | Source-relative member | Whole SHA256 |
|---|---|---|
| `base_inputs` | `scripts/ci/first-login-enrollment-native-source/payload/native/base_inputs_current_v3.py` | `9e35c3ae6c3e1e9596f54806279d05cc77ae6a2cb5fb284d469df549e1d3abc6` |
| `private_seed` | `bootstrap/scripts/ci/old_four_seed.py` | `a14e0318549d24a9bc91ceeb03ec2c1fa2d12f2b3a4f9b0a4cccfb64be34b2b7` |
| `material_transport` | `native/retained_transport.py` | `46708771ccb93bbfe22c4f449f3a54052bc9494c4fb572e10b0853b5aa47bdef` |
| `retained_transport_core` | `scripts/maintenance/retained_git_transport.py` | `9b90c423fd67c261d8be1dddd8450df5b927b6dbaba9972c4daff8c0da2836b7` |
| `owned_process` | `scripts/virtual/owned_process.py` | `83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f` |
| `retained_prepare` | `bootstrap/scripts/ci/setup6-retained-helpers/prepare.py` | `6c688c315cb962c641b8c0b1d9d88f94778d57ae19bcef251e88e49cb4be6316` |
| `retained_prefill` | `bootstrap/scripts/ci/setup6-retained-helpers/legacy_prefill.py` | `05a91a91efd69b3b2e06561f5bbf08bdbb105998d42dbf133e75fd1fe25945ac` |

Material roles `retained_carrier_profile` and `retained_prefill_profile` select the
unchanged `carrier-profile.json` and `legacy-prefill-profile.json` beside prepare,
with hashes4089fd79… and9cc82d4e… respectively. These and the original helper pins
are checked against the genuine Source139 factory profile, whole body
`ad874751a48cfd7e7d94f5d38d79caa138679be067cb113ead35150f0d3c78fa`.
The original lock remains328101 bytes/beca39e0…; bootstrap profile168201 bytes/
2c42c705…; baseline349 inventory6800 bytes/57998119… . The maintained provider
checks all exact341+fixed8 metadata/architecture/version joins before acquisition.

A further material role `public14_profile` is the canonical3024-byte DATA returned
by `encoded(public14_profile())`, SHA256
`5fe4761bc96d21ec388322ead3b97c735d2f689c38061c560afc90a2143de346`.
Its table is derived from actual committed public Source
`04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd`, closes all18 original files including
14 input leaves, and pins seed a7857658… / index a388c8c8… . This is closure metadata
for the existing seeder, not a new seeder. The maintained native248 profile closes
all1154 files /1046432165 bytes of actual Source
`ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad`. Missing/different Source roles or profiles
are named HOLD conditions, not an invitation to download unreviewed code.

The constructor must add these dependencies to a new closed Source when Root
selects it. Existing Source139 and existing project recipes/owners remain held.

## Runtime proposal and conditional grant

Root must explicitly select `capability.allow_material_staging=true` and the whole
`policy.material_staging_current_v3 == PROPOSAL`. This proposes a separate
3600-second physical scope inside the **same** whole7560-second Root lifetime,
not an extra3600 seconds. The delegation lifetime, and explicit maximum delegation
and context-age limits, must be7560 seconds or less as enforced in the program;
context maximum age is selected exactly7560 so each internal child can replay the
same authentic context across the bounded staging phase. This is an explicit new
policy selection; an older shorter context TTL is never silently waived.

The scope name is `cachy-current-materials-<nonce>.scope`, with512MiB memory,
CPU1 (100000/100000),64PIDs,swap0, RuntimeMaxSec at most3600 and no later than actual
Root expiry. Controller AS is an explicitly proposed2GiB virtual ceiling, CPU hard ceiling3600,
core0. Physical memory remains512MiB. This separately reviewed new-role AS proposal
allows room for the >1GiB immutable Git carrier pack; no actual transport memory
qualification is claimed and old launcher/executor512MiB AS caps are unchanged. The helper checks
actual kernel membership/limits, PID/start identity and actual systemd activation/
runtime before acquisition. Root expiry is capped by delegation-issued+7560; a
later launcher cannot reset that Root expiry. Staging records the actual remaining
absolute monotonic deadline for its caller. The later7200-second stage remains a
ceiling and may have substantially less available time. The caller must explicitly
adopt the same deadline/expiry when composing the pipeline; no full7200 claim is
made after consuming staging/prerequisite time.

The caller-provisioned mounted DATA domain is selected by the grant, named
`cachy-current-material-domain-<nonce>`, mode0700/caller-owned, on a separate actual
filesystem. Actual statvfs must report finite total capacity at most8GiB and20000
inodes, at least6GiB/18000 nodes free; zero/unreported inode capacity refuses.
A root-owned or ordinary unbounded host directory is not silently accepted. The
caller retains storage custody through consumption and owns eventual close-only
unmount/disposal. Resource review must account for this input storage alongside
later image storage; this is not an old storage-policy waiver. Census bounds all
staging data/logs/files continuously and receipts are capped at2MiB each.

The canonical staging-grant object has exactly these keys. This is an unissued
schema sketch; actual selectors remain NULL:

```json
{
  "schema": 3,
  "kind": "ROOT_CURRENT_COMPLETE517_STAGING_V3",
  "issuer": "Root",
  "approved": null,
  "source": null,
  "ref": null,
  "source_lock": null,
  "nonce": null,
  "policy": null,
  "issued_epoch": null,
  "expires_epoch": null,
  "redirect_urls": null,
  "secret_provider": null,
  "scope": null,
  "storage_parent": null
}
```

An issued grant must select scope `COMPLETE517_PUBLIC_DATA_ONLY` and provider kind
`CALLER_ONE_SHOT_EXACT22`. Source/ref/map/nonce/policy must match the actual context.
`redirect_urls` must explicitly name all21 fixed parent/supplement files, each with
0..2 exact reviewed HTTPS redirect URLs (an empty list explicitly forbids redirects).
No broad domain wildcard, HTTP credential, query credential, token, cookie or
Authorization header is accepted. Only fixed frozen original URLs plus those
exact Root aliases are used, at most3 requests per file/63 requests and42 redirects
for these downloads,90 seconds each, no retry. Whole expected lengths/hashes,
including the0-byte revoked public file, are checked before references return.

## Actual acquisition order and secret boundary

The runtime obtains its vectors from maintained `base_inputs_current_v3.acquisition_plan`.
It invokes `native/retained_transport.deliver` for public14 and native248 using
unchanged400-second shared fetch /480-second transport /500-second outer clocks.
These perform their original two filtered Git fetch roles per carrier, whole raw
commit/tree/object/profile/filesystem proof, no checkout, history, lazy fetch,
credential helper, extra authorization header or Git redirect. No private chunks
are passed to either Git role. Exact fetched original seeds execute only after
that proof. No arbitrary fetched program is selected.

Next, one private child invokes the unchanged
`old_four_seed.seed_current_build_cache(cache, fixed_lock_sha)` under its original
60-second seed deadline, with a65-second outer custody budget. A caller-owned
`OneShotSecrets` object owns exactly the22 existing chunk values: old-four
JBIGKIT2/JBIGKIT_SIG1/LIBTIFF15/LIBTIFF_SIG1 and retained bubblewrap PACKAGE2 /
SIGNATURE1. `secret_names()` exposes the complete exact list. The only additional
private-child fields are the public constants `CACHY_OLD_FOUR_SCHEMA=1` and
`CACHY_OLD_FOUR_SOURCE_EPOCH=1791748800`. The stager never looks up ambient secrets,
credential stores or private homes. Its explicit injected dictionary is cleared
on success and failure, including failed authorization; the frozen child removes
all matching environment entries. This is name/reference cleanup, not a claim of
cryptographic memory erasure.

Private values never appear in argv, receipts or raw retained diagnostics. They
reach one minimal-environment private child only. Every other child has a new
minimal environment with no matching secret names. The helper does not fetch
secrets. A future separately reviewed workflow/caller must explicitly bind these
22 GitHub secret names and capture them into this ownership boundary; no such
binding or secret use was performed here.

The proven public14 seeder then runs unchanged. The original retained
`prepare(..., mode='native248', original_deadline, git_dir)` performs its complete
1154-leaf source/Git proof and original496-member native package join, preserving
all existing private/public cache identities. Only afterward are the5 original
parent rootfs/keyring leaves and16 supplemental archive/signature leaves fetched.
The original provider finally verifies the exact517-member cache and produces
`assembler_fields` with group sizes498/16/3. GPG/trust/ALPM remain separate later
gates; a downloaded public keyring is not trust admission.

There are at most27 outer commands. Internal child audit counters bound public
transport to32 subprocesses, native transport1170, retained prepare1160; together
with outer commands this is below2400 controlled Python Popen commands. Git
internal subprocesses remain inside the same physical PID/CPU/time domains; this
is not a claim of an observed cumulative operating-system fork count. Fixed original seeds have no subprocess
allowance. Child process trees share the physical staging cgroup; direct children
use unchanged held PIDFD supervision, WNOWAIT-before-transfer and natural complete
retirement. Forced/timeout/incomplete results never become accepted references.
Carrier bodies/Git objects/raw transport logs are removed after complete verified
success; the exact cache remains for the consumer. On failure the original
transports' bounded partial-DATA inverse is preserved as HOLD/CLOSEONLY, with no
retry, partial acceptance or cleanup of uncertain/foreign state. Caller still owns
actual scope retirement and finite-domain disposal. Runtime seeds do materialize
cache bodies; the provider's `archive_copies=0` refers only to its verification
pass and is labeled separately in the staging receipt.

## Evidence and remaining integration

Fifteen portable fenced tests pass on Python3.12/3.14. They cover Root external pin/
schema/source/expiry/context policy, missing helper HOLD, explicit secret ownership
and cleanup, exact public carrier identity, finite filesystem refusal, resource/
namespace bounds, natural/forced command outcomes and no shell, exact HTTPS body/
empty leaf, closed redirects, absent/extra/wrong body and no retry. All process and
HTTP operations are modeled. No live secret/environment or privileged role runs.

The actual `validate_local_references` API also revalidated all517 existing local
public body references /1558660382 bytes via the exact maintained provider, with
no archive copy and `hosted_delivery:false`. Evidence is the new private packet
`work/onboarding-complete517-staging-local-evidence-DATA-20261116-r1` in the author
worktree. That actual offline byte/reference evidence is not a hosted acquisition
or physical resource qualification.

Remaining genuine holds: Root must select/issue the new policy and conditional
grant, construct the new Source helper/profile closure, provide the finite physical
scope/storage owner and explicitly authorized22-secret caller, and wire this phase
before assembly/launch using the same expiry. Those actual selectors remain NULL.
Official/TEST trust, real hosted staged delivery/cleanup, GPG, native builds, Reader
and Root acceptance remain NOT RUN here. No workflow, launcher, executor,
constructor, shared manifest, recipe, frozen Source or public branch is modified.
