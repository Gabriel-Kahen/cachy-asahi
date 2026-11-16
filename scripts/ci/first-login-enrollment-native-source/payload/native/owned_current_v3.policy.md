# Full current onboarding policy proposal

`owned_current_v3.policy.PROPOSAL.json` composes the existing context/image
contracts and executor7778865c proposal into one finite candidate. It is
unissued DATA. Root issuance, runtime, actual binding/images and all acceptance
fields are NULL. No native resource, image or stage observation is supplied.

All three proposed stage capabilities have4CPU/4GiB/512PID,512 commands,1800s
maximum image/bootstrap command and7200s total. The proposed wrapper adds180s
setup and180s cleanup:7560s controller and7380s service maximum. Image verification,
bootstrap, stage, inspection and reserved image cleanup stay60/1800/180/15/90s;
image cleanup is inside the image/stage budget, not a further time allowance.
These are new wrapper proposals, not changes to any frozen Source or actor.

`frozen_stage_limits` separately records existing route/build constraints:
180s command,1800s admission total,600s implemented old owned-session ceiling
including its retirement reserve up to60s. Build containers stay4CPU/4GiB,
memory-swap equal to memory (zero additional swap),512PID and4GiB tmpfs.
The new delegated owner/route must explicitly preserve these nested limits;
the7200s wrapper cannot silently become a7200s old actor. Their actual committed
policy-consumption interface remains a listed prerequisite, not an inferred fact.
The common7200s deadline is shared by image construction, trust checks, the native
stage and retention; every handoff must preserve its remaining time.

Controller memory is512MiB/1CPU/64PID; owner2GiB/1CPU/256PID; daemon plus all
containers6GiB/4CPU/768PID, all swap0. The daemon PID subgroup is finite as well,
but its ancestor aggregate is counted once. Total accounted memory is8.5GiB;
12GiB minimum fresh availability covers this plus2GiB reserve. Controller/owner
AS ceilings stay512MiB/2GiB. Runtime kernel observations must still establish
every exact PID/start/cgroup/limit and both bounded daemon domains.

The32GiB physically allocated filesystem bounds all image owner/context/daemon
writes, including owner temporary aliases.40GiB minimum fresh disk covers it,
2GiB host reserve,3GiB controller receipts and512MiB public evidence. These
availability checks are not reservations of host RAM.1024 controller rows cover
ten-second polling of7200s plus256 setup/cleanup commands; the3GiB receipt
reserve also covers both bounded1MiB streams plus metadata for every row.
Retention's separate8MiB/file,16MiB logical,512-member and8MiB capsule caps are
unchanged;512MiB controller public space does not enlarge those capsule limits.

`context` proposes30s/1MiB metadata acquisition,7560s maximum context age and
delegation lifetime. These limits concern metadata/contract freshness; they do
not enlarge build commands. A shorter Root-issued expiry remains stricter and
may keep HOLD before a full stage completes. The actual controller/service
deadline is further clipped by observed activation and remaining authority.
Root must choose issue/expiry times with real dispatch latency in mind.

Normal local `pacman -U` keeps dependencies, hooks and scriptlets. Required
package/local signatures, offline GPG and selected public certificates remain
strict. The image's existing eight ALPM capabilities and old lifecycle's five
capabilities are recorded separately. No signing/private key, hook masking,
scriptlet suppression, nodeps, sync, acquisition fallback or network is enabled.

`private_stage.test` selects the observed public Setup8 primary fingerprint
`D9D7A9FC25B9914CF6F2CE55952AEDD8A209B4C0` and fixed Source alias
`setup8_current_public_key`. Source139 maps its original `Setup8/current_public_key`
role to `carrier/inputs/public/setup8-current.asc`:437 bytes, SHA256
`01ffe16c6215c2030914d0cfc7f27f14ae15cb58da1e4723ac1651c423c1e289`.
Those bytes equal `Root-setup8-TEST-sign-r1/setup8-TEST-public.asc` and the key
pin in its historical verification JSON; the v4 public-key packet fingerprint
was independently recomputed from those public bytes. No private TEST home or
private key was read. This identity fact is not current Root trust admission,
signature mathematics, revocation or expiry approval. The separate trust field
remains NULL and the actual future GPG/trust checks remain mandatory.

The exact policy interfaces already consumed by committed guards are `context`,
`stage_capabilities`, `image_domains`, `image_endpoint_template`, `image_steps`,
`image_storage_bytes`, `image_alpm_capabilities`, `executor_current_v3`.
`stage_capability_proposals` is retained verbatim from the executor fragment;
`stage_capabilities` is its explicit equal projection for context validation.
The remaining metadata states unissued scope and unresolved interfaces. The
proposal does not make an absent owner adapter, launcher, inputs assembler,
public Reader or genuine externally supplied Source349 data available.
Context-v4's separately authenticated cross-run producer adoption remains an
explicit pending contract. The current numeric checks use committed context-v3;
they neither relax its strict same-run gate nor assert compatibility with an
uncommitted v4 implementation. Root will select its actual committed descriptor
and API. Keeping the closed Source kind V3 does not relabel that context program.

Root's external delegation must separately authenticate/select this exact whole
Source-relative policy body and all committed program/material descriptors,
including owned_process and hosted_launcher. Its stage capability selects the
same7200s proposal required by the current executor, and its context_limits must
equal this policy's context. Source/ref/map/nonce and bounded private scope are
predispatch selections; run/job/image IDs remain NULL. Actual poststart context,
Root public trust admissions, inputs and resources still require their genuine
checks. This proposal supplies no Root signature, approval, grant or final
component/hardware/release decision.

Run `python3 -I -B -Werror::ResourceWarning
scripts/ci/first-login-enrollment-native-source/payload/native/test_owned_current_v3_policy.py`.
The pure controls call the actual committed executor policy guard, image domain
guard and context numeric guards. They use no authority-shaped Root test grants,
native/kernel observations, process, Docker, GPG, network or lease operations.
