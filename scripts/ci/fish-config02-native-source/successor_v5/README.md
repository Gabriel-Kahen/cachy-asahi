# Fish finite Docker CLI VA successor v5

New family only; frozen code a729b1e5 and Source50 remain unchanged. The original
21 source controls are not modified. Native ARM startup, Fish pair, M2 and release
acceptance are NOT RUN. Root owns publication, registration and canonical roles.

## Observed chain and finite scope

Source50's `hosted_owner.main` sets controller RLIMIT_AS soft=hard512MiB.
`Controller.setup -> docker(info) -> tool/H.checked -> run -> Popen` supplies no
child limit override, so that child inherits both512MiB. The separate ordinary
owner's existing2GiB domain is not part of this controller exception. Root's
llhttp native failure and local Go probe motivate this change; they do not prove
that this Fish ARM operation now succeeds.

The exact reused helper is Root commit
`b156e3886a12f95cb3d364b84fc3a946bb7d2967` (parent
`400d912f71981e1f8f498c2061ac188fd3038ce1`), `go_cli_va.py`,1996B/SHA256
`3b2feba315f3a0e4cfed2498160e75591d64c7b8f0e8f5c11b46321b04b5eff3`.
Its bytes are copied exactly, not reimplemented. Its complete API is
controller_limit(policy), child_plan(argv,observed_tools,policy), child_limits(plan).
`helper.REQUIRED.json` binds that whole operand; NULL/foreign pins refuse before
helper load or output. No uncommitted helper is discovered automatically.

Controller soft AS stays512MiB, hard ceiling becomes2GiB solely to permit child
selection. Only the qualified observed exact canonical Docker CLI path gets
soft=hard2GiB. Every other qualified child explicitly gets512/512MiB, including
dockerd/systemd-run/GPG/Python; basename/PATH/caller flags do not select Docker.
H.checked remains before launch. The parent pair is checked before every child,
the child callback checks its applied pair, and command receipts record the plan.
There is no unlimited limit or fallback.

Only one Root declaration is added to policy. Removing docker_cli_address_space
restores every original policy field, including physical controller512MiB RSS,
CPU1/PID64/swap0, owner/daemon resources, timers, output caps, storage and reserves.
The four finite owner projection inverses restore every original owner byte.
No supervisor, resource/custody/retirement, native signature/dependency, zero-APT,
XZ/semantic check, workflow or held base33 behavior is changed.

## Complete Source construction

```sh
python3 -I -B scripts/ci/fish-config02-native-source/successor_v5/prepare.py \
  --base /absolute/exact-Source50 --output /absolute/fresh-successor
```

The constructor requires the complete50-file/892625B source, fixed root map
`93bd88bf41da2a067cc7f04ebaa70374963bfda350cb821a7e6cf9278235c021` and tree
`dff997f10bd4e917709f2b76d4c32f07ed379a03`. It adds the exact helper, its immutable
binding and a complete Source50 inverse: computed count53. Owner/data/policy,
README, program and map are new pinned bodies. All base33 bytes are exact.

The new outer validator reconstructs all50 original bodies/modes/map/tree, then
runs the original full48 inverse on that reconstructed50. This avoids relabeling
old source snapshots or bypassing their checks. Maps/program/policy/helper are
independently pinned; all actual/grant/run/role selectors remain NULL. Fresh Root
Source/program/policy/runtime review is required. The existing no-host-APT v4
document schema is retained, with exact new Source and policy pins; old documents
cannot satisfy the new map/program/policy joins.

The native workflow bytes and shared Fish concurrency group remain exact. Actual
Root runtime54/canonical lease, global EMPTY, Main CAS, proof freshness and
retirement still apply outside this DATA constructor. No Root grant/nonce/output,
role reservation, actor, native POST, Original GET, host repair or push occurs.

## Focused DATA controls

```sh
TMPDIR=/dev/shm python3 -I -B -W error::ResourceWarning \
  scripts/ci/fish-config02-native-source/successor_v5/test_data.py \
  --base /absolute/exact-Source50
```

The eight controls construct their own disposable Source53 preview. They exercise
the actual generated controller run method and exact Root helper with modeled
executable observations, child creation, resource limits and supervision. An
audit fence rejects real resource setters, processes, network and custody actors.
They check Docker-only selection, finite parent/child pairs, unchanged retirement
guards, full53-to50-to48 inversion, deterministic construction and pin refusals.
These source checks establish no native startup, physical RSS or hardware result.
