# Coupled SessionLock and Settings native Source v2

This versioned successor preserves the complete frozen v1 qualification target:
`cachy-asahi-session-lock`0.1.0-1 **and**
`cachy-asahi-hyprland-settings`0.1.1-1. It does not remove Settings or lower any
build, dependency, signature, payload, cleanup, restoration or Reader gate.
The original `session-lock-settings-native-source/` remains unchanged. The
separate helper-only draft is not this successor's basis or publication target.

## Concrete change from v1

V1 ran helper help, screenshot help and Hyprland config verification in the
installed states. Its24 helper readiness/cancellation/refusal subprocess controls
ran inside makepkg check() against build sources, not installed/moved CLI bytes.

V2 retains those checks and adds one whole-pinned verification script. At both
installed and reinstalled states it validates the four installed helper bytes
and modes, runs the unchanged24 controls against that CLI, then runs them again
against an owned moved copy. Children are inert fixtures; real compositor/PAM,
Swaylock, logind suspend and resume are not tested or claimed. The native owned
command supervises the checker; its combined stdout/stderr is canonical JSON.

Projection and passive Reader independently join all48 observations per state,
exact command argv, output log pin, four payload identities, both24-test
locations and refusal/acceptance fields. Missing results, altered modes/hashes,
forged locations/counts/diagnostics, incomplete output or supervision refuse.
This is new installed-byte coverage and custody, not a new duplicate lifecycle
actor. The v2 operation is `session-lock-settings-alpm-v2`; v1 receipts cannot
supply v2 credit.

## Preserved full route

All four dependency-enabled makepkg runs remain: two helper builds with actual
24+2 check blocks, two Settings builds with actual5+2 blocks. Helper installation
really satisfies Settings' local dependency in each clean build iteration, with
349→350→349 bootstrap inventory. The signed two-package journey remains
349→351→349→351→349. Neither `--nodeps`, `--nocheck` nor `--syncdeps` is allowed.
Both packages' archive pairs, PKGINFO/BUILDINFO/MTREE and all13 payload leaves
must match their source. The original coupled offline13-file verifier/profile
is unchanged, including all nine Settings leaves. Unknown-key/tamper refusal,
Required/Required TEST trust, ALPM ownership, install reasons, protected homes,
user data, cache restoration and complete image/process/key-agent cleanup remain.

The unchanged23 source-bundle members gain only
`verification/check_installed.py`, giving24 members. Both complete recipes,
source notices/licenses and frozen349 dependency inventory are preserved. No
new external dependency or acquisition gap is introduced. Python3.14.8-1,
Swaylock1.8.6-1 and systemd262-1 remain the exact direct helper providers. The
new script uses only Python's standard library. The recipes remain original MIT.

## Frozen construction and unissued handoff

The existing finite constructor preserves Source97 commit
`97a44c4c7cb206704bf76e9fd1f1afb2266278c2`, tree
`81d61d9e1f33c1638e9f67fbd7e39b158c603451`, as the physical inverse basis.
It verifies every parent Git blob/body/mode, uses no-follow single-link reads,
bounded snapshots, an independent nonrecursive map and atomic fresh no-replace
publication. The draft remains200 files/199 map rows,13 replacement operands
plus the resealed map, with186 other leaves unchanged. No operand code is
imported by the constructor.

The profile is62439 bytes, SHA256
`d0e4b44fd14908813dcfb842c2a5af6293b6e837fda22c825f286493163fd200`.
The draft Source tree is `fc1ac059557d8dd7a69c33e234cf3adfec31f14d`;
its map SHA256 is
`7b592707e2692af66143f457696d2eda3d8703a6da144f657e72520c0c0c800b`.
`DRAFT.json` records the same pins and resource proposal. Actual Root trust/signing, Source/ref/run/job/artifact, capacity
admission, runtime, publication and all acceptance choices are NULL. Source
construction is DATA preparation, not a native result or issued Source binding.
No central workflow or manifest is changed; payload workflow aliases are inert
Source operands, not a dispatch.

The existing HEAVY_NON_KERNEL proposal remains2 CPUs,4GiB,256 PIDs,2GiB tmpfs,
no network, read-only consumer root, dropped capabilities and
no-new-privileges. The operation/command budgets remain450/180 seconds with
90/20-second cleanup budgets,1MiB output, the serialized native-arm-build group
and135-minute workflow cap. Effective image-build daemon limits remain UNKNOWN;
Root must independently qualify actual capacity and admission.

## Validation

All30 controls pass on Python3.12.14/3.14.7: the original24 full-factory
controls, four image-lifecycle controls and two new installed-control custody
refusals. The standalone export passes the same checks. The checker itself is exercised against
staged source bytes and a moved copy with real owned inert subprocesses; this
supplies no native installed-system evidence. The constructor is also checked
from a standalone export against the exact physical parent, with complete
Source/inverse agreement.

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/session-lock-settings-native-source-v2/test_data.py
python3 -I -B -Werror::ResourceWarning scripts/ci/session-lock-settings-native-source-v2/test_image_lifecycle_data.py
python3 -I -B -Werror::ResourceWarning scripts/ci/session-lock-settings-native-source-v2/test_runtime_v2.py
python3 -I -B scripts/ci/session-lock-settings-native-source-v2/prepare.py \
  --parent-source /absolute/exact-Source97/source \
  --profile-sha256 d0e4b44fd14908813dcfb842c2a5af6293b6e837fda22c825f286493163fd200 \
  --output /absolute/private-parent/fresh-coupled-v2-source
```

No native build, ALPM installation, GPG, Docker, compositor/PAM/suspend action,
Original GET, publication or push was performed. Full native execution and
independent native/target acceptance remain unfinished.
