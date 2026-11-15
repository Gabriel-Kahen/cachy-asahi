# LLVM hosted alias correction Source

The closed run 43720263251 failed before secrets/bootstrap/native work because
`hosted/common.py` retained the v1 workflow alias. The actual v2 packet contains
the generic alias and v2 alias. The failure reaches that stale tuple through
`hosted/entry.py:base_binding`; the same tuple also rejects the named v2 workflow
reference and governs bootstrap's repeated Source validation.

The new [successor_v3 constructor](../../scripts/ci/llvm23-source-reference-native/successor_v3/)
keeps the operational outer v2/inner v1 contract. It changes one alias literal
in common.py and its embedded SHA in each of the two identical workflows.
Hosted entry, all actors, candidate/original200, policy/resource limits and
the existing v2 inverse remain unchanged. A retained parent map and correction
descriptor make the new 253→251 inverse self-contained; controls also exercise
the existing 251→248 ancestor inverse using the exact Root-retained r3/r2 DATA.

The regression runs the actual named `base_binding` and `proof` function bodies
against finite, sealed DATA under process/network/ctypes fences. It models the
future Source/ref/admission and Git command boundary, and checks both corrected
success and the original stale-alias refusal. It does not grant authority or
execute an actual hosted proof, Git process, GET, lease, actor or native role.

Prospective Source/profile pins and validation are recorded in the owned
subtree. Actual Source/ref/run/job/Reader/authority/approval/artifact/image
selectors stay null. Root must review the profile, construct and publish a
fresh Source/ref, and separately admit any once-only attempt. The failed 6d
Source, job and absence of an Original artifact remain historical evidence.

Prospective rendered packet: 253 files / 40,862,047 bytes; map 49,842 bytes,
SHA256 `5c19a2699856e081712d159c551ce496919938bd456f2182c0c905f03cbd2ef0`;
Git tree `2f90eaaaa532d14574c0ce1f1c93b02310f44d91`.
The 1,835-byte constructor profile has SHA256
`aa5e19a9df3da4dbead98ca975a2f791c7a1995cbad398ec76be5231999b6d35`.
All 22 controls passed on actual Python 3.12.13 and 3.14.7. These include
the actual named guard bodies with a synthetic future binding, complete
253→251→248 DATA inverses and tamper cases with recomputed closed maps.
The exact profile SHA gate passed and a wrong external SHA refused.

Actual 253-file construction, Git publication and hosted execution were not
performed. The independent v2 Reader remains fixed to 6d/251; interpreting a
future Original needs a separate reviewed new Source binding and inverse
projection. This constructor does not change that Reader or its historical
records.
