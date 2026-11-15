# Installed Perl retained-result Source correction, 2026-11-15

Actual installed241 run43728748795/job132856306730 is a closed failure. Root retained
Original14168080440 (1,472,931B, SHA256
`45d5e47852001f6f07767e8043e4c15938b238f72e1f71e1155fe1cadcedbc0b`).
Fresh signed349 bootstrap/image qualification and seven-cap inspect passed. Actor
start retired naturally, with container Exit0/OOMfalse and empty run streams; the
subsequent Docker cp failed to find `/work/result`. No actor report survived, so
no transaction/refusal/rollback or installation acceptance follows from Exit0.

The missing-file stderr is143B/SHA256
`08ec7bddf210cd69f6e14bfebc4a6522e5f1275fd3506f89f05d4462f70543b6`.
Source wrote exclusively into `/work/result`, `/work` was a256MiB tmpfs, and export
occurred after stop. This is an evidenced retention mismatch; an actual unmount
event and transient contents remain unobserved. The independent7373B diagnosis is
pinned as `f682b1c3ca89fbde262f703a0085a2768ee118b5195dbfa4862eda4acf126231`.

The new `successor_v3` actor creates a previously absent Root-owned0700
`/cachy-asahi-perl-lifecycle/result` on the existing owned writable layer before
commands. Creation refuses existing files/directories/symlinks, races, wrong owner,
mode or device. Producer exports that exact stopped-container path and requires the
actor's exact `retained_output` proof. TAR basename/result files and existing64MiB/
16MiB/<160 limits remain unchanged. Scratch tmpfs, normal ALPM/default hooks, public
trust, package/user handling, CapEff/Prm0x800400cb/InhAmb0/NNP1 checks and all resource
budgets are unchanged. No direct CapBnd check is newly claimed. The only new mutation
domain is this private retained-output directory inside the already-owned container;
no host bind, capability, package-owned path or service mutation is added.

Actual retained-parent DATA checks and twelve fenced controls pass on Python3.12.13
and3.14.7. The proposed Source facts are identical on both:

| Field | Exact proposed value |
| --- | --- |
| Files / bytes | 252 / 81,364,853 |
| Source map | 49,159B / `2bbf2c808562d13a158d654f7e7d3adb71c7e577444e82ea05a0aad5cf0f3c97` |
| Tree | `f8bbb62a4adbe9157b98c13bb8d5b9148bfc12f0` |
| Actor | 25,836B / `7d8a4bf6d990579bd27b2d9744b3771cb197566bfcbb8c810d91188f35ed6ac3` |
| Producer | 15,229B / `123feb39856cf531ab67b42d09c98c01eb16816b2264821bd7ad563374887ce2` |
| Capsule | 40,366,080B / `64921dc8625c54c1a0502d811f7e32e608eb407541d824659e18117d70a979c1` |

Full252→241→232 and original200 byte/mode/tree inverses pass. Ten parent core files,
seventeen capsule members and all compiled package/trust/review/policy inputs remain
exact; four inverse tamper cases refuse. The prior capability correction is preserved
explicitly as historical metadata. No duplicate old capsule or new Source export was
created. The issued prerequisite review31aeecaa… remains unchanged and grants no new
runtime authority by itself.

A focused compatibility check executes only the unchanged capsule Reader's pure
status/channel/TAR/report/command predicates over synthetic DATA. It accepts the
supplemental retained_output field and new absolute export argv with unchanged
`result/report.json`, and rejects wrong roots/traversal/oversized members. Hosted
Reader still delegates unchanged paths; no hidden old `/work/result` check exists.
This is not an operational Reader or a full synthetic lifecycle acceptance.

Root must export/publish a fresh Source/ref, update once/Reader bindings for252 and
its full241 inverse plus explicit output retention domain, and separately admit an
actual run. The old241 Source/once/Original remain closed and immutable. No worker
actor, ALPM, GPG, compiler, network, lease, dispatch, actual Reader or publication ran.
Native installed acceptance,16K,M2 and release remain open.
