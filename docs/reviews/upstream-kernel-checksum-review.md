# Upstream kernel config checksum review

Independent bounded review on 2026-10-12 of `/tmp/cachy-asahi-upstream-config-20261012`, based on upstream `asahi-alarm/PKGBUILDs` main commit `1c6daffd905c1b8f76202949ed48b80a4759ab73`. The updated roadmap, outline and package inventory were read first. Only this review document was written; no recipe execution, download, compiler, installer, Git mutation, network access or upstream message was performed.

**Outcome: PASS for the two-line checksum correction; no actionable source defect found.**

After the initial read-only inspection, the coordinator committed the correction as `d28ebe2abba533e12e4cd748cf1da65cce4f54de`, whose parent is the reviewed base `1c6daffd905c1b8f76202949ed48b80a4759ab73`. A second read-only check verified that the committed PKGBUILD has exactly the reviewed bytes, the commit changes only two lines in `linux-asahi/PKGBUILD`, and `git diff --check HEAD^ HEAD` exits 0. The worktree status below describes the initial inspection before that coordinator commit.

The current `linux-asahi/config` is byte-identical to the checkout's HEAD blob and contains 240,666 bytes. Independently calculated hashes match the proposed second entries, which correspond to `config` in the source array:

| Algorithm | Correct config checksum |
| --- | --- |
| SHA-256 | `a8412899bac7e09fa870a382e3cb97264bc071e9714c509800fa36f256633e2b` |
| BLAKE2b-512 | `ab502e3957e6b155dfe66359cbc7ab969282b2059e499acb90b3fc6a80f420c123d5a9a366ee401be78bdb9c05f018553eb36354959b0221c7fa3324aff5db80` |

The old config values are `d8769170a86c16d29ae7537c77d49c9b20074617ce3f10996cd8624b52b0f6f0` and `68defcd0a03bfc9f81e80a0d1491cced816f38ebb6e0e97f3b02657b96804c68dabd96def8d72dbc08ab6cf63b67889b7b255c2d8f5305d1051e4fe1ab8d2c48`; neither equals the current config's corresponding hash. A byte-level assertion verified that the proposed PKGBUILD is exactly the HEAD blob with those two strings replaced once each. The precise diff changes only the second SHA-256 and second BLAKE2 entries at lines 32 and 34. `git status --porcelain` contains only ` M linux-asahi/PKGBUILD`. Config bytes, source URL/order, build flags/functions, kernel version, package release and first-array checksums are unchanged. The corrected PKGBUILD SHA-256 is `9a4d7add831bf9df89bd828da3874e878942f7a5fa0be83cdd0f23a553e66cd4`.

The retained `artifacts/platform/kernel-history-20261012/linux-asahi-7.1.13-3.tar.gz` is 262,965,559 bytes. A streaming read independently verified both unchanged first-array entries:

| Algorithm | Retained archive checksum |
| --- | --- |
| SHA-256 | `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad` |
| BLAKE2b-512 | `b5cd9166b03ce28c12ea4dc38f217f0eb912dba998d6919229ad6fe8ec978b5aeb2f2ff033ad2e05c948ee9caeda9a3600d0cc22ad8ad217b80136a11916564f` |

`bash --noprofile --norc -n linux-asahi/PKGBUILD`, with `BASH_ENV` and `ENV` removed from the child environment, exited 0. This parsed syntax without sourcing the recipe or evaluating its commands.

The checkout is shallow, so it does not independently establish historical last-change commits. The coordinator's current primary-API attribution—config `b6c99b08e5f6d9bad8e23b88db69570436471961`, PKGBUILD `356454b49e45059b1dca34089c5a5ddba3dd29fe`—remains explicitly coordinator-supplied. This review directly establishes the config and recipe bytes at the stated HEAD and the retained archive's checksum consistency.

The narrow correction is ready for the coordinator's draft upstream submission. Submission and merge status are external outcomes to record separately; no upstream submission was made by this reviewer. This result provides no kernel build, 16K-page boot, M2 hardware, performance, or full-port acceptance evidence.
