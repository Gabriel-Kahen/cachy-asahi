# LLVM 23 native Source execution packet

The new [`llvm23-source-reference-native`](../../scripts/ci/llvm23-source-reference-native/README.md) constructor produces a closed, licensed, standalone Source packet for Root to review, publish and dispatch. The new operation is **`llvm23-source-reference-native-v1`**, with dedicated workflow aliases `native-arm-build.yml` and `native-arm-llvm23-source-reference-v1.yml`. It never enters the old Perl producer or old Native POST. All actual selectors remain NULL until Root's separate admission and publication.

## Concrete build route

The route reuses Root's frozen Perl25dc original200 source, signed rootfs/keyring policy, original248+fixed8 package inputs, signature checks, owned-child lifecycle supervision and Rootful local daemon constraints. The expected installed lock remains349 packages, SHA-256 `579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453`. The exact package-version DATA audit contains GCC, binutils, CMake, Ninja, Python, libarchive, bubblewrap, glibc, libgcc/libstdc++, zlib/zstd, bash, Perl, pkgconf, make, fakeroot and pacman. No package additions were identified from that lock; actual tool paths/bytes/link chains/owners remain future observations, not inferred availability.

After a Root-approved Source/ref/map/resource operand, the proposed workflow verifies the whole published Source before existing secret use, uses the same retained input seeding/transport mechanisms, obtains the actual same-run job ID, rejoins retained LLVM upstream signature/provenance evidence, and acquires the single exact LLVM source original. It then creates the fresh signed349 image and runs one ordinary dependency-checked makepkg build.

LLVM source is fixed to23.1.1 / commit `6dfe1677ab8dffbc6ec13d53a1e0215d75147689`,179168672 bytes, SHA-256 `ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6`. It is not in Git or the Source packet. The future job allows at most four verified-TLS HTTPS requests including redirects,192MiB response bytes and600s for acquisition plus DATA extraction, with no automatic retry. Every download is joined to the previously retained authenticated source hash; Source notices, extraction containment and the actual extracted tree digest are checked before compilation. There is no package acquisition path beyond the frozen signed349 mechanism.

The candidate is copied as exact DATA from Root's separate LLVM candidate worktree. Its build script retains AArch64-only backends, Clang/LLD, shared LLVM with RTTI, compiler-rt builtins/profile, libunwind, explicit private RPATHs and16KiB link geometry. The packet calls its pure staging/ELF/inventory functions. The existing bwrap mode stays intact and unentered: this new mode has independent Root container qualification, not a fallback or a claim that nested namespaces work.

The one filesystem addition to the bootstrap Dockerfile is recorded with before/after hashes and exact append text: `/opt/cachy-asahi/llvm23-source-reference` points to `/work/dest/opt/cachy-asahi/llvm23-source-reference`. It lets newly built private tools drive the runtime/check stage while the container root remains read-only. No package is added to349, no host path is modified, and no pre-built LLVM is required. This matches Root's private Rust consumer prefix join (`dd6871d5`); that consumer's linking/runtime qualification remains separate.

## Proposed resources and actual guards

The public `policy.json` is a **proposal**, not resource approval or a reservation. Root must separately admit it for the actual host/daemon/image:

- Native Linux AArch64, existing local Rootful unremapped Docker daemon and stable root-owned `/var/run/docker.sock`; no daemon launch/reconfiguration/rootless substitution.
- One workload container, UID/GID1001,2 CPUs,8GiB memory, zero swap,512 PIDs, cap-drop ALL, no-new-privileges, default seccomp, read-only root, exact read-only inputs/source binds and one private work volume; no host homes or service socket mounts.
- At least12GiB host available memory,64GiB free storage and600000 free inodes on each relevant device before actors; active4GiB host memory and1GiB storage reserves.
- Overall native budget19800s, including bootstrap4500s, source intake600s, actor14400s and cleanup300s. Actor makepkg is bounded13800s; tools10800s, runtimes1800s, check600s. Workflow job360min, native step330min with a reserved termination/cleanup window. Timeouts/forced retirement cannot earn success.
- Logs/JSON64MiB each, private package2GiB, flat export4GiB. Export is streamed under an inherited file-size cap; no multi-GiB archive is read into host RAM. PAX/GNU metadata, header counts, expanded sizes and zero-only tar termination are checked by the DATA reader.

Actual Docker inspect, entry/init UID maps, PID lineage, cap0/NNP/seccomp, mount flags, loopback-only network and cgroup files must match. Both4KiB and16KiB native page sizes are accepted as observed geometry; no M2 hardware or pre-built-toolchain gate is invented. A4KiB run does not qualify16KiB or M2.

## Constructing the standalone Source

These are local DATA-only commands. The frozen Source and candidate/evidence operands must match their pins; altered frozen leaves fail even if the old map file is retained. Output must be fresh and disjoint from inputs. Create the output parent first.

```sh
python -I -B scripts/ci/llvm23-source-reference-native/prepare.py \
  --profile-sha256 855e5395952723fa387cb6d43f35076fe3becb6d26e2a150f7c22c953c236fb9 \
  --frozen-source /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-hosted-source-r1/source-tree \
  --candidate /home/gabe/Documents/ChatGPT/cachy-asahi-llvm23-source-reference-20261115/packages/port/llvm23-source-reference \
  --evidence-root /home/gabe/Documents/ChatGPT/cachy-asahi \
  --output /absolute/fresh-private-output/source-tree
```

The packet includes Root's exact existing source authentication/LLVM archive audit records, candidate notices and project MIT license. The frozen Original subtree is restored byte-for-byte and mode-for-mode by the emitted inverse. The old actual Source/run/approval is never used as LLVM authority. No archive download, container or build occurs while constructing it.

Root still supplies these concrete operands:

1. The reviewed candidate snapshot and resulting whole Source map/prospective tree. If the candidate changes, reconstruct; do not reuse a stale map or admission.
2. A distinct published Source commit/ref and Root's externally authenticated canonical JSON admission. The supplied template is `UNADMITTED`; fill status `ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT`, authority, exact source/ref/map, matching resource policy and source-review/holds fields only after actual review. Its SHA-256 is the workflow approval operand. The constructor cannot create approval.
3. The existing retained input secrets/public14/carrier route already used by the frozen signed349 constructor, with no new secrets or silent packages.
4. Current host/daemon/storage/resource admission for the stated proposal and permission for this one new operation. Workflow first-attempt/manual/source/ref/job guards prevent treating an old Native body as the new role.

Root owns Main workflow integration, artifact publication choices and dispatch. This worker performed none of them.

## Export and independent DATA reader

The actor preserves original/effective PKGBUILD and its exact single-line inverse, original/effective makepkg configuration, complete349 ALPM lock and tool ownership records, source/helper/admission pins, actual runtime, all command argv/deadline/log/ownership receipts, both CMake caches, staged and packaged path/mode/byte inventories, package metadata and the full private package. Package extraction is never installation. All files export through a bounded flat envelope; only Root-owned image/container/volume names may retire. Uncertain creation is recorded before mutations so cleanup still examines planned owned resources.

The workflow retains complete Source/job/daemon/bootstrap/signature/input/operation and workload DATA, excluding secrets, private keyring state, caches, copied source archives and extracted source/build trees. It never automatically invokes a Reader. Root separately authenticates Source/ref/run/job/image/approval/artifact, then supplies a binding with scope `ROOT_AUTHENTICATED_LLVM23_DATA_READER_ONLY`, operation, source/ref/run/job/approval/source_map_sha256/image/export_sha256. Using the actual authenticated standalone Source and retained evidence:

```sh
python3.14 -I -B hosted/reader.py \
  --binding /absolute/root-authenticated-binding.json \
  --binding-sha256 EXACT_BINDING_SHA256 \
  --evidence /absolute/retained-workflow-evidence \
  --output /absolute/fresh-reader-data
```

This reader checks the exact tuple, published Source/job observations,257 approved signer statuses,349 lock, create/runtime/retirement facts, Source-bound recipe transformation, source/helper/admission joins, command logs/natural exits and whole private package versus the packaged inventory. Python>=3.14 with actual stdlib zstd is required. Its result is **DATA parity only**, not independent-machine attestation, source/legal acceptance, production trust or release admission.

## Actual authoring results

The Source packet was actually constructed privately and its complete membership/byte/mode map checked. Ten constructor/controller/DATA controls and15 actor static/refusal controls pass; Bash/Python syntax checks pass. They exercise stale operation/attempt refusal, frozen-source tampering, exact inverses, resource create operands, PAX/tail refusal and actor input/layout controls. No CMake, compiler, makepkg, package acquisition, container, daemon, job, lease, signing, operational Reader, publication or dispatch ran.

All original-four recipe correspondence mismatches and license108/source/legal/delivery holds remain open. Native build/runtime/16KiB, both M2 Air sizes, Rust consumer linkage, performance and release conclusions remain NOT RUN/NOT ADMITTED. The next action belongs to Root: review the emitted Source and actual resource/provider premises, then admit and dispatch a distinct operation.


## Root checkpoint and exact operands

The concise machine-readable handoff is [`handoff.json`](../../scripts/ci/llvm23-source-reference-native/handoff.json); its constructor input profile is [`constructor-profile.json`](../../scripts/ci/llvm23-source-reference-native/constructor-profile.json). The CLI now requires the reviewed profile SHA and verifies constructor/payload/candidate descriptors, exact input paths and the prospective Source map/tree before publishing local DATA. This profile is a checkpoint, never Root approval.

| Checkpoint | Files / bytes | Source map SHA-256 | Prospective Git tree |
| --- | --- | --- | --- |
| Accepted `a5b1f382` / r2 | 248 / 40,787,836 | `8b01d92c3b810246967f932de22046a086a08fc429a2a1c0175ad20e7aac3936` | `e35e4eb0c8c4cea3fdeab8f5d04f35ee714b9f4e` |
| Mode-preserving successor / r3 | 248 / 40,788,233 | `b462bebb24a5dcf18aaecb5843b75cba0f6c3f89b920c313263abff91f7e7e33` | `b6d4f3bcbfb7454b1760c3ff9f9910d734d8bece` |

Constructor profile SHA-256: `855e5395952723fa387cb6d43f35076fe3becb6d26e2a150f7c22c953c236fb9`.

Exact resource-policy SHA-256: `46704d4b848682e82c8c910e6087688ec4a5b02015d50dbb65d41b664dc9fb99`. The policy is still proposed and unreserved: 2 CPUs / 8 GiB / no swap / 512 PIDs, at least 12 GiB host available memory and 64 GiB/600000 inodes per relevant device, with the deadlines and reserves already listed above. Root's external admission must carry the exact `policy.json` object; it does not mutate the proposal into proof of actual capacity.

The retained successor Source is:

```text
/home/gabe/Documents/ChatGPT/cachy-asahi-rust-submodule-closure-20261115/scripts/ci/llvm23-source-reference-native/work/source-tree-r3
```

For publication, Root supplies a fresh actual Git commit in public `Gabriel-Kahen/cachy-asahi`, with the successor prospective tree above. The proposed distinct ref is `refs/heads/codex/llvm23-source-reference-native-20261115-r3`; it has not been published. Root may choose another distinct `codex/` ref, but must bind that exact ref in the new admission. The manual workflow operands are `source_sha` (actual published commit, currently NULL), `source_map_sha256` (successor hash above), `operation=llvm23-source-reference-native-v1`, canonical external `root_admission_json`, and `approval_sha256` of exactly those admission bytes. Run/job/image/artifact/Reader remain actual future observations; no old Native body or selectors substitute for them.

The mode review found wrapper `copyfile` calls that could normalize admitted protected files. These now use mode-preserving copies; the derived PKGBUILD is written to a fresh destination before its original mode is applied. A fixture verifies exact 0444/0555 input modes and bytes. Existing tree-copy and package-inventory paths retain recorded ordinary modes. The filesystem helper's 0644/0755 restriction applies only to canonical Git Source publication, not runtime/package protected-tree admission. The frozen LLVM candidate is unchanged. This successor has 10 constructor/DATA and 15 actor static/refusal controls passing, with no new actors or qualification credit.
