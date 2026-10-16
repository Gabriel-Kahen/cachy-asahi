# Opt-in 16 KiB Rust LV2 userspace candidate

**Implemented source candidate; native compilation, capture and VM execution NOT RUN.** Twelve portable controls pass with zero skips; Bash syntax passes. No Docker, network, package, host installation, Git, CI or hardware actor ran locally. The canonical generic16K lane is unchanged. Root owns adoption, the final source/workflow freeze and actual dispatch.

## Concrete pipeline

`ci_sequence.sh` drives the existing owned Rust job's init/seed/build/retrieve phases, acquires only the already pinned kernel source, copies the unchanged generic kernel build helper/fragment into a fresh owned work directory, and builds the successful diagnostic profile. Its new trial adapter then:

1. Verifies the unchanged immutable574 image, inventory and package-input contracts through the existing `asahi-lsp-build/run.py` preflight.
2. Reuses the existing exact archive inspector and two LV2 bundle extraction calls. **No Rust package rebuild or installation occurs.**
3. Starts one owned, nonroot, read-only, capability-free, network-free native574 container using the existing runtime-command API. `native_capture.py` checks the original headers, compiles the unchanged `asahi-rust-lv2-offline/host.c` exactly once with the existing GCC/pkg-config recipe, then captures its binary and same-image ELF closure.
4. Builds a diskless initramfs from that captured userspace, both accepted bundles and their unchanged notices. It uses the current574 image's bash/uname/getconf/interpreter/libraries. **The August rootfs is neither fetched nor used as guest userspace in this pipeline.**
5. Runs the unchanged generic page probe, both separate `RTLD_NOW` loader calls, and the unchanged Rust host's full60-case/120-instance property call under the diagnostic16KiB QEMU kernel. The original strict processing projection validates the entire grid and numerical bounds. No new DSP algorithm or oracle is introduced.
6. Requires the exact release/aarch64/PAGESIZE16384/page probe/nonce proof, all three successful reports, captured-library path membership, natural QEMU exit0, private removal and exact owned-container absence. The existing outer image owner subsequently retires its newly created574 image.

Historical native host hash `5c03fe21379ed34da154afebd0dbe17db873b22fce48c8a550ac67870d76202b` is evidence only: its private binary was not exported by run38810834920 and has no held retrieval API. **This producer is fully implemented and compiles a NEW same-job host.** Its actual source/compiler/header/flags/binary/ELF identities are recorded in `native.json`; no historical byte-reproducibility requirement or claim is made.

## Exact held boundaries

`dependencies.json` binds20 existing source/input files by size/SHA256, the unchanged574 lock `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`, and the nine system-library hashes exported by the accepted native Rust runtime. The producer must observe the complete exact nine-library audio set, records every captured ELF's `DT_NEEDED`, version requirements and structural16KiB check, and recursively includes each interpreter/dependency from the same native image. Guest loading and processing remain the actual ABI test; architecture/alignment or an August libc label is insufficient.

| Selected input | Archive bytes / SHA256 | ELF SHA256 |
| --- | --- | --- |
| bankstown1.1.0-4 | 144404 / `5ce529103e77d6cc509e270d925f9ecaa126d6a9b14302cdb41c14b72ed0d3af` | `5ad5c45ead516c32b0639af52a9f9a2772994973d2c3f7870d1e0c8795cdc352` |
| triforce-lv2 0.3.2-3 | 334900 / `d123dca2cd67099dfe3e45af9edc7f61ba11bf650a482695350184badd7dfa3c` | `8c49f609fb86cc1d46d9971e4b9967f7dc5a60fa2185810eb85f368d5aad0e51` |

These retain their existing `TEST-signed-native-output` provenance and frozen run38801968699 retrieval frames. No new detached signatures are invented. The existing retrieval API still obtains all five project archives and the official LSP archive/signature; this candidate consumes only the two Rust archives. If any held retrieval object is unavailable, retrieval refuses rather than skipping or replacing it. The574 owner's existing1153-object/pinned-keyring signature boundary is unchanged. No fresh signature verification was performed during this source-only work.

Harness source remains SHA256 `8e17986c68bb7fdbee644026bbdce4045179e65a0d34d210622260654b9e72a7` (MIT). Accepted Bankstown/Triforce notices/licenses are copied byte-for-byte from their pinned archives into the private payload. Existing library/source-release licensing limits remain; no compiled binary is published.

## Runnable CI handoff

Adoption: copy the canonical-shaped `staged/` tree by its declared map: new source files under **`scripts/ci/generic16k-audio-userspace/`**, and `native-arm-generic16k-audio-userspace.yml` under **`.github/workflows/`**. Held dependency copies in that proof tree are unchanged verification inputs; Root should copy only the declared new files. `candidate-files.json` uses repository-relative paths and covers the new source and workflow; `dependencies.json` pins the existing APIs. Keep the existing source APIs at their exact bytes, and use the established product/desktop checkouts:

- Product API: `db1010de321cc056a01672f006e6cc25d3c8a8b7`.
- Maintained574 preparation: `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2`.
- New source checkout: Root's frozen commit containing this candidate and the already accepted generic diagnostic helpers.

On a disposable Ubuntu24.04 ARM64 GitHub runner, provision the previously used build/QEMU prerequisites in a separate workflow step: build-essential, bc, clang, lld, llvm, flex, bison, libssl-dev, libelf-dev, Python3, qemu-system-arm, zstd and an available local default Docker daemon. The script performs no apt installation or service changes. Supply the same22 retained seed secrets used by the existing owned574 lane and an actions-read `GH_TOKEN` for the fixed retrieval API. Secrets are forwarded only to the existing seed/retrieve phases, not to kernel compilation or the native/VM trial.

```sh
export AUDIO16K_SOURCE_COMMIT=ROOT_FROZEN_40_HEX_SOURCE
export AUDIO16K_CANDIDATE_SHA256=SHA256_OF_ADOPTED_CANDIDATE_FILES_JSON
bash "$GITHUB_WORKSPACE/audio-source/scripts/ci/generic16k-audio-userspace/ci_sequence.sh" \
  "$GITHUB_WORKSPACE/audio-source" \
  "$GITHUB_WORKSPACE/product-api" \
  "$GITHUB_WORKSPACE/desktop-base" \
  "$RUNNER_TEMP/audio16k-owner" \
  "$RUNNER_TEMP/audio16k-kernel-work"
```

The source commit and manifest values must be supplied explicitly after Root adoption. The five paths must be fresh/ordinary and satisfy the existing owner's separation checks. The source manifest is verified before actors. All new source and kernel helper outputs stay outside canonical generic16K sources: the helper is copied by exact pin into the owned work directory before build.

If Root already owns a prepared574 image, exact retrieved archives and a genuine fresh diagnostic kernel receipt in the same job, the reusable core can also run directly:

```sh
python3 -B scripts/ci/generic16k-audio-userspace/run.py \
  --source-root "$SOURCE_ROOT" --product "$PRODUCT_API" --desktop "$DESKTOP_BASE" \
  --builder "$PREPARED574" --archives "$ACCEPTED_AUDIO_ARCHIVES" \
  --kernel-receipt "$NEW_KERNEL_BUILD/build-receipt.json" \
  --private "$RUNNER_TEMP/audio16k-private" --output "$RUNNER_TEMP/audio16k-public" --execute
```

This direct route preserves the borrowed image/kernel; their outer owner must perform final cleanup. Omitting `--execute` validates held source dependencies only. It does not compile, start Docker or run QEMU.

## Bounds, receipts and unfinished validation

Native compilation retains the existing60-second compiler and15-second ELF metadata bounds; the capture container/controller has480 seconds,1 MiB console output,1 GiB memory,2 CPUs and128 PIDs. Payloads are regular files only, at most96 files/64 MiB, with all bytes/modes/hash/interpreter/dependency joins checked before initramfs construction. The separate VM has600 seconds/1 MiB UART,512 MiB memory,one TCG CPU,no disk and no NIC. These explicit trial bounds do not change the canonical page lane's180-second limit.

The new trial controller retires owned QEMU/compiler groups through the existing bounded supervisor, uses the existing exact container cleanup API under a60-second deadline, removes its private binary/archive/initramfs workspace, and preserves its borrowed574 image. The job adapter preserves the existing image owner's cleanup and public-file boundary. Whole-job wrappers retain the existing interrupted-build/probe ownership limits as UNKNOWN/FAIL; this candidate does not claim to repair that older gap. Overall success requires an uncancelled normal CI exit and successful source/build/VM/resource joins, not saved PASS text alone.

After job cleanup, only **`public/result.json` and `public/runtime.json`** remain. They hold the new native receipt, full strict processing metadata, loader closure identities, exact observed guest proof lines, source/kernel/config/binary hashes, borrowed-resource and owner-cleanup status. The sequence attaches bounded kernel input/config/build/controller metadata/tails before removing kernel work. No executable, package, payload tar, initramfs or samples are public. Root can transport these two files through the unchanged bounded `scripts/ci/log_evidence.py` mechanism after verifying normal completion. On failure, bounded available native/VM receipts remain marked FAIL/NOT ACCEPTED.

Portable command:

```sh
python3 -B -Werror::ResourceWarning -m unittest discover \
  -s artifacts/development/generic16k-audio-userspace-20261016 -p 'test_*.py' -v
bash -n artifacts/development/generic16k-audio-userspace-20261016/ci_sequence.sh
```

The12 controls cover source drift, native recipe/readonly command construction, preserved image-owner routing, bounded failure publication, regular/closed payload and16KiB structure, exact page/nonce/natural-exit proof, and refusal of a changed original oracle/grid or foreign loader path. The retained native4KiB report in `test-data/` is inert validator input, not a new execution result. **Fresh native host capture and 16KiB LV2 processing are NOT RUN.** Real audio devices, PipeWire graphs, speaker safety, M2/Asahi integration, performance and release acceptance remain outside this candidate.

The supplied workflow is opt-in only, uses pinned checkouts and the exact manifest gate, provisions runner tools separately, and invokes the complete same-job sequence. It has a195-minute job budget; the main sequence watchdog is9000 seconds plus240 seconds cleanup grace within a156-minute step. Root must freeze its actual source commit and manifest SHA before dispatch. No existing workflow is modified by this candidate.
