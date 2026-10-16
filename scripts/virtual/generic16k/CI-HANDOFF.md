# Single actual CI caller candidate

Prepared only: **no apt, input download, CI dispatch or guest execution occurred locally**. This extends the artifact-only kernel/fixture candidate; it does not change the accepted 4 KiB or Asahi lanes. Root owns source adoption, Git, final manifest freeze and dispatch.

## Adoption

Copy files named under `scripts/virtual/generic16k/` in `ci-files.json` from this directory into that new canonical directory. Copy `generic-arm64-16k.yml` to `.github/workflows/generic-arm64-16k.yml`. The manifest includes the exact workflow bytes. Copy `ci-files.json` alongside the code, then dispatch that workflow at the same committed Source using the manifest file's SHA256 as `candidate_sha256`. Source and workflow changes require regenerating the manifest; do not reuse a stale manifest SHA.

The workflow checks out the selected commit without persisted credentials and verifies the complete expected manifest before provisioning. It uses `ubuntu-24.04-arm`, repository read permission, explicit dispatch only, serialized runs, and no default-lane changes. Ubuntu apt prerequisites are installed only on that disposable runner: build-essential, bc, clang, lld, llvm, flex, bison, libssl-dev, libelf-dev, Python3, qemu-system-arm and ca-certificates. Apt update/install are separately bounded to 180/240 seconds with retries disabled. Apt versions are recorded at runtime rather than predeclared reproducible binary pins. Ubuntu's [clang package](https://packages.ubuntu.com/noble/clang) selects Clang18; the held kernel source declares LLVM15 minimum for arm64. Actual installation and compilation remain untested until dispatch.

## Finite execution

`ci_call.py --execute` requires a nonroot Linux ARM64 GitHub runner. It captures selected package versions plus clang/QEMU versions, then runs exactly one fetch phase, one native Image build, and one explicit diskless TCG fixture. It verifies the source manifest again before either execution or publication. `--publish` alone performs no acquisition/build/VM work.

`inputs.json` and `fetch_inputs.py` retain these exact previously held inputs:

| Input | Official URL | Bytes | SHA256 |
| --- | --- | ---: | --- |
| Kernel source | https://github.com/AsahiLinux/linux/archive/asahi-7.1.13-3.tar.gz | 262965559 | `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad` |
| ARM64 rootfs | https://ca.us.mirror.archlinuxarm.org/os/multi/ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz | 829367415 | `42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319` |

The source URL and github.com→codeload.github.com transport are recorded in `artifacts/platform/kernel-history-20261012/kernel-source-archive.json`. The rootfs URL, size and hash are recorded in `scripts/ci/maintained-desktop574-inputs.json#rootfs` and the maintained successor lock. No URL or input hash was guessed or weakened. Fetching uses default HTTPS certificate validation, no proxies/credentials, exact allowed hosts, one attempt per input, a 30-second request timeout and 300-second whole-fetch alarm. Length/header/hash drift, unexpected encoding/origin or partial content refuses. Owned partial files are removed on errors and catchable cancellation. This is HTTPS plus retained checksum verification; fresh signature verification is not claimed.

The existing build helper checks the whole generic fragment, builds only Image with two jobs and a 3600-second deadline, and records the exact commands, executable hashes, config, release, source license and Image identities. Modules are disabled; runtime drivers are built in. Its existing file/address-space/log/workspace bounds remain active. The fixture joins that genuine successful receipt before preparing its eight-file rootfs ELF closure and executing the static memory/page smoke under TCG.

The CI caller gives fetch/build/fixture 320/3700/300 seconds, respectively. On timeout it sends TERM to the owned child group, allowing the helper to retire nested make/QEMU groups before a 12-second KILL fallback. Owned archive inputs, build and VM directories are removed in separately bounded 60-second cleanup children. Cleanup failure makes the caller fail. The outer workflow watchdog is 4800 seconds plus a 30-second termination grace; the whole job is 100 minutes including provisioning and publication. No disks, host kernel installation, flashing, physical target or hardware acceptance is involved.

## Public evidence

After selection and cleanup, `ci-<run>-<attempt>/public/` contains a closed manifest and at most 256 KiB total raw content: caller/fetch/build/fixture receipts, input/source manifests, full generated kernel config and fragment, kernel COPYING/GPL/syscall/license-rules records, selected package/tool versions, and 8-KiB tails of finite phase/config/build/compiler/UART logs. Large archives, source trees, Image and initramfs are not public outputs. All command argument vectors and retained log hashes remain in receipts.

The final always-step emits one `GENERIC16K_PUBLIC_BEGIN` / `GENERIC16K_PUBLIC_END` JSON frame containing names, lengths, SHA256 and Base64 bytes of this bounded set. A passing saved receipt is accepted only with successful uncancelled normal workflow completion, exact Source/manifest and all fetch/build/guest/cleanup joins. Kernel compilation, header bits or synthetic controls cannot establish the actual 16 KiB guest result. Generic software PASS is separate from signed transactions, M2, Asahi integration, performance and release acceptance.

## Portable verification

The existing kernel/fixture controls and the new fetch/caller controls run without network or package actors:

```sh
python3 -B -Werror::ResourceWarning -m unittest discover \
  -s artifacts/development/generic-arm64-16k-20261016 -p 'test_*.py' -v
```

The added controls check exact input/schema/origin/length/hash refusals, partial cleanup/deadlines, source manifest tampering, public-frame byte bindings, and real owned-child normal/failure/TERM cleanup. They do not fetch the large inputs or run QEMU. `ci-controls.log` records the final combined result. `CI-SHA256.txt` holds the manifest SHA for Root's adoption check.


## Opt-in boot diagnostics after actual 38862416370

That actual verified both exact inputs and built the native 16 KiB Image, then timed out in QEMU before any userspace marker. Its complete 4934-byte UART capture ends at entry to `clk_disable_unused`; it does not prove that callback failed to return. This candidate adds observability, not a proven boot repair.

Dispatch with `boot_diagnostics=true` (default false). The caller forwards `--boot-diagnostics` to both build and VM. Only that build overlays `CONFIG_KALLSYMS=y` and `CONFIG_PRINTK_TIME=y` in a new owned `diagnostic.fragment`, retaining its identity in the build receipt. The fixture requires the matching diagnostic receipt/config and adds `initcall_debug ignore_loglevel printk.time=1` to the existing command line. Named, timestamped initcall entry/return pairs localize the last entered or unreturned callback; the global pre-init waits remain separately identifiable by completed initcalls and absence of Run /init.

Diagnostic selection additionally exports the exact captured `uart.full.log` file (at most the existing 1 MiB capture bound) and effective diagnostic fragment. The diagnostic public raw-content budget is 2 MiB; default publication remains 256 KiB. UART capture/VM execution still stops at 1 MiB or 180 seconds, and reaching either limit remains failure. A capture limited by output-budget failure is a bounded prefix, never a claim of a complete unbounded stream. Frame rows bind exact retained file bytes with length and SHA256. The registered workflow alias must retain the same changed body as the manifest-bound original workflow; Root owns this duplication and dispatch.

No source input pin, timeout, marker requirement, natural-QEMU-exit requirement, cleanup or hardware/performance gate is relaxed. No diagnostic build or VM has run locally.
