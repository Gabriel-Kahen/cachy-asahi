# Separate Root-native container proposal

**Source proposal only. No runtime entry, Root binding, container, namespace,
compiler or native build has run here.** The original bubblewrap candidate at
commit `0b83da9d3b77ba538c843e2c5c06b850384ac09c` stays byte-for-byte frozen.
Its native namespace path remains held unless actually probed and qualified.
A normal rootful Docker container with zero capabilities and NoNewPrivs does
not establish permission or support for nested bubblewrap/user namespaces.

This directory exposes a fixed CMake/staging contract for the separate hosted
LLVM Source worker. It does not select a weaker fallback or authorize a job.
`contract.py` has no process-launch, extraction or runtime-entry path. It verifies
the pinned `build.sh`, `reference.py` and `inputs.json` hashes from the live
`source_commit`, returns the four fixed phase commands, and exposes the
selected static staging checks. `frozen_driver_commit` records the origin of
the identical `build.sh` bytes. The controller and fixed native entry must be
separately pinned and technically admitted by Root.
The declaration itself, a status string or passing synthetic tests supplies no
runtime evidence. There is no new generic supervision or isolation framework.

## Proposed fixed native entry

1. Root's host controller pins the exact source/controller/native-entry/driver
   and policy. It verifies the existing source archive size, hash and retained
   authentication; extracts only through its separately qualified source-input
   preparation path, inventories/reviews the consumed tree and notices, and binds
   that exact tree before CMake. The 349-package native bootstrap supplies GCC
   and dependencies; it is not an LLVM build. No existing LLVM23 binary is needed.
2. The controller creates a fresh owned work tree, including `home`, `tmp` and
   `dest/opt/cachy-asahi/llvm23-source-reference`. Creating this **empty** stage
   mountpoint is trusted setup, not a prerequisite compiled artifact. It mounts
   that work tree read/write at `/work`, the extracted tree read-only at `/source`,
   and frozen driver read-only at `/driver`. The stage prefix is also mounted
   read-only at its final `/opt/cachy-asahi/llvm23-source-reference` path, referring
   to the *same* owned directory as `/work/dest/opt/...`. A Root-owned host bind
   directory can supply both aliases; a volume-subpath implementation needs its
   own observed source/alias proof. Do not assume nested mount privileges.
3. Before upstream code, Root joins actual Docker inspect/create records with
   actual entry/init observations: actor and image IDs; native architecture/page
   size; nonzero configured and kernel credentials; zero capability sets and
   NoNewPrivs; observed seccomp state; full UID/GID maps; process executable,
   command line, PID/starttime/parent and namespace lineage; root/source/driver
   read-only mounts, writable work, private-prefix alias; network isolation and
   actual cgroup/resource bounds. `contract.json` lists the finite evidence set.
   Reuse the existing Perl lane's observation/reader design where sufficient,
   with a separately pinned LLVM policy, mount set and resource profile. A Perl
   pass cannot qualify this actor. The reader must reject missing/changed proof.
4. Select `ROOT_NATIVE_CONTAINER_DOMAIN` explicitly before launch. Record nested
   bwrap/unshare as `NOT_INVOKED_NOT_QUALIFIED`, not PASS. A container-private
   cgroup namespace reporting `0::/` is valid only when joined to the dedicated
   outer cgroup observed by Root. Rootful identity UID/GID maps and the absence
   of a nested user namespace are explicit domain facts, not failed observations
   to conceal. Existing `reference.preflight/run/sandbox` are not invoked here.
5. The fixed entry clears the environment, sets only `contract.json` values and
   uses `TMPDIR=/work/tmp` in the owned writable work tree. It runs
   `phase_command('probe')`, then `'tools'`, then `'runtimes'`, then `'check'`.
   The tools phase stages LLVM/Clang/LLD through DESTDIR. Newly built tools become
   visible through the already-created final-prefix read-only alias. Runtimes
   therefore use the correct private Clang pathname without changing rootfs or
   installing anything globally. Source stays read-only. The prefix's writable
   `/work/dest/...` alias is intentional staging, not an immutable-output claim.
6. Require `inspect_stage('/work/dest')` before smoke probes and again before
   exporting the stage. Preserve the ELF AArch64/16K geometry and private LLVM
   RPATH checks, upstream SONAME/symlink chain and exact notices. The check phase
   performs the frozen C/profile/exception compile/link/run probes. Root owns
   bounded logs, actual wall/resource limits, signal handling, exclusive child
   wait/retirement, and exact Docker actor retirement. Passing static inspection
   is not proof of build execution or source provenance.

The entry must refuse before upstream execution if any domain/source/dependency
or resource observation is missing or mismatched. It must not call the frozen
recipe's main/build/package functions as a way around their bwrap checks. Package
assembly, real dependent Rust loader execution, signed install/remove/reinstall,
16K-native execution, M2, reproducibility, performance and release stay separate.
All four original binary recipe mismatches and existing source/license holds stay.

## Source-only verification

```sh
python -m unittest discover -s packages/port/llvm23-source-reference/native_container -p 'test_*.py'
```

The fixed native entry and actual observations are still owned by Root/the hosted
Source worker. This proposal can be consumed without editing the frozen recipe;
its tests never manufacture native-domain acceptance.
