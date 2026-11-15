# Emulated ARM16K RTC signed project lifecycle, 2026-11-15

Root’s fresh r3 trial **passed** `PASS_EMULATED_ARM16K_RTC_SIGNED_PROJECT_INSTALL_REMOVE_ONLY`. This is a real dependency-checked package lifecycle inside an emulated aarch64/16K systemd guest. It is not native ARM, Apple/M2, KSM kernel-functionality, performance or release acceptance.

## Actual scope

The guest reported aarch64, `getconf PAGESIZE=16384`, PID1 systemd, active logind/D-Bus and a normal UID1000 `builder` PAM TTY session. It installed the unchanged `cachy-asahi-ksmctl 0.1.0-1` plus signed ALARM `python 3.14.8-1` and `mpdecimal 4.0.1-3`: exact inventory111→114→111. Ordinary `pacman -U`/`-R` used Required/TrustedOnly signatures and unsuppressed hooks/scriptlets. No `--nodeps`, hook suppression, dependency stub, host installation or service mutation was used.

The installed CLI ran as UID1000: help/version exited0; status/report exited3, a supported unavailable/held diagnostic; enable/disable each refused with exit2. No KSM policy action or sysfs tuning was requested. This establishes these CLI behaviors, not functioning KSM memory merging.

Baseline regular-file hashes, ALPM database hashes, xattrs and the defined metadata comparison view matched after removal. The guest also compared package path sets exactly, confirmed exclusive payload absence and retained user-owned configuration/data sentinels. Private TEST trust was removed. `DURABLE_RECEIPTS=sync_f_completed` records the source’s actual durability boundary before terminal publication.

The runtime confirmed PL031 rtc0, hctosys1 and an advancing clock before crypto. Actual QEMU-start host UTC was2026-11-15T07:47:31Z (1794728851); guest and RTC before-crypto UTC both1794728863. No clock was set. The actor checked fresh host UTC/monotonic agreement and signer validity; the guest checked RTC/system/host agreement before GPG and ALPM. Fresh TEST signer `C98720061248F50811843544A8EC89D416F7A112` was created1794716090 and expires1795320890. Old expired signatures remain historical; this fresh disposable trust is not production/release trust.

Normal PAM logout was observed. Root then requested QMP quit; QEMU naturally exited0, was reaped, and its process group census was empty twice, without timeout or signals. Owned-container removal/absence and cleanup ownership passed; cleanup errors were empty. Guest shutdown itself is **not qualified**: the emulator quit after logout.

## Precise restoration boundary and preserved failures

Closed r1 held at restoration’s `same_bytes` assertion; its volatile snapshots could not establish the mismatch. Closed r2 added durable bounded raw snapshots and held on metadata. Root’s subsequent read-only, offline DATA recovery validated nonce/manifest pins and found exactly one differing metadata field: `/proc/` nlink. Path sets, all regular-file and database hashes, xattrs and every other metadata field were equal. The backing/overlay hashes were unchanged by recovery; it executed no guest code and conferred no acceptance itself.

The source correction requires an ordinary non-symlink `/proc/`, exact procfs magic/type `9fa0:proc`, and the fixed live proc mount identity in `/proc/self/mountinfo`. It retains original numeric before/after nlink values in the private raw snapshots. Only the separate equality view replaces the one `/proc/` nlink with `VOLATILE_LIVE_PROCFS_NLINK`; this is a label, not a fabricated observed zero. Mode, UID, GID, path and quoted name remain exact there, as do every metadata field for every other path. There is no broad pseudo-filesystem exclusion. Therefore **raw `/proc/` nlink equality is expressly outside the passed restoration scope**.

The exact built kernel’s [proc_root_getattr](https://github.com/AsahiLinux/linux/blob/94fb23346d522edf53722357c426a3e58030beea/fs/proc/root.c#L369-L376) adds `nr_processes()` to the root link count. This explains its volatility; no particular extra process identity was inferred. The bounded source copy was11500bytes, SHA-256 `82e961f5994758310ee13f062c069f36047c7307003710b92d109864c6e96687`.

The KSM source correction is commit `4e3b03fc059bbaba6818df4a854d4adae695693f`. Its72 source/private-host controls passed, including refusal for wrong/fake/missing procfs, malformed/missing/duplicate metadata, other-path link-count differences and every non-nlink field change. These controls support the source guard; the actual r3 report supplies guest execution evidence. Old r1/r2 inputs, markers and results remain closed and unmodified.

## Exact retained inputs and result

All SHA-256 values below identify local retained bytes. These paths are local proof locations; `/dev/shm` is volatile. This document does not claim public artifact publication or durable public retention.

| Local proof | Bytes | SHA-256 |
| --- | ---: | --- |
| `/dev/shm/cachy-asahi-ksm-rtc-first-boot-root-20261115-r3/report.json` |3439|`e77fc144535f86175ba4881f0bc336e7b783dda869ce4d6265d28b1d658df719`|
| `/dev/shm/cachy-asahi-ksm-rtc-preparation-root-20261115-r3/assembly/prepared.json` |106782|`d9a221afb36606d1e6a25be5f7464b26c0bc1536d780ef75746361edde8b2ab0`|
| `/dev/shm/cachy-asahi-ksm-rtc-preparation-root-20261115-r3/input-manifest.json` |20846|`37d06beb62a610649880ac07d55f6e4fdfcd7d54d0fc1d6506815f4ba9e0f9ae`|
| `/dev/shm/cachy-asahi-ksm-rtc-first-boot-root-20261115-r1/report.json` |2083|`61b7686866ace554004eb91ac395e1f2aa7698146b9fbd3f397b87de1205dfc3`|
| `/dev/shm/cachy-asahi-ksm-rtc-first-boot-root-20261115-r2/report.json` |2406|`82e5c33f1d3d3ddbd791d6b3cdc958aa7ee0503277f84dc6c93c86e031ace3c5`|
| `/dev/shm/cachy-asahi-ksm-restoration-data-root-20261115-r2/report.json` |7624|`e5edf2b0b2c6abc9f15baf2fc9fc0dcd8eed3025f65ec0158375bcd3b9f77192`|

The prepared manifest binds the actual source,111-package base, package archives/signatures, fresh public signing lineage and external RTC authority. Key input pins are:

- KSM archive17244bytes: `b518e711c41b8d6bcdae71364b5529aaac982d12cef600f1b2fa17f51c895a4a`; new signature119bytes: `757c93f95fef436916a1be6ecae41abdf5307bba4f60e5055e7af5fc5f68bbcb`.
- Python archive13588352bytes: `5e00dbb30ab55fd160d64205e1f3418c8bcf5b295ff07bf9af7ad4ab85bc6984`; mpdecimal93808bytes: `388611eba7f9b0dddcc03adb4f28bcb8fd2c42fbd8c930ca6b9b0f9e4ece0f1e`. Both signatures identify ALARM signer `68B3537F39A313B3E574D06777193F152BDBE6A6`.
- Built RTC bundle8988bytes: `68f3ff68c78fa3aa8b3d66c3b301472c846a7eb8d2a830ba565d61547029492f`; Image9019400bytes: `505ff41b342647828c399241d51b0cbd9527c6191607a6a3abdeec40a55c3266`; config71589bytes: `020243b2d55a0c093280581a70f337baa01d9822ab4075588ad74fca8857f1c9`.
- Kernel `7.1.13-generic16k-managed-gui-rtc1`, AsahiLinux revision `94fb23346d522edf53722357c426a3e58030beea`; separate host-cross Clang22.1.8 construction, not the historical LLVM18 toolchain. Exact RTC11 states, eight feature changes including LOCALVERSION and fifteen reviewed compiler facts were admitted; baseline buses/other feature states stay held.
- Explicit RTC actor4371bytes: `eb347660a25e80efaf9666ee6e551abd92ae0267b9acdd89560f62e8b62c9b1a`; tools image `sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207`.

Root’s authority/resource receipts are in `/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-KSM-RTC-first-boot.ACTUAL-r3.json` and `Root-KSM-RTC-first-boot-resource-r3.json`. The latter binds integrated source `bc5d92201833e596e35bb4321f818ea96510a629` and the exact prepared hash above. Actual argv/retirement and redacted serial are adjacent to the r3 report in `qemu-argv.json`, `qemu-retirement.json` and `serial.redacted.log`; no command here authorizes replay of its consumed marker.

The Root-controlled controller entry was `scripts/integration/arm16k_project_lifecycle_rtc/boot.py --allow-first-arm16k-rtc-project-lifecycle`, with separately pinned preparation/authority/kernel/signing inputs. Recorded QEMU used `virt`, multi-thread TCG, `-rtc base=utc,clock=host`, CPUmax,2vCPUs/1536MiB, ext4 virtio disk and ttyAMA0/systemd; `-nic none`, no display, no KVM and sandbox enabled. The rootless host container had no added capabilities/devices, all capabilities dropped, read-only root, networknone,2CPU/3GiB/256PIDs. Preparation allocated654352384bytes; the run’s overlay was separately bounded. No host device, desktop, trust or services were exercised.

## Remaining gates

This is a disposable generic emulated software reference. It does not establish Apple boot integration, native16K execution, M2 compatibility, KSM kernel functionality, tuning/performance, source/legal completeness or maintained release acceptance. Normal guest shutdown and target hardware workflows remain separate. The genuine r3 report can serve as the precisely pinned KSM prerequisite for a separately authorized C01 RTC trial; it does not predict that trial’s result.
