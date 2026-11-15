# Emulated ARM16K RTC C01 correctness lifecycle, 2026-11-15

Root’s fresh trial **passed** `PASS_EMULATED_ARM16K_C01_RTC_CORRECTNESS_INSTALL_REMOVE_ONLY`. Both retained zlib baseline/LTO packages executed their fixed correctness workload after ordinary signed ALPM installation in a real systemd/PAM guest under aarch6416K TCG emulation. Performance was **NOT_MEASURED**; native ARM/16K, Apple/M2 and release acceptance were **NOT RUN**.

## Actual workload and restoration

The exact111-package guest already satisfied both packages’ glibc dependency. Required/TrustedOnly ALPM installed `cachy-asahi-zlib-baseline 1.3.2-1` and `cachy-asahi-zlib-lto 1.3.2-1`, with hooks/scriptlets unsuppressed: inventory111→113→111 after normal removal. No compilation, acquisition, `--nodeps`, hook suppression, dependency stubs or host installation occurred in this trial.

As UID1000, both installed probes matched their pinned JSON. Each encoder processed seven pinned corpora at levels1/6/9, including empty input and16383/16384/16385-byte page-boundary cases. The actual terminal counts were2 probes,42 encodes,84 cross-decodes through the installed baseline/LTO strict decoders, and42 independent GNU gzip decodes. Decoded bytes matched the corresponding corpus exactly. Six malformed-member checks each required exit2, the fixed stderr and exact expected partial output. The fixed workload source was2086bytes, SHA-256 `b3f3eaf6562af9ca3ca53d07542a732943514d3369acf6979ab9f89b2a14ee83`; its private temporary workspace was removed by its mandatory cleanup.

After package removal, baseline regular-file hashes, ALPM database hashes, xattrs and metadata-view hashes matched; the guest also compared exact package path sets. User-owned configuration/data sentinels matched, exclusive package payload was absent and private TEST trust was removed. Raw metadata snapshots retained actual numeric link counts. As in the [passed KSM prerequisite](arm16k-rtc-signed-project-lifecycle-20261115.md), equality omits **only verified live `/proc/` nlink**, using an explicit volatile label. Every other field/path remains exact. This is not raw `/proc/` nlink equality or a general pseudo-filesystem exclusion. C01 retained its raw snapshots privately in `/run`; it did not gain KSM’s separate durable snapshot collector.

PL031 rtc0/hctosys1 and an advancing RTC passed before crypto. Actual host boot UTC was2026-11-15T07:56:23Z (1794729383), RTC before crypto1794729396 and guest1794729397. No clock was set or temporal check waived. Normal UID1000 `builder` PAM TTY login, active logind/D-Bus, aarch64 and pagesize16384 were observed. Durable summary/GPG receipts crossed the actual `sync -f` boundary.

Normal PAM logout passed. Root requested QMP quit; QEMU naturally exited0 and was reaped, with empty process-group census twice, no signals and no timeout. Owned-container removal/absence and cleanup ownership passed; cleanup errors were empty. Guest shutdown remains unqualified: QMP quit followed logout.

## Exact local proof and admission

These are local retained paths, not public artifact publication. `/dev/shm` is volatile; this document makes no public-durability claim.

| Local proof | Bytes | SHA-256 |
| --- | ---: | --- |
| `/dev/shm/cachy-asahi-c01-rtc-first-boot-root-20261115-r1/report.json` |3351|`a1f07ce1a728dc4de79bbd713175341591bff53a6b3786852ef9f78c913cd394`|
| `/dev/shm/cachy-asahi-c01-rtc-preparation-root-20261115-r1/assembly/prepared.json` |109503|`40be2c9a50a9a3bfb2d109eaf81bcc99b5e4d6d0d81d56a22e6ee30dc9c03212`|
| `/dev/shm/cachy-asahi-c01-rtc-preparation-root-20261115-r1/input-manifest.json` |22339|`dd41a85fb889d2e5a7f7935daa5284666c0d0b07f9b5349f823c5fb16b26636a`|
| `/dev/shm/cachy-asahi-c01-rtc-preparation-root-20261115-r1/preparation.json` |22352|`8c052b276e4f9669033dce830a0d4690e26d6b7817bcde21cd5c561bc38231cb`|

The input manifest binds actual source/fixtures/packages, current signing lineage, built RTC bundle and the **genuine** KSM r3 PASS prerequisite:3439bytes, SHA-256 `e77fc144535f86175ba4881f0bc336e7b783dda869ce4d6265d28b1d658df719`. No modeled/held KSM result substituted for it. Fresh TEST signer `28883796E039C3CC08603F3EFD56E30AF1115613` was created1794713061, expires1795317861; only its public certificate entered the actor. This is disposable TEST trust, not production trust.

| Archive/signature | Bytes | SHA-256 |
| --- | ---: | --- |
| `cachy-asahi-zlib-baseline-1.3.2-1-aarch64.pkg.tar.xz` |1730592|`30a5de643b71603d1158982163a0560841fda50c2bd68f7cbbfea81403451924`|
| baseline detached signature |119|`9c89d96b41effc0c6075279c5afe338f00886bbbd425cf0e43eb75421ea9443c`|
| `cachy-asahi-zlib-lto-1.3.2-1-aarch64.pkg.tar.xz` |2136328|`0bf11d89052f419546ea43d922b1d5eb36ca2f2e6612971750442f77ff57a084`|
| LTO detached signature |119|`337f36639be23adabbd074c4b212bc8e57100d91acdf7e557179484ab0dcd254`|

The exact RTC bundle/Image/config and tools image are the same pins recorded in the KSM validation. C01 uses its explicitly separate4442-byte actor, SHA-256 `d232365f0c9d1306df9e86c430cd0b506a6620eb68644361aa7d1eab147c4141`. The prepared manifest pins C01 guest-root8066bytes/SHA `7965e25b33f165ef4ceabee13e309d36d8a52ced37c2be8dd89a1f437554d212` and runtime4406bytes/SHA `d027ba0967707d295e547ca0a32e4c3ac0144fb58fe26670c0436bdd278aeeb3`, including the byte-identical KSM procfs helper. Source correction `858b518c18dc70f4b85b6b5c337a8230fce0761c` passed40 actor-fenced controls and8 separately labeled private-host helper controls before this trial.

Root authority/resource records are `/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-C01-RTC-first-boot.ACTUAL-r1.json` and `Root-C01-RTC-first-boot-resource-r1.json`; authority SHA-256 `a3035f4d47d9732134042d7402420e786a9278014886335cb9a8c46e71ae1754`. The controller entry was `scripts/integration/arm16k_c01_workflow_rtc/boot.py --allow-first-arm16k-c01-rtc-workflow`, with independently pinned preparation/authority/kernel/signing/KSM inputs. Recorded argv, retirement and redacted serial are adjacent to the report. Its consumed marker is not replay authorization.

QEMU used virt/TCG, PL031 UTC host RTC,2vCPUs/1536MiB, no NIC/KVM/display and sandbox confinement. The rootless host container had all capabilities dropped, no added devices, read-only root, networknone,2CPU/3GiB/256PIDs. Preparation allocated631676928bytes. No host services, trust, devices or user desktop were exercised.

This validates the fixed installed correctness/lifecycle workload in emulation. It does not establish a speedup, original compiler reproducibility, source/legal completeness, Apple boot/graphics/audio integration, native16K or M2 compatibility, normal guest shutdown, or release acceptance. Historical closed trials and their markers remain unchanged.
