# Actual corrected-provider 624-archive ELF inspection

Actual outcome: **FAIL-static-data-inspection / exit 1**. The committed provider correction resolves the historical false omissions, but the same 22 firmware parser refusals keep the overall report FAIL and the candidate inventory incomplete. This is a complete inert archive/data inspection, not installed-system, loader, ABI, native build, 16K runtime, M2 or performance acceptance.

The coordinator adopted the 52-test source at commit `7360b61541e58f0ebe039cb4c8a1e709eaedfce5` and authorized this separate full run. A fresh two-file copy was authenticated against exact committed Git blobs and modes; execution used that copy with `-I -B`, no PYC and the existing guarded ARTIFACTS output boundary. The original 1,071-byte contract `17b5a1414fb7575fde9168fbf7378f310ddef2edabef8c8b24784fcc1648a418` was copied without modification. All original 624 archive references, prior payload report/handoff and authentication bindings remain unchanged.

| Committed source, mode0644 | SHA256 | Git blob |
| --- | --- | --- |
| `scripts/platform/elf_audit.py` | `72ec18c7d8580094164b3ea4c11fcff2583519b4cd861e5c436ec9d7a779401b` | `e0a24f88359778f0dd2048d998bc1929d7683a97` |
| `scripts/platform/test_elf_audit.py` | `16a5a49d0fc90c1998fb2be2ffc6dc1d5f3f9d941451b7258cd247396329f340` | `91f0aa88d664f37d691d0ee5fe506c57ffa2f9b8` |

The journaled exec wrapper enforced 2 GiB address space, 1195 CPU seconds, 256 MiB per-file resource limits and no core. Outer timeout was 1195 seconds with five-second forced-termination grace, within the 20-minute wall ceiling. The reader retained its unchanged 2 GiB compressed total/300 MB archive, 1 GiB decoded archive/8 GiB decoded total, 500,000 total nodes and all existing file/table/string/deadline bounds. Output serialization remained capped at 64 MiB. Private output stayed on the project filesystem, which had 102,949,478,400 free bytes at preflight. Final inclusive retention is 43,797,087 bytes, below the 256 MiB aggregate ceiling. The protected output directories are mode0700; reports/diagnostics are mode0600 at final handoff. The measured 112.200 seconds from launch journal through controller finalization includes completion polling and report inspection; it is not pure parser runtime or a performance comparison.

## Actual findings

All **624 archives** passed fresh checksum and complete payload correlation. Compressed archive bytes total **1,323,663,952**; actual decoded bytes **5,709,117,440**, nodes **138,317**. The full report observes **7,129 ELF files**:

| Observed classification | Count |
| --- | ---: |
| AArch64 loadable ELF forms | 4,322 |
| Relocatable ELF data | 2,404 |
| Other ELF data or unresolved runtime scope | 350 |
| Parsed firmware ELF data | 31 |
| General-parser refusals | 22 |

Every object record and archive result is exactly equal to the historical committed46-source report, including package/data hashes, dynamic mapping, interpreters, SONAME, needed names and alignment observations. All 22 refused paths are under `usr/lib/firmware/`, in linux-firmware-atheros/linux-firmware-other: 13 `elf-file-range`, nine `elf-load-order`. These are general-parser refusals of vendor firmware layouts, not proof of corrupt firmware or a failed runtime executable. No exception, blanket exemption or cap increase was introduced.

The corrected full run reports **2,147 observed interpreter candidates**, **18,370 single observed library candidates**, and **27 missing observed-provider requests**. Against the historical graph, exactly 4,509 omissions now have a single candidate: 4,250 libc.so.6, 224 libQt6Core.so.6 and 35 libcap.so.2 requests. The three original no-interpreter/no-SONAME basename edges remain: perl and texinfo request libperl.so, and krb5 requests liblmdb.so. No new missing request was introduced. The actual 27 residual records equal the previously reviewed metadata-only reduction, but this evidence comes from a new complete archive/hash/parser run rather than substituting that reduction for execution.

The 27 residual requests cover 22 names. Repeated requests are libmpi.so.40 (four), libfltk.so.1.3 (two), libtcl8.6.so (two). One request each remains for libKF6GuiAddons.so.6, libKF6WindowSystem.so.6, libQt5Core.so.5, libQt5Network.so.5, libQt6Core5Compat.so.6, libQt6Svg.so.6, libXaw.so.7, libXmu.so.6, libdb-6.2.so, libell.so.0, libfido2.so.1, libgd.so.3, libheif.so.1, libmariadb.so.3, libodbc.so.2, libpq.so.5, librrd.so.8, libtk8.6.so and libxfce4panel-2.0.so.4. Complete consumer/package/path/hash records remain in the full report and summary. Global candidate matching does not implement RPATH/RUNPATH, environment, cache, hwcaps, symbol/relocation compatibility or actual loader selection; a missing candidate is not a demonstrated installed load failure.

Five previously unobserved namespace targets remain unchanged: three CA certificate aliases target generated tls-ca-bundle.pem; /etc/mtab targets proc/self; /var/lock targets run/lock. They do not become accepted generated paths merely because the archives were inspected. All 4,322 parsed AArch64 loadable forms retain observed modulo16384 load congruence and declared alignment at least16384. Actual 16K execution remains false.

## Exact retained handoff

New private evidence is under `artifacts/platform/elf-audit-provider-corrected-20261012/`. Unified execution session75551 returned actual exit1; stdout reports the exact FAIL/counts, stderr is empty. The original 29 indexed historical files and original handoff were independently rehashed both before capture and after execution, unchanged. The prior FAIL report and source captures remain immutable.

| Evidence | SHA256 |
| --- | --- |
| `actual-source-proof.json` | `13311326bd3552aa70aa7d225f60a90a1c82370dc91725ec38a3267eb0f4e850` |
| `actual-report.json`, 21,843,306 bytes, identical guarded copy | `b257a737a5a0a5a96935fdf613f7ebe1621e60c6761b698b3da11ef000eb7cd1` |
| `actual-summary.json`, 17,544 bytes | `7b081fa83f293c012942774f4ff416422ba0e556de253ae8483071d27e2e43b7` |
| `actual-handoff.json`, 6,008 bytes | `9b404a4f4cc1abb8ca5b0241f91830208a7a070149b7618db8d1cb57a59a8a29` |

The handoff binds every new retained source/contract/wrapper/journal/diagnostic/report/receipt file, exact lengths and final modes. No archive extraction, payload/loader execution, installation, keys/trust mutation, Docker/native workload, mount or host system change occurred. Archive authentication belongs to the unchanged prior acquisition provenance; this ELF helper does not verify signatures, independent owner trust, source grants or production custody. Installed transaction/recovery, runtime ABI/imports, hardware integration and performance acceptance remain open.
