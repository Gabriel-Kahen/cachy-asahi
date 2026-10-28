# Residual ELF provider and firmware closure proposal

Status: **retained-data classification and finite proposal only**. The actual corrected624 scan remains **FAIL**, with27 missing observed-provider requests and22 firmware parser refusals. None is waived or replaced by an optional-dependency label. No package was acquired, installed, executed or added to a shared release inventory in this work.

The hash-bound [actual scan](../reviews/platform-elf-corrected-execution.md) supplies the27 exact consumer/path/name/hash records. The completed624 inert payload report supplies archive-correlated `.PKGINFO` text and node hashes. Captured core/extra DB descriptors and file catalogs supply exact proposed provider versions, filenames, sizes, digests, embedded signature digests, dependencies, licenses and named library paths. These catalog transport/hash observations are not newly authenticated provider archives or independent owner trust. All sources and per-request signed-metadata provenance are retained in the private classification receipt.

## Consumer feature and dependency classification

**24 requests** directly match a consumer's declared optional dependency; **two** are mandatory dependencies of a declared optional component; **one** is a shipped plugin edge absent from the consumer's dependency declarations. No direct match to an explicitly required consumer dependency was found in this bounded mapping. That does not establish overall dependency closure or working core functions: optional functionality becomes required when selected for the release. The [46-root desktop/application proposal](../port/desktop-coverage.md), [tools functionality scope](../port/tools-functionality.md), roadmap and manifest remain proposals/development inventory, not a final release feature definition.

| Consumer/version and affected payload | Missing request(s) | Exact declaration or unresolved scope |
| --- | --- | --- |
| alsa-tools1.2.15-3: hdspconf, hdspmixer | libfltk.so.1.3 ×2 | `fltk1.3: for hdspconf, hdspmixer`; these interfaces cannot be advertised without closure. Apple audio still needs its separate protected safety/DSP path. |
| bluez-utils5.87-2: btpclient | libell.so.0 | `ell: for btpclient`; Bluetooth core operation remains an independent required target test. |
| boost-libs1.92.0-1: four MPI/parallel libraries | libmpi.so.40 ×4 | `openmpi: for mpi support`; the generic native development journey does not establish this optional MPI feature. |
| glycin2.1.5-2: glycin-heif | libheif.so.1 | `libheif: Load .avif, .heic and .heif`; image-format support must be explicitly selected/tested. |
| gpsd3.27.5-1: libQgpsmm | libQt5Network.so.5, libQt5Core.so.5 | `qt5-base: for Qgpsmm`; no Qt5 payload compatibility claim follows. |
| libnewt0.52.25-2: whiptcl | libtcl8.6.so | `tcl: whiptcl support`. |
| lm_sensors1:3.6.2-1: sensord | librrd.so.8 | `rrdtool: for logging with sensord`; Apple sensor/thermal support remains separately required. |
| python3.14.8-1: _tkinter extension | libtk8.6.so, libtcl8.6.so | `tk: for tkinter`; captured tk8.6.16-1 requires tcl. This is the unadopted coordinated Python proposal, not approval to change the protected3.14.7 tuple. |
| qt6-base6.12.0-2: MySQL/ODBC/PostgreSQL driver plugins | libmariadb.so.3, libodbc.so.2, libpq.so.5 | Declared mariadb-libs/unixodbc/postgresql-libs optional SQL drivers. |
| qt6-declarative6.12.0-1: QuickVectorImageGenerator | libQt6Svg.so.6 | `qt6-svg: for QtQuickVectorImage and svgtoqml`; selected Qt apps may make this functionality required. |
| thunar4.20.10-1: libthunar-tpa panel plugin | libxfce4panel-2.0.so.4 | **Undeclared shipped-plugin edge**: neither depends nor optdepends names xfce4-panel. Thunar file management is a core proposed desktop function; the Xfce panel integration needs an explicit packaging/feature decision and cannot be silently ignored. |
| v4l-utils1.32.0-2: qv4l2 | libQt6Core5Compat.so.6 | `qt6-5compat: for qv4l2`; camera/video acceptance remains required independently. |
| glibc2.43+r22+g8362e8ce10b2-2: memusagestat | libgd.so.3 | `gd: for memusagestat`; no libc core-load failure is established by this optional utility finding. |
| iproute2 7.2.0-1: arpd | libdb-6.2.so | `db: userspace arp daemon`; core networking acceptance remains open. |
| pinentry1.3.3-1: pinentry-qt | libKF6WindowSystem.so.6, libKF6GuiAddons.so.6 | kwindowsystem/kguiaddons optional Qt6 backend. Working credential prompts remain core: select and test the actual supported backend rather than waiving credentials. |
| groff1.24.1-1: gxditview | libXaw.so.7, libXmu.so.6 | `libxaw: for gxditview`; captured libxaw depends on libxmu. Terminal manuals and any selected graphical viewer need their own tests. |
| openssh10.5p1-1: ssh-sk-helper | libfido2.so.1 | `libfido2: FIDO/U2F support`; explicitly decide/test security-key functionality without inferring ordinary SSH failure or compatibility. |

The first classification projection conservatively left Python's libtcl edge unclassified. The final projection follows the captured tk→tcl dependency and preserves the first receipt as history. All27 requests remain OPEN, including the26 optional-associated requests. The static archive report does not identify what a user actually loads.

## Exact finite provider candidates

All22 requested names have matching filename paths in the **existing captured** catalogs, across21 direct provider packages. Each is absent from the624 inspected set. No direct provider version gap was observed at this metadata level; in particular the catalog has matching tcl/tk8.6.16, OpenMPI's libmpi.so.40 and the required Qt major names. File-list paths and declared version/SONAME names still do not prove the archive's ELF identity or ABI. No URL or alternate filename was guessed.

| Proposed direct provider | Captured version | Repo | Covered request |
| --- | --- | --- | --- |
| fltk1.3 | 1.3.11-4 | extra | libfltk.so.1.3 |
| ell | 0.83-1 | extra | libell.so.0 |
| openmpi | 5.0.11-1 | extra | libmpi.so.40 |
| libheif | 1.23.6-1 | extra | libheif.so.1 |
| qt5-base | 5.15.19+kde+r96-1 | extra | libQt5Core.so.5, libQt5Network.so.5 |
| tcl | 8.6.16-1 | extra | libtcl8.6.so |
| tk | 8.6.16-1 | extra | libtk8.6.so |
| rrdtool | 1.11.0-1 | extra | librrd.so.8 |
| mariadb-libs | 13.0.2-2 | extra | libmariadb.so.3 |
| unixodbc | 2.3.14-1 | core | libodbc.so.2 |
| postgresql-libs | 18.6-2 | extra | libpq.so.5 |
| qt6-svg | 6.12.0-1 | extra | libQt6Svg.so.6 |
| xfce4-panel | 4.20.8-1 | extra | libxfce4panel-2.0.so.4 |
| qt6-5compat | 6.12.0-1 | extra | libQt6Core5Compat.so.6 |
| gd | 2.3.3-9 | extra | libgd.so.3 |
| db | 6.2.32-4 | core | libdb-6.2.so |
| kguiaddons | 6.30.0-2 | extra | libKF6GuiAddons.so.6 |
| kwindowsystem | 6.30.0-1 | extra | libKF6WindowSystem.so.6 |
| libxaw | 1.0.16-2 | extra | libXaw.so.7 |
| libxmu | 1.3.1-1 | extra | libXmu.so.6 |
| libfido2 | 1.17.0-1 | extra | libfido2.so.1 |

Their declared compressed bytes total **34,989,696** before transitive closure, signatures or source material. This is neither an authorized download total nor a complete extension. The receipt records19 additional unsatisfied mandatory dependency directives on the proposed providers (some package/SONAME pairs and duplicate declarations): libxpm, libavif, libcbor/libcbor.so=0.14-64, aom/libaom.so=3-64, libde265, openh264/libopenh264.so=8-64, hwloc, libfabric, openpmix/libpmix.so=2-64, prrte, qt5-translations, qt6-shadertools, garcon, libwnck3 and libxfce4windowing. Declared libltdl is supplied by an existing package's provides field; the conservative first-level accounting marks it for formal provider-transaction confirmation rather than claiming a new absent package. No recursive or version-qualified solver acceptance is claimed.

Concrete next proposal, subject to coordinator selection: retain the21 exact direct roots as an **unadopted** optional-feature closure candidate; resolve their full mandatory transaction against the immutable working platform tuple and preserved original strict/Python-proposal distinction; reject conflicting protected-version changes. Capture exact additional package/version/filename/hash/signature pins and ownership/file collisions before acquisition. Authenticate original archives/signatures with pinned official public keys in an isolated public-only verifier, compare full PKGINFO identity/dependencies/provides/hooks to these catalog observations, and resolve corresponding source revisions/licenses/grants. Reuse the inert payload/ELF audits on a new bound contract before any installed import/application test. Each selected feature gets a target test; an excluded optional component must be explicitly scoped in the release declaration while its original residual record remains preserved. No file trimming or core-function exclusion is proposed here.

Ownership proposal: the package/repository owner (M5/R1) owns archive/source/license/dependency maintenance; the target transaction/platform owner preserves protected versions and rollback; desktop/tool owners (M6/R4) select actual backend/module behavior and verify core functionality; the release coordinator adopts the finite inventory. These are proposed responsibilities, not accepted named-human custody or a production signing policy.

## Firmware observations and separate future scope

The22 refused files were independently located by exact archive/member/hash and read as inert bytes, with no extraction. All have ELF32 little-endian ET_EXEC header labels. Machine values are **3 ×6**, **164 ×8**, **40 ×7**, **243 ×1**. Linux's pinned [v6.19 ELF machine definitions](https://github.com/torvalds/linux/blob/v6.19/include/uapi/linux/elf-em.h) label these i386, Qualcomm Hexagon, ARM32 and RISC-V respectively. A firmware header tag is not evidence that its instruction payload executes on that CPU, nor that the host distribution requires that CPU; none is an AArch64 userspace-header identity.

Twelve paths are paired `.mdt`/`.b00` files for ath11k IPQ5018/IPQ6018/IPQ8074 m3/q6 firmware. Their same signed-package namespace contains matching `.bNN` segments. Seven are ath11k/ath12k amss.bin ARM32-labeled images; two are Hexagon-labeled wpss.mbn/q6_fw0.mbn; one is MorseMicro mm8108.bin RISC-V-labeled data. Full22 path/hash/header/sibling records are retained. Twelve split items plus wpss.mbn have the file-range refusal; the other nine have load-order refusal. Qualcomm's pinned [v6.19 MDT loader](https://github.com/torvalds/linux/blob/v6.19/drivers/soc/qcom/mdt_loader.c) explicitly loads separate `.bNN` segments and uses physical segment addresses. That supports a firmware-container interpretation for the split pairs; it does not validate these actual images. The remaining vendor formats and actual firmware loading were not audited.

A potential **separate reporting proposal** is an explicitly declared userspace ELF inventory alongside a kernel/device-owned firmware inventory, requiring authenticated package identity, exact namespace/member role and bounded header/container evidence. Arbitrary placement beneath a firmware directory must not hide a claimed userspace executable; unsupported/ambiguous firmware would remain an explicit firmware result. Vendor-specific split/physical-loading validation would have its own source and limits. This task introduces no predicate, parser exception or acceptance change: all22 general-parser refusals and the original aggregate FAIL remain intact. Actual Apple firmware integration still requires the preserved Asahi stack and exact-model hardware tests.

Private evidence: `artifacts/platform/elf-residual-closure-20261012/classification-final.json`, SHA256 `0579cf5a413bea46db8f115f2a5fb9ee0a5a3b62a6cd2caf1e47ce17f7e2fd48`,226,084bytes. The first projection and finite audit script are retained separately. Initial read-only capture ran in4.707seconds under a180-second outer ceiling,2GiB address space/180 CPU seconds/32MiB per-file report cap; the small final projection followed existing metadata only. No network refresh, package execution, installation, shared source/manifest/Git change, loader/ABI/16K/hardware test or performance claim occurred.
