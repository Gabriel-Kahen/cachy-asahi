# Package validation

An automated static-pass, successful package assembly, installation test and exact-model hardware PASS are different records. Current local tooling tests exercise synthetic fixtures and metadata boundaries; they do not supply ARM or M2 evidence.

## Automated checks

| Check | Tool | Failure boundary |
| --- | --- | --- |
| Recursive recipe discovery | `package_checks.py recipes --require-recipes` | No recipes, missing metadata, split/duplicate declarations, unsupported architecture |
| Source verification | Same | Local traversal/symlink/missing/checksum mismatch; unchecked remote archive; unpinned Git commit |
| Effective dependency graph | `dependencies.py INVENTORY.json` | Missing/version-mismatched dependencies, conflicts/replacements intersecting snapshot, overlay cycles |
| Isolated execution contract | `build.py` | Unpinned/missing/non-ARM image, incorrect native/emulated label, stale input review, changed dependency lock, existing output directory |
| Recipe metadata binding | Same | Reviewed versus isolated-generated metadata differs in either direction, including architecture-specific dependencies and added hook declarations |
| Artifact metadata binding | Same | Wrong name/base/version/architecture/license/dependency relations, changed PKGBUILD digest in `.BUILDINFO`, unexpected hook, more than one artifact |
| Archive inspection | `package_checks.py artifacts PACKAGE...` | Unsafe/duplicate paths, special files, setuid/setgid, non-root ownership, symlink ancestors, invalid hardlinks, missing/duplicate package metadata, oversized members/archive |
| Protected Asahi stack | Same | Payloads in boot, modules, firmware, initcpio, ALSA, PipeWire/WirePlumber, udev, modprobe/modules-load/sysctl or named speaker-protection service/binary paths |
| Hooks | Same | `.INSTALL` or a `.hook` requires separate explicit review; automatic package gate fails rather than silently approving it |
| ELF inspection | Same | Wrong machine/endian/class, malformed headers, executable/shared object missing program headers/PT_LOAD, PT_LOAD failing structural 16K alignment, ELF hidden in arch=any |
| Overlay file ownership | Same with multiple archives | Non-directory path collision between overlays |
| Second-build evidence | `compare.py FIRST SECOND` | Failed builds, tampered/missing evidence/input/artifact hashes, stale artifact set, reused run identity, different inputs/image/mode/epoch, changed installed contents or `.PKGINFO` |
| Byte reproducibility | Same with `--require-bytes` | Whole-archive hashes differ even when installed contents match |

No archive is extracted onto the host. zstd streams are read through an argument-list subprocess; filenames are never shell commands. Uncompressed member size is limited to 128 MiB and total archive size to 512 MiB, suitable for the initial configuration overlay. If future larger packages need other limits, revise this policy explicitly. Relocatable ELF objects receive a page-alignment-not-applicable label, not a successful executable 16K claim.

The protected prefix list is a conservative initial guard, not a replacement for a complete base ownership inventory. Dependency inventory is an explicit snapshot input; repository package existence alone does not prove installation compatibility. The release worker's target-transaction checks must bind the full installed base file set, protected package names/provides/conflicts/replaces, coordinated graphics/desktop versions, and accepted release package set.

## Independent package review

Before acceptance record reviewer, date, recipe input hashes and actual archive SHA-256. Review:

1. Original and third-party licenses/notices, attribution, redistribution obligations, exact upstream commits or archive digests, and retained retrievable sources. A `license` string alone is not permission.
2. Whole PKGBUILD body, generated metadata, build/check/runtime/optional dependencies, target availability, resolved transaction, platform package relations and installed file ownership. Static metadata parsing deliberately cannot prove shell behavior.
3. Every path, mode, owner, symlink/hardlink and executable; services/session startup; all hooks; package backup/config semantics; source-to-payload correspondence; `.MTREE` consistency. Automated archive checks report independent hashes but do not validate `.MTREE` contents as an installation test.
4. Opt-in configuration setup, existing-user preservation, fresh/repeat setup, remove/reinstall, interruption behavior and documented recovery. Archive inspection does not exercise pacman or user setup helpers.
5. If compiled binaries are introduced, structural ELF inspection **plus actual execution on 16K-page Asahi**, with relevant loading/plugin/runtime workloads. Inspecting ELF alignment is a necessary structural screen, not a sufficient runtime compatibility guarantee.
6. Two fresh ARM build records, dependency/base provenance, content comparison and byte comparison. Explain all differences. Cross or emulated work remains distinctly labeled and cannot satisfy native build acceptance.

Archive gate hook failures are intentionally visible. Do not disable the check or silently drop a selected package to claim a complete overlay. Independently reviewed future hooks need a coordinator-approved policy/schema extension before the automated build status can pass.

## Installation and hardware acceptance

Use the coordinator's baseline and hardware documents. Collect exact M2 Air model/size, machine ID, base repository hashes, preserved firmware/boot/kernel/Mesa/audio versions, artifact hashes and validation contract before installation. Run installation/removal and all specified functional checks, followed by upgrade/failure/rollback/recovery on the exact accepted machines. Preserve PASS/FAIL/NOT RUN and logs. No test in this directory changes a system, suspends a machine, installs packages or assigns hardware status.

## Current test coverage

`python3 -m unittest discover -s tests -v` covers read-only shell handling, local-source escape/tampering, remote/Git source requirements, recursive discovery, hostile tar members/links/permissions, Asahi audio override paths, 16K ELF headers, complete metadata binding, a mocked full runner accepting valid evidence and rejecting changed version/dependencies/provides/hooks, image pins, dependency/version/provider/cycle boundaries, evidence tampering, copied-run rejection, and context-only provisioning without any Docker call. Mocked Docker execution is labeled test machinery, not an actual build result. The build/validation suite currently has 33 tests; it also checks native/image architecture labels before execution, missing evidence, malformed archive failure records, exact timeout cleanup, special input files, symlinked metadata without reading external targets and empty discovery. Targeted provisioning regressions cover mixed original zst/xz/gz archive/signature bytes, checksum tampering and rejected unsupported/mismatched extensions. The isolated `.SRCINFO` comparison accepts full-line comments/blank lines while rejecting changed fields/order/values, inline comment changes, unexpected architecture dependencies/hooks and missing inputs.

CI runs these tests, the read-only baseline collector tests, the benchmark worker's tests and the release worker's tests, shell syntax checks and recursive recipe inspection. Release integration tests explicitly skip when Arch tools (`repo-add`, `bsdtar`, `vercmp`) are absent on the Ubuntu runner; that skip is visible and is not a release PASS. Full release tests must be run in an environment already providing those tools. GitHub Actions itself has not yet been run by this workstream. The checkout action is pinned to [v7.0.0](https://github.com/actions/checkout/tree/9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0), verified through its upstream tag on October 11, 2026, with credential persistence disabled and read-only repository permissions.
