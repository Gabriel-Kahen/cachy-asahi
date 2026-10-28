# Complete development composition, native ARM — 2026-10-15

[Run 38774794165](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38774794165), workflow Source **`ff65cb16ffe94d5e9e4210d2412531bbd0f6d524`**, passed the signed, offline disposable composition trial. Both `public/result.json` and `public/coordinator.json` report `status=PASS`, `phase=completed`; the workflow records `Development composition step: success`. All ten selected project packages and four upstream additions installed together, replacing upstream FDK, and the subsequent dependency, integrity, ownership and native library checks completed. Scoped cleanup passed with no recorded failures.

This closes the fixed generic ARM development transaction described below. The complete supported Asahi target, application/session behavior, composed package/configuration lifecycle and release acceptance remain separate work.

## Exact selection and installed inventory

| Input | Tested identity |
| --- | --- |
| Ten project recipe selection | `a58fca33c4db5f2ab3ea6111f4d7842a932cc336` |
| Updater compiler implementation and recipe | `1aea667aec50a62ba0ab2dad44be24a4dc3bd098`, updater **4.4.2-1** |
| Runtime-base builder implementation | `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2` |
| Original-four builder implementation | `a79c4ca92486854f9edb639cd970d2c90fda4b12` |
| Initial 341-package compiler inventory SHA256 | `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25` |
| Updater 354-package compiler inventory SHA256 | `5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee` |
| Initial 574-package runtime inventory SHA256 | `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac` |
| Final 587-package installed inventory SHA256 | `c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463` |

The runner required the actual initial inventory to equal its exact 574-package lock, then the installed inventory to equal the fixed 587-package lock. The arithmetic is **574 + four upstream additions − upstream FDK + ten project packages = 587**. Exact `xdg-utils 1.2.1-2` was already present; the helper authenticated all five upstream inputs and selected only the four missing additions. The final inventory retains the other 573 base package versions. This is the proven runtime-base selection, not a newly resolved union from the compiler inventory.

Local inspection verified that the tested Source's expected lock has 587 unique rows and the final digest above, and that all 14 retained package versions agree with it. The public bundle records the equality gate and digest; it does not retain a separate raw `pacman -Q` listing because successful command stdout is not printed by this runner.

| Incoming package | Version | Actual archive SHA256 |
| --- | --- | --- |
| cachy-asahi-hyprland-settings | 0.1.0-2 | `0b22b778ec83d8b98d98d06fa4f016bd4e3f581b69efa83d6526c5265c2adf5e` |
| cachy-asahi-fish-config | 0.1.0-1 | `38e766158d13a0e13b8f811766119d10c018ccc256f5d99c3561b74c99d12705` |
| cachy-asahi-zsh-config | 0.1.0-1 | `be2ef8ed4f0263720ed6290bff9992d5df53c7bf689a40478f2be329ba2d50e7` |
| cachy-asahi-setup | 0.1.0-3 | `85ab7b964cd628ef21f5df6133aa9d046d32ea35cd6af3de0e5b888341550f0c` |
| cachy-asahi-ksmctl | 0.1.0-1 | `00757d41be50b18e3cd46988b13308f7e05f8d4df8f16fbd61909e944122bfdf` |
| cachy-asahi-update | 4.4.2-1 | `5902153ed1a7798ca533ad1e8cdab124c6355549797048982193fbe4cabfa968` |
| cachy-asahi-fdk-aac | 3.0.0-1 | `237b7812435bd78456d72c157f5703f258f5b6b7455cb99e5b075f642071c247` |
| cachy-asahi-zsh-autosuggestions | 0.7.1-1 | `ff59a185f52e80dc4fd08c666d093cccefa3e57f2513085c900602da597f29b9` |
| cachy-asahi-topmem | 0.1.0-1 | `583ffacd614bd741722486d5fbc64b79bb283d62c87974063fc1484dfcbe199b` |
| cachy-asahi-fish-bang-bang | 0.1.0-1 | `9d5a043691152b7555acafc877eb960750c85417ceef4c41b5f91382645f4b1c` |
| archlinux-contrib | 20261009-1 | `0cda9e6618956615a9065265300af78d1c4b5693bbfe3f6aab7f58b8aa0eeca3` |
| htmlq | 0.4.0-3 | `325ab19a2414dc47d118a48dfce4dee082c65f058afb994ffac2cbc1498055f8` |
| pacman-contrib | 1.13.1-1 | `7f89d02bae727950f543ec969145212b93abea947675de27280c6978cfe9b946` |
| pyalpm | 0.12.0-1 | `1fba3d5b99aba62d4e7b85481e19a993863995f44b20a6a5bf2e30b37be845f5` |

The job consumed its fresh original-four and FDK pairs, built the four small tool packages on the unchanged 341 compiler, and built a fresh updater pair on the unchanged 354 compiler. The updater public comparison records equal archive bytes, installed contents and package metadata, with zero errors. The four small packages were each built once in this composition step; their earlier pair evidence remains separate. All ten archives were checked against the selected actual recipe metadata/build information before copying and TEST signing. The runtime base was freshly constructed in the same job; its report records native aarch64 host/daemon, 574 packages, build return code zero and `PASS_NATIVE_OFFLINE_574_TRANSACTION`.

## Actual signed transaction and post-install checks

The retained caller invokes `scripts/ci/full-development-composition/run.py` with explicit product, updater, desktop, native-output, FDK-output, cache and owned output paths. It uses a clean environment and private HOME without `DOCKER_*` variables. The installation ran as root inside an explicitly selected native aarch64 disposable container, with network disabled and inputs mounted read-only. No target root or user home was mounted.

The four upstream archives retained their pinned signatures and ALARM signer `68B3537F39A313B3E574D06777193F152BDBE6A6`. All ten project archives received signatures from a temporary TEST identity. The private pacman configuration required signatures, and one `pacman -U` transaction installed all 14 archives. No dependency waiver, assumed provider or overwrite option was used. The conflict answer was allowed only after checking that the sole applicable conflict was project FDK replacing `libfdk-aac`. Scriptlets were **DISABLED** and observed installed/incoming hooks **MASKED**.

| Check | Observed result and scope |
| --- | --- |
| Actual archive identity and input bytes | PASS: archive/signature pins, `.PKGINFO`, project metadata and archive payload lists checked before installation |
| Exact installed inventory | PASS: 587 entries equal the fixed lock; upstream `libfdk-aac` absent |
| `pacman -Dk` | Returned zero: installed database consistency check completed |
| `pacman -T` | Returned zero for the dependency expressions collected from all 14 actual incoming archives; result records `PASS-no-waivers` |
| `pacman -Qkk` | Returned zero for all ten project packages; this did not check the complete upstream base's payload integrity |
| Installed project payloads | PASS: every declared non-directory payload has its expected file/symlink type and project package owner; symlink targets agree with the inspected archive |
| FDK provider ownership | PASS: both `/usr/lib/libfdk-aac.so.2` and `/usr/lib/libfdk-xhe-aac.so.0` belong to `cachy-asahi-fdk-aac` |
| Native pyalpm | PASS: isolated Python imported pyalpm and constructed `pyalpm.Handle("/", "/var/lib/pacman")` |
| Installed FDK libraries | PASS: the same native Python process loaded both classic and xHE SONAMEs with `ctypes.CDLL` |
| Container trust cleanup | PASS: private `gpgconf --kill all` and temporary trust-directory removal completed before container result publication |
| Coordinator cleanup | PASS, empty failure list: named composition container absence checked, two newly created builder images removed and checked absent, scoped GPG homes stopped, private trial files removed |

The complete 177,531-byte transaction log includes these command invocations, 1,253 owner-query invocations and the terminal PASS result. Successful command stdout is omitted, so individual `-Qkk` file counts and query responses are not independently retained. The detailed PASS credits follow the exact tested runner's enforced checks and its completed result. Installed payload ownership/type checks do not independently hash every installed project file; `-Qkk` is the package integrity check used here. Native library loading does not itself exercise a codec. The earlier [FDK provider/PipeWire trial](fdk-provider-native-20261015.md) separately covers actual AAC-LC callbacks and upstream restoration.

Cleanup is scoped to the owned composition resources. The original builder is borrowed and protected from image removal. This is not a claim that the entire Docker daemon, unrelated images, caches or all parent layers were erased. Updater output passed through its existing public projector; private updater logs/binaries and signing material were not added to the public bundle.

## Earlier failure and retained evidence

Run **38771650607** installed the same selected package/version set and passed its exact 587-package inventory, then failed before the database check because the shared pacman prefix included install-only `--noscriptlet`. The retry moves `--noconfirm --noscriptlet` into the install call alone. Its actual installation arguments remain unchanged; the subsequent read/check commands now omit those flags. This later run establishes successful downstream checks; it does not change the earlier overall FAIL into a PASS.

Root collected [the retained log ZIP](../../artifacts/development/full-composition-run38774794165/logs.zip) once. Its SHA256 is `ec42b27da867d2bd26408933838ee58ba71ae264baa0255ba37f7dea913ba390`. This documentation pass decoded the `public` frame in `native/16_Retain bounded development composition metadata.txt`, verified **108,448 compressed bytes** and SHA256 **`e497d4635aaa93718a594b097e215ce0c7ac7b4065a1b1810368326d3e862920`**, then inspected its 46 regular members in memory. These include coordinator/result/package records, the full transaction log, bounded small-package/runtime-base diagnostics and sanitized updater build records. No logs were recollected and no package, build, container or broad test suite was rerun for this note.

## Proposed canonical adoption and next software work

Root can adopt the exact ten files under `scripts/ci/full-development-composition/` from Source `ff65cb16ffe94d5e9e4210d2412531bbd0f6d524`, including the install-option regression. The separately tested provider prerequisite has twelve files under `scripts/ci/fdk-provider-trial/`, including its selected private headers and license notices. Both directories are absent from the canonical tree inspected for this note. Adoption should preserve their tested input/recipe/version pins. The feature workflow differs substantially from canonical's registered probe/build/integration workflow: integrate the necessary caller steps deliberately instead of replacing the entire workflow. Root retains ownership of workflow, inventory and shared status edits. This note proposes adoption; it does not claim it has occurred.

The next ordinary lifecycle increment is to extend the existing disposable integration path to this exact ten-package/587-package composition: exercise fresh/existing user setup, repeated/interrupted setup, changed-version upgrade, removal, reinstall and restoration of the original 574-package inventory, including upstream FDK restoration and preservation of user edits. Reuse the existing [core lifecycle](desktop-core-native-20261015.md), [tools interaction](tools-interactive-native-20261015.md) and FDK provider helpers. This adds missing composed behavior; it needs no new signing or execution-admission framework. With scriptlets/hooks still suppressed, it would remain generic software evidence.

The updater's newer **4.4.2-2** real-Check correction is a separate successor exercise. Once its own native result is reviewed, substitute only that reviewed recipe/dependency change and test its real Check failure/success behavior in the combined environment; retain this 4.4.2-1 result unchanged. Existing desktop-session and installer work can continue independently. The [roadmap](../roadmap.md) still requires a selected Asahi platform/dependency set, actual service/hook/session behavior, target installation/update/removal and boot recovery, both exact M2 Air sizes, physical 16 KiB execution, maintained signed publication and measured performance. None is established by this generic transaction. Release selection remains **false**; full R1–R5 and M5–M9 completion remains open.
