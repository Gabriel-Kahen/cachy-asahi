# Core desktop native integration — 2026-10-15

[Run 38763443973](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38763443973) completed successfully on hosted Linux ARM. The retained integration summary records **PASS** for fixtures, signer, lifecycle, repository and desktop software checks. This establishes the four-package disposable-container workflow below; it does not establish an installed desktop session or Apple hardware compatibility.

| Selection | Exact identity |
| --- | --- |
| Workflow revision | `61f1715b14aff4a66f780e42d0571901496a5326` |
| Checked-out/tested product | `41a0c43515cebf48dff399cdd15bdef83bc6ef82` |
| Workflow branch | `codex/desktop-integration-resume-v1` |
| Inputs SHA256 | `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f` |
| Recipes SHA256 | `a5fb287b4dda2a90bf61d4fa8cbbc5d666dad8bb450a70544d00545b091f36e3` |
| Recipe-source selection | `465bf53545e1d83053bf3c412e210493961b74ae` |
| Source-date epoch | `1791748800` |
| Base inventory SHA256 | `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25` |

Workflow and product revisions differ only in `.github/workflows/native-arm-build.yml`. The workflow builds once, freezes the package-integration selection, and invokes `integration_resume.py` on the same daemon. It uses `package_only=True`; onboarding and the broader source suites are explicitly **NOT RUN** in the summary.

## Native builds and actual package bytes

The runner records Linux/aarch64, four Neoverse-N2 CPUs, 4096-byte pages, kernel `6.17.0-1022-azure`, non-root UID/GID 1001 and a local aarch64 Docker 28.0.4 daemon. These are hosted execution observations, not physical Mac or independent bare-metal attestation.

Acquisition records contain 501 PASS, zero FAIL and zero pending inputs. All 249 detached-signature checks (rootfs plus 248 packages) record exit 0. The scratch bootstrap records the exact 341-package inventory above, 6674 bytes, and image:

`sha256:30e38befd837a2c537af5ecba6ebf05c0a28c4d190496e105eff9de6b1bb5c50`.

Each original package completed two native builds, exit 0, in eight distinct recorded build containers using that one image and epoch. All four comparison reports record `contents-reproduced`, with no errors. Offline inspection of the retained bundle rehashed all eight original archives against provenance and confirmed equal bytes within each pair; it did not run additional builds.

| Original package | Version | Bytes per archive | SHA256 of both archives |
| --- | --- | ---: | --- |
| cachy-asahi-fish-config | 0.1.0-1 | 5396 | `38e766158d13a0e13b8f811766119d10c018ccc256f5d99c3561b74c99d12705` |
| cachy-asahi-hyprland-settings | 0.1.0-2 | 12740 | `0b22b778ec83d8b98d98d06fa4f016bd4e3f581b69efa83d6526c5265c2adf5e` |
| cachy-asahi-setup | 0.1.0-3 | 14496 | `85ab7b964cd628ef21f5df6133aa9d046d32ea35cd6af3de0e5b888341550f0c` |
| cachy-asahi-zsh-config | 0.1.0-1 | 6244 | `be2ef8ed4f0263720ed6290bff9992d5df53c7bf689a40478f2be329ba2d50e7` |

These are the original `arch=any` packages. Distinct containers on one builder do not establish reproduction on an independent machine or optimized ARM binary performance.

## Installation, configuration, updates, removal and recovery

`lifecycle/lifecycle/result.json` records **PASS**, 166 passing checks, 82 commands, native aarch64 execution and 4096-byte pages. Actual operations used disposable container accounts and user fixtures:

| Behavior | Retained checks establish |
| --- | --- |
| Initial installation | Overlay initially absent; exact baseline inventory, package ownership and payload hashes after installing all four originals |
| Configuration | Read-only preview, idempotent repeated activation, existing prefixes/modes and base session configuration preserved |
| Controlled upgrade | Signed test derivatives upgrade the complete selected inventory; unmodified configuration copies refresh and edited copies survive |
| Removal and reinstall | Base inventory restored and package-owned payload absent after removal; user files survive; reinstall restores exact inventory, ownership and payloads |
| Deactivation | Fresh owned files removed; existing configuration edited surgically; edited desktop files retained |
| Interrupted activation/removal | Journals retained, preview remains read-only, recovery completes, and all selected components reach the expected restored/removed state |
| User edits and cleanup | Edits inside managed blocks survive repeated operation; login shells and base configuration remain unchanged; fixture accounts, homes, journals and test keyring are cleaned |

The lifecycle contract is `2a3fd1eadd39337552bb9232f46d8369589a5597e5f6ba2828eb2c881657a779`. The sanitized baseline handoff records 345 installed packages, the four original versions/payload maps, the original setup helper, restored account databases and preservation of the original ALARM keyring. Its private cleanup records PASS. These are package/configuration recovery checks, not boot recovery or an interrupted real-machine system upgrade.

A fresh read-only check of the committed installed image records PASS, including its underlying temporary directory and original payloads:

`sha256:7eff6acc9262fac2bd8dcb32b0e9f966d3d2d72713ecd3fbea3f2edef04b039e`.

The final summary's `owned_image_cleanup` records `status=PASS`, `absence_verified=true`, `cleanup_uncertain=false` for exactly that owned image; `cancelled=false`. Parent-layer erasure is explicitly **NOT CLAIMED**. This does not assert absence of the original builder image, all daemon images, caches or unrelated resources.

## Repository transactions and rejection behavior

`repository/result.json` records **PASS**, 208 commands and all 11 cases passing. It exercises complete `-Syyu`/`-Syyuu` transactions over the copied generic 341-package builder inventory, with four reviewed changed-package derivatives and a synthetic tamper probe. The test repositories use ephemeral A/B identities; they are not production trust or a published release.

- Successful cases: trusted baseline full installation, trusted B rotation/full upgrade, full rollback to retained A, and final upgrade with unrevoked B.
- Rejected cases: untrusted A, untrusted B rotation, tampered package signature, tampered database signature, missing package signature, missing database signatures and revoked A.
- All seven rejection cases retain equal before/after installed-inventory and payload snapshots. The missing-database-signature case uses the explicit local sidecar-presence contract for `integration.db.sig` and `integration.db.tar.gz.sig`; it is not evidence that pacman alone rejects every missing-signature `file://` database configuration.
- The revocation path records a controlled sync-cache reset. Test private state removal is true. The signer records eight TEST-only signatures and `production_credentials_used=false`.

The repository result keeps `published=false`, `stable_promotion=NOT RUN`; the integration summary keeps `production_trust=NOT RUN` and `selected_for_release=false`. These tests do not accept the full maintained package set, an Asahi platform transaction or production repository operation.

## Desktop software scope

`desktop/desktop/desktop.json` records `desktop-container-verifier-pass`, 24 commands and seven check groups:

- Exact installed ownership/hash checks for eight Hyprland package payloads, including the screenshot helper, and the complete runtime inventory.
- Lua syntax and real Hyprland `--verify-config` for default and optional-startup configuration.
- Waybar strict JSON **syntax only**, GTK3 `CssProvider` CSS parsing with `display_created=false`, and the source-audited Mako configuration subset.

Headless compositor execution is **BLOCKED, attempted=false**: pinned Aquamarine 0.15.1 requires a DRM-backed GBM allocator, while `/dev/dri` is excluded. Waybar and Mako application runtime are **NOT RUN** and those applications are not installed in this frozen lock. No bar/notifier, compositor, graphical login or installed user session was launched. The record leaves graphics acceleration, portal/audio session, hardware validation and optimization acceptance **NOT RUN**. Screenshot-helper payload validation is not a real screenshot-capture test.

## Current package equivalence and integration gap

At Root's canonical integration baseline `3adab042c79b4d47357f2b25fabfd8e4ac8ae661`, all four package directories, the 72 reviewed recipe-input hashes, `native_arm.py`, input lock and recipe lock match tested product `41a0c435…`. The updater adoption in that baseline is separate evidence; this desktop run did not test the updater. The subsequently added tools work is also outside this run.

The tested consumers have now been adopted byte-for-byte into canonical through the targeted 18-file patch, including `scripts/ci/installed_handoff.py`, `integration.py`, `integration_resume.py`, `desktop_projection.py`, `repository_projection.py`, and `scripts/integration/{desktop,fixtures,lifecycle,repository}.py` with their focused tests. The historical integration lock remains held for its older composition contract. New runs freeze a separate lock against their exact final source using the existing freezer; an older stored Source selection is not copied over it. This source adoption does not make the complete assembled canonical composition runtime-tested.

For the separately documented maintained-composition branch at `d8fa351c136a562b58ad60f5d22f0258a3c241a1`, Fish/Zsh match, but Hyprland remains 0.1.0-1 and setup 0.1.0-2. Relative to tested product, Hyprland differs in `.SRCINFO`, `NOTICE`, `PKGBUILD`, `README.md`, screenshot helper and `hyprland.lua`; setup differs in `.SRCINFO`, `PKGBUILD`, `README.md`, helper and `source-provenance.json`. This report does not transfer the current package result to those older recipes.

## Retained evidence

Root collected the logs once at `artifacts/development/desktop-run38763443973/logs.zip`: **4,307,019 bytes**, SHA256 `3f6a32dc83b7c2b7194f0cee18f2f812f40c2d2c9b770240e03458506e1c4b8f`. This documentation pass read that ZIP offline, verified each of the ten curated frame byte counts/digests, and inspected bounded regular tar members in memory. GitHub timestamp prefixes and transport BOMs were removed before decoding; the resulting compressed bytes match the declared digests. No evidence was recollected, overwritten or executed.

| Curated frame | Compressed bytes | SHA256 |
| --- | ---: | --- |
| native-evidence | 1276995 | `208c78401d7faa42edda7d2e6d5fb4e8ddeea30c13ae4bf010a08514472c3fee` |
| desktop | 30300 | `2497a17df29bcdf305ce79d991fbfdfa6e262fc0cf864affdb4249630d7c8c58` |
| fixture-archives | 40281 | `814ee5346cc18ecb66fc0cea6108f686653705c2ae308c9b2f77ebca21b1c774` |
| fixtures | 59958 | `7e90d3a5c4505c42d88b32bd0d2a3b2629e09c6f6e81f602aec8faf378085eb0` |
| lifecycle | 66120 | `6e5874a5e28812ce3e553662eaf87b4cab47faa2715b14a32123862b52d613c9` |
| repository | 136868 | `9a188cd5329bf3a623c587a298e551f2f022275f82b15b8ab9073e55ab67f50f` |
| repository-public-artifacts | 279115 | `1b5021bba69490d131c74c5b22935f557738deb0bdc02a980af48ce3909dfc07` |
| signer | 4357 | `30d9abf8fa20a24cb92dd6d08b4c747c7896968305aa574bf8fda0fd21a632f0` |
| signer-public-artifacts | 5058 | `5207b1c5b9ad17cd6db69bea86ff40a48912fcca7ba2d90de08e858c49f2a54d` |
| summary | 976 | `6706b67e3dc4ad3537cfb91d1de81460f65c445f1b2289c923b413e2a3f452f7` |

No broad suites or new native operations were run for this note. Both M2 Air sizes, physical 16 KiB execution, the Asahi stack, an actual accelerated desktop session, full-system installation/recovery and measured performance remain outside this result.
