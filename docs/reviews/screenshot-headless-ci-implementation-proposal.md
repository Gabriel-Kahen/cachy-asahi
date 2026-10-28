# Screenshot helper: pinned software CI implementation proposal

Status: **Source proposal and inert controls complete; runtime image build, compositor, real captures and CI dispatch NOT RUN.** This finite trial concerns the existing standalone screenshot helper under Sway on Linux amd64. It establishes no Hyprland compatibility, ARM archive execution, Asahi installation, M2 hardware behavior or performance result. The earlier screenshot Source `92a3f0612c558b91accc15cd6495d98d6463b943` and ARM archive `0b22…` remain separate evidence.

All deliverables are under [`artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/`](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/). This work changes no canonical workflow/helper, Git ref, repository variable or CI run. Prior screenshot-actual evidence remains immutable.

## Exact implementation and runtime

[`copy-list.json`](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/copy-list.json) proposes seven additions whose canonical preimages were checked absent. They are one manual workflow, `ci.py`, `run.py`, `validate_png.py`, `Containerfile`, `runtime.lock.json` and `source.lock.json`. The Source lock binds ten leaves: the six other additions plus the unchanged screenshot helper, project license, and package license/notice. Root registration binds the Source lock itself, avoiding a self-hash. The existing helper remains 8,523 bytes, mode 0755, SHA256 `5a920a5dd7a40463417a9b15e64a6620acfe7b2328960bf7014c9f587c4b69a8`.

The pinned amd64 base is `docker.io/library/debian@sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483`. The authoritative [runtime successor lock](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/runtime-closure/successor/runtime.lock.json), copied byte-for-byte into proposed Source, is SHA256 `dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05`. It freezes OCI manifest/config/layer identities, all 196 binary package versions/architectures/URLs/sizes/hashes, 127 source versions with 406 source-archive pins, copyright notices/common licenses, signed repository metadata and 597 required dependency joins. All 196 binary archives, their internal controls and copyright notices were checked. Five selected tool source archive sets were downloaded and inspected; other source archives are pinned by signed metadata, not claimed downloaded or rebuilt.

| Tool | Selected Debian version |
| --- | --- |
| Sway | 1.10.1-2 |
| wlroots | 0.18.2-3 |
| swaybg | 1.2.1-1 |
| grim | 1.4.0+ds-2+b1 |
| slurp | 1.5.0-1 |
| Pillow | 11.1.0-5+deb13u4 |
| Python interpreter | 3.13.5-2+deb13u5 |

These differ explicitly from the earlier source-only Sway 1.11/wlroots 0.19 proposal. The [closure report](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/runtime-closure/report.md) audits the selected Debian sources and patches: explicit `WLR_BACKENDS=headless` bypasses host/default hardware backends; `WLR_RENDERER=pixman` selects the software renderer; those capabilities select SHM allocation. Passive ELF symbol inspection supports availability of the constructors. This is source analysis, not an observed device syscall trace or proof of binary/source reproducibility. Official registry HTTPS and OCI digests establish captured image integrity; no independent publisher signature is claimed. Debian InRelease signatures were verified against the archive keyring extracted from that pinned base; the keyring is not an independent out-of-band trust anchor.

The configured output is **320×240 at scale 1**. wlroots' 1280×720 initial default is not the test geometry. The successor changes only that runtime-contract description, importing the immutable first closure seal. Both closure receipts must remain available.

The pinned checkout v7.0.1 and upload-artifact v6 action commits, complete source archives, action definitions, MIT licenses and npm dependency locks are captured in [action-provenance](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/action-provenance/actions.json). Hosted Ubuntu/Docker tooling is not represented as this pinned container runtime; the future job records OS and Docker versions. No action was executed during preparation.

## What the proposed single trial actually does

Before checkout, the workflow requires an exact eight-key Root plan, manual dispatch, the registered ref, and equality of Source SHA and workflow SHA with the registered commit. The checked-out driver repeats that guard, authenticates the Source lock, every listed byte/mode and the runtime/base hashes before downloading or using Docker. Well-formed digest syntax alone is not approval: the subsequent content joins must also match. Missing registration refuses execution.

The driver downloads all 196 exact hash-checked debs from the recorded official HTTPS URLs. Every Docker invocation explicitly selects `--context default`, and explicit Docker host/context environment overrides are refused. It pulls only the immutable base and builds with `--network=none`; the Containerfile uses offline `apt-get --no-download --no-install-recommends` and prevents service starts through policy-rc.d. No apt update or host package installation occurs. The resulting image ID is recorded only after a real build. Installation success and the final image ID remain unobserved now.

Only Source-lock-selected public leaves are staged for a read-only `/source` bind. The container has no network, writable root, capabilities, privilege, device grants, physical TTY, host display/IPC socket or clipboard access. It runs as the CI user's non-root UID/GID with no-new-privileges, 128 PIDs, 512 MiB RAM, two CPUs, a 64 MiB private tmpfs and 16 MiB SHM. Its only writable host bind is its new private evidence directory. Docker inspection checks the isolation before start. A unique random name, owner label and cidfile identify only this job's container for cleanup.

Inside, the runner first compares the complete installed Package/Version/Architecture inventory with all 196 lock rows. It creates fresh owned 0700 HOME/runtime/output directories, sets an absent private SWAYSOCK and discovers the sole owned Wayland socket. Sway receives the explicit headless/pixman environment and Xwayland-disabled private configuration. Bounded IPC validates its complete header/body and checks one active output at the required dimensions/scale. The debug log must contain the selected headless, pixman and SHM initialization markers.

Actual `swaybg` supplies `#123456`, followed by two actual helper `full` captures; a fresh background supplies `#654321`, followed by a third. A 250 ms frame interval is a finite preparation interval, not readiness proof. Wrong/unready pixels fail the trial; no fixture or fallback image can count as a capture. Each invocation must print one fresh absolute direct-child path, create exactly one new PNG, leave no partial and preserve every earlier file identity/hash/mode.

The independent validator process requires an owned regular 0600 direct child of an owned 0700 directory, stable opened-file and directory identities, at most 8 MiB, valid PNG signature/chunk bounds/order/CRCs/IHDR/IEND, no unknown critical chunks or trailing data, exact dimensions and 8-bit RGB/RGBA. Pillow verify, reopen and full decode must establish **every** expected RGB pixel and opaque alpha. Decoder fixtures never enter capture output or result generation.

The same real helper then performs full/offline twice, region/offline once and refusal of a preexisting 0755 output directory with a 0600 sentinel. Exact failure diagnostics, empty saved-path output, preservation of prior PNGs/sentinel/modes and absence of partials are required. Region success is not exercised: no synthetic input selects a region.

The runner retains the first failure, retires only its owned backgrounds/compositor, refuses forced-kill cleanup and requires no remaining runtime entries. Its internal operation budget is 180 seconds; the Docker attach timeout is 220 seconds and the workflow timeout is 25 minutes. Command output uses regular files with resource size limits. Download checks enforce per-response timeouts and a 480-second check between packages; that check is not an absolute trickle-resistant network deadline. The workflow is the final wall-clock bound. Cancellation/host failure without completed cleanup evidence is UNKNOWN/FAIL, never PASS.

The outer driver requires a clean non-OOM container exit, the positive capture/result fields and verified removal of the exact owned container. Unresolved identity/cleanup fails. Evidence includes actual PNGs, stdout/stderr and compositor logs, exact package inventory, Root plan/runtime lock, image ID, container inspections, host tool versions and both result JSON files. The artifact is retained for seven days; no release or repository image is published.

## Review, adoption and remaining work

The separate [PNG review](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/png-validation/report.md) records 34 passing inert checks: 33 decoder/filesystem/CLI controls and one Python 3.11/3.13 syntax group. Execution used host Python 3.14.7/Pillow 12.3.0; it does not claim testing on the selected Python 3.13/Pillow 11.1 runtime. Runner/registration/IPC/cleanup controls and their final Source bindings are recorded in [runner-review](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/runner-review/). They execute extracted safe functions with owned fixtures/fake processes; no Docker, compositor or helper actor ran.

Root's remaining sequence is concrete: authenticate this parent seal and independent review; copy exactly the seven additions after checking absent preimages and unchanged helper/license pins; commit/review that exact Source; fill the two null values in [registration-template.json](../../artifacts/reviews/screenshot-headless-ci-implementation-proposal-20261014/registration-template.json) with the adopted Source commit and independent peer receipt; register/read back the complete plan; publish the exact matching ref; manually dispatch **one** trial and independently inspect its complete artifact and cleanup evidence. The suggested ref in the template is a proposal, not an existing branch. The guard does not itself enforce a global one-dispatch quota; Root owns that finite dispatch boundary. No actor work is authorized by the invalid pending template.

Only an actually successful, fully retained trial can establish this bounded standalone software behavior. Even then, Hyprland behavior, the separate ARM package archive, target installation and exact M2 hardware checks remain open.
