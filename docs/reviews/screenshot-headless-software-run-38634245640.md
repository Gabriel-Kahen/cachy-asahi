# Screenshot software pilot 38634245640: retained bounded success

Status: **PASS for one actual x86_64 standalone screenshot-helper trial under Sway headless/pixman/SHM**. [Run 38634245640](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38634245640), attempt 1, completed successfully with Source `453699c276ecd7377cf9e1ef682acf9e9554cf61`, ref `codex/screenshot-headless-software-v1`, workflow `384750899` and job `116093229938`. It ran from 16:41:51 to 16:42:39 EDT on October 14, 2026. The review checked actual retained evidence rather than accepting the workflow conclusion alone.

This is not ARM archive execution, Hyprland compatibility, M2 hardware, license/admission or performance acceptance. Successful region selection was not tested. The earlier [APT100 failure](screenshot-headless-software-run-38628618206.md) remains separate and immutable; this changed trial does not rewrite that result. No extra CI actor, replay, retry, cancellation, Source/Git write or variable change was performed by this review.

## Exact retained identities

The [review packet](../../artifacts/reviews/screenshot-headless-software-run-38634245640-20261014/) and [fresh retention namespace](../../artifacts/retained/screenshot-headless-software-run-38634245640-20261014/) retain terminal run/job/artifact metadata, original ZIPs, safe plain members, committed Source snapshots and actual registration data.

| Evidence | Exact identity |
| --- | --- |
| Artifact | `11927572296`, `screenshot-headless-software-38634245640-1`, 133,372 bytes |
| Artifact ZIP SHA256 | `a1384b8b9162d1e098504202dae9005d723adb8411970946044c254c7cbdb812` — matches GitHub API digest |
| Log ZIP | 14,583 bytes, SHA256 `772f246ff5b08242d3e7e69d652c73f38142bbbad464bab0de22d57c1a58c50e` |
| Registered literal | 529 bytes, SHA256 `8581aa6a2dcefca913d644f238cb6388dc7ebe6c278c25d80a91cccbb9b0207a` |
| Source lock | `5d2c1b75fae1bb1b93a001ce92d5a9afd5bafb745460e8cdfb4374cdf846515c` |
| Runtime lock | `dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05` |
| Built image ID | `sha256:c4c17ac94528b416ff1ecc0348fafbaf5fdc831f35cbd3f5ebd54f60a5a780bb` |
| Owned trial container | `453f18b89826502e76d64eb68f3d1610d0753b053d0e548ffce10c469b036d15` |

Safe ZIP retention checked 59 artifact files and nine log files for bounded counts/depth/expanded sizes, canonical relative paths, duplicate/traversal/symlink/special/encrypted members, CRC/read length and exact hashes. No downloaded code was executed. Extracted copies are normalized to 0600 under 0700 directories; these local modes do not prove original runtime file permissions. The GitHub artifact expires October 21, 2026 at 16:42:33 EDT; local retained bytes remain independent of that expiry.

The artifact's pretty `root-plan.json` semantically matches the exact registered literal and actual Source/ref/peer pins. The captured Root readback/proof records match that literal. These historical records do not grant another dispatch or establish a global slot reservation.

## Actual build, inventory and runtime

Guard, pinned checkout, runtime driver and evidence upload steps all completed successfully. Docker version/info, pinned base pull, offline image build, create, inspect, attach/start, post-inspect, owned identity check and removal returned the recorded expected codes. The build log records package configuration and image export to the image ID above; the ID file and before/after container inspections match it. This establishes one actual corrected image installation/build, without claiming reproducible image identity or publication of a runtime image.

The actual `dpkg-query` transcript has **196 exact Package/Version/Architecture rows**, independently compared with all runtime-lock rows and the runner's structured inventory. It includes APT 3.0.3, Sway 1.10.1-2, wlroots 0.18.2-3, grim 1.4.0+ds-2+b1, slurp 1.5.0-1, Python 3.13.5-2+deb13u5 and Pillow 11.1.0-5+deb13u4. This is an installed inventory result, unlike the prior failed run's input lock. The all-196 download/hash gates passed by audited Source control flow; raw downloaded deb bodies were not retained in this artifact for independent rehashing.

The container inspections establish non-root UID/GID1001, no network, read-only root, dropped capabilities, no-new-privileges, no granted DRM/input devices, no physical TTY, 512 MiB RAM and a 128-PID cap. The create command specifies two CPUs, private tmpfs/SHM and only selected read-only Source plus the private evidence bind. The output query records one `HEADLESS-1` output at 320×240, scale1. The real Sway log contains headless backend, pixman renderer and SHM allocator initialization markers. These are bounded software-path observations, not a universal syscall/device-access proof.

## Three real captures and independent retained-byte validation

The actual helper commands returned three distinct absolute direct-child paths under `/evidence/shots`, each with exit0, empty stderr and exactly one printed path. Separate validator invocations returned matching path/hash/dimension/color records. Runtime file inodes were distinct; the first two identical-color PNGs intentionally have identical content hashes.

| Capture | Bytes | Independently checked content | SHA256 |
| --- | --- | --- | --- |
| A1, filename ending `ff852df9621f8aa95129a60b.png` | 782 | 320×240; 76,800 pixels RGB18,52,86; opaque alpha | `056616b64d89eeec2d4e63aebe0d60e221505a3676d77e718f5d393695ec8ca5` |
| A2, ending `842f9ffc19399e695072ee3d.png` | 782 | Same dimensions/color, distinct path/inode | `056616b64d89eeec2d4e63aebe0d60e221505a3676d77e718f5d393695ec8ca5` |
| B, ending `d8c3a0c176619e48a1107628.png` | 782 | 320×240; 76,800 pixels RGB101,67,33; opaque alpha | `a2f4a44a1f5a4eea6474c7d8d0e97ce547920bb3caed91217c15806177e95648` |

The offline review directly read retained PNG files, checked signature, bounded chunks, every CRC, critical chunk order, exact RGB8 IHDR, final IEND and no trailing bytes. Independent Pillow verify/reopen/full decode then compared all **230,400 pixels and alpha bytes** with expected values. It did not execute the repository validator, compositor or helper. PNG decoding alone establishes content, not provenance; provenance is joined separately through the actual Source/command/validator/metadata/artifact records. No synthetic image substituted for an actual capture.

The runtime validator records owned file0600/root0700 and stable identities. Source assertions require one fresh file/no partial and preservation of each earlier file's bytes/mode/inode. The retained set contains exactly the three PNGs and no partial. Original runtime permissions and temporal preservation rely on those recorded runtime checks; normalized retained modes or final file presence alone do not independently prove the earlier filesystem states.

## Actual negatives and owned cleanup

The runtime's eleven internal command records include the actual inventory, three helper captures, three validators and four expected failures. Two full captures against an absent display return1 with empty stdout and `grim failed; no screenshot was published.` The absent-display region case returns1 with empty stdout and the no-full-screen-fallback diagnostic. A full capture to the preexisting insecure directory returns1 with empty stdout and the permissions-preserved diagnostic. The retained sentinel is exactly `preserve me\n`; its directory has no other retained member. Source assertions checked unchanged prior captures, sentinel identity/mode, insecure directory0755 and no new partials/runtime entries. No successful region selection or physical input operation occurred.

The runner records both owned backgrounds retired without forced kill (SIGTERM exit−15), Sway exit0 and no remaining runtime entries. The container post-inspect records exited/0/non-OOM. Exact-ID `docker rm --force` returns0, followed by inspect exit1 and `No such object` for that same ID. This supports the declared owned runtime/process/container cleanup boundary.

The base image, final built image, build cache/intermediates, download/context directories and deb retirement remain **UNKNOWN/UNRECORDED**: the held driver does not delete or certify those resources. Successful trial-container removal must not be generalized to total host/image/cache cleanup, and hosted-runner disposal is not directly observed here. The build's own final `rm` instruction does not certify host-side context/cache retirement.

The [independent peer review](../../artifacts/reviews/screenshot-headless-software-run-38634245640-20261014/peer-review/) separately joins these actual records and directly decodes the retained PNGs. The result admits only this one standalone Sway software behavior at this exact Source/runtime; it adds no package-license, ARM archive, Asahi target, Hyprland, M2 or performance acceptance and authorizes no additional trial.
