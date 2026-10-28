# Fresh independent review: actual screenshot software run 38634245640

**PASS: one actual x86_64 standalone Sway headless/pixman software trial on Source `453699c276ecd7377cf9e1ef682acf9e9554cf61`.** The corrected offline runtime image built, its installed inventory matched all 196 package pins, three full screenshots passed independent pixel checks, four expected refusal cases passed, and the exact owned container was retired. This establishes the finite software behavior exercised by this run. Successful region selection, native ARM archives, accelerated Hyprland, Asahi/M2 hardware, package installation/removal, licensing/distribution closure and performance acceptance remain open.

## Authenticated evidence

The sealed Desktop review receipt is `artifacts/reviews/screenshot-headless-software-run-38634245640-20261014/receipt.json`, SHA256 `15d9e50f4968d59ad82540ebff3a9164eebedae8119c6cec557255d282fc2960`. This fresh peer independently authenticated its actual index schema and all **13 owned and five external rows**, then the retention receipt/index and all **87 retained rows** under `artifacts/retained/screenshot-headless-software-run-38634245640-20261014/`.

Original artifact ZIP **11927572296** is 133372 bytes, SHA256 `a1384b8b9162d1e098504202dae9005d723adb8411970946044c254c7cbdb812`; it matches both retained artifact metadata and the retention receipt. All **59 file members** were compared directly to the extracted retained bytes without extracting or executing them. No live API call or downloaded-code replay was used.

Run **38634245640**, attempt **1**, and its sole software job **116093229938** are retained as completed/success on the exact Source and manual workflow event. The registered literal is 529 bytes, SHA256 `8581aa6a2dcefca913d644f238cb6388dc7ebe6c278c25d80a91cccbb9b0207a`; retained variable readback is byte-identical, its Source/ref match the terminal run and Source proof, and the emitted runtime Root plan matches it. Its Source lock `5d2c1b75fae1bb1b93a001ce92d5a9afd5bafb745460e8cdfb4374cdf846515c` and runtime lock `dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05` authenticate. Six retained Source inputs match their lock rows by bytes/hash; the Root's retained Source proof records the full ten-row closure and two-replacement adoption. Normalized retention modes are separate from original Source/runtime mode evidence.

## Actual runtime and captures

The actual recorded Docker build used `--network=none` and linux/amd64; its preceding pull used the registered Debian base digest `sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483`. Build and trial commands returned zero. Actual dpkg-query stdout independently joins all **196 unique package/version/architecture rows** to both the held runtime lock and trial result. The resulting image ID is `sha256:c4c17ac94528b416ff1ecc0348fafbaf5fdc831f35cbd3f5ebd54f60a5a780bb`, consistently recorded in the image file, CI result and before/after/cleanup container records.

The records show nonroot UID/GID 1001, network none, read-only rootfs, no privileges/devices/device requests, dropped capabilities, no-new-privileges, finite resource limits, no TTY/stdin and only the new Source/evidence bind mounts. The recorded environment uses private HOME/runtime, one headless output and pixman. The actual Sway log contains headless/pixman/SHM markers, and IPC output is one active `HEADLESS-1`, 320×240, scale 1. Sway reports 1.10.1. These runtime facts accompany actual helper command records and retained PNGs; the workflow's green conclusion alone is not the acceptance basis.

| Capture | Expected RGB | Bytes | Independent SHA256 |
| --- | --- | --- | --- |
| First full capture | 18, 52, 86 | 782 | `056616b64d89eeec2d4e63aebe0d60e221505a3676d77e718f5d393695ec8ca5` |
| Repeat full capture | 18, 52, 86 | 782 | `056616b64d89eeec2d4e63aebe0d60e221505a3676d77e718f5d393695ec8ca5` |
| Changed-colour full capture | 101, 67, 33 | 782 | `a2f4a44a1f5a4eea6474c7d8d0e97ce547920bb3caed91217c15806177e95648` |

The fresh decoder traversed chunks/CRC/order/end boundaries and independently used local Pillow verify, reopen and full decode to compare **230400 pixels**, including opaque alpha. All PNGs are 320×240 RGB. The first two image byte strings are equal; the third differs. Their recorded filenames and original inodes are distinct. Each helper stdout names the corresponding file; each validator stdout matches its capture summary and both children returned zero without stderr. Four separate bounded in-memory corruption controls reject wrong colour, truncation, trailing data and bad CRC. These are decoder controls, not additional captures.

Retained original-runtime validator records say each PNG was user-owned 0600 under an owned 0700 output root. The retained copies were normalized to 0600/0700 during extraction; their current modes alone cannot prove history. Prior-image and private-directory preservation checks are enforced by the held runner Source and passing actual result; this review did not replay those private filesystem operations.

## Refusal and cleanup evidence

The actual four negative helper records have exit 1, empty stdout and matching raw stderr: offline full twice, offline region with no full-screen fallback, and refusal of the insecure output directory. The preserved sentinel bytes are retained, with no other retained insecure-output entries; only three shot entries and no partial entries are retained. A successful interactive region selection was **not exercised**.

Owned background-A/background-B processes ended by termination without forced kill; Sway exited zero, with no remaining runtime entries recorded. The after-inspect record shows the exact container exited zero without OOM. Cleanup identifies matching random name, ownership label, image and ID **453f18b89826502e76d64eb68f3d1610d0753b053d0e548ffce10c469b036d15**. Its exact-ID removal returned zero and echoed that ID. The following inspect returned 1 with `No such object` for the same ID. This supports **owned container retirement**, not retirement of the base image, final image, build cache, context or downloaded debs; those remain **UNKNOWN/UNRECORDED**.

The fresh peer ran **40 finite retained-data/decoder checks**, all passing. It performed no APT, Docker, compositor, helper, capture, API, Git write, repository-variable mutation or dispatch. It owns only this report and `artifacts/reviews/screenshot-run-38634245640-fresh-root-peer-20261014/`. The previous actual run **38628618206** remains an immutable APT/build failure; this changed successful trial does not rewrite that history. No further retry or new running-job policy is introduced by this review.
