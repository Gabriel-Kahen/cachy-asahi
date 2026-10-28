# Current604 desktop profiles on generic ARM16K

The minimal and overlay profiles pass for the same source, `bd3c8d616bdec7fb9d29f253be5bda4b6dbd9e5e`. This is finite desktop component acceptance in a generic ARM VM; Apple hardware and release admission remain **NOT RUN / NOT ADMITTED**.

| Profile | Original native run | Strict replay | Original GUI frames |
| --- | --- | --- | --- |
| Minimal | [39300288120](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39300288120) | PASS | 12 reviewed |
| Overlay | [39194659089](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39194659089) | PASS | 12 reviewed |

Both original collections pass the source-bound positive reader under one complete binding for this pair. The overlay collection was replayed passively; neither original collection was downloaded again. Each profile verifies 604 installed packages, 16384-byte guest pages, 17 management actions, 3886 ELF records and a 114235-node installed capture with zero capability-bearing files. All source leaves are joined to the published commit.

Root reviewed all 24 original frames: Welcome home/system/guides, launched Files and Terminal, Doctor and orphan reports, locked-database refusal, missing tools and closing during an active check. Text and application contents are legible, without blank frames or visible rendering corruption.

Cleanup is retained, source-bound evidence and was not independently reobserved live. Full private node/ownership/capability maps and kernel Image bytes are not exported. The installed maps differ between profiles; each is checked against its own original capture. Signatures are TEST signatures with the original native ALPM gates. This does not establish current606 package preservation, updater recovery, physical rendering, performance or M2 compatibility.
