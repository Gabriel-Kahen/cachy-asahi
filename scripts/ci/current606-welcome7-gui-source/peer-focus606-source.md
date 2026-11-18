# Current606 peer-focus Source correction

Current606 R2 run `44302338878`, ARM job `134795000444`, reached the hosted/guest clock join and the exact 606 guest and 590 controller inventories. Its GUI step ended after 650 seconds when scrolling to **Assess orphan packages** failed at the actual peer-focused-state check. Seven frame pins and failure-path management restore and ordered cleanup verified. The installed606 preservation verifier never entered. [R2 native run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44302338878/job/134795000444)

R1 and R2 emitted identical accessibility drivers. R1 and the earlier 4 KiB run reached the orphan control through the already-unclipped path. The 4 KiB run also recorded an actual focused enabled **View report** action. In R2, the disabled orphan control took the peer fallback. The driver accepted the one focus reply, found the target geometry, then read the refreshed peer focus once and refused it. The original evidence locates the refusal. Whether focus would have appeared on a later refresh remains unverified. [R1 run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44278633141) · [Earlier 4 KiB run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40202454241)

R4 evaluates full target geometry and refreshed actual peer focus inside the same bounded settle loop. The original single focus request and exact process, role and panel checks still apply. The successful sample requires the peer to be focused, enabled and sensitive and a readable state set that confirms the target is disabled. The four changed Source leaves preserve the original emitter in the held inverse, and the existing clock and signed-input selection stay pinned. [Published R4 commit](https://github.com/Gabriel-Kahen/cachy-asahi/commit/ddfe829c6ea053d4cb47f47e1652599954bfdfc0)

Use a local Git repository with the published R4 ref fetched. Its ancestry contains the exact R3 parent `659614002fdc67f9170d4dec8db9e27dd6b6d89b`. The exporter checks both commit headers, reconstructs the four changes from R3, and checks the exact resulting 592-leaf tree `dd9abb3fd1ccaef93d043284f77781cea6367173`. Set the output to a fresh path outside the input repository.

```bash
lane=scripts/ci/current606-welcome7-gui-source
python3 -I -B "$lane/peer_focus606_source.py" --repository "$R4_GIT" --output "$R4_OUTPUT"
python3 -I -B "$lane/test_peer_focus606_source.py" --repository "$R4_GIT"
```

The focused controls check all exported bodies and modes against the published commit and compile the emitted settle predicate against eight scripted geometry and AT-SPI state cases. Four source-only fixture renders also reproduced the corrected driver. Live R4 peer focus, installed606 preservation, visual review and physical M2 validation remain pending.
