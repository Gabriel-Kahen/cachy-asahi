# Current606 scoped report-focus correction

R4 run `44316744292`, ARM job `134844769340`, retained ten reviewed original frames and reached the intentional ALPM-lock refusal case. Its scoped **Orphan assessment / View report** scroll received a successful AT-SPI GrabFocus reply and obtained complete geometry. The refreshed focus state was absent when the driver checked it. The earlier orphan assessment had already completed. The retained run does not establish when native focus would have arrived. [R4 native job](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44316744292/job/134844769340)

R5 uses the existing bounded settle loop to observe complete geometry and fresh focus on that exact enabled report control after the single GrabFocus request. The successful sample also requires the control to be enabled and sensitive. The driver still freshly checks focus before returning. The change preserves the peer and DNS paths, the ingress inverse, the signed-input selection and the workflows. [Published R5 commit](https://github.com/Gabriel-Kahen/cachy-asahi/commit/bde2e0fc62bdfe677a6d686b83232bbc0db6e65a)

The exporter reads exact R4 and R5 commit headers from local Git and reconstructs the three changed leaves from R4. It verifies all 592 bodies and modes against the published R5 tree `583943a220c868abad80acc26c06aa63e1d91e09`. Fetch the exact R5 ref and its R4 parent before running it. Use a fresh output path outside that repository. The optional driver check takes the retained R4 `a11y_driver.c` and verifies the exact emitted R5 C alongside unchanged focus request counts and guest entry guard.

```bash
lane=scripts/ci/current606-welcome7-gui-source
python3 -I -B "$lane/target_focus606_source.py" --repository "$R5_GIT" --output "$R5_OUTPUT"
python3 -I -B "$lane/test_target_focus606_source.py" --repository "$R5_GIT" --r4-driver "$R4_DRIVER"
```

In a separate host control, the product GTK3 viewport moved while a second X window held native input focus. Both drivers used an isolated Xvfb and AT-SPI bus against the product report widget. R4 refused at 2.024 seconds. R5 received a native focus transfer and returned `FOCUS_SCROLL` with a nine-node geometry chain at 2.493 seconds. R5 still refused at 4.049 seconds when focus stayed withheld. The retained host control has SHA-256 `7d7c81d88bf4f5464d7e8028bee2f9b964b9db1e01df8c1c8c4c6cf9e02adcc3`. The host driver copies had private-session admission and the reader control supplied synthetic Wayland metadata. Native R5 Wayland behavior, installed606 preservation and physical M2 validation remain open here.
