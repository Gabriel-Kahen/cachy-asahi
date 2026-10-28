# Native ARM offline audio graph loadability

[Trial 38824671422](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38824671422) passes the bounded loadability checks for all four selected J413/J415 speaker and microphone graphs at 48 kHz, plus all eight expected refusal controls. Root accepts the retained readout and one independent peer review. Graph processing and real audio were not exercised.

Source is `bb1bd8502cab4a8d1c8dc98032642cc6f779fda4`; workflow is `626d005d9ba0cdff57ff53d52fc9d5d69b00577d`. The ten retained controller hashes match that Source. Host source SHA256 is `2ba9f0f469faab6ce426611f1a24d8ba0a26f2891bee09a0080d89946741f4bb`; the compiled ELF hash is `dd7e99a11b0e86c01359afd003b3adc6a9c6703e6017a62a30890804b36814dc`. Seven ELF structural checks and four full-equality original-SPA graph conversions pass.

| Graph | Channels | Nodes | LV2 / builtin | Convolvers | Links | Controls/readbacks |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| J413 speakers | 2 to 4 | 9 | 5 / 4 | 4 | 10 | 326 / 326 |
| J415 speakers | 2 to 6 | 13 | 5 / 8 | 4 | 14 | 326 / 326 |
| J413 microphone | 3 to 1 | 7 | 1 / 6 | 0 | 6 | 57 / 57 |
| J415 microphone | 3 to 1 | 7 | 1 / 6 | 0 | 6 | 57 / 57 |
| Total | | 36 | 12 / 24 | 8 | 36 | 766 / 766 |

All positive input, syntax, metadata, port, control, activation, stage, FIR, library, readback, volume and retirement predicates pass. Eight convolver instances select four unique exact 48 kHz FIR identities/hashes from the held set of sixteen candidates. Speaker snapshots identify the selected Bankstown DSP and official LSP DSP; microphone snapshots identify Triforce. Official LSP DSP SHA256 is `c54028900c19493f891dc1a262280f177f10c62db27184f938591662fee61747`; this is a different binary from the earlier headless LSP result. The selected LSP UI binary is absent from the retained active-library snapshots.

The speaker volume predicate sets `[0.125, 0.421875]`, checks graph properties `ell:volume=-23.75` and `elr:volume=-11.875`, then restores `[1, 1]` and requires both values zero. Microphone volume checks are inapplicable. Scalar and volume values are enforced by the hash-bound host and exported as counts/predicate booleans; individual raw values were not retained. These observations are graph properties, not sample output or direct plugin backing cells.

| Refusal control | Expected and observed category |
| --- | --- |
| Malformed graph | syntax |
| Duplicate key | duplicate |
| Trailing input | trailing |
| Missing URI | missing_uri |
| Invalid port | port |
| All FIRs absent | fir_unavailable |
| 48 kHz FIRs absent | fir_selection |
| Unknown control | control |

The missing-48 kHz control activates and observes its stages, then correctly refuses a 44.1 kHz tweeter FIR. Activation alone cannot satisfy the exact FIR gate. All twelve fresh host children report zero process calls, retirement and applicable cleanup success; four converter prerequisites are counted separately.

The external builder remains `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2`, with helper SHA256 `6ca8813aa7a704251d842e1d7e05404aa56e4029067ccacb57b0a7a3c8af80e5`. Its unchanged signed transaction acquires 1,153 objects. The additive public seed remains `88a88bc5f3be3998e992881bf090137df16f1aae`, copying twelve original files / 4,045,396 bytes into the existing cache before the original signature gates. Runtime inventory stays at the exact 574-package lock, SHA256 `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`.

Runtime-container absence, owned-image absence and private-root removal pass. The borrowed builder is preserved by the graph caller and then removed by its outer owner. This completed normal run does not exercise the caller's existing interrupted-bootstrap/probe ownership gap, which remains UNKNOWN/FAIL. Cleanup is scoped; unrelated daemon state and leak-free partial factory internals are not established.

Root retains `artifacts/development/asahi-audio-offline-graph-run38824671422/logs.zip`: 54,014 bytes, SHA256 `22dc4c9256ce19561bb022c6ebe96d128768cb33eccc2e3f9c828bd8942786b8`. Review decodes only the dedicated public metadata frame: result JSON 2,899 bytes / `0a822a981145968aca76043e34e202c2af79936121def72cef84cead95a4780d`, runtime JSON 48,325 bytes / `1cfd68422e89fadbf61cd656be72415945fa056783eb462af00cd377ceb4cec0`. Package/binary/TTL/sample payloads were not reconstructed. The retained passive audit passes with an actor tripwire, and the peer reports no unresolved finding.

The earlier diagnostic 38822449653 activated its first graph but failed observation because the host expected an LV2 URI where the engine logs the descriptor label. The corrected matcher retains exact node/label/index/rate matching; it passes 38 affected Root checks before this actual run. Earlier failed results remain historical failures.

Processing/event/non-alias correctness, service routing, WirePlumber and speaker protection, target installation and recovery, both M2 Air sizes, physical 16 KiB execution, acoustic safety, performance, complete corresponding-source/license delivery and release selection remain open. Structural ELF checks are not 16 KiB execution. Every release-selection flag remains false.
