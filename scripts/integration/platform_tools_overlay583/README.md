# Platform Tools v2 Overlay583 Reader

Use this opt-in projection for a sealed, signed Platform Tools v2 Overlay583
stage whose independent Reader still expects the historical First Login
package. The projection uses the Platform Tools archive's whole sealed pin,
package metadata and recipe provenance to derive the installed row. It checks
the signed supplement's installed lock and independently reconstructs the
exact 583-package base, 584-package install and 583-package removal locks.

```sh
python3.14 -I -B -Werror scripts/integration/platform_tools_overlay583/project_reader.py \
  --stage "$signed_stage" --handoff-sha256 "$handoff_sha256" \
  --reader-sha256 "$uncorrected_reader_sha256" --output "$new_reader"
```

Use absolute operands and a fresh output path outside the sealed stage. The stage contains the sealed
`HANDOFF.DATA.json`, uncorrected `readback.py`, and its selected
`first-login/supplement.json` and archive. The command returns the corrected
Reader's size and SHA-256. Use these bytes and pin in the existing private
Reader projection, alongside the original stage inputs. Continue to use the
existing preflight, signature and guest checks for the actual rehearsal.

The source-only tests exercise the projected Reader, stale inventory pins,
wrong package provenance, and a base that already contains Platform Tools.

```sh
python3.14 -I -B -Werror scripts/integration/platform_tools_overlay583/test_project_reader.py
```
