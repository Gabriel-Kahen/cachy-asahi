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

## Private mount-root successor

The earlier fixture ran ordinary bubblewrap from inside a chroot. Linux rejects
creation of a user namespace from that context. The mount-root successor first
creates a private guest mount namespace, reuses the installed target and its
four API mounts, detaches the boot root, and then runs the same ordinary-user
probe. The independent Reader links that mount-root witness to the ordinary
process. A complete, naturally reaped bubblewrap failure carries a finite
reason, byte count and digest.

Project the exact three source leaves from the reviewed prior stage. This
expects the already-corrected Platform Tools Reader described above.

```sh
python3.14 -I -B -Werror scripts/integration/platform_tools_overlay583/project_mount_root.py \
  --stage "$previous_stage" --handoff-sha256 "$previous_handoff_sha256" \
  --output "$new_source_directory"
python3.14 -I -B -Werror scripts/integration/platform_tools_overlay583/test_mount_root.py
```

The output directory must be new and outside the previous stage. The projection
changes only the guest driver, target driver and independent Reader. Stage
assembly and live authorization still require separate exact source, package,
plan and scope bindings. The tests exercise fixture code with inert system calls.
Actual verification requires the separate owned ARM16K guest and all original
package, inventory, fallback and cleanup checks.
