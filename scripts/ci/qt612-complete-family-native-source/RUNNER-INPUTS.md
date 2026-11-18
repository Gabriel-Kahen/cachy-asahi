# Prepare Qt family inputs on an owned runner filesystem

The family [source preparer](README.md) binds the original local 517-file base
provider and six-package candidate map. Their absolute paths belong to that
preparation host. Export and bind the verified Source to carry exact byte pins
between machines without transferring the donor's path references.

```sh
adapter=scripts/ci/qt612-complete-family-native-source
python3 -I -B "$adapter/runner_inputs.py" export \
  --source "$ORIGINAL_SOURCE" --source-map-sha256 "$ORIGINAL_SOURCE_MAP_SHA256" \
  --output "$FRESH_PORTABLE"
```

The export has the original `source-map.json`, a pathless `selection.DATA.json`
and an exact Source skeleton. It retains the independent historical candidate
map, original base provider and original family input pins. The selection
describes exact files from the public Git checkout and exact upstream Qt
archives. Place those files in the prepared runner volume before binding.
Supply the selection SHA-256 through an independently authorized channel.

Use the acquired exact operands under the same privately owned ext4 mount.

| Operand directory | Leaves |
| --- | --- |
| `metadata` | `base-input.lock.json`, `bootstrap-profile.json`, `expected349.lock` |
| `base-materials` | Dated ALARM rootfs, archives, and their detached signatures |
| `supplemental-materials` | Eight pinned bootstrap archives and their signatures |
| `keyrings` | Three exact ALARM public files, including the empty revocations list |
| `dependencies` | Seven exact addition archives and seven detached signatures |
| `qt-upstream` | The five pinned Qt 6.12 upstream source archives |

The framework root holds the exact public files at the repo-relative paths
listed under `public_git` in the selection. Keep the independently selected
md4c TEST public certificate for the Root-owned trust check. The original
selected md4c archive and signature belong under `dependencies`.

```sh
python3 -I -B "$adapter/runner_inputs.py" bind \
  --workspace "$OWNED_EXT4_MOUNTPOINT" --workspace-device "$OBSERVED_ST_DEV" \
  --workspace-inode "$OBSERVED_ST_INO" --workspace-mount-id "$OBSERVED_MNT_ID" \
  --portable "$IN_VOLUME_PORTABLE" --selection-sha256 "$SELECTED_INPUT_SHA256" \
  --operands "$IN_VOLUME_OPERANDS" --framework "$IN_VOLUME_PUBLIC_FILES" \
  --output "$FRESH_IN_VOLUME_BINDING"
```

The mount identity comes from the existing reservation owner. The binder holds
a directory FD and compares its device, inode and mount ID with procfs before
and after the copy. It refuses a nested mount or symlink. The output contains
`base-provider.DATA.json`, the complete `Source-DATA` and
`runner-inputs.DATA.json` with the new Source map SHA-256. Use that pin and the
bound `expected356.lock` with the existing planner. The recipe, archive and
inventory pins stay byte-identical. The two Source path-binding files are
regenerated for every new destination.

Signature authentication, the signed image build, resource admission, and
native execution remain Root-owned steps. These commands only prepare inputs
and run no network, image, package, key-import or signing operations.
