# ARM111 installed metadata and fixed namespace DATA join

Actual **PASS_ARM111_BASELINE_METADATA_NAMESPACE_DATA_ONLY** supplies the missing
baseline association for the separately proposed minimal155 seat fixture. It is
not a guest, package installation, Polkit decision, native build or M2 result.
No 44-archive authentication work was duplicated.

The output is
`/tmp/cachy-asahi-arm16k-baseline-namespace-20261115-v2/baseline-namespace.json`,
1,704,403 bytes, SHA256
`082eb121e387d919fd336bda4418383d25c82d4b8013ba415d32d03d74248fb7`.
Its exact constructor interface is:

- `baseline_metadata`: dict of 111 package names → exact version/directory,
  declared ALPM `provides` and owned relative `files`.
- `baseline_metadata_provenance`: exact prepared/raw/rootfs-index/selection pins,
  association method and 222 actual raw installed desc/FILES hashes.
- `original_file_pins`: seven absolute paths → SHA256.
- `required_namespace`: seven relative paths → unique owner and actual regular
  payload type, numeric mode/UID/GID, size, SHA256 and empty link.

All 111 names/versions/directories match the pinned prepared reference. Actual
read-only `debugfs` reads of every installed `desc` and `files` match the pinned
rootfs-index and selected package records exactly. There are 142 distinct
PROVIDES expressions, 30,642 package-owned paths and 31,097 selected paths; the
latter also includes 455 package-database nodes. Empty FILES for ca-certificates
and dbus-units are real metapackage records, not missing packages. Directory
trailing slashes are normalized for membership; the three genuine literal
backslash systemd filenames remain literal, without decoding or pruning.

Original raw: 1,610,612,736 bytes, SHA256
`f69d74fbb0043793c96424d0f91ad2f6fb2d8cf3a72fb94024ea9cc40dae4cd3`.
This full hash was freshly checked before **and after** inspection, alongside
stable device/inode/mode/link-count/size/mtime/ctime. Raw reads use no `-w`, host
mount, loop/device, journal replay, clone or VM. Temporary public metadata leaves
were removed normally. No credential, account database, private key, hook,
scriptlet, typelib or package program was executed or inspected as code.

Fixed leaves are `/etc/pam.d/{login,system-login,system-local-login,system-auth}`,
`/usr/lib/udev/rules.d/71-seat.rules` and actual
`/usr/lib/girepository-1.0/{Gio,GLib}-2.0.typelib`. Numeric inode metadata was read
independently from the raw and matched retained observations, while byte hashes
came from the actual raw reads. Owners are util-linux for login, pambase for the
other three PAM files, systemd for the rules, and glib2 for both typelibs.
[actual-result.json](actual-result.json) records every fixed hash without copying
binary typelibs or policy payloads into Git. The constructor must independently
read back these namespace bytes before its own offline preparation can pass.

```sh
python -I -B scripts/port/arm16k-first-login-ui-inputs/baseline_namespace/audit.py \
  --output /tmp/new-private-baseline-namespace
python -I -B -m unittest discover \
  -s scripts/port/arm16k-first-login-ui-inputs/baseline_namespace -p 'test_*.py' -v
```

Five controls pass. The actual v2 run took 2.375 seconds, with 256 MiB address
space, 90 CPU seconds, a 180-second wall bound and at least 2 GiB free plus a
16 MiB export reserve. `inputs.json` pins all retained DATA. Initial source
validation caught three legitimate backslash filenames before raw reads; the
parser now preserves those Linux names. No filesystem, PAM, seat or package
contents were changed to satisfy the join. Whole-rootfs custody, incomplete
source/legal provenance, signature freshness and ARM/M2/runtime/release holds
remain distinct from these installed metadata/namespace observations.
