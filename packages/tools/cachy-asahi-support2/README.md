# cachy-asahi-support 0.2.0-1

The installed command runs without a source checkout. Collect current read-only
observations as the affected ordinary user, using a new private output directory:

```sh
cachy-asahi-support collect \
  --release-id synthetic-support-demo \
  --release-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --source-commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --output-dir ./new-private-support-case
```

Those example identity values are synthetic. Supply the exact public release
label/hash/source object under investigation for a real case. Labels and context
are declarations; collection authenticates no release or hardware claim.
`--model-id`, `--baseline-sha256`, `--execution-context` and explicit
`--reviewed-health PATH SHA256` are optional. Health never runs automatically.
`cachy-asahi-support collect --help` lists these options.

Keep the whole case directory private. Original Doctor/session reports and the
collection receipt stay there. Only `share/support-bundle.tar` is a sanitized
sharing candidate. Retain its archive SHA-256 from `collection.json`, then:

```sh
cachy-asahi-support verify \
  --archive ./new-private-support-case/share/support-bundle.tar \
  --sha256 EXPECTED_ARCHIVE_SHA256 --extract-to ./new-private-review
```

Review the extracted summary/reports before manually sharing. Nothing uploads.
Exit 0 means a verified archive was created, not health or acceptance. Failures,
unknown/unavailable observations and physical NOT RUN remain visible. Failed or
interrupted collection retains completed private reports and a stage receipt;
use a new directory for retry. A hard kill may leave COLLECTING/pending output.

`create` and `verify` keep the unchanged v1 offline command, schemas, archive
format and exact runtime bytes. `--version` identifies this package. See
support-bundle.md for selected input/verification limits and collect-support.md
for collection details. No journal, broad environment, private keys or network
identifiers are collected; finite hashes/times/model labels can still correlate.

The isolated launcher checks four pinned private runtime files, resolves its own
installed prefix and ignores current directory, PYTHONPATH and user-site imports.
The mirror under /usr/lib/cachy-asahi/support supplies existing loader contracts
without importing installed peer packages or the checkout. Python >=3.11 is the
only runtime dependency. Existing pacman/systemd/Hyprland/Mesa/PipeWire clients
are optional observations, not dependencies to install or enable. Missing
clients/endpoints yield unknown or unavailable checks. Normal IPC/GLES context
bookkeeping can occur; no repair/config/service/volume/sleep change is requested.

Package payload is exactly twelve files: launcher, four private runtime files,
five documentation/provenance files and two license files. No hooks, services,
autostarts, privileged helpers, backup/config entries or platform changes.
Removal affects only owned payload and preserves user support cases. This same
package name upgrades v1; the separate support2 recipe preserves v1 source/export
history. No shared manifest or default package selection changes here.

check() validates finite source/metadata/payload pins and runs six new installed
CLI controls. bubblewrap is an explicit check dependency, never a runtime one.
Pure package() staging plus unprivileged namespaces hide checkout, networking,
/run and /sys for actual headless collect/verify/relocation tests. Tests install
nothing on the host. Native package archives/BUILDINFO, ALPM lifecycle, 16K and
M2 workflows remain separate. arch=any is a recipe declaration only. MIT.
