# Recipe-bound release payload image assembly

`scripts/platform/release_image.py` connects the existing authenticated archive
intake, verified staging, direct archive inode metadata and portable ext4 encoder
through one pinned recipe. It produces an ordinary local filesystem image. The
image is explicitly `PRISTINE_ARCHIVE_PAYLOAD_ONLY`: there is no package database,
trust bootstrap, package transaction, scriptlet/hook execution, generated state,
ESP, Apple firmware setup, mount or host installation.

This is an M8 implementation component. A usable installed system and the complete
macOS-to-Hyprland installation/recovery journey remain separate work. Installed
payload correspondence and its historical debugfs adapter do not supply missing
installed state to this pipeline. The portable encoder's pinned raw reader checks
the newly created image directly.

## Dependencies and supported inputs

Use the committed source graph. The entrypoint and signed-intake adapter pin
`scripts/platform/metadata_gated_ext4.py` at SHA-256
`467cbb9562189b79926deb9d15d9b027d7c73d2a27ba07bc01d6740941567227`.
The bridge and adapter pin `scripts/virtual/owned_process.py` at SHA-256
`83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`.
The entrypoint pins `scripts/platform/signed_archive_intake.py` at SHA-256
`b7857ba4d83a7475e173f33fc6430fcb0099c3e51d4a312b5b3afc965c30ac91`.
The CLI uses local inputs and tools. Original code is MIT licensed. Upstream
archive licensing and redistribution approval remain separate.

The recipe kind determines which authentication inputs to supply.

- `cachy-asahi-pristine-payload-ext4-v1` uses the retained historical signature
  proof for exactly two aarch64 packages, NetworkManager 1.58.1-1 and Perl
  5.42.2-2. Supply the original selection and proof with their exact retained
  archive/signature paths, hashes and file identities. This path checks the
  historical proof without running a fresh GPG verification.
- `cachy-asahi-policy-signed-payload-ext4-v1` uses the
  [operator-policy signed selection](signed-archive-intake.md#inputs). Supply the
  canonical selection as `selection` and the canonical operator policy as
  `authentication`. The policy binds the selection digest, signer windows,
  public keyring, trusted and revoked lists, and GPG executable. Assembly
  freshly verifies detached signatures offline before parsing package payloads.
  The policy and signer windows must be current whenever the recipe is read,
  including verification and completed-output resume.

Both paths produce an archive-payload image. Independent key ownership,
distribution rights, full dependency closure, and boot or install qualification
require their own evidence.

Tool and metadata inputs are separately SHA256-pinned schema2 profiles captured
for explicit local tool/library configurations. Follow
`docs/workstreams/platform-image-encoding.md` and the opt-in
`tests/platform/check_host_components.py capture/check` commands to capture and
qualify a host. This CLI rechecks the actual profiles during assembly. Capturing
identities alone is not qualification. No tool installation or fallback occurs.

The recipe is a UTF-8 JSON file with exactly these fields:

```json
{
  "schema_version": 1,
  "kind": "cachy-asahi-pristine-payload-ext4-v1",
  "epoch": 1700000000,
  "inputs": {
    "selection": {"path": "/absolute/selection.json", "sha256": "<64 lowercase hex>"},
    "authentication": {"path": "/absolute/authentication.json", "sha256": "<64 lowercase hex>"},
    "tool_pins": {"path": "/absolute/tool-profile.json", "sha256": "<64 lowercase hex>"},
    "metadata_pins": {"path": "/absolute/metadata-profile.json", "sha256": "<64 lowercase hex>"},
    "root_policy": {"path": "/absolute/root-policy.json", "sha256": "<64 lowercase hex>"}
  }
}
```

Replace the placeholders with the actual lowercase SHA256 of each complete file.
The example uses the historical recipe kind. For the policy-signed kind, change
`kind` and use the selection and policy schemas above. The root policy
is exactly `{"mode":493,"uid":0,"gid":0,"acl":null,"xattrs":{}}`;
it is a generated-root policy proved in a separate image, not an archive root
ownership claim. Epoch must be an integer from 0 through 2147483647. Duplicate
JSON keys, nonfinite constants, extra recipe fields, symlink/hardlinked inputs,
older dependency profiles and installed-system recipe kinds refuse.

## Commands and outputs

```sh
/usr/bin/python3 -I -B -S scripts/platform/release_image.py plan \
  --recipe /absolute/recipe.json --recipe-sha256 RECIPE_SHA256
/usr/bin/python3 -I -B -S scripts/platform/release_image.py assemble \
  --recipe /absolute/recipe.json --recipe-sha256 RECIPE_SHA256 \
  --output /absolute/nonexistent-output
```

`plan` reads pinned JSON/source files and validates the supported selection,
including the signer policy for the policy-signed kind. Archive access, signature
verification where applicable, and native tool/profile checks occur during
assembly.
Assembly reuses the existing bridge's intake/verifier/metadata/encoder validators.
It performs an additional raw readback comparison of every node's type, owner,
mode, timestamp, attributes, regular contents, symlink and hardlink association.
No image is created before the bridge's direct metadata joins succeed.

The result prints the recipe binding, image identity and final receipt SHA256.
Retain that final digest outside the output directory. The directory contains
the exact `recipe.json`, five JSON input copies, `pipeline/` staging/metadata,
the image at `pipeline/encoded/root.ext4`, raw readback inventory, native actor
logs/receipts, and the final top-level `receipt.json`. Its ledger seals all
retained files, modes and directories, including empty directories. Files are
flushed and directories synced before final receipt publication. The canonical
recipe binding excludes output location and runtime durations, but includes the
raw recipe digest, canonical JSON digest, all input digests, epoch, source pins
and explicit payload state. Full receipts also bind runtime evidence and may
differ across executions. One fresh image is not a two-build reproducibility
result.

```sh
/usr/bin/python3 -I -B -S scripts/platform/release_image.py verify \
  --recipe /absolute/recipe.json --recipe-sha256 RECIPE_SHA256 \
  --output /absolute/completed-output --receipt-sha256 RECEIPT_SHA256
/usr/bin/python3 -I -B -S scripts/platform/release_image.py assemble \
  --recipe /absolute/recipe.json --recipe-sha256 RECIPE_SHA256 \
  --output /absolute/completed-output --resume-receipt-sha256 RECEIPT_SHA256
```

Verification and completed-output resume check the external receipt pin, exact
recipe/source/input binding, full artifact closure and a fresh raw image
readback. They run no native tool or archive actor. They do not replay signature
verification or prove that the currently installed host tools still match the
captured profile. The input JSON files and exact source graph must remain
available. Keep artifact modes and private output mode 0700 when moving a result.

Existing output without a resume pin refuses before input/native work. Incomplete
output always refuses, even if the child pipeline finished: an interrupted parent
is not accepted. Failures retain `INCOMPLETE.json`, diagnostic evidence and
`failure.json`; choose a new nonexistent destination to retry. No partial-stage
reuse, deletion, repair or overwrite is implicit. A receipt filename alone is
insufficient authority; verification needs its independently retained digest.

CLI resources are bounded to 600 seconds wall time, 300 seconds CPU, 2GiB address
space, 256 open descriptors and 256MiB per output file. Retained artifact checks
allow at most 100,000 nodes, 64 levels and 8GiB total. Existing dependency limits
also apply. Native child commands use the pinned exclusive-wait supervisor;
they are never retired with an independently invented PID-signalling path.

## Historical two-package image evidence, 2026-10-27

The development packet ran this CLI from a fresh private projection with
`/usr/bin/python3` 3.14.7, Linux x86_64, libarchive 3.8.9 and e2fsprogs 1.47.4.
Profiles were freshly captured; historical archives were read as explicit
inputs, and historical image/results were not imported. The fresh authenticated
two-package run independently verified 3,588 serialized payload nodes and direct
metadata for 371 NetworkManager and 3,230 Perl archive members. It built/read back
a 132,120,576-byte ext4 image, SHA256
`52d02d056119d80a5548d9de74a29bfed8fb42798253b6908a8e0e6b6072eb02`,
with `e2fsck -f -n` exit 0. All 33 inner assembly actor receipts report successful
exclusive reaping, complete output, no signals and no timeout. Separate CLI
verification and pinned completed-output resume both passed without native
actors. The final assembly receipt SHA256 is
`6be6104ce0dc32570b800d39cd883d6785e2fe3c317810617b7979d3ccc92107`.

The focused 29 pure controls pass with ResourceWarning treated as error. Their
inert services cover recipe/refusal, publication, input/source drift and artifact
closure; those tests do not authenticate packages or qualify native tools.
The separate [policy-signed intake record](signed-archive-intake.md#uninterrupted-full-cli-qualification-2026-10-27)
verified detached signatures and a pristine staging tar for five packages.
That evidence ends at staging. Full-set image composition, installed state,
trust bootstrap, native ARM and 16 KiB execution, Asahi boot, physical
installation and recovery, performance, and release qualification remain open.
