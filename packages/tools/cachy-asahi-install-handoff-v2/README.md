# Install and recovery handoff tools 0.1.0-2

The opt-in `cachy-asahi-install-handoff` package prepares and verifies an offline
development candidate and its retained recovery inputs. The package keeps the
existing launcher, package paths, runtime dependencies and lack of install
hooks. Its interface and inventory witnesses are bound to
`8f736cd4954b24b80fdb58c9d39ea5bea4407c54`.

Authenticate the package and obtain its runtime SHA-256 independently. Both
`prepare` and `verify` accept `--recovery-state-dir` for a predecessor's
external receiver checkpoint. Use it when the candidate and predecessor have
separately maintained state, for example when their namespaces differ. With
only `--state-dir`, both verifications use the same checkpoint as before.

```sh
cachy-asahi-install-handoff --runtime-sha256 "$RUNTIME_SHA256" -- prepare \
  --selection /absolute/operator-selection.json \
  --selection-sha256 "$SELECTION_SHA256" \
  --candidate /absolute/candidate-kit \
  --recovery /absolute/recovery-workspace \
  --state-dir /absolute/candidate-state \
  --recovery-state-dir /absolute/predecessor-state \
  --output /absolute/private-parent/new-handoff

cachy-asahi-install-handoff --runtime-sha256 "$RUNTIME_SHA256" -- verify \
  --workspace /absolute/private-parent/new-handoff \
  --receipt-sha256 "$HANDOFF_RECEIPT_SHA256" \
  --selection-sha256 "$SELECTION_SHA256" \
  --state-dir /absolute/candidate-state \
  --recovery-state-dir /absolute/predecessor-state
```

The selection's `source_commit` must match the delivered source lock.
Use the original matching runtime and pins for an existing 0.1.0-1 handoff.
Preparing the same retained inputs with 0.1.0-2 creates a new handoff and receipt.
Keep those pins and both checkpoint directories outside the transported handoff
and package paths. The tool reads the checkpoints and keeps the result at
`HELD_DEVELOPMENT_HANDOFF`. Removing the package leaves receiver state and
prepared handoffs under the operator's ownership.

## Build from the local source

This directory materializes the standard recipe and all its local inputs in a
fresh directory. Git and Python 3.11 or later are needed for assembly. The local
repository must contain the selected source commit above and the frozen recipe
commit `282364173f497f1052267c3901dda395dd59e03f`. The assembler reads those Git
objects and preserves the 33-file runtime and 36-file check rosters.

```sh
stage="$(mktemp -d)"
python3 -I -B packages/tools/cachy-asahi-install-handoff-v2/assemble.py \
  --git-root "$PWD" --output "$stage/recipe"
cd "$stage/recipe"
makepkg --cleanbuild --nosign --noconfirm
```

Runtime dependencies are Python, GnuPG, pacman, coreutils, libarchive and Bash.
The inherited checks require bubblewrap and util-linux. They check the exact
runtime inventory, moved launcher and genuine disposable TEST signatures in an
isolated namespace. This is an unsigned opt-in build route. Native ARM,
installation, physical M2 and release acceptance remain unqualified.
