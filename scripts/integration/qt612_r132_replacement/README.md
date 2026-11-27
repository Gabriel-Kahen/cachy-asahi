# Qt provider replacement input handoff for Asahi629

This source-only handoff prepares the inputs for a future scoped replacement
and restoration on the exact inventory from the successful Asahi629 rollback.
It uses the Qt provider comparison originally made on R132 and replayed
against the 629-package lock.

The producer verifies the recovered unsigned Qtbase archive and its
independent recovery seal. It verifies the original detached signature on
the official rollback archive with the pinned ALARM public certificate,
then reads the two package identities and relations from their original
`.PKGINFO` members. The observed Asahi629 result and retirement receipt bind
the baseline lock. The comparison and prepare-only ALPM transcript bind
the same packages and inventory.

```sh
python3 -I -B -Werror prepare.py \
  --recovery "$QT_RECOVERY_DIRECTORY" \
  --official-archive "$ALARM_QT_ARCHIVE" \
  --rollback-evidence "$ASAHI629_EVIDENCE_DIRECTORY" \
  --terminal "$ASAHI629_OWNED_TERMINAL" \
  --public-key "$ALARM_PUBLIC_KEY" \
  --audit "$QT629_COMPARISON_DIRECTORY" \
  > "$UNISSUED_HANDOFF"

python3 -I -B -Werror test_prepare.py
```

Use absolute paths. The recovery directory holds the unsigned archive and
`recovery.SEAL.json`. The official archive is
`qt6-base-6.12.0-3-aarch64.pkg.tar.xz` with its adjacent original `.sig`.
The Asahi629 evidence directory holds `result.json` and `rollback.lock`.
The completed run supplies `owned-terminal.json`. The read-only audit
supplies `comparison.json` and `alpm-prepare.txt`.

The emitted JSON binds every input to its SHA-256 and byte count. The
forward projection removes official `qt6-base` and adds the project
provider. Restoration adds the official archive and removes the project
provider. Each step changes one package name and preserves the other 628
rows. The final projected inventory must reproduce the baseline lock
byte for byte. The JSON carries no authority or candidate signature.
The handoff describes input verification and inventory projection.

The offline audit checked 18,661 Qt Base references in 145 retained
AArch64 consumer objects. The retained baseline lacks optional provider
packages for Quick Vector Image, `svgtoqml`, `qv4l2` and `pinentry-qt`.
The candidate archive also omits 22 official plugins. A separate signed
trial needs ordinary-user Qt Quick, Wayland and Vulkan runtime checks,
followed by restoration and readback of the official provider.
