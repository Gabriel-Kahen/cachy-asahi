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

## Scoped transaction source, November 27

The subsequent source lane prepares a **new disposable trial** on the exact
Asahi629 rollback checkpoint. `transaction.py` uses libalpm's ordinary
signature, dependency and conflict handling, admits only the selected Qt
provider conflict, and records both commits and three installed inventories.
`guest_entry.py` binds the selected boot nonce and separate Asahi629 and Qt
public-certificate byte pins before the first commit. A failed runtime probe
still calls the official-provider restoration. An ambiguous commit or failed
readback requires discarding that writable clone.

The optional Weston 15.0.1-3 input is an ALARM-signed, scratch-only test
fixture; it is not added to Pacman's 629-package database. The ordinary-user
Qt probes use its headless Pixman output and the guest's pinned Lavapipe ICD.
`weston_run.py` supervises the compositor, and `readback.py` requires bounded
server-side Wayland configure, buffer-commit and frame-callback evidence
joined to each Qt client's nonce, PID and process start. This establishes a
software presentation path in generic AArch64/16 KiB QEMU, not accelerated
Asahi graphics or M2 hardware behavior. See the
[guest display plan](../../../docs/workstreams/qt629-wayland-guest-plan.md).

`host_stage.py`, `controller.py` and `export.py` stage copies of the pinned
Asahi629 worker, preserve PASS and HOLD evidence, and export only allowlisted
files from a stopped disposable disk. `launch.py` binds a separately issued
root selection to those staged bytes and observes the owned container and
QEMU retirement. `receipt.py` only publishes a completed receipt when the
stopped disk nonce, guest journal, host timestamps, restoration and
independent readback agree. The previously completed Asahi629 run and its
receipts remain unchanged. A prepared controller packet is **unissued**: it
needs a fresh scoped TEST certificate and detached candidate signature,
exact source-pin refresh after integration, a separately issued boot plan,
an actual guest run, and independent terminal readback. No Qt replacement
install or reversal is claimed from the source tests.

Run the source tests in separate processes because another Qt lane has a
same-named test module:

```sh
lane=scripts/integration/qt612_r132_replacement
for test in test_prepare.py test_transaction.py test_readback.py \
            test_runtime_probes.py test_guest_entry.py test_export.py \
            test_host_stage.py test_weston_fixture.py test_weston_run.py \
            test_controller.py test_receipt.py test_launch.py; do
  python3 -I -B -Werror::ResourceWarning "$lane/$test"
done
```
