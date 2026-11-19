# Installed development onboarding on Overlay583 ARM16K

This capsule uses the exact held signed Overlay583 installation and its existing rootless QEMU TCG controller. The trial exercises the #583/#587 `examples/development/onboarding.py` CLI after the ordinary 583-package transaction. The selected stock archives already supply Git, GCC/cc1, GNU assembler/linker/readelf, glibc, Python, Bash and Nano. Preparation rejoins all nine package archives and their detached signatures to the retained authenticated preflight and records the selected tool bytes and aliases.

The small deterministic Git fixture includes the exact `hello.c`, `onboarding.py`, documentation and MIT license from commit `868f7f4aca866605c69ae911508c4767d2b18280`. Its separate fixture commit makes local sparse cloning reproducible without transferring the whole project. The installed guest enters a real Bash child as ordinary UID/GID 29085, clones that local fixture, prepares and runs the baseline, makes the documented scripted edit, rebuilds and runs it, verifies both receipts, and inspects both executables as AArch64 ELF. The guest retires each child, unmounts the original guest-only API mounts, removes its private workspace, and confirms the exact 583-package inventory. The overall guest deadline remains 3,600 seconds. The added probe takes at most 240 seconds within that deadline. No network or new package transaction is needed.

## Data preparation

The R2 preparation requires the exact accepted Overlay583 controller capsule, its retained boot and base inputs, the held Runtime44 wrapper, and a trusted checkout with both Git source revisions. Choose the capsule and wrapper by their reviewed whole inputs. Use a fresh absolute private output. R2 adds the onboarding receipt to the guest's fixed export list and keeps the final package inventory stream separate from pacman's keyring warning.

```sh
/usr/bin/python3.14 -I -B -Werror scripts/integration/development_onboarding_overlay583/capsule.py \
  --held "$OVERLAY583_CAPSULE" --runtime-wrapper "$HELD_WRAPPER" --output "$OUT"
CACHY_ONBOARDING_HELD="$OVERLAY583_CAPSULE" CACHY_ONBOARDING_RUNTIME_WRAPPER="$HELD_WRAPPER" \
  /usr/bin/python3.14 -I -B -Werror scripts/integration/development_onboarding_overlay583/test_capsule.py -v
/usr/bin/python3.14 -I -B -Werror "$OUT/enter.py" --check-code
/usr/bin/bash "$OUT/root-entry.sh" --preflight "$HANDOFF_SHA"
```

For an independently authorized Root operation, refresh canonical Runtime44 while other actors and local scopes are absent. Run the exact owned bind/run path in `cachy-overlay583-development-onboarding-r2.scope`. The locked wrapper retains the descriptor through container retirement. The parent must retain the once intent on interruption. After the scope exits:

```sh
/usr/bin/systemd-run --user --scope --unit=cachy-overlay583-development-onboarding-r2.scope \
  /usr/bin/python3.14 -I -B -Werror "$OUT/enter.py" \
  --runtime44-profile "$RUNTIME44" --runtime44-profile-sha256 "$RUNTIME44_SHA" \
  --handoff-sha256 "$HANDOFF_SHA"
attempt=$(cat "$OUT/root-run.claim/attempt.path")
/usr/bin/python3.14 -I -B -Werror "$OUT/readback.py" --handoff-sha256 "$HANDOFF_SHA" close --attempt "$attempt"
```

The independent reader checks controller authority, QEMU and container retirement, the boot's 16K marker, exact installed inventory, original file exports against the result ext4 disk, and both saved build/report pairs without running their executables. The guest report explicitly distinguishes the local scripted edit and compiler workflow from independent human onboarding, desktop terminal interaction and physical M2.

The ordinary Git clone and both compiled programs run beneath the guest's `/var/tmp` on writable ext4 scratch. The guest keeps `/run` and `/tmp` mounted with `noexec`. A software control runs the same clone, edit, build and verification under the development host's executable `/var/tmp`. It needs Git, a C compiler and a regular checkout of the example sources.

```sh
python -I -B scripts/integration/development_onboarding_overlay583/test_capsule.py PortableSourceChecks -v
```
