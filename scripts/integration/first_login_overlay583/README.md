# Installed first-login on Overlay583

This addon uses the existing signed `cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst` unchanged. It was assembled on x86_64 and signed by the disposable UI TEST key `18E721CE9D7928221AD3163BA91B1AFC7142F94E`. The package recipe is the original CLI package at `eb762634`, with embedded implementation commit `409cb24ba224508aeea1b692b1a164505cd0101a`. The package requires Python ≥3.11 and Setup ≥0.3.0. The exact admitted Overlay583 lock includes Python 3.14.8, Setup8 0.3.0-1, historical Fish/Zsh 0.1.0-1 templates, Fish 4.9.3, Zsh 5.9.2, util-linux and shadow. This is candidate evidence for installed software behavior on the generic emulated target. Native ARM package-build, graphical login, physical M2 and release gates remain open.

## Local data preparation

Use `python3 -I -B stage.py` with six absolute operands:

- `--staging` is the existing Overlay583 staging directory.
- `--preflight` is its exact retained `retained583.json`.
- `--archive`, `--signature` and `--public-key` are the pinned FirstLogin candidate and its detached signature and test key. Durable copies are `0034-cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst`, `0035-cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst.sig` and `0321-project-public.gpg` in the retained GUI r5 data.
- `--output` is a new private directory.

The producer checks the exact signatures' and package's bytes, the immutable 583 lock and retained preflight, and copies its own addon code, the existing installed journey and existing bounded process supervisor. It emits a whole `supplement.json` pin and an exact 584-package lock digest.

## Owner integration

In the existing offline controller tool environment, bind a new selection using the prepared supplement directory and its whole manifest digest. Use absolute paths, a new dedicated output path, and a fresh 32-character lowercase hexadecimal nonce. This selection is exclusive with lifecycle, signature recovery and predecessor upgrade.

```sh
python3 -I -B scripts/install/overlay583_trial/controller.py bind \
  --staging "$staging" --preflight "$preflight" \
  --kernel "$kernel" --config "$kernel_config" --baseline "$baseline" \
  --output "$output" --nonce "$nonce" \
  --first-login "$supplement" --first-login-sha256 "$supplement_sha256"
```

The passive bind returns a candidate for separate Root issuance. Use the existing transaction entry after Root issues that exact selection.

```sh
python3 -I -B scripts/install/overlay583_trial/controller.py run \
  --authority "$authority" --authority-sha256 "$authority_sha256"
```

The controller binds the supplement manifest, signed materials and exact helper bytes in the plan. The guest receives them under `/trial-code/first-login` on the existing read-only code media. After the regular 583 install and database check, the guest verifies the detached TEST signature, trusts the extra key in the disposable keyring, and installs the package using the normal signature policy, hooks and scriptlets. It verifies the exact 584 inventory and installed launcher and backend bytes. The target driver uses the installed Python, real Setup8 and shell programs and templates, and a distinct ordinary account in the scratch target. It reuses the maintained 27-command journey, including ten scripted interactive shell startups, interrupted activation and journal recovery, and deactivation. Pacman removal must restore the 583 lock and preserve both user edits byte-for-byte.

The controller verifies the exact before, installed and removed inventories, the original command outputs and the target command ownership receipts from `first-login.json`. A failed stage is recorded as `HOLD_DISPOSABLE_OVERLAY583_FIRST_LOGIN_LIFECYCLE` and retains the original disks and logs. This integration has source and fixture evidence. A new ARM16K guest run is required for installed candidate evidence.

## Available local checks

`python3 -I -B test_addon.py` tests operation order, exact staging and installed path bindings, wrong signer refusal before trust or installation, and user-edit preservation after package removal. The unchanged installed journey can also be retested with its documented exact four-archive selection. The host callback validates real extracted software and preserves private user files in temporary state. It cannot certify the ARM chroot, actual ALPM installation, or a PTY/graphical login.
