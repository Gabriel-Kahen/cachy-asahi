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

Use a mutually exclusive first-login selection on top of the existing verified fresh Overlay583 transaction. Keep the shared upgrade selection in its own path. The owner binds the supplement's complete manifest digest and adapter source hash into the separately admitted plan, then delivers the staged directory as `/trial-code/first-login` on the existing read-only code media. Keep the package-repository media unchanged and extend the code-media census by exactly the staged leaf set.

After the normal 583 install and database check, and before retirement of the guest-only trust directory, call the pinned `guest.run(trial, supplement_sha256=..., nonce=..., env=..., command=...)`. The caller owns the actor and supplies a bounded command callback with the existing `command(step, argv, seconds, contents=None)` inputs. The callback returns the command's original stdout on a naturally retired successful exit. Retain addon stdout/stderr, command receipts and return JSON in a separate evidence namespace such as `/trial-work/first-login-evidence`, leaving the existing exact Overlay583 evidence leaf set intact. The callback is only for the already admitted VM running the exact boot nonce. The existing API mount helper supplies the normal guest target mounts through a scoped ExitStack.

The addon checks 583 again, verifies the exact detached TEST signature, and trusts the extra key inside the existing disposable guest keyring. It installs the one signed archive with normal hooks and scriptlets and requires the exact 584 inventory and installed launcher/backend bytes. The target driver uses the installed Python, the real installed Setup8 and shell programs and templates, and a distinct ordinary account inside the scratch target chroot. It reuses the maintained 27-command journey with actual user identity, activation and repeat, ten scripted interactive shell startups, process exit75 and journal recovery, and deactivation. Pacman removal must restore the 583 lock and leave both checked user edits byte-identical. The account and /run scratch belong to the disposable target.

The current shared harness has no addon hook. Integrating this single opt-in hook and independently verifying its exported evidence remain coordinator tasks. This checkout has no guest launch or package transaction.

## Available local checks

`python3 -I -B test_addon.py` tests operation order, exact staging and installed path bindings, wrong signer refusal before trust or installation, and user-edit preservation after package removal. The unchanged installed journey can also be retested with its documented exact four-archive selection. The host callback validates real extracted software and preserves private user files in temporary state. It cannot certify the ARM chroot, actual ALPM installation, or a PTY/graphical login.
