# Offline Setup7 to Setup8 upgrade in Overlay583

This opt-in path uses the same 574-package ALARM base and eight shell packages
as the existing Overlay583 trial. It starts with the original
`cachy-asahi-setup 0.1.0-7` from the native pair in GitHub run 40490674681, then
upgrades it to the exact `0.3.0-1` in the current staged TEST repository. The
predecessor package was a native component build. Its TEST signature is created
for this disposable rehearsal and does not establish a prior published release.

## Prepare the exact inputs

Locate the retained original artifact from run 40490674681. The stage command
selects both original 30,316-byte Setup7 archives, requires their exact
byte equality, and signs one with a fresh one-day TEST key. It removes its
private key home after verifying the signature. Use a fresh absolute directory
whose parent exists.

```sh
python3 -I -B scripts/install/overlay583_upgrade/upgrade.py stage \
  --artifact "$retained_setup7_pair_zip" --output "$predecessor"
sha256sum "$predecessor/predecessor.json"
```

In the existing offline controller tooling image, mount the predecessor and
other selected inputs read-only. Provide an unused absolute destination and a
fresh nonce. The bind step emits a candidate selection for independent Root
issuance.

```sh
python3 -I -B scripts/install/overlay583_trial/controller.py bind \
  --staging "$staging" --preflight "$preflight" --kernel "$kernel" \
  --config "$kernel_config" --baseline "$baseline" --output "$output" \
  --nonce "$nonce" --predecessor "$predecessor" \
  --predecessor-sha256 "$predecessor_receipt_sha256"
```

The normal controller run entry takes the separately issued selection and its
whole-file SHA-256.

```sh
python3 -I -B scripts/install/overlay583_trial/controller.py run \
  --authority "$root_selection" --authority-sha256 "$root_selection_sha256"
```

The two predecessor arguments select the upgrade and cannot be combined with
removal/reinstall or signature-recovery mode. The guest installs the 582
repository-qualified packages that exclude Setup8, installs TEST-signed Setup7,
and compares the complete predecessor lock. It requires the sync preview to
select only Setup8 in the current signed overlay and upgrades through an empty
cache with ordinary dependency checks, hooks and scriptlets. It then checks the
complete 583-package target and its database. The independent reader reopens the
receipt, exact snapshots, command logs, and ALPM log. The ALPM log must show the
exact 583 initial installations and one Setup7-to-Setup8 upgrade.

| Checkpoint | Inventory SHA-256 |
| --- | --- |
| 582 packages before Setup7 | `21fc2315170fafc7f1d62880c1e5a275a5902b1cf5161e62b88373e64c63fbb0` |
| 583 packages with Setup7 | `04df9690be73672d23060bce266ba2073b27091400de7da7f055313d67820ec9` |
| 583 packages with Setup8 | `12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba` |

A retained-artifact stage, actual Overlay583 preparation, and a real pacman
print-only 582-package resolution passed locally. No ARM VM was selected or run
for this path. Planned scope is the signed package transition in a disposable
AArch64 16 KiB guest. Release-to-release deployment, user configuration
migration, Asahi integration, and physical M2 evidence remain separate.
