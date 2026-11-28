# Asahi629 coordinated-update input preflight

The read-only preflight uses the actual Asahi629 reversal lock as the before
inventory. It selects the original forward lock as the candidate and the
reversal lock as the exact recovery inventory. Each has 629 package rows.
The historic rehearsal started from the 261-package Minimal seed. Updating
this 629-package before inventory through the installed updater remains
untested.

| Package | Before and recovery | Candidate |
| --- | --- | --- |
| NetworkManager | `1.58.1-1` | `1.58.1-2` |
| Perl | `5.42.2-2` | `5.42.3-1` |
| Python | `3.14.7-1` | `3.14.8-1` |

The preflight checks the complete lock pins, the exact three changes, the
complete inverse, and the six archive/signature pairs selected by the original
transport manifest. It verifies complete pairs with the pinned ALARM public
certificate in a temporary offline GnuPG home. Missing retained files are
listed by relative path. A wrong pin, aliased file or invalid signature refuses
the input. The optional updater operand verifies the exact retained
`cachy-asahi-update 4.4.2-3` archive pin.

```sh
python3 -I -B scripts/update/asahi629_preflight.py \
  --before "$ACTUAL_ASAHI629_EVIDENCE/rollback.lock" \
  --candidate "$RETAINED_ASAHI629_MEDIA/forward.lock" \
  --recovery "$RETAINED_ASAHI629_MEDIA/rollback.lock" \
  --media "$RETAINED_ASAHI629_MEDIA" \
  --updater "$UPDATER_ARCHIVE"
```

Use canonical absolute paths. The tool exits zero when it emits the audit,
whose status remains **HOLD**. A refused input exits nonzero. No release or
launch authority is issued. [Retained Asahi629 rehearsal](../install/asahi629_trial/README.md)

## Unselected inputs

- The 629-package lock lacks the updater and its direct package names
  `archlinux-contrib` and `htmlq`. The older Q3 lane supplies reference versions
  `archlinux-contrib 20261009-1` and `htmlq 0.4.0-3` with detached ALARM
  signatures. Bind the exact dependency closure, including any adapters the
  new lane selects, to a fresh updater-equipped before inventory.
  [Q3 input lock](../ci/updater-optional-check/historical/dependencies/inputs.lock.json)
- The exact updater needs a detached signature under a current reviewed
  disposable TEST certificate for this profile. The candidate and recovery
  repositories each need a pinned database and detached database signature
  under the selected trust policy. The six ALARM package signatures verify
  archive bodies. A signed database must also bind what each repository
  offers. The older Q3 signed repository advertised an inert fixture against
  a different inventory.
  [Q3 transaction and refusal](../../docs/validation/updater-q3-emulated-arm16k-20261126.md)
- A coordinated Apple update needs exact protected before/candidate package
  versions and owned kernel module paths, signed transition evidence, and
  pinned pre- and post-transaction observations. The three-version replay
  selects no new Apple boot, kernel, firmware, graphics or audio tuple.
  The current copied-root updater rejects protected changes, and its scaled
  profile selects one changed package on a 587-package baseline. Recovery
  needs its own reviewed path for the three downgrades, retained boot assets
  and an observed boot/session restore.
  [Platform guard](platform_policy.py) · [Scaled profile](scale_update.py)

The source controls cover candidate/recovery confusion, drift within a
same-count inventory, a missing detached recovery signature, exchanged
detached signatures, and a signature alias. The Apple policy controls also
exercise the three-version maintenance delta alongside protected changes.

```sh
python3 -I -B scripts/update/test_asahi629_preflight.py
python3 -I -B scripts/update/test_platform_policy.py
```
