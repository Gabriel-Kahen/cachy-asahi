# Qt AArch64 root filesystem signature regression

This host-side check replays the root filesystem signature gate that held
the offline Qt rehearsal Q2. The input is the retained Qt operand directory
and the reviewed whole SHA-256 of its `plan.json`. Only the original root
filesystem, detached signature and three official Arch Linux ARM trust
files are read from that directory. Their pins are checked against the
repository's reviewed builder lock and again after verification.

```bash
python3 -I -B scripts/integration/qt612_rootfs_trust_check/check.py \
  --media "$qt_operands" --plan-sha256 "$qt_plan_sha256"
```

The check uses GnuPG in a temporary public-only directory. It compares
GnuPG's dearmored output with the existing independent public key decoder
and its pinned binary digest. It checks the official primary, its key
status and the exact detached signature over all 829,367,415 archive
bytes. It also runs the old armored-keyring command with the same
official bytes. On the Q2 verifier family, that command exits 2 with
`NO_PUBKEY` and an invalid keyring diagnostic. A verifier that supports
the armored form may pass that control. The binary ring must still
verify the original archive and must reject a different payload using
the original signature.

The command emits the bounded original key and signature observations
as JSON. It uses existing read-only pin and verifier supervision helpers,
streams the archive, and leaves the retained inputs unchanged. It does
not extract the root filesystem, use an installed keyring, start a guest,
install a package or issue authority.

Run the plan-pin and early-refusal controls without the retained archive.

```bash
python3 -I -B scripts/integration/qt612_rootfs_trust_check/test_check.py
```
