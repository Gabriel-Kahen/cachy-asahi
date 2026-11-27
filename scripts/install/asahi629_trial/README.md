# Offline Asahi 629-package rehearsal

The runner uses the original Asahi Minimal seed on a disposable 16 GiB
clone. A separately reviewed cold generic AArch64 control boots with 16 KiB
pages and no NIC. The guest checks the initial 261 package versions, applies
371 local operands, then reverses NetworkManager, Perl and Python. Both final
locks contain 629 packages, including all five Overlay Preview 1 packages
and vendor Qt6 Base 6.12.0-3.

The 629 profile binds the archive preflight, path-ownership preflight,
original 626 transport manifest, composition selection and inventories,
three-version proposal and Preview archive/source join record. It checks the
complete staged tree. All 369 vendor operands retain their exact detached
signatures. The five project operands use a distinct, current TEST
certificate and five separately reviewed detached signatures over the exact
archive bodies. The controller checks the full 5,820-second allowance at
entry. The guest rechecks the project certificate and signature timing,
verifies vendor and project operands in separate temporary homes and uses a
third temporary keyring for pacman's required local signatures.

The controller reopens the result disk independently. A successful receipt
covers the complete lock sequence, successful ALPM commands and hook
inspection, unchanged boot and mount data, restored original initramfs,
retired guest mounts and trust homes, and owned QEMU retirement. The generic
control boot exercises the Asahi filesystem transaction. Installed Asahi
kernel boot, physical M2 installation and composition approval remain open.

## Stage the reviewed selection

Use a fresh directory and a canonical JSON review issued for this TEST scope.
The review has these fields.

- `kind` is `ASAHI629_EXACT_PREVIEW_TEST_REVIEW_V1`, `issuer` is `Root`,
  `scope` is `project-test`, and `approval_status` is `UNAPPROVED`.
- `provenance` equals the whole path-to-pin map `PROVENANCE` in
  [operands.py](operands.py). Each pin has integer `bytes` and the lowercase
  `sha256`.
- `key` contains the uppercase primary `fingerprint`, the public
  `certificate` pin and the integer UNIX seconds `not_before` and
  `not_after` from that certificate.
- `operands` maps the five exact project package names to their `archive`
  and fresh `signature` pins. The input directory contains
  `preview-test.gpg` and one detached signature per archive with the
  corresponding `.sig` name.

```sh
trial=scripts/install/asahi629_trial/controller.py
python3 -I -B "$trial" prepare-transport \
  --preflight-dir "$preflight" --ownership-receipt "$ownership" \
  --original-transport "$r132_transport" \
  --test-review "$test_review" --test-review-sha256 "$test_review_digest" \
  --test-inputs "$public_test_inputs" --output "$staging"
```

This command stages public data only. Use the emitted manifest digest as
`media_digest`. The original preflight contains the local references to the
released project archive bodies and the selected composition provenance.

## Bind and run inside the owned offline actor

Use the qualified Overlay583 controller image with a read-only root and code,
read-only input mounts, a writable private output parent, zero capabilities,
no-new-privileges, no KVM and no network. Bind the independent cold assembly
directory containing `independent-readback-PASS.json`,
`assembly-only-receipt.json`, the independent ext4 and ALPM reports and the
rehashed `verified-candidate/` outputs. The binder verifies the exact
111-package selection and the recorded retirement. Point `seed` at the
original whole 3,680,501,760-byte ext4 image. If using the retained compressed
copy, unpack it into private storage and check the raw digest
`76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db`.

```sh
python3 -I -B "$trial" bind \
  --staging "$staging" --seed "$seed" --control "$cold_control" \
  --control-receipt-sha256 "$cold_receipt_digest" \
  --output "$new_private_output" --nonce "$fresh_32_hex_nonce" \
  --media-digest "$media_digest"
```

The binding remains unissued. Root must independently select the exact
binding for one run and supply its whole digest. Invoke the same entry
point with the actor environment `CACHY_ASAHI_OVERLAY583_ACTOR=1` and
`CACHY_ASAHI_629_ACTOR=1`. The controller writes a durable nonce claim beside
the selected output, then verifies all five project signatures before
constructing the clone. Retire the outer owned container and verify its
absence twice.

```sh
python3 -I -B "$trial" run \
  --authority "$issued_binding" --authority-sha256 "$issued_binding_digest"
```

## Source controls

```sh
python3 -I -B -m unittest discover -s scripts/install/asahi629_trial -p "test_*.py" -v
```

Set `ASAHI629_PREFLIGHT`, `ASAHI629_OWNERSHIP` and
`ASAHI629_R132_TRANSPORT` to include the retained-data test. It verifies
the staged archive and provenance pins using deliberately unusable TEST
fixture bytes and deletes its temporary stage. Set `ASAHI629_CONTROL` and
`ASAHI629_CONTROL_SHA256` to reopen the independent cold-control evidence.
The simulated guest tests exercise both transactions, refusal before either
apply, and cleanup evidence.
