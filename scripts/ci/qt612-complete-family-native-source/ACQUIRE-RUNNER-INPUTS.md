# Acquire the exact Qt family operands

Run acquisition after the owner opens the identified ext4 reservation and
before starting the offline builder. Supply the independently selected
[portable input description](RUNNER-INPUTS.md) and public route plan. The
reader resolves 517 base files, 12 official dependency files, three base
metadata files, five Qt archives and the listed public framework files.
It checks every route against the selected size and SHA-256.

The public route plan uses the retained immutable Git carrier for the 524
baseline and addition package/signature leaves, including both libffi files.
The dated ALARM root filesystem and its detached signature use their locked
official URLs. The three public ALARM keyring files use immutable Git URLs,
including the zero-byte revocations file. The five Qt archives use the
observed archive mirror with their exact official Qt lock pins.

Use an explicit external md4c input directory in the same reservation.
It contains the selected `md4c-0.5.3-1-aarch64.pkg.tar.xz.sig` and
`md4c-r128-TEST-public.gpg`. For the archive body, either supply the selected
`md4c-0.5.3-1-aarch64.pkg.tar.xz` in that directory or use
`--r128-job-log "$IN_VOLUME_R128_ORIGINAL"`.

That optional flag accepts only the independently retained Original for job
`134591565463` in run `44241902162`. Supply it inside the owned volume after
a separately authorized read of `GET /repos/Gabriel-Kahen/cachy-asahi/actions/jobs/134591565463/logs`.
The whole log must be 2,255,414 bytes and match SHA-256
`ec0b1d79132cb9bcb2e5646ac2e70f675c57b8747f60cdab2737dc5bacc4d734`.
The reader verifies the original compressed envelope, then reads only the
exact build-1 package member from it. The selected body is 74,076 bytes and
matches both independently retained native builds. The reader accepts no
GitHub credentials and emits no raw log or unrelated archive member.

```sh
adapter=scripts/ci/qt612-complete-family-native-source
python3 -I -B "$adapter/acquire_runner_inputs.py" \
  --workspace "$OWNED_EXT4_MOUNTPOINT" --workspace-device "$OBSERVED_ST_DEV" \
  --workspace-inode "$OBSERVED_ST_INO" --workspace-mount-id "$OBSERVED_MNT_ID" \
  --portable "$IN_VOLUME_PORTABLE" --selection-sha256 "$SELECTED_INPUT_SHA256" \
  --route-plan "$IN_VOLUME_PUBLIC_ROUTE_PLAN" --route-plan-sha256 "$ROUTE_PLAN_SHA256" \
  --md4c-input "$IN_VOLUME_MD4C_INPUT" --md4c-cert-bytes "$MD4C_TEST_CERT_BYTES" \
  --md4c-cert-sha256 "$MD4C_TEST_CERT_SHA256" --timeout-seconds "$ACQUISITION_SECONDS" \
  --output "$FRESH_IN_VOLUME_ACQUISITION"
```

The reader streams an HTTPS response directly into an exclusive file under the
same retained mount. It refuses redirect responses, transformed bodies,
incorrect sizes and digests, and deadlines above 1,800 seconds. TLS uses the
system certificate store. A failed input discards the temporary acquisition.
After full readback, a no-replace rename publishes the complete local output.

The result contains `operands/`, `framework/`, `trust/` and
`acquisition.DATA.json`. Pass the first two directories to the existing binder.
The Root-owned signed ALARM bootstrap and isolated `Required TrustedOnly`
dependency transaction must still verify the original detached signatures and
the selected md4c certificate's fingerprint, scope and current validity.
Start native execution only through its separate admission path.
