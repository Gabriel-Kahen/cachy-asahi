# cachy-asahi-recovery-tools 0.1.0-1

Offline preparation of an explicitly selected predecessor and the existing finite
16-package recovery inventory. `materialize` and `verify` take the original
recovery_bundle.py arguments. See offline-recovery-bundle.md for the exact schema,
external signer/namespace/sequence/receiver-state authority and receipt custody.

Build with `makepkg --cleanbuild --nodeps` after checking the pinned source profile.
Runtime: Python >=3.14, GnuPG, Linux glibc renameat2(RENAME_NOREPLACE). Build: ordinary
base-devel. No pip, libalpm, repo-add, bsdtar or zstd is required by the supported
lifecycle. Separate producer integration needs repo-add, bsdtar and vercmp.

```
cachy-asahi-recovery-tools materialize --selection /absolute/selection.json \
  --selection-sha256 "$SELECTION_SHA256" --kit /absolute/kit \
  --signer "$KIT_SIGNER" --namespace "$KIT_NAMESPACE" \
  --minimum-sequence "$KIT_MINIMUM_SEQUENCE" --state-dir /absolute/private-state \
  --output /absolute/private-parent/absent-workspace
cachy-asahi-recovery-tools verify --workspace /absolute/moved-workspace \
  --receipt-sha256 "$RECEIPT_SHA256" --selection-sha256 "$SELECTION_SHA256" \
  --signer "$KIT_SIGNER" --namespace "$KIT_NAMESPACE" \
  --minimum-sequence "$KIT_MINIMUM_SEQUENCE" --state-dir /absolute/private-state
```

The isolated launcher verifies 15 exact original sources under
usr/lib/cachy-asahi/recovery-tools before import. Missing, changed, foreign,
symlink, hardlinked, or group/world-writable runtime files refuse. Prefix and
workspace may move independently. Other private-module entrypoints are unsupported.
No source copied from the kit is executed. Source revision:
852d1b7324e4ad840fa94ea7c9fc994b1aa07280; no upstream source repair.

Only usr/bin/cachy-asahi-recovery-tools, its private runtime, documentation and
license directory are installed. No hooks, services, config, trust bootstrap,
mount, ALPM or signing home is installed. Removal deletes package-owned files;
operator workspaces, receiver state and interrupted .recovery-bundle-* staging
remain operator-owned external data. Preserve/inspect interrupted staging and
retry with a fresh destination; there is no automatic resume/cleanup/overwrite.

check() runs the original 23 custody tests with explicitly mocked authentication
seams and new packaging controls without signing keys. Separate host integration
uses real isolated TEST signatures and retained ALARM data. Recovery observations
keep fresh_recovery_signature_verification=false. Native ARM, emulated16K,
ALPM installation, physical M2, boot/session recovery and release remain NOT RUN;
performance is NOT MEASURED. Host staging is not an installed Asahi lifecycle.

The separately proposed recovery_tools_source_delivery_v1.py and exact
recovery-tools-source-profile-v1.json pack/verify/unpack all recipe sources,
original private archive, tests, license, provenance and exporter/profile without
executing the recipe. Independently pin profile and source.tar SHA-256. Local
rebuild inputs do not establish package/release authority or legal acceptance.
