# Repository enrollment 0.2.0 host package evidence

Status: **PASS host package build and synthetic relocated workflow**, November
14, 2026. This is opt-in software packaging evidence, not native ARM, actual
Asahi installation/lifecycle, supported-M2, production trust or release
acceptance. No host pacman configuration, package database or trust was changed.

The new
[`packages/tools/cachy-asahi-repository-enrollment-v2`](../../packages/tools/cachy-asahi-repository-enrollment-v2/README.md)
recipe produces `cachy-asahi-repository-enrollment 0.2.0-1`, retaining configure
and rotate and adding the authenticated transition command. The prior 0.1.0
directory and evidence remain unchanged. No shared inventory/default selection,
CI workflow, central runtime source or prior source archive was edited.

The private source archive is exactly eight unchanged Python files from source
revision `e97dd34454096ce2a277922e4e5e32b8b315e592`, with 129,318 total runtime
bytes. The archive SHA-256 is
`b733d05ea58cdcc9c49f6fddcd9654f347ceaa3557e4d6b72930c3556d498c72`.
`source-provenance.json` and `payload-map.json` pin all eight lengths, modes and
digests. A static check joined every archived file back to the central source,
and separately confirmed the enrollment/rotation bytes match the original 0.1.0
recipe's frozen copies. Tar entries have deterministic zero UID/GID/mtime and
ordinary 0644 file modes. `.SRCINFO` exactly matches `makepkg --printsrcinfo`.

The runtime needs Python >=3.11, gnupg, pacman, coreutils and libarchive.
Python >=3.11 is source-audited; this execution used Python **3.14.7**. Package
and database compression is handled by libarchive's `bsdtar`, including the real
zstd package fixture below. There is no Python tarfile/`compression.zstd` import
or zstd CLI invocation in the installed finite runtime. Bubblewrap is check-only.

The recipe was copied into an owned temporary build directory, then run with:

```bash
makepkg --verifysource
REPOSITORY_ENROLLMENT_HIDE_ROOT=/absolute/original/checkout \
  makepkg --nodeps --cleanbuild --force --noconfirm
```

Both commands passed. `--nodeps` skipped dependency checks; the required tools
were already installed and no dependency installation was attempted. The host
had gnupg 2.4.9, pacman 7.1.0.r9.g54d9411, libarchive 3.8.9 and Python 3.14.7.

`check()` staged the actual `package()` payload, moved its prefix, verified all
14 exact installed files/modes and eight runtime digests, and exercised all
command help/version dispatch. It then used two real disposable TEST identities
to sign complete synthetic repositories containing a zstd-compressed package
and declared source-delivery associations. The dual-signed transition was
verified through the moved launcher, with source/fixture trees hidden and a
loopback-only network namespace. Hostile caller Python environment/modules did
not select runtime code. Target configuration/keyring bytes stayed identical;
transition-signature corruption was refused. The exact package-file removal
inverse preserved a foreign user file.

The emitted check report was:

```json
{
  "status": "PASS_HOST_SYNTHETIC_PACKAGE_ONLY",
  "payload_files": 14,
  "runtime_files": 8,
  "moved_prefix": true,
  "source_trees_hidden": true,
  "python_environment_isolated": true,
  "network_namespace": "loopback-only",
  "zstd_package_and_declared_sources_verified": true,
  "signed_transition_preview": "PASS",
  "tamper_refusal": "PASS",
  "target_state_unchanged": true,
  "removal": "EXACT_PAYLOAD_INVERSE_FOREIGN_CONTENT_PRESERVED",
  "native_arm_build": "NOT_RUN",
  "alpm_installation": "NOT_RUN",
  "supported_m2": "NOT_RUN"
}
```

The actual host-built archive was 49,765 bytes, with SHA-256
`1e7efb6f211128f48fbdf7033d35be9493daebc7e8059540199b05276f7f273b`.
Its retained local build path was
`/tmp/cachy-asahi-enrollment-v2-build-pkyeua8k/recipe/cachy-asahi-repository-enrollment-0.2.0-1-any.pkg.tar.zst`;
this temporary host location is not permanent release retention. Independent
archive inspection confirmed the package/version/architecture/runtime dependency
metadata, exactly 14 payload files under `/usr`, and no `.install`, ALPM hook,
`/etc` or `/var` payload. Extraction into another owned temporary directory
followed by relocated version/configure/rotate/transition help also passed.

The installed command now contains its finite verifier and can preview or
explicitly apply an authenticated handoff without a source checkout. This
packaging result does not qualify production signing/distribution, snapshot
upgrade acceptance, target ALPM upgrade/removal or the native/hardware gates.
The underlying bridge's mapped-root apply/refusal tests are separate source
evidence documented in [the bridge workflow](../repository-signing-transition.md).
