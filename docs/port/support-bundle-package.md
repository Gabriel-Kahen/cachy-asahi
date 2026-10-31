# Installable offline support command

The proposed `packages/tools/cachy-asahi-support` recipe ships
`cachy-asahi-support 0.1.0-1`. It wraps the exact previously host-tested support
command with a prefix-relative, isolated launcher and a private pinned runtime.
It does not need another project package to provide import paths.

## Runtime closure and dependencies

The runtime contains exactly the unchanged support command, Doctor2 command and
session module. All are original MIT project code; headers, NOTICE, LICENSE and
`source-provenance.json` preserve their origins and exact SHA-256 values. The
support command came from a reviewed uncommitted proposal, so its Git revision
is explicitly NULL. The two canonical APIs are selected from integration base
`a0bbaee4da1c588f33375b6d4cda372d89a85f77` and remain byte-pinned.

The only dependency is `python>=3.11`. The retained
`scripts/ci/current606-ksm2-copy/expected606.lock` includes `python 3.14.8-1`;
its hash and scope are recorded in provenance. This is an inventory observation,
not a claim about the host's or target's installed packages. No GPG, pacman,
session/graphics/audio client, network client or absent project runtime package
is introduced as a dependency. Although the private modules also define live
collectors for their original commands, this launcher calls only the support
CLI's offline parsers/validators. No collector is invoked.

The launcher verifies each private runtime file's exact hash before execution,
uses isolated Python without bytecode writes and resolves paths from its own
installed prefix. The private tree retains the relative filenames required by
the original APIs. It uses no source-checkout, artifact-packet, current-directory,
PYTHONPATH or absolute workspace imports. A changed/missing/aliased runtime
returns 2. See the packaged `support-bundle.md` for explicit reviewed input pairs,
release binding, privacy fields, output rules and verification limits.

## Package-owned files and removal

The ten-file payload is fully listed in `payload-map.json`:

| Location | Purpose |
| --- | --- |
| `/usr/bin/cachy-asahi-support` | Mode-0755 launcher |
| `/usr/lib/cachy-asahi/support/scripts/support/support_bundle.py` | Exact bundle CLI |
| `/usr/lib/cachy-asahi/support/scripts/hardware/session_probe.py` | Exact session parser/constants API |
| `/usr/lib/cachy-asahi/support/packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor` | Exact Doctor2 validation/comparison API |
| `/usr/share/doc/cachy-asahi-support/` | Four documentation/provenance/payload-map files |
| `/usr/share/licenses/cachy-asahi-support/` | Original NOTICE/LICENSE |

All non-launcher files are mode 0644 and intermediate directories mode 0755.
There are no hooks, install scripts, services, autostarts, backup entries,
configuration/boot/platform writes or privilege helpers. Removal affects only
these package-owned files. Reports and bundles at explicitly selected user
destinations remain untouched. The command has no upload or send operation.

## Source and staging checks

```sh
python -I -B packages/tools/cachy-asahi-support/check_package.py
python -I -B -Werror::ResourceWarning packages/tools/cachy-asahi-support/test_package.py -v
python -I -B -Werror::ResourceWarning scripts/release/test_support_source_delivery_v1.py -v
```

The recipe's `check()` runs the first two checks against its explicit recipe
root. The tests copy only the finite declared files, so makepkg's separate
log/FIFO/src/pkg entries are never recursively copied. They execute only this
reviewed recipe's pure `package()` function into fresh private pkgdirs, check
all payload bytes and modes, and invoke the actual staged command. No host
makepkg or ALPM operation occurs.

Tests cover creation/repetition, exact extraction, prefix relocation after the
recipe source is deleted, private-marker omission, failure preservation,
malformed/tampered inputs, changed/missing/aliased runtime, source/metadata pins,
foreign payload/modes and simulated removal preserving reports. A bubblewrap
case unshares networking and exposes only read-only `/usr`, the staged prefix
and a writable private work directory. It verifies `/home` and the source
checkout are absent, then creates, verifies and extracts with the actual staged
command. If bubblewrap is unavailable that case is explicitly skipped; it must
not be reported as source-hidden success. This packet records a real PASS.

## Versioned source delivery

`scripts/release/support_source_delivery_v1.py` adds one exact recipe/SRCINFO
profile using a private instance of the existing source transport. Original
`recipe_source_delivery.py`, `source_delivery.py`, their historical profiles and
consumers remain unchanged. The new adapter pins those helper bytes and refuses
if they drift. It exports only this `0.1.0-1` recipe's finite, complete local
inputs in the existing deterministic source-tar format.

```sh
python -I -B scripts/release/support_source_delivery_v1.py pack \
  --recipe packages/tools/cachy-asahi-support \
  --source-revision FULL_OBSERVED_COMMIT --output ./support-source
python -I -B scripts/release/support_source_delivery_v1.py unpack \
  --bundle ./support-source/source.tar --sha256 EXPECTED_SOURCE_TAR_SHA256 \
  --output ./support-source-relocated
```

The observed revision labels an integration state, while the exact recipe pair
and all source pins bind bytes. This source-only adapter has no binary archive
association option. Receipts remain `UNBOUND_NO_ARCHIVE_SUPPLIED`; no release
source index, package archive, BUILDINFO or native result is fabricated.

The candidate recipe declares `arch=('any')`. Actual clean native ARM build
pairs, native 16K execution, signed ALPM lifecycle, selected Asahi composition,
physical M2 on both Air sizes, recovery, performance and release acceptance are
NOT RUN / NOT ESTABLISHED. The separate future native request keeps all actual
bindings NULL. Root owns any canonical adoption, manifest selection and CI.
