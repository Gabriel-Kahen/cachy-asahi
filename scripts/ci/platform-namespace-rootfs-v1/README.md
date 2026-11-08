# Namespace rootfs DATA assembler v1

`assemble.py` reads explicitly pinned retained `.pkg.tar.xz` archives and their
detached signatures. It writes an uncompressed, sorted USTAR of regular files,
an exact `guest-rootfs.json`, and a separate `assembly-report.json` containing
archive, metadata, recipe, license, source-URL and file provenance. It never
extracts inputs to the host, installs packages, downloads, or executes guest code.

The package versions must match the 349-row lock at
`50d50603305c5a64ee090313b05f68e11ca64bce:native/expected349.lock`.
Required roots are bubblewrap 0.13.0-1, Python 3.14.8-1, and
mkinitcpio-busybox 1.36.1-1. A caller-supplied plan pins every archive, signature,
metadata member, selected file, flattened alias, license and upstream source URL.
The plan SHA256 is an explicit CLI operand. Original `.PKGINFO`, `.BUILDINFO`,
and `.MTREE` hashes plus the `.BUILDINFO` recipe hash are checked before assembly.
The metadata identities and retained provenance archive/signature/metadata pins
are joined to the selected package inputs. Retained authentication pointers remain
evidence references; preserving them does not perform a new signature authentication or establish corresponding-source
availability. Source URLs are original package metadata, not fetched source trees.

The default profile requires the complete packaged `usr/lib/python3.14/`, including
all extensions. The explicitly named `finite-headless-namespace-v1` profile permits
pinned `_tkinter`, tkinter, turtle, turtledemo and idlelib exclusions, plus one
exact build-DATA exception: `config-3.14-aarch64-linux-gnu/python.o` under the
stdlib prefix, exactly 1480 bytes/SHA256
`f23e0477f0b8035aea1692221ddb6f42f420d138348221c406f725cd5c2bc26b`.
The finite probe never links this object; its controller requires load segments
for every included ELF. This does not permit other objects or an ET_REL skip. Every
excluded path records its original Python package, member, size, hash, mode and
reason; arbitrary exclusions and automatic missing-library skipping are refused.
The finite probe sources are pinned, their AST imports must exactly match the
declared module inventory, and those modules plus startup sources must exist in
the selected stdlib or pinned probe sources. `sys` and `time` are explicitly
classified CPython core builtins. This is static availability, not executed imports.
Every package's `usr/share/licenses/` payload must be retained. Aliases become
exact regular-byte copies with recorded original members. `/busybox`,
`/usr/bin/python3`, and `/usr/bin/bwrap` are required executables without setuid.
The literal ELF interpreter path must physically exist in the output; the audit
does not imagine a `/lib` symlink.

The ELF auditor checks every selected ELF, not just the entrypoints, for bounded
AArch64 ELF64 little-endian structure and physical PT_INTERP/DT_NEEDED closure.
Nonloadable relocatable objects, including Python's `python.o`, are retained as
inert DATA and cannot become interpreters, providers, or required entrypoints.
It supports direct absolute or `$ORIGIN` RUNPATH and the documented default
library directories. It refuses unsupported loader behavior (legacy RPATH-only,
cache/preload, hardware-capability subtrees, audit/filter tags, and NODEFLIB).
Symbol versions, actual loading, imports, kernel behavior and hardware remain
unqualified. The output status is a DATA format label; `generic16k` in that label
is not evidence of a successful 16K-page guest boot or namespace operation.

Output contains at most 8192 unique canonical relative names, at most 256 MiB of
payload and tar bytes, and modes 0644/0755. It excludes the reserved prefixes
`probe`, `init`, `proc`, `dev`, `tmp`, `home`, and `var/lib/pacman`. It has no links,
directories, special files, PAX headers, setuid or ownership metadata from inputs.
Package inputs also reject GNU/PAX extension records before processing their
content, and have aggregate compressed/expanded byte caps.
The tar is read back in memory and must reproduce the exact manifest and canonical
tar bytes. All checks finish before a fresh output directory is created.

```sh
python3 -B scripts/ci/platform-namespace-rootfs-v1/assemble.py \
  --plan /absolute/path/assembly-plan.json --plan-sha256 PLAN_SHA256 \
  --input-root /absolute/path/retained-inputs \
  --lock /absolute/path/expected349.lock --output /absolute/path/new-output
python3 -B -Werror::ResourceWarning -m unittest discover \
  -s scripts/ci/platform-namespace-rootfs-v1 -p 'test_*.py'
```

The synthetic tests run only host Python DATA operations. They never load or
execute the synthetic AArch64 bytes. No qualification descriptor, Source push,
actual reader, Native, Original or runtime selector is produced; `actual` remains
null. Root owns qualification, admission and any subsequent runtime trial.

## Retained input boundary

The original full-stdlib plan remains preserved with its Tcl/Tk closure failure;
neither Tcl nor Tk exists in frozen349. The headless profile explicitly excludes
412 unused GUI files and the exact build object, retaining 2534 regular files, with every included runtime
ELF and interpreter closed. It does not support Tk/GUI or claim full Python package
coverage. `retained-inputs.json` records the package identities, exact exclusions,
probe-source pins and retained plan identities, separately from any Root qualification
descriptor. The original 2535-file payload and actual-controller refusal remain
preserved. Fresh assembly and the actual controller's payload/ELF preflight are
DATA checks; they do not qualify imports, guest execution, namespace behavior or
hardware.
