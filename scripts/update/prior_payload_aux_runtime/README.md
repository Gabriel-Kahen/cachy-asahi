# Opt-in static payload with retained auxiliary state

`prior_payload_aux_runtime` is a new explicit Python sibling of the data-only
prior adapter. It adds a bounded static executable/direct script payload contract
for one unrelated installed package in the existing guarded disposable root.
Existing modules, default routes, command-line interfaces and platform package
contracts are unchanged:

```python
import prior_payload_aux_runtime
result = prior_payload_aux_runtime.apply(args, comparator_path=pinned_comparator)
```

The existing release, settings, policy, exact587 inventory, root/workspace guard,
capacity, ALPM lock, signature and commit/checkpoint checks still run. The exact
old archive and adjacent signature must authenticate with the selected release
keyring and agree with the installed identity, version and complete ownership.
The adapter rechecks original/copied prior identities and hashes, old live leaf
bytes, metadata, foreign ownership and aggregate old/new inspection budgets.
Neither old nor new package backup semantics are supported. This is not rollback
authorization, a root installer, or a general payload executor.

## Accepted payload

Canonical direct `usr/bin/NAME` leaves, package-private
`usr/libexec/PACKAGE/`, `usr/share/PACKAGE/`, `usr/share/doc/PACKAGE/` and
`usr/share/licenses/PACKAGE/` leaves may contain ordinary data, bounded static
ELF executables, direct scripts and contained links. Existing unchanged
structural directory headers are allowed; creating, removing or replacing
directories is unsupported. A new leaf cannot overwrite an unselected node.

Native files must be ELF64 little-endian static ET_EXEC for the current host's
x86_64 or aarch64 machine, flags0, OSABI0/3 and ABI version0. The existing
`platform/elf_audit.py` parser must find no PT_INTERP, dynamic table, NEEDED,
RPATH or RUNPATH; executable entry bytes must be file-backed, PT_LOAD offsets
congruent and load flags non-W+X. Native inspection is capped at8MiB. Global
provider candidate lookup is not used as dependency acceptance. An empty
initial ELF loader dependency list does not prove complete runtime closure:
static programs can load files/libraries or launch other processes. Format
results explicitly retain `runtime_verified=False` and target acceptance
`NOT ESTABLISHED`. No entry-point success, ARM16K or M2 behavior is inferred.

Scripts require a bounded ASCII direct absolute shebang with no arguments,
`env` or PATH lookup. Each interpreter must be explicitly reviewed through
`args.payload_interpreters` (at most8 entries):

```python
args.payload_interpreters = {
    '/usr/bin/example-static-interpreter': {'bytes': exact_size,
                                          'sha256': exact_sha256},
}
```

The interpreter must itself pass the static ELF gate, be a canonical executable
regular file owned by another installed package, have UID/GID0, and remain
byte/metadata-identical. It cannot be a selected old path, alias, hardlink group
or privileged file. This candidate does not support shell/Python interpreters
that need dynamic loaders, recursive interpreter wrappers or optional shebang
arguments.

Contained symlink literal, old endpoint and final endpoint must belong to the
selected package's old/new payload namespaces. The final target must remain a
regular package file after obsolete leaves are removed. Parent aliases,
foreign ownership aliases, hardlink groups, special files/modes, archive
xattrs/ACLs/capabilities, live extended attributes, unknown PAX metadata,
`.INSTALL`, service/socket/hook/desktop-entry leaves and protected platform
paths refuse. The independent decoder and hashing facade are private instances;
shared parsers, stdlib hashing and archive budgets are unchanged.

The complete held auxiliary scan/config/cache/helper/library closure and selected
raw links/endpoints remain protected. Descriptor-bound xattr observations cover
selected leaves, provider files, auxiliary closure and selected links, including
final precommit. The existing private eligible projection restores helper/raw
links before complete-map comparison. Commit readiness follows live prior,
provider, metadata and auxiliary checks. Failure retains the engine's known or
unknown commit/checkpoint state. Rollback is not implemented. The adapter itself
reports helper exit status `NOT OBSERVED`; the independent TEST actor below
provides its own observed exit evidence.

## Focused checks and actual TEST transaction

Ordinary `test_prior_payload_aux_runtime.py -v` runs19 focused cases using fresh
real TEST signatures and unchanged pinned host ALPM read-only handles, with an
explicitly inert auxiliary fixture. It compiles fixed original MIT C fixtures
using existing `/usr/bin/cc -static -fno-pie -no-pie -Os -Wl,--build-id=none
-Wl,-s`. Static libc is the installed host input; the resulting programs are
fixture artifacts, not port packages. Compiler logs, sources, commands and
binary hashes are retained by the actual actor. No installation or acquisition
is attempted. Unit refusal cases cover dynamic/wrong-machine ELF, unreviewed or
changed interpreters, executable text, privileged metadata, altered prior/native
bytes, foreign ownership/hardlinks/aliases, hooks, backup metadata and protected
auxiliary/selected-link writes. Ordinary checks do not run ALPM commit or helper.

`--actual --sandbox ABS_EMPTY --evidence ABS_PRIVATE` explicitly runs a genuine
signed upgrade through the release pipeline, ALPM prepare/commit/checkpoint,
actual helper and old/new program execution. It compiles inert static V1/V2
programs and a static interpreter, upgrades executable/script/data/contained-link
leaves, removes obsolete executable/data leaves, checks all587 inventory rows,
held provider/helper/libc/links and both raw caches, and removes the copied root.
No packages are installed on the host. Before/after maps, inputs, compilation
receipts, actual execution outputs, result flags, helper trace and cleanup are
exported. No private signing key is exported.

This actor deliberately reuses the accepted lifecycle helper from commit
`3ab6007b93e037bdf072642f55147d26aff78959` (22252bytes,
SHA256 `8fd402e691ab28f294710e54a2a60fe0456545894be90c5c2477761d094a14b1`).
That file is absent from this candidate's base361ed74e. Co-adopt it at
`scripts/update/test_prior_aux_lifecycle.py`, or set
`CACHY_ASAHI_LIFECYCLE_FIXTURE` to its exact absolute file. The loader checks
captured bytes and executes them against this checkout's engine. Ordinary tests
do not require the helper. Its existing host TEST profile pins unchanged
libalpm16.0.1, x86_64 ldconfig and libc; it validates original ARM comparator
source/binding separately, overrides host helper/scan pins explicitly, and
requires both caches RAW_EQUAL. **Comparator-to-running-host-helper source
correspondence is NOT VERIFIED; production ARM explicit targets are NOT
EXERCISED.** GDB independently observes actual helper executable hash and exit0
because ALPM success alone does not establish that exit.

Run the actual actor only under a fresh owned user transient scope enforcing
memory≤512MiB, swap0, one CPU,≤64 PIDs, RuntimeMaxSec180s and TimeoutStopSec10s;
enter `unshare -Urnm` with a clean environment. It refuses absent bounds, a
nonempty sandbox, a non-single-UID mapped root or network interfaces beyond
loopback. It mounts only that owned sandbox as a private64MiB/20000-inode
nodev/nosuid tmpfs, preserving real capacity gates. Source/copy limits remain
16MiB/4000nodes; GDB worker limit45s/1MiB. Existing tools required are Python,
GPG/GPGCONF, C compiler/static libc, GDB with Python, mount/umount and unshare.
Agents, owned mount, copied workspace and scope are retired; no canonical actor,
lease, network fetch, host keys/trust, operational workflow or shared CI is used.

The recorded host run passed all19 focused checks and one genuine static
native/script TEST lifecycle. The old executable/script produced V1; the new
executable/script/alias produced V2 with exit0. Actual helper hash/exit0,
commit/checkpoint, raw cache equality and cleanup passed. Peak memory was
271130624bytes and peak tasks32. These results establish this bounded host
fixture only. Dynamic payload support, complete Asahi/full587 composition,
production ARM helper coverage, native ARM/M2 hardware, rollback, release
acceptance and performance gains remain unestablished.
