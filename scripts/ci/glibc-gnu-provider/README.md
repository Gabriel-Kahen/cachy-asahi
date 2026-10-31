# Unselected conventional /usr GNU libc native pair

This dedicated lane builds `cachy-asahi-glibc-gnu-provider 2.43.caa1-1` twice
from the complete retained GNU 2.43 source. It does not install a system libc,
alter the source builder, replace any selected package/platform manifest, or
admit a release. Installed-provider lifecycle belongs to its separate owner.

The implementation is adapted from the accepted `glibc-official-release` lane.
Its full archive inspector, signature verification policy, eleven-library ABI
checker, C-header checker/probe, GNU status collector, build-entry settings,
process owner, container limits, exclusive lease and ordered cleanup remain.
The ABI/header/collector source files are byte-identical to the original lane.
No architecture declaration, syntax check or inert fixture is native build proof.

## Exact source materialization

There is no new fetcher. Root froze the three original public files and flat
`index.json` at checkout 5303b00e8bb66a3e58f2792fa1b60306d464e540,
ref `codex/glibc-gnu-source-inputs-v1`. The original retained run
is 38915137670, Source d1055cf95f7d236fc55396db36b432df5191ff2a. File identities:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| glibc-2.43.tar.gz | 40287809 | e1e622cbd635019090fa23260e5d9ec219b12f97ae7ae02f033d4ae42cf2c004 |
| glibc-2.43.tar.gz.sig | 1018 | bfd0c5a9924e4f084281cd2f3ba96e5c6e87a6d363113e7a0f98c5151463c9e3 |
| gnu-keyring.gpg | 3698125 | 0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca |

Packet index schema is exactly:

```json
{
  "schema_version": 1,
  "status": "ROOT_BOUND_COMPLETE_GNU243_INPUT_PACKET",
  "accepted_native_run": 38915137670,
  "files": {"glibc-2.43.tar.gz": {"bytes": 40287809, "sha256": "..."}, "...": {}}
}
```

The `files` mapping must contain exactly the three real rows above. `bindings.json` pins
the actual packet checkout SHA and the 559-byte index SHA256
fc25f22892fb76b04091e27aff91029f72cebe0174b5fee7d4278ae0b694b467.
`job.py packet` checks the complete input set; the workflow also checks checkout
HEAD against the bound SHA. This checkout identity is a transport identity, not
an upstream glibc Git revision. Materialization and `run.py inputs` independently
rehash the full 20,740-file, 267,112,798-byte source tree to derived tree identity
97ac10e146c65ecbd22d36e3743eb5b5e9166ae9, then verify the exact detached signature.
The two existing project patches are pinned and applied with zero fuzz by the
unchanged recipe preparation. No partial source snapshot or forged receipt can
stand in for the full archive.

KEYEXPIRED/EXPKEYSIG remains a recorded limitation, alongside absence of
independent pretrusted fingerprint authority. BADSIG/revocation/unknown-key,
wrong signature identities/epoch, or failure exit is fatal. This preserves the
accepted unselected experiment policy; it provides no stable-promotion trust
exception. The old held binary's missing corresponding recipe and GNU-vs-r22
downstream/security patch equivalence remain unresolved.

## Build, package and staged runtime

The native owner borrows the exact authenticated owned574 image/lock and creates
two clean `/work` builds at epoch1769201640. Containers remain non-root,
offline, read-only except owned work/tmpfs, cap-drop ALL/no-new-privileges,
4CPU/12GiB/1024PIDs/8192fds with 512MiB tmpfs. Keep the original measured 40GiB
disk reserve, 15000s process budget, 6300s/build, 900s ABI/header/runtime stage,
900s cleanup reserve, source/archive limits and 768MiB closed export cap.

Build-entry invokes actual makepkg `--printsrcinfo` and compares all metadata
fields with `expected.SRCINFO`. That file is a review expectation derived from
literal recipe assignments, not host-generated metadata. Native makepkg's
actual output is retained. Both builds retain complete GNU check and check-abi,
named upstream status/unsupported/XFAIL evidence, actual toolchain/inventory,
BUILDINFO and concrete recipe SHA. Failure/XPASS/error/malformed records or
nonzero make exits are fatal; no tests or ABI expectations are waived.

The package provides only `glibc=2.43`, conflicts with `glibc`, has no Replaces,
and depends on held linux-api-headers, filesystem and tzdata. Native staging
checks those actual PKGINFO fields, the actual BUILDINFO recipe identity and
the reviewed helper bytes. Conventional payload is extracted under
`/work/stage/root`; package metadata stays separately under `/work/stage`.
Only expected `/usr` subtrees and `/etc/gai.conf`, `/etc/rpc` are accepted;
scriptlets, hooks outside those paths, root aliases and foreign configuration
are refused. The shared recipe audit checks all staged ELF load alignment,
the exact 18-byte `_nl_default_dirname` OBJECT and its `/usr/share/locale` bytes,
required C.utf8/gconv/license files, contained links and absence of private paths.

An inert reader scans all 574 actual ALPM database identities and file lists
against the fixed inventory. Only paths owned by the replaced held glibc are
allowed to overlap. Retained tzdata's three commands are absent from the new
package, and filesystem's aliases/configuration remain outside it. Any other
ownership collision fails without overwrite or dependency bypass. This scan
does not establish an installed dependency transaction.

Each pair side runs the unchanged public ABI comparison, candidate-only C-header
check with `-nostdinc` and recorded GCC/kernel inputs, and unchanged owned runtime
suite through its explicit staged loader. The original six runtime sources,
13 compiler/tool commands, 14 total commands, eight cases, nine parent/child test
records and exact provider/file identity checks are retained. Native page size
is recorded; this stage does not assert normal installed lookup or M2 behavior.
Both final package archives must be byte-identical.

## Separate normal-interpreter compile products

The lifecycle lane consumes additional `smoke-normal`, `exec-child`, `plugin.so`
files from each pair side under `runtime/{a,b}/normal-clients/bin/`, plus
`receipt.json`. Normal products are compiled separately in the same owned smoke
consumer using the unchanged compiler driver with `spec=None`, hence no private
PT_INTERP override. Both programs must have `/lib/ld-linux-aarch64.so.1` or
`/usr/lib/ld-linux-aarch64.so.1` PT_INTERP; the plugin must have none. Static ELF
architecture and 16K alignment checks are mandatory, and pair hashes must match.

Relinking alone does not make the original child-exec case normal. This lane binds
the lifecycle owner's exact source as `normal-child-exec.patch`, altering only
`abi_smoke.c` to invoke exec-child directly. `normal-client-policy.json` binds
the patch bytes and exact resulting source bytes/hash. The helper verifies
the unchanged original manifest, copies six source files into a fresh private
workspace, applies that one patch with zero fuzz, verifies the sole allowed
source change, then calls the original compile suite. The original staged
sources/probes are never modified. A pending patch blocks source proof before
secrets and native execution before any container.

The separate normal receipt retains original and patched source identities,
actual GCC/cc1/collect2/as/ld identities and version, all actual header dependency
identities, 13 compiler/tool command records, a separately counted bounded patch
command/tool identity, binary hashes/ELF metadata and policy hash. Normal clients
are never executed in this lane. Their normal parent/child maps and all cases
must pass in the separate installed-provider lifecycle. Keeping the original
staged suite intact prevents either receipt from impersonating the other.

## Root join before dispatch

`bindings.json` binds the accepted private16K run 38941180852, Source
308c9b0cba5ad6c90530e4b10f0e3fb3e01dcbfb, its exact runtime receipt and Root
verification. Source proof and native `--execute` both require explicit Root
acceptance, complete guest cases/identity protocol, natural QEMU/actor exits,
consumer/producer/kernel cleanup and the exact accepted private pair. The
Root verification's raw UART/private-client/bootstrap/kernel export limitation
is carried verbatim into the new source proof and pair result.

The normal-child patch, private16K prerequisite and exact GNU packet are bound.
The dedicated source/integration manifests and manual workflow hashes are stamped
in this proposal. Root must adopt the files, force-add the two already-public
prerequisite records at their bound paths, commit the final exact source and
dispatch that revision. Any concurrent source changes require refreshing the
manifests and workflow hashes before that freeze. Integration pins must cover
this lane and its source manifest, the nine provider recipe files, unchanged
owned runtime manifest/files, unchanged maintained574 seed/build/test inputs and
process owner, generic16K receipt checker, and both prerequisite evidence files.
Do not replace selected inventory or another lane's manifest. The manual
workflow refuses unfinished hashes and bindings before secrets/actors.

The current source proposal has no native actor result. Source materialization
and inert controls establish data/source properties only. Normal installed
replacement, locale migration/cache hooks, rollback/recovery, generic16K system
provider runtime, exact M2 hardware, security/maintenance review and release
admission remain separate unfinished gates.
