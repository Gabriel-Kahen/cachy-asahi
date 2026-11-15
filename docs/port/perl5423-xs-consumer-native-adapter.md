# Native Perl 5.42.3 XS consumer adapter

This is a source-only operation proposal. No Docker, daemon, image, native job,
Reader, Perl, make, compiler, XS load, network or package-install/extraction role
ran while authoring it. Root accepted exact ARM4K native pair run43692477455
after independentReader3. Root's canonical decision is5804 bytes with SHA256
`27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1`;
the accepted package is22071176 bytes with SHA256
`647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22`.
XS remains NOT RUN and requires its separate admission. The outer artifact SHA256
`75323ce74aabe9b64d250486c18ce5c58809726a8ba9f76b618d6bc9abf35c77`
is not the native Perl package archive hash.

`scripts/port/perl5423-xs-consumer/native_adapter/native.py producer` provides
one future native local-Docker operation around the frozen runner87add6b2 and
fixture2991f582. It uses the existing Perl native policy's rootful local daemon,
nonroot main actor, ordinary build model and finite owned-child supervision.
It invokes no nested namespace tool: `nested_invocation=NOT_INVOKED` and
`nested_qualification=NOT_QUALIFIED`. A separate optional namespace diagnostic
is not an input requirement and cannot grant this operation acceptance.
The accepted package comes from the ordinary makepkg route; this consumer
reuses its archive and runs only the four XS commands, without rebuilding Perl.

Root owns Source/workflow integration, publication/readback, current daemon
admission, signature trust, signed349 image preparation, artifact/Original
Reader acceptance, package-prefix preparation and one-heavy-actor scheduling.
The adapter does none of those jobs and cannot promote a default provider.
The existing runner, fixture, preflight, recipes and shared manifests remain
unchanged. Support copies of the existing native common/runtime/export helpers
are whole-file pinned; their original sources remain unchanged.

## Concrete Root inputs

Root must independently accept the pair first and prepare a complete readonly
bundle. The template in `native_adapter/operation.TEMPLATE.json` intentionally
has null actual selectors and cannot run. Actual `operation.json` must bind the
new XS Source/ref/run/job, Root approval/readback, immutable ARM image, current
daemon proof, signed input audit, accepted pair Source/run/job and every input
hash. Set `authorization=ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS` only after
those decisions. Hashes bind Root's supplied bytes; they do not authenticate
Root or turn locally generated DATA into acceptance.

The bundle is mounted exactly at `/inputs`. It contains:

| Path relative to bundle | Required content |
| --- | --- |
| `consumer/` | Whole original fixture/preflight and frozen runner, plus this new native adapter/support source |
| `operation.json` | Root's actual operation admission, separately SHA256-pinned on the command line |
| `bundle-map.json` | `{ "files": { "relative/path": {"bytes": actual, "sha256": actual} } }` covering every regular bundle leaf except this map and `operation.json` |
| `xs-admission.json` | Frozen XS admission schema, exact1.3 candidate, native pair selectors, actual root/archive/metadata/toolchain pins |
| `xs-inputs.json` | Complete actual executable/runtime/header/Config/MakeMaker/libperl inventory, tied to accepted archive |
| `xs-plan.json` | Entire canonical frozen preflight plan approved by Root, using exact paths below |
| `prefix/` | Already Root-prepared ordinary alias-free runtime/header prefix, owned by UID1001; actual device/inode recorded |
| `perl-5.42.3-1.3-aarch64.pkg.tar.zst` | Actual accepted newly built archive, with its package SHA256 and byte count |
| `accepted-reader.json` | Actual Root-accepted Original Reader receipt, whole-pinned by operation admission |
| `daemon.json` | Current Root-pinned `OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS` proof from the held native daemon route |
| Metadata/inventory operands | Actual package `.PKGINFO`, `.BUILDINFO` sidecars and sorted349 package lock at the exact `/inputs/...` admission paths |

The bundle map is finite (at most6000 files/14000 nodes/224 MiB); leaves must be
ordinary stable single-link files. It must be private to Root and protected
against changes during the operation. Producer and entry both recheck its whole
pin and complete leaf namespace. Root supplies the map through its existing
Source/input integration; this adapter adds no workflow or shared manifest.

The XS prefix is `/inputs/prefix`, source stage `/xs-work/xs-stage`, admission
`/inputs/xs-admission.json`, inputs `/inputs/xs-inputs.json`, and archive the
fixed `/inputs/perl-5.42.3-1.3-aarch64.pkg.tar.zst`. Root's approved plan uses
these paths without runtime rewriting. Compiler, linker-driver and make must
be explicitly pinned ordinary single-link binaries under `/usr/bin` in the
immutable signed349 image; aliases are refused by frozen preflight. Root must
prepare suitable inputs rather than relax that requirement. The actor derives
the actual package lock directly from the image's local ALPM descriptors and
compares it to the fixed349 lock and admission inventory, without a subprocess.

All external inputs are checked before the first Docker call. Within the
container, the frozen runner again validates the complete prefix, target ELF,
metadata, archive, runtime/header inventory and tools, stages the exact five
fixture files and compares the entire regenerated plan before its first XS
command. Source-only controls do not establish that these future operands or
image tools exist.

## Native sandbox and runtime observation seam

The fixed daemon endpoint is `/usr/bin/docker --host=unix:///var/run/docker.sock`.
Before creating resources, producer joins the pinned daemon proof to current
socket ownership/stability, daemon ID, security options, architecture, cgroup
enforcement, storage directory and complete Server version. Rootless/remapped
daemons refuse. Native coordinator UID/GID1001 is required. Runtime UID/GID maps
must be the initial unremapped map. Root still owns validation of its proof body
and the signed image/input trust chain.

The main actor uses UID/GID1001, 2 CPUs, 4 GiB memory, zero added swap,256 PIDs,
network-none, read-only root, cap-drop ALL, no-new-privileges, injected init,
private cgroup namespace, exact readonly `/inputs` bind, and one private `/work`
volume. A separate bounded root actor has only CHOWN and runs the literal
`chown 1001:1001 /work` to initialize that owned volume. Actual init and main
container inspect records are retained and checked before either starts.

The old `/tmp`64 MiB and `/run`8 MiB noexec tmpfs mounts remain. This derivative
adds an explicit `/xs-work`256 MiB `rw,exec,nosuid,nodev,uid=1001,gid=1001,mode=0700`
tmpfs because frozen runner staging must be its own mount and XS must load.
This extra mount is an explicit new policy choice requiring Root admission; it
does not inherit qualification merely by citing the old native domain hash.
Actual mount properties, capabilities, runtime architecture, cgroup controls,
init/entry continuity and network interfaces are checked before runner execution.

The container's namespace/cgroup/mount inode numbers cannot be known before
creation. Root's operation explicitly binds this exact `native.py` hash in
`runtime_identity_generator_sha256`, the frozen runner hash, fixed plan hash,
and `authorize_runtime_observation_only=true`. That permission delegates only
filling observed identity fields under the fixed policy. Entry retains the
separate Root operation pin and actual runtime observation; its generated
sandbox hash is an integrity pin, not a preexisting Root-approved observation
or a new independent approval. Root's independent reader must join it to the
actual pre-start inspect, image, daemon proof and Root operation.

Entry invokes `runner.execute` in the same Python process, with no persistent
wrapper child changing the runner's exclusive cgroup membership snapshot.
Only the frozen four XS commands execute. The runner's per-command/resource/
output/cancellation/retirement/cleanup controls remain in force. No configure,
test or provenance receipt is invented.

## Evidence and future invocation

Producer's total policy is600 seconds with90 seconds reserved for owned cleanup;
the attached actor has a300-second cap, and export up to120 seconds within the
remaining budget. Output is an owned CLI stream with256 MiB hard inherited
file-size cap, parsed by the unchanged bounded plain-DATA tar reader. Logs have
8 MiB file-size/output caps. At least1 GiB evidence space,2 GiB daemon storage
and8 GiB available host memory are required in addition to Root's admission.
The existing runner governs its own240-second smoke budget. No bootstrap/image
build cost is claimed to fit inside these limits.

Actor flattens actual runner evidence into at most50 files/128 MiB with a map
of original paths, byte counts and SHA256s. Raw command streams, generated
Makefile/dependencies/C/object/extension, Config/module/libperl provenance,
runner plan/admission/input/sandbox copies, actual runtime/installed inventory,
Root operation and accepted Reader receipt are retained. Producer retains raw
Docker command lifecycle/logs, image and actual daemon observations, init/main
pre-start inspect, post-stop inspect, complete raw tar and parsed DATA export.
Mapped leaf pins and the complete export namespace must match. The independent
reader can reconstruct original runner paths from `evidence-map.json`.

On an attached CLI failure the producer attempts to stop the daemon-owned actor
and export stopped failure evidence; a disconnected CLI alone proves no
container retirement. Cleanup checks the exact Root-admission label before
removing owned containers/volume, uses observed container IDs for removal, and
verifies final absence. Unknown fate, changed ownership, resource failure,
cancellation, failed/incomplete export or cleanup remains FAIL. A stage retained
by the runner on uncertain child fate grants no XS credit; exported failure
evidence may consequently lack final generated files and cannot establish a
successful smoke.

After all Root gates, the future explicit entry point on the admitted native
coordinator is:

```sh
/usr/bin/python3 -I -B scripts/port/perl5423-xs-consumer/native_adapter/native.py producer \
  --bundle /root-admitted/private-bundle --admission-sha256 ACTUAL_OPERATION_SHA256 \
  --output /root-owned/fresh-xs-evidence
```

Even `SMOKE_EVIDENCE_EXPORTED_PENDING_INDEPENDENT_READER` grants no acceptance:
`native_acceptance=false`, `XS_acceptance=false`, `qualification=NOT_GRANTED`.
Root separately owns the actual run and independent reader decision. This
cannot establish general XS ABI, default-provider/installation lifecycle,
16K/M2 hardware, performance or release qualification.

The seven authoring controls are actor-fenced synthetic refusal DATA: pending or
missing acceptance/delegation, missing real inputs before any actor, wrong
architecture/native-pair join, fixed bounded argv, changed Docker policy/mounts/
command, Rootless/remapped/stale daemon or wrong socket, and substituted export
bytes. Both Python3.12.13
and3.14.6 pass; no production entry or actual resource/sandbox trial ran.
