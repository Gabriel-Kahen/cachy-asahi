# Zsh autosuggestions: same-job native addon proposal

Status: **source-audited proposal, held for coordinator selection**. No implementation,
native build, Docker/GPG actor, installation, or test was run for this proposal.
The addon is selected in the development inventory and remains unselected for release.
The source capture and machine-readable proposal are in
`artifacts/reviews/zsh-native-integration-proposal-20261012/`.

The proposed consumer builds one reviewed package twice in the existing native
development job, borrowing the exact original builder image and authenticated
package inventory. It retains the original four-package producer and its acceptance
rules. Native package acceptance will still leave target installation, removal,
interactive behavior on the selected Asahi system, both supported M2 Air sizes,
and performance measurements unfinished, as required by the roadmap.

## Evidence and fixed boundaries

The capture matched all 211 currently registered development sources and all twelve
live addon files against their held source records. The handoff digest is
`0b8a04d84d8aee2ea099558c5e08bf2d1c1b030f84783946456b37618f2a8f8f`;
the independent peer digest is
`62593a7ba6d4620b30a6f6f31575bffada236c1a779dc55916d1f37d569551fe`.
Coordinator adoption is captured separately; its publication commit reference is
reported by the coordinator, not verified here by a Git actor.

| Boundary | Captured count | Proposed treatment |
| --- | ---: | --- |
| Original recipes | 4 | Keep `scripts/ci/recipes.lock.json` and producer expectations unchanged |
| Original recipe input hashes | 71 | Preserve all entries |
| Original integration sources | 159 | Preserve every path, byte and mode |
| Original generated fixture records | 125 | Preserve; let the unchanged original gate rederive them |
| Current development source map | 211 | Coordinator expands only after source review |
| Addon packages | 1 | Separate consumer; never a fifth original recipe |
| Addon directory files / build input hashes | 12 | Closed recursive set, all supplied to `--reviewed-inputs` |
| PKGBUILD local `source=` entries | 6 | Subset of the twelve reviewed files |
| Installed regular payload files | 6 | Exact paths, content hashes and modes |
| New proposed control sources | 3 | Adapter, causal fixtures, one reviewed contract |

The initial capture's `addon_existing_recipe_inputs: 6` describes the six local
`source=` entries. It is not the CLI input-map cardinality. Captured
`package_checks.recipe()` hashes every regular file recursively, including
`.SRCINFO`, PKGBUILD, review helpers and documentation: **twelve hashes** are required.
`proposal.json` records this correction without rewriting the capture.

The package is `cachy-asahi-zsh-autosuggestions` 0.7.1-1, `arch=any`, MIT,
with `zsh>=4.3.11` and an optional coreutils dependency for upstream completion
suggestions. The pinned upstream revision is
`85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5`; the unchanged aggregate module digest is
`eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a`.
`check()` syntax-checks the module and opt-in script. Packaging installs six regular
0644 files and defines no install hook, service or global shell startup mutation.

Held host assemblies have equal payloads and PKGINFO but **unequal archive bytes**:
`95d092cdfdb1740291b28df3b1d3d26694427d9c767b6a16291cc3000a49ffa2`
and `956ffcd1175733bea6dc6dfb60594c811dc37ccda80f56ad416b0c3a40ef68f9`.
BUILDINFO differs in builddir/startdir. These records establish host assembly,
not native byte acceptance. The recorded host PTY checks likewise establish only
their explicit host interaction cases.

## Minimal files and source authority

Propose three new registered files:

1. `scripts/ci/development/zsh_addon.py`: original-view preparation, the addon
   consumer, a narrow finite Docker gate and scoped cleanup in one reviewed module.
2. `scripts/ci/development/test_zsh_addon.py`: causal source/model fixtures for
   source authority, acceptance and cleanup refusal. They must not claim Docker,
   native ARM, installation or hardware evidence.
3. `manifests/reviewed/zsh-native-addon.json`: one closed contract containing the
   twelve source pins, complete twelve-entry recipe map, six payload records,
   metadata, actor bounds and byte-acceptance policy. Avoid a duplicate addon lock.

The coordinator owns changes to the existing separate development `packet.py`,
`controller.py` and their appropriate fixtures, contract registration, packet
regeneration and workflow dispatch pin. Keep the existing workflow family and
runner/job. Do not edit original `native_arm.py`, `integration.py`, `build.py`,
`compare.py`, their original metadata locks or `integration_export.py`.

Registration adds twelve package files plus three control sources: **211 + 15 =
226** for this Zsh change alone. The two separately held SVG probe sources would
make 228 if jointly admitted; other concurrent admissions require recomputation.
Editing an existing registered path changes its digest, not the path count.
The proposal document and review artifacts are evidence, not executable control
sources. No registration has occurred in this task.

There is a source-boundary blocker to a naive consumer addition. Both development
`packet.initial_paths()` and unchanged original `integration.scan()` traverse
`packages/shells`. The new package therefore enters the original gate. Expanding
only the 211-file map, or excluding it only in the development scanner, does not
preserve the original 159-file execution gate. `freeze-recipes` also discovers five
recipes and deliberately refuses its expected-four check; do not run it to produce
addon metadata or change that check.

Use a fresh private **original-only view** containing the exact 159 pinned original
sources and the separately pinned `scripts/ci/integration.lock.json`: 160 copied
files before the original actor starts. Copy from the verified full development
snapshot; verify bytes/modes and closed path sets during and after copying. Reject
links, special files, unknown files, pyc/cache files and partial copies. Source
verification before and after the actor must distinguish actor outputs from source
inputs. Existing `packet.snapshot()` requires the complete development map and
cannot directly produce this subset.

Load the canonical unchanged native producer from this view in a fresh import
context. Its `ROOT` and its imported original integration/check modules must resolve
to that view. Keep the admitted checkout as the outer cwd: the producer's existing
`git rev-parse HEAD` call has no `cwd`/`-C`, so the view needs no `.git` copy. Avoid
reusing previously imported modules from the full tree. Verify executable origin,
Python path and cache policy; a successful path loader alone is not proof that the
captured bytes were the bytes executed. The registered adapter implementing this
transition remains subject to the outer packet's authority checks.
Apply this origin and no-PYC policy to the nested build/comparison helpers and their
imports as well; the illustrative `python` commands below mean the bound absolute
interpreter, not a new ambient PATH lookup.

Keep the full verified development snapshot for the addon and other consumers.
Development packet scanning needs an **exact exclusion of this package directory
from its initial subset**, followed by explicit addon-root and contract selection
in the development scan, pins and read-only Git selector. Unknown shell directories
must still fail closed. The original scanner remains unchanged and sees only its
original view. This preserves the held package paths and avoids a new general addon
framework or relocating the package.

## Same-job interface and prerequisites

Proposed adapter interface:

```text
prepare_initial_view(full_snapshot, fresh_target, packet) -> verified_view
run_zsh(controller, full_snapshot, fresh_output, cache) -> stage_record
```

Register `zsh-addon` as the first development callback action, before existing
KSM/ARM/client/virtual actions. The callback already follows the four native build
pairs and seven original integration stages. Keep `virtual` last because public
aggregation uses `STAGES[:-1]` for ordinary required stages. Callback entry alone
does not prove the initial stages passed or the producer exited cleanly: the original
controller can call consumers after an ordinary initial-stage failure.

Before the first addon actor, require the original native-build PASS, the exact
same-job immutable image ID, linux/arm64 image and aarch64/arm64 daemon, authenticated
341-package inventory, bootstrap image-provisioned binding, source commit,
source-date epoch and exact reviewed source/control pins. `common.base_prerequisite`
provides part of this binding; additionally freeze the actual Docker CLI,
context/endpoint/socket and daemon identity, native runner/UID/GID and parent job.
Do not accept an arbitrary image tag, cache provenance or architecture declaration
as these facts. Cache is not build acceptance authority.

The addon borrows `controller.image` and the original native output's package lock.
It never rebuilds/commits an image, installs packages, signs, uploads, removes the
base image, or removes the original controller's installed derivative. The original
cleanup routine explicitly preserves the base image. Its callback comment claiming
the image is removed afterward is inaccurate and must not define addon ownership.

The adapter derives a plain twelve-entry reviewed-input JSON from the closed
contract. Each attempt uses a new evidence directory, unchanged scripts and the
original image inventory:

```text
python <original-view>/scripts/build/build.py <full-snapshot>/packages/shells/cachy-asahi-zsh-autosuggestions \
  --image <exact-image-id> --mode native --network none \
  --source-date-epoch <original-epoch> --expected-packages <authenticated-lock> \
  --reviewed-inputs <derived-twelve-entry-json> --timeout 300 --output <fresh-attempt>
python <original-view>/scripts/build/compare.py <attempt-1> <attempt-2> --require-bytes
```

Do not execute the package review helper as an addon CI prerequisite. The unchanged
builder verifies sources, generated SRCINFO, exact package inventory and package
metadata inside a fresh nonroot, network-disabled container with its existing
restricted resources. Require two distinct clean environment names and actual
container custody records; names alone are not independent machines.

## Finite execution and scoped cleanup

Use one nonrenewable **1200-second** stage deadline: up to 1080 seconds for work,
with 120 reserved for cleanup. Start every operation only if its bound and cleanup
reserve fit. Bound build-helper parent calls to 360 seconds each and comparison to
120; use the remaining monotonic deadline as the tighter bound. Read-only Docker
operations are at most 30 seconds; owned removal is at most 60 seconds. Process
group termination/reaping must fit the reserved deadline, with explicit status
when it cannot be proved. Retrying a failed actor must not reset this deadline.

The unchanged builder has a cleanup gap: its timeout path calls `docker rm -f`
without a subprocess timeout, and cancellation can bypass that branch. Process
group termination and Docker `--rm` do not prove daemon-side container absence.
Consequently, the small adapter must supervise Docker itself before an actor is
admissible; simply wrapping the builder in `common.command()` is insufficient.
Use an adapter-local bounded supervisor with an explicit reviewed environment:
the captured `common.command()` rebuilds PATH/environment and cannot carry this
private Docker launcher unchanged. Do not relax that shared helper's environment
policy for other stages.

Propose an ephemeral `docker` launcher generated by the registered adapter, with
its bytes recorded, ahead of PATH only for the addon helper. It dispatches the
adapter's gate using the pinned absolute Python and adapter path. The gate validates
only the helper's exact image-inspect, architecture-query and restricted run forms;
unknown commands fail immediately. Bind the real CLI and explicit endpoint so the
launcher cannot recurse or drift to another daemon. Every forwarded real CLI call
has a finite bound. Cap a run at 270 seconds, before the helper's 300-second internal
timeout. Reject the helper's nested `rm` immediately; the parent owns removal.
The helper's timeout message saying it removed a container is not cleanup evidence.

Before dispatch, persist exact trusted run intent and prove the generated name is
absent. The gate may add only a reviewed `--cidfile` in a fresh private lane directory
to the effective run argv, retaining both the original and effective argv. Validate
and retain the daemon-issued CID, exact name, image, user, mounts and endpoint.
This addition changes the effective Docker argv and must be reviewed as part of
the adapter, although the build helper source stays unchanged. Do not trust a
package-written file or provenance JSON as a cleanup grant.
Capture the actual CID/configuration while the owned client/container is live.
The unchanged run uses `--rm`: a fast successful container can disappear before
post-run inspection. A cidfile alone does not prove observed configuration; a
missed observation window therefore retains UNKNOWN/FAIL. Removing `--rm` would
be another effective-argv change and is outside this proposed single addition.

On success, failure or cancellation, use bounded endpoint-bound inspection and
final absence checks. Remove by the retained CID only when its observed configuration
matches the trusted intent. Never delete by an unverified reused name, perform global
pruning or remove an image. Ambiguous ownership, changed daemon binding, missing
custody evidence or unproved teardown produces cleanup UNKNOWN/FAIL and refuses
stage PASS. Preserve the first build failure separately from any cleanup failure.
Attempt two is NOT RUN if attempt one fails. No target package mutation occurs.

## Acceptance and receipt/publication contract

Require both helpers to exit zero with `built-package-static-pass`, no validation
errors, exact twelve inputs, exact metadata, one package artifact per attempt and
the same bound image/inventory/epoch/entry script. Independently verify six regular
root-owned 0644 payloads and content digests against the contract:

| Installed path under `usr/share/` | Source file |
| --- | --- |
| `cachy-asahi/zsh-autosuggestions/zsh-autosuggestions.zsh` | `zsh-autosuggestions.zsh` |
| `cachy-asahi/zsh-autosuggestions/opt-in.zsh` | `opt-in.zsh` |
| `cachy-asahi/zsh-autosuggestions/README.md` | `usage.md` |
| `licenses/cachy-asahi-zsh-autosuggestions/LICENSE.upstream` | `LICENSE.upstream` |
| `licenses/cachy-asahi-zsh-autosuggestions/LICENSE.project` | `LICENSE.project` |
| `licenses/cachy-asahi-zsh-autosuggestions/NOTICE` | `NOTICE` |

Permit only required parent directories and the explicit normal package metadata
members; reject extra files, hooks, unsafe paths, special files or links. Metadata
expectations include the reviewed PKGBUILD hash, dependencies, version and `any`
architecture. `arch=any` does not waive the native builder requirement.

The selected proposed reproducibility gate is the unchanged comparator with
`--require-bytes`: zero exit plus installed contents equal, PKGINFO equal and archive
bytes equal. Record BUILDINFO equality separately. Content-only equality with byte
inequality is useful diagnostic evidence but stage FAIL under this policy. If the
native pair reproduces the host BUILDINFO difference, retain that result; changing
to content-only acceptance requires a separately selected contract, never an
automatic fallback. Root selection of this proposal does not establish byte success.

Private output retains attempt inputs, build logs, package/environment/configuration
records, validation, provenance, package archives, comparison JSON, trusted actor
intent/CID bindings and cleanup observations. Bound retention before reading or
publishing; reject unexpected path sets and oversized records rather than walking
raw workspaces. Proposed addon caps: 256 private regular files/64 MiB total, each
archive at most 8 MiB; public at most 32 regular JSON files/2 MiB total/256 KiB each.
Expose controlled failure codes, not raw exception text or arbitrary workspace data.

Register exact public selectors for `zsh-addon`: `adapter-status` and `public`.
Publish only closed JSON receipts with source/contract/control hashes, image and
inventory bindings, attempt exit/status, artifact digest/length, payload/metadata
summary, comparison flags, cleanup result and first failure. Archive digests refer
to retained private artifacts; this JSON-only proposal does not publish package
archives or imply they are downloadable. Existing public policy has no addon binary
grant. Do not widen immutable `integration_export.py` or original artifact grants.
Recover these same two selectors after interruption. Existing outer file/byte limits
and credential filtering still apply.

The addon stage record includes `status`, `cleanup`, `attempts`, `comparison`,
`source_binding`, `actor_binding`, `hardware_status: NOT RUN`, and its explicit
public trees. Its PASS is provisional until the original producer returns cleanly,
initial integration and cleanup pass, all required development stages pass and
bounded publication succeeds. Add the stage to separate development aggregation;
keep the original four-package summary unchanged. Record public bundle SHA/length
and the terminal development summary separately from private actor evidence.

## Review and remaining gates

Implementation fixtures should causally reject source/contract drift or a fifth
original recipe; contaminated imports/view paths; extra package payload/hook;
wrong image/inventory/daemon; duplicate clean identities; content-equal/byte-unequal
comparison; cancellation/dirty producer exit; nested unbounded Docker cleanup;
foreign CID/changed endpoint; and cleanup whose deadline or absence proof is missing.
Verify projection/source-selection/public-selector cardinalities. These are proposed
fixtures, **NOT RUN** in this task.

The coordinator must select the file/interface/byte policy, implement and independently
review the source authority and finite Docker gate, register exact final files and
digests, and run the appropriate source/model checks before dispatching the existing
native job. A successful same-job addon pair then needs retained actual actor and
publication receipts. Installation/removal and exact M2/Asahi behavior remain separate
future work. This proposal is complete as a source-only handoff; actor readiness and
native acceptance remain unproved.
