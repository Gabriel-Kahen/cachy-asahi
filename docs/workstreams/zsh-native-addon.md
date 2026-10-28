# Held Zsh native addon implementation

Status: held source implementation; inert model results are in the sealed receipt. No native,
Docker, GPG, installation, namespace or network actor was run for this work. The
original proposal remains held unchanged in `zsh-native-integration-proposal.md`.

The coordinator selected a separate same-job addon for one package, with strict
`compare.py --require-bytes` acceptance and no content-only fallback. This owner
adds only `scripts/ci/development/zsh_addon.py`, its inert tests, this document and
`artifacts/reviews/zsh-native-addon-20261012/`. The proposed reviewed contract is
an **artifact copy** there; the actual manifest, packet, controller, workflow and
registration remain coordinator-owned. This source cannot claim native acceptance
before that integration and actual actor evidence.

## The selected Docker exception

The held proposal allowed adding a cidfile to `docker run --rm`. The coordinator
explicitly selected a different adaptation to eliminate the fast-container
observation race. The private gate accepts only the unchanged build helper's exact
image query, native architecture query and exact restricted `run` grammar. Nested
helper `rm`, arbitrary commands, resources, mounts, images and names are refused.

For the exact admitted run, the gate records original argv and transforms only
that invocation into `create`, deliberately drops `--rm`, and adds a private
cidfile. Image, name, user, entrypoint, command, four bind mounts, two explicit
environment overrides, network isolation and resource restrictions stay bound
to the original intent. This effective-argv exception is selected explicitly;
`scripts/build/build.py` remains byte-for-byte unchanged.

Create must return a full CID equal to the private regular cidfile. The gate
inspects that CID **before start**, checks identity and actual configuration,
and requires a created, nonrunning, healthy state. Only then may finite
`start --attach CID` run. Afterward it checks the same CID/configuration and
actual terminal container exit. Both CLI success and container success are
required. The stopped container remains available for parent inspection and
ownership-checked removal by CID, followed by a successful full absence query.
No name-based forced deletion, image removal, commit or global pruning exists.

The stage has one 1200-second deadline, with work ending at 1080 seconds. Each
lane's parent establishes a single 270-second cutoff before invoking its helper;
all gate processes share it, including helper queries, create, inspections and
attach. It cannot renew across commands. Helper internal timeout remains 300,
outer supervision is at most 360, comparison 120, queries 30 and owned removal
60 seconds, always clipped to the applicable absolute cutoff. Cleanup operations
may use the fixed remaining stage reserve. Expiry, binding change, ambiguous
ownership, unproved process reaping or container absence refuses PASS.

Each operation checks an absolute CLI, its observed bytes/mode/ownership, an explicit local
socket and its identity, empty private Docker configuration and observed daemon
ID/OS/architecture/version/root/runtime. Before/after checks detect observed
drift; they are not an atomic proof against an unobserved daemon restart. Ambient
Docker redirection is not inherited. Host HOME is preserved. Container defaults
are checked against the actual base image, with private IPC/cgroup namespaces,
no restart, inherited environment plus the two exact overrides, and both declared
and effective mount records. Actual compatibility with the runner's inspect
schema remains a native actor question.
The CLI and interpreter must be root-owned without group/other write permission.
Execution uses the paths on a trusted, stable host: pre/post checks do not seal an
ELF executable or interpreter against a transient privileged replacement. The
adapter makes no immutable executable-FD transport claim.

The outer builder owns one process group. Inner gate Docker clients remain in
that group instead of creating separately orphanable sessions. Other parent
queries own their own groups. Spawn registers the process while cancellation
signals are blocked; cleanup sends KILL even at expiry, performs no renewed wait,
and requires disposal evidence before success. Workspace enumeration streams
entries, refuses at node 1025/depth 25, and checks live file/byte quotas during
work. The same quota refusal cannot prevent narrowly scoped cleanup: disposal
omits the live workspace quota while retaining ownership/tool/daemon/deadline
checks. A late interruption during finalization revokes all three terminal
status receipts before cancellation propagates.

## Source authority and integration interface

`prepare_initial_view(full_snapshot, fresh_target, packet)` produces the exact
159 original sources plus separately pinned `integration.lock.json`: 160 files.
It verifies the original four recipes/71 inputs and 125 generated-fixture records,
copied bytes/modes and closed file set. It does not refreeze recipes, scan the addon
as a fifth original package or change any original source/metadata file.

`SourceAuthority(full_snapshot, packet_sha256, view=original_view)` is a scoped
captured-byte loader. The coordinator must enter it **before** loading project
modules and retain it across deferred imports, consumers and publication. It
rejects foreign project preloads, retains verified bytes, compiles those bytes
directly, suppresses PYC, and checks actual loaded module/function/class method
identity. Canonical original modules resolve to the original view; explicitly
selected development modules resolve to the full snapshot. Reviewed direct
`spec_from_file_location` aliases receive the same byte loader; unknown aliases,
custom loaders and unknown project-path imports are refused. Trusted Python
stdlib/extension imports remain the interpreter's responsibility.

The dispatcher temporarily replaces `importlib.util.spec_from_file_location`
within this scoped process and restores it, project module registrations, Python
path and cache settings afterward. It is therefore intended for the serial
coordinator, not concurrent unrelated imports in one interpreter. It does not
silently accept a module merely because its `__file__` looks reviewed.

`authority.run_native(argv, consumers)` invokes the canonical captured
`native_arm.main` and binds the actual `integration.Controller` passed through
its original callback. `run_zsh(controller, full_snapshot, fresh_output,
cache=None, authority=authority)` requires that same active controller instance,
checks its own original 159-file source snapshot, and refuses fabricated
controllers or dictionary substitutes. Root must route the existing development
producer wrapper through this API; its existing duplicate alias path loader is
not admissible. Keep the admitted checkout cwd for the original Git HEAD check.

The parent loader does not propagate into arbitrary subprocesses or containers.
Original producer children retain their original reviewed source authority policy;
the scoped no-PYC environment also reaches their inherited environment. The
addon explicitly generates separate captured-byte bootstraps for the unchanged
build/comparison helper graph and a pinned private gate launcher. Their actual
execution still requires native evidence. The adapter does not strengthen an
original container's source-execution claim by inference from these parent models.

The adapter requires the coordinator's actual packet to include the reviewed
contract and new control sources. With today's unexpanded packet it refuses;
the artifact contract is never a runtime registration substitute. The borrowed
base must be the original native producer's exact immutable linux/arm64 image
and authenticated 341-package inventory, with its source commit, epoch, native
runner, UID/GID and job record. It does not provision another image or install
anything onto the host.

## Acceptance and evidence

The contract carries all twelve recursive recipe file hashes, including PKGBUILD,
metadata, helpers and documentation. Six `source=` entries and six regular
root-owned 0644 installed payloads are separate subsets. Each helper must produce
one bound package, exact input snapshot/inventory, zero exit and valid source/
package metadata. Parent checks the helper's retained report and evidence hashes;
the unchanged comparator reopens both actual archives within its bounded child
process. Two distinct witnessed container identities and clean evidence directories
are required. Installed contents, PKGINFO and archive bytes must all compare equal.
BUILDINFO equality is reported separately. Unequal host archive bytes remain host
diagnostics and are not native evidence.

Private output retains source snapshots, configuration, original/effective argv,
CID custody, logs, package/environment validation, archives, comparator results
and cleanup receipts. File count/byte limits apply. Exact public selectors are
`adapter-status` and `public`, containing only closed JSON status/receipt records.
No package archive or raw log is published by this adapter. Existing public
credential policy and outer publication bounds still require coordinator checks.

Adapter PASS is explicitly **provisional**. Root must register `zsh-addon` as a
required ordinary development stage before the existing consumers, keep virtual
last, and reconcile cancellation/initial producer exit, original integration and
cleanup, all required stages and bounded publication in its separate aggregate.
The original four-package summary stays unchanged. Missing these gates never
becomes accepted native addon work because a private receipt says PASS.

Registration adds twelve package sources plus adapter, tests and reviewed contract:
15 paths; the captured 211-file map would become 226 for Zsh alone. Joint admission
of the separately held two SVG files would yield 228, before any other concurrent
changes. Root must recompute final maps and dispatch hashes from the selected
committed tree. This owner changes neither the initial 159/125 boundaries nor the
original four-package/71-input lock.

## Remaining work

The sealed receipt will identify exact held sources, artifact contract, stdlib-only
dependencies, inert model results and any unresolved review findings. Coordinator
source peer review, integration, exact registration and actor admission remain
required. Actual native pair/cleanup/publication, target installation/removal,
Asahi and exact M2 behavior, and performance acceptance are NOT RUN here.
