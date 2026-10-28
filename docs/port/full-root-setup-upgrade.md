# Disposable complete persistent-root setup upgrade

The separate caller in `scripts/ci/full-root-upgrade-caller/` prepares the signed
initial587-package composition with updater4.4.2-2 and setup0.1.0-3. It stages
the complete persistent data, then uses `scripts/ci/full-root-upgrade/` to perform
one real signed setup0.1.0-4 upgrade in a second, owned copy. The first native
trial38858858112 failed before staging because an ownership record lacked a
FILES field. This refusal was reproduced with valid zero-byte ALPM metapackage
records; the actual offending package was not retained. No upgrade commit began; outer cleanup and
owned-volume absence passed. Full persistent-source preservation was not
established. The corrected parser retains empty metapackages and still rejects
missing records or nonempty records without a FILES field. Five focused controls
and34 caller controls pass; an actual successful commit remains pending.

Retry38862588064 passes initial/postdriver persistent-source and staging checks:
124745 nodes,587 packages and113759 package-owned non-directory paths, with the
same complete manifest digest before and after. It then fails copy preflight at
the auxiliary library-link closure check. Upgrade commit flags remain false;
reported commit count and driver copy cleanup are UNKNOWN. Outer cleanup and
owned-volume absence pass. No capacity or deadline failed.

The checkpoint incorrectly applies its library-only endpoint rule to every link
in ordinary scan directories. The correction follows the pinned glibc DSO-name
predicate, while preserving non-library links and their contained dependency
targets in the checked state. DSO/hwcaps closure and all limits remain held.
All24 auxiliary controls pass in an isolated user namespace. The actual failed
path was not retained; future errors include its name, and a retry must confirm
whether this source-demonstrated mismatch explains the actual refusal.

Actual38867099756 passes the complete124745-node copy, its one-shot initializer
(observed helper exit0), prepared baseline, repository construction, unchanged
persistent source and owned-copy/outer cleanup. It then refuses snapshot
authentication because the helper requires synthetic metadata while this
constructor correctly declares actual provenance. Upgrade commit flags remain
false; aggregate transaction count remains UNKNOWN. The correction selects an
explicit hash-bound `release_synthetic=false` only for this generic disposable
repository-update context. Both metadata and semantically verified spec must
match; signature and semantic verification remain mandatory. Legacy synthetic
defaults pass all19 real signed update and10 snapshot controls;15 new selection
controls and34 caller controls pass. A real upgrade retry is still required.

Retry38873660215 passes release selection and reaches observe-before, then
refuses a missing/unsupported root path before commit. Complete copying,
one-shot initialization, source preservation, copy disposal and outer/volume
cleanup pass. All three commit/checkpoint flags remain false; aggregate commit
count remains UNKNOWN. The first failed path was not exported.

Root passively hash-verifies the retained rootfs and all574 package archives,
then reconstructs their path metadata without executing/installing them. Apart
from the already handled mtab link, only filesystem's var/lock -> ../run/lock
has a missing endpoint after runtime staging empties run. The exact filesystem
archive is14864 bytes/SHA256
`228b63ef4a88501a68856231a19325a1ad31d92016a692d0a8be181edc70703f`.
The narrow correction treats only that root-owned0777 literal, with exact0755
var and run parent-directory shapes and absent run/lock, as comparison data. It
grants no Reader/node/child traversal, preserves the original87-chain table and
keeps general path resolution strict. Future missing-path errors name the node.
Five new controls,17 path,7 finite-link,34 caller and28 failure-case controls pass.
Normal retry38880148414 and queued failure-case38880150909 use separate frozen
sources; actual success is still pending. This source-demonstrated prerequisite
does not identify the earlier run's unexported first path.

The successor is the retained setup package with SHA256
`c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a`.
The constructor keeps its real341-package build identity separate from the587
installation base. It uses an ephemeral external TEST signer and the existing
release/client contracts. It publishes no stable repository or production trust.

The stage includes package-owned files, user/configuration data, boot/firmware
data, internal hardlink groups and the three ordinary Docker configuration
mounts. Volatile contents and exact infrastructure mounts are explicitly
excluded; runtime directory nodes remain empty. The stage is compared with the
entire persistent source before and after the driver. It is not a whole live
container snapshot. Timestamps and xattrs are outside the recorded metadata.

The second copy has no exclusions. Its one pinned, contained cache initialization
runs before the updater baseline; it is never repeated at transaction
checkpoints. Subsequent checks preserve all other nodes, package databases,
protected payload and user files. Source-selected link policy admits the87
measured paths. Only `etc/mtab` has two supported proc spellings, both inert
absent endpoints; its observed literal is reported and must remain unchanged.
No policy grants permission to traverse those proc targets.

Successful completion requires a durable commit, the exact587 before/after
inventories with only setup changed, preservation of the unchanged persistent
source, owned-copy disposal, and separately verified outer-container/volume
retirement. Failure or interruption retains known commit flags, or UNKNOWN
where necessary. No automatic retry, downgrade or lock-file removal is used.

The pinned configuration selects200000 nodes and6GiB against the measured
124739-node,4927246495-byte setup4 footprint, retaining the file, capacity,
deadline and cleanup guards. All22 link/copy controls and34 caller controls pass;
the isolated47-file closure and11 workflow shell blocks validate. The workflow
proposal is a sibling `workflow.yml`; Root freezes its Source and uses an
isolated registered ARM dispatch path. The main workflows are preserved.

This is generic software validation. Native-container installer P0, physical
16KiB/M2 behavior, boot recovery, production release acceptance and maintenance
remain separate unfinished requirements.
