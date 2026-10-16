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
