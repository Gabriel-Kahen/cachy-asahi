# Maintenance package native execution context

This standalone development lane builds the frozen `cachy-asahi-maintenance`
0.1.0-2 package twice, compares complete artifacts, and runs its actual installed
CLI through a disposable native ARM ALPM lifecycle. It is unselected and grants
no hardware, security, release or maintenance acceptance.

`prepare.py` copies exactly the frozen package's 20 files (18 recipe sources),
18 hash-bound existing infrastructure files, and this lane. No repository history,
old development packets or existing signed TEST fixture are copied. The release2 package changes fixture copying, declared source-file safety checks,
packaging metadata and the launcher version; all nine private modules remain
byte-exact to the earlier package proposal. Runtime imports resolve only its
nine installed private modules. All mutable data and build outputs live outside
the source context. The original frozen package packet is read-only input.

```sh
python -I -B scripts/ci/maintenance-native/prepare.py \
  --source /absolute/reviewed-infrastructure-root \
  --recipe /absolute/frozen-maintenance-recipe --output /absolute/new-context
```

After coordinator publication of the exact package recipe, add
`--package-source EXACT40HEX` to bind every byte to that published source. The
constructor verifies those Git object bytes; it never commits or publishes.
The default candidate/source/ref/run fields are null. A null candidate source
refuses hosted proof before secrets or actors. Actual source/ref/run are chosen
by the coordinator/hosted dispatch; this context does not invent them.

Both `.github/workflows/native-arm-maintenance-candidate.yml` and the registered
`.github/workflows/native-arm-build.yml` alias are emitted with identical bytes
**before** source pins and the complete manifest are computed. Dispatcher workflow
ID is **381664314**. The workflow pins `job.py`; proof verifies the complete source
manifest, both workflows, the complete secondary pins and source/workflow revision
identity. This avoids a raw workflow/manifest checksum cycle. Only the manifest
excludes its own bytes. The external constructor authorization map includes it.

The actor reuses the existing retained-input secrets and the exact fourteen-file
public seed checkout. It creates the existing owned offline native574 builder
transaction. No new download source, machine image shortcut or dependency skip is
introduced. All four consumer names are persisted with a source/run-derived token
and label before launch: one inventory/dependency probe, two clean build actors,
and one installed lifecycle actor. The pinned existing builder records its actual
architecture, page size, package lock, generated metadata and provenance. All 18
package controls must run in each build. Payload, PKGINFO, BUILDINFO and complete
archive bytes must match between the two distinct clean containers.

The lifecycle actor requires native ARM, UID0/PID1 and its dedicated guard inside
the owned container. It begins with the exact574 inventory. It signs the built
candidate with a newly generated private TEST key at actual system time, verifies
that signature, and uses a temporary pacman config/keyring with required local
signatures. Production trust/config are untouched. It performs install575,
same-version-reinstall575, remove574, reinstall575 and final-remove574. At every
installed phase it verifies the complete 16-file ALPM ownership/bytes/modes/root
ownership map and the nine-module private closure. Removal must leave all owned
files absent and restore the exact574 inventory.

Two distinct ordinary fixture accounts (`alarm` and a container-only UID2201
`maintenance-fixture`) with separate home contexts run the same signed TEST controls from a
working directory unrelated to the source or private runtime. Each creates a
fresh actual-time ed25519 TEST signer and two synthetic signed release generations
using only the installed helper closure. It removes its signing home before
review. Context bootstrap, JSON/text repeated output, missing observations and six
clean refusal cases run through the real executable. All five observation kinds
must replay; native runtime and exact source receipts are recorded. Advisory data
and owner/capacity inputs stay synthetic/null, ARM affectedness stays unknown, and
held plans stay held. The existing frozen expiry helper evaluates the explicit
`--as-of` (chosen from current wall time); signature generation and verification
use actual system time with no override. No expired historical signature is reused.

Ordinary user configuration, a configuration symlink, caller-owned output and
unrelated system pacman/mirror configuration are preserved across transitions.
Previously generated public reports/observations remain unchanged after removal
and reinstall. Fixture signing secrets are never retained. Public fixture files
are individually bounded to 2 MiB, each observation to 16 MiB, and the entire
declared fixture set to 128 MiB. The complete public artifact is capped at 192 MiB
and retained for three days; no HOME dump, signing secret, socket, cache, arbitrary
build output or container layer is uploaded.

Cleanup acquires the consumer lease, verifies each actual container name/ID/image
and ownership label, removes only confirmed owned IDs and verifies absence. It
then invokes existing token-bound producer cleanup. Foreign/unknown daemon state
or an active lease refuses cleanup and cannot earn acceptance. The always-run
retention step requires all four consumer retirements before producer retirement,
both archive identities, all CLI observations and exact public evidence hashes.
Failures retain bounded diagnostics and remain failures.

Local source checks, before any dispatch:

```sh
python -B -m unittest discover -s scripts/ci/maintenance-native -p 'test_*.py'
python -I -B scripts/ci/test_maintained_desktop574.py
```

Hosted pre-producer checks run `test_context.py`; fresh release-fixture controls
need Arch `repo-add`, `bsdtar` and `vercmp` and run inside the owned native574
lifecycle. On this Arch host, the full suite also runs those actual TEST controls.

Host source controls and unprivileged staging do not establish native ARM or ALPM
execution. Native build/lifecycle, 16K runtime and physical M2 remain NOT RUN until
the corresponding actor receipts exist. Root alone publishes and dispatches.


## First native correction

Before the original producer, the workflow checks out the exact full original574
carrier ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad. producer.py runs the unchanged
qualified desktop574 preparation with full immutable Git/blob/filesystem proof,
original lock and existing cache preservation, inside the original2300-second
producer timeout. It then execs the unchanged producer. All package bytes, GPG,
metadata, native, ownership, cleanup and runtime gates remain mandatory. The six
added retained-helper inputs supply only the reachable desktop574 closure; other
preparation modes are not an interface of this maintenance lane. The registered
workflow alias remains byte-identical and part of the complete source manifest.

## makepkg fixture correction

The first retained574 native build passed checksum validation but its check()
setup tried to recursively copy makepkg's live logpipe FIFO. Release2 copies
only the exact20 declared recipe inputs after validation. All18 package controls,
including a live FIFO regression and refusal of unsafe declared inputs, remain
required. No native result is transferred from release1.
