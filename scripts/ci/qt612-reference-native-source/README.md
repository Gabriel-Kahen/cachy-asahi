# Qt 6.12 reference native preparation

This is a **source-only constructor and input/admission contract**. It has no
operational entry: `native_gate()` always refuses. Qt native builds, signatures,
ALPM transactions, native 16K/M2 checks and release acceptance are NOT RUN. It
creates no Root truth, host package mutation, lease, seed, daemon or dispatch.

The independent recipe belongs exclusively to
`packages/port/qt612-source-reference/`. No recipe/provider/source actual tuple
is selected here. Original official Qt binary recipe hash `0bd04f4…2272` remains
HELD; an original project recipe cannot retroactively establish that match.

## Interface required from F

`recipe-API.UNBOUND.json` specifies the required externally whole-pinned handoff.
The constructor refuses that unbound template as an actual recipe selection.
Once F freezes its actual commit, Root can independently select a completed
manifest with the same closed schema:

- Exact recipe commit, upstream commit and fixed recipe path/version.
- Complete file map with whole bytes/SHA256/modes, including `PKGBUILD`, `.SRCINFO`,
  `source.json` and all patch/smoke/license inputs. No extra files/directories.
- Ordinary explicit source aliases and whole pins. Source aliases and SHA256
  must exactly join `.SRCINFO`, including aarch64-specific source lists. No SKIP.
- Exact output names, release/version, aarch64 XZ basenames and dependency classes,
  including aarch64-specific dependencies. Nonzero epoch is not yet supported.
- Real `check()` required in both attempts, XZ package format, an explicit feature
  set and declared maximum writable bytes. No self binary dependency.

A frozen manifest is DATA selected by its external SHA256, not proof that a Git
server has published that commit. This first slice joins file/source pins and
SRCINFO identities; it does not interpret F's not-yet-frozen `source.json` schema
or accept upstream/license provenance. `source_correspondence` remains UNBOUND
pending that schema and Root source review. No package recipe is executed here.

## Retained producer and confinement contracts

`basis.lock.json` pins Main `620b5b28…` llhttp/libgit2 library producer bodies,
normal builder/comparator, signed input lock, baseline inventory and owned-process
helper. It also pins five retained Source85 DATA files. Copies remain opaque
`.DATA` leaves; no actor module is imported. No guard projection is applied.
The exact Source85 read-only guard and owner/kernel/storage/retirement bodies
remain unchanged. Source85's diagnostic declaration retains Root closure review
PENDING, failed actual87 payload, and native pair NOT RUN. It supplies no fix,
confinement acceptance or retroactive success.

The eventual Qt operation must retain normal signed dependencies, source checksum,
generated SRCINFO and real check phases in **two distinct clean ordinary offline
makepkg builds**. The comparator must retain whole archive, payload, PKGINFO and
BUILDINFO equality, plus a future Qt-specific license/ELF/check finisher. That
runtime projection/finisher is explicitly missing from this first slice.

One nonce owner, its initially empty dedicated daemon/socket, observed executable
custody, finite kernel cgroups and storage, complete bounded command output,
natural reaping, original PID/start/PIDFD joins and twice-empty censuses remain
required. Failed-owner retirement can clean an already-failed owned service; it
never converts payload failure into pair success. Cancellation, uncertain cleanup,
nonempty services, wrong mount/device/backing joins and residual storage stay HOLD.
Source85's `ProtectSystem=strict`, fixed read-only paths, sole quota work writes
and refusing `os.access` guard are not relaxed by this preparation.

## Exact input plan and proposed capacity

`signed-input-plan.DATA.json` lists **501 original roles**: rootfs pair, 248 signed
package pairs and 3 public keyring files. All paths are UNBOUND. The frozen
341-package metadata union is checked against the expected 349 vector. Eight
supplemental names/versions need 16 explicit archive/signature pins and provider
refs; no supplemental pin is invented. Required material roles total 517, bound 0.
Current official public trust, a full provider tuple and actual inventory remain
missing. The plan never executes the historical private seed helper.

After a recipe is frozen, dependency rows show baseline name/version candidates
and names needing signed provider resolution. This does not implement pacman
version/provides resolution or accept any dependency. A separate reviewed signed
transaction is required for additions; unsigned installation, --nodeps, --nocheck,
network fallback and broad skips are unavailable.

The library's 8 MiB archive / 24 MiB expanded limits cannot describe the already
retained 301,824,000-byte Qt source tar. The unaccepted proposal permits 512 MiB per
source / 2 GiB total and records future extraction caps 2 GiB / 100000 members. This
constructor streams pinned source files; it does not extract or claim those
future extraction guards are implemented.

`resource-PROPOSAL.json` keeps controller 512 MiB, owner 2 GiB and exact canonical
observed-Docker-only 2 GiB VA (other children 512 MiB). Its separately proposed Qt
ceilings are builder 8 GiB / 4 CPU / PID 512, daemon 12 GiB / 4 CPU / PID 768, 64 GiB quota filesystem,
72 GiB free disk and 18 GiB available RAM; build 5400s / check 900s per attempt, pair 14400s,
controller work 14610s / scope 14790s and cleanup 180s. These are reviewable limits,
**not measurements, approval, proof of sufficiency or proof an existing runner
fits**. F's frozen feature/storage demand and Root capacity review may reject or
replace them. VA allowances do not increase physical cgroup limits implicitly.
No host package-manager command or mutation is permitted.

## Construction and checks

Output must be fresh and disjoint from the framework, Source85 tree and any recipe
checkout. Source files are streamed through bounded ordinary single-link reads;
output creation uses retained directory descriptors. The complete physical Source
namespace, modes, file hashes and all-null actual selectors are then rechecked.

```sh
python3.14 -I -B -Werror scripts/ci/qt612-reference-native-source/prepare.py \
  --framework /absolute/pinned-framework-checkout \
  --diagnostic-basis /absolute/retained-Source85-closed-tree \
  --output /absolute/fresh-preparation-Source
```

For later F binding add `--recipe-selection`, `--recipe-selection-sha256` and
`--recipe-root`. The constructor copies only explicitly pinned source inputs;
no fetch/build/signing occurs. It emits the input plan, Source map, review report
and separate admission/runtime templates (`accepted=false`, all Root fields null).
An external Source-map hash only admits preparation DATA; native entry refuses.

```sh
python3.14 -I -B -Werror scripts/ci/qt612-reference-native-source/test_data.py -v
```

Controls are actor-fenced MODELs and refusal checks, never real Qt provenance,
GPG, kernel custody, build, native acceptance or hardware evidence. The genuine
unbound constructor run is separate retained DATA. Missing bindings remain named.
