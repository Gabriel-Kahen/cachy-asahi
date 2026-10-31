# Owned GNU libc successor harness

Status: implementation proposal with inert controls. The complete GNU source
archive is missing. No native libc build, upstream suite, ABI observation or
candidate execution has occurred. This is a separately named successor; the old
binary's recipe correspondence remains unresolved.

The candidate is `cachy-asahi-glibc-rebuild` version
`2.43.r22.g8362e8ce10b2.caa1-1`, architecture `aarch64`. It has no `provides`,
`replaces`, conflicts, install scriptlet, hooks or selection change. Its runtime
payload is confined to
`/opt/cachy-asahi/glibc-rebuild/2.43-r22-g8362e8ce10b2-caa1`; notices use
`/usr/share/licenses/cachy-asahi-glibc-rebuild`. The harness never installs it.
Removal of this proposed package would remove its owned payload and notices;
there are no cache, locale-gen, service or global library changes to undo.
Installation/removal lifecycle remains NOT RUN and requires a separately owned
future lane before admission.

## Sources and recipe

`packages/core/cachy-asahi-glibc-rebuild/source-lock.json` records the exact GNU
commit `8362e8ce10b24068bacc19552c128dd10e082fd9` and Git tree
`912828afc79878e39e0e771d461f11080c25b715`, retained primary records, six ordered
ALARM packaging patches and all twelve retained input hashes/licenses.
`PKGBUILD.in` is an inert template, not an executable completed source package.
There is no `SKIP` checksum. Its two tokens are replaced only after a complete
source archive passes bounded Git blob/tree hashing, including executable modes
and symlink contents. A public mirror may transport data, but must reproduce the
primary GNU tree exactly. A tar export that omits tracked files cannot pass.
The GNU epoch is `1776591129` (2026-04-19 09:32:09 UTC).

The recipe uses ordinary `-O2 -g`, no CPU tuning, LTO or PGO. Systemtap and nscd
are disabled. Optional GD-dependent memusagestat is unavailable in the accepted
bootstrap. The six pinned patches retain their applicable upstream regression
tests. No tests are deleted. The build also creates candidate C.utf8 locale data
and requires ISO8859-1 gconv. Configure, patch application, locale generation and
installation semantics await the exact full source and native execution.

Dependencies: baseline `glibc`, `filesystem`, `tzdata`; build tools `gcc`,
`binutils`, `make`, `bison`, `gawk`, `python`, `perl`, `texinfo`, `patch`,
`linux-api-headers`, plus makepkg/fakeroot/xz provided by the accepted bootstrap.
No dependencies are installed or fetched by the offline harness. All inputs
must be present in the exact accepted 574-package image; missing tools fail.
GNU source notices are retained in full; packaging patches are GPL-2.0-or-later,
ALARM packaging metadata is 0BSD, and this harness/recipe implementation is MIT.
The GNU package's mixed source notices are authoritative, rather than a claim
that every source file uses one license.

## Data-only preparation

Use absolute simple paths, without whitespace, commas, colons or symlink parents.
In the proposal, substitute the full path to its `proposed` directory below;
after canonical adoption, substitute the repository root.

```sh
python3 /ABS/proposed/scripts/ci/glibc-owned-rebuild/materialize.py \
  --recipe /ABS/proposed/packages/core/cachy-asahi-glibc-rebuild \
  --upstream-archive /ABS/exact-full-glibc-source.tar.gz \
  --output /ABS/fresh-offline-glibc-source
```

Omitting `--upstream-archive` refuses with `MISSING_PREREQUISITE` and creates no
output. The materializer neither sources PKGBUILD nor launches a toolchain.
Review the resulting bundle and retain its `bundle.json` SHA256. The runner
recomputes the entire GNU Git tree independently of the receipt before actors.
Bounded inputs: 96 MiB compressed, 512 MiB payload, 60,000 members, 64 MiB per
file, 180 seconds, plus a bound on decoded tar headers/PAX bytes.

## Explicit native lane (not run here)

Prerequisites: ordinary unprivileged native Linux/aarch64 coordinator, local
Docker default context at `unix:///var/run/docker.sock`, at least 40 GiB measured
free space, and the accepted owned574 `base-dir` retaining its PASS report,
immutable arm64 image ID, ownership token and installed-packages.lock SHA256
`cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`.
The immutable image is borrowed; it is never committed, removed or modified.

```sh
python3 /ABS/proposed/scripts/ci/glibc-owned-rebuild/run.py \
  --bundle /ABS/fresh-offline-glibc-source \
  --bundle-manifest-sha256 REVIEWED_BUNDLE_MANIFEST_SHA256 \
  --harness-manifest-sha256 REVIEWED_HARNESS_MANIFEST_SHA256 \
  --base-dir /ABS/accepted-owned574-output \
  --source-root /ABS/cachy-asahi \
  --smoke-dir /ABS/cachy-asahi/scripts/ci/glibc-owned-runtime \
  --smoke-manifest /ABS/cachy-asahi/scripts/ci/glibc-owned-runtime/source-manifest.json \
  --output /ABS/fresh-glibc-native-pair
```

Without `--execute`, this only validates inputs. The caller must deliberately add
`--execute` for native work. No actor command has been run for this proposal.
The adopted runtime smoke is consumed unchanged, pinned to manifest SHA256
`e10336aef200731c7dd4b06546b718e095c1ecf7718e4a25fa57d6bbed6270a6`.
The process ownership runtime is pinned to SHA256
`8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821`.
Only a private imported resource facade changes its exact 128-descriptor request
to 8192. Shared runtime and smoke sources are never edited.

The owner freezes reviewed sources into a private output directory. Containers
have token labels, no network, a read-only root, no capabilities, no new
privileges, an ordinary numeric UID/GID, four CPUs, 12 GiB memory, 1024 PIDs and
8192 descriptors. Only their own `/work` and bounded `/tmp` are writable. The
read-only account overlay supplies getpwuid/getgrgid data without changing the
base image. A separate bounded root probe only reads account/package records.

Two fresh native builds use identical `/work` paths and fixed epoch. Each runs
`makepkg --verifysource`, ordinary compilation, `make -k -j4 check` and upstream
`check-abi`. Actual exit codes and named `.test-result` statuses are retained;
FAIL, XPASS, ERROR, malformed results or nonzero make exit fail the lane.
Upstream UNSUPPORTED and XFAIL remain visible by name/diagnostic. Their presence
is never called proof that the unsupported functionality works.

A separate fresh container per side checks archive paths/identity and binds
`.BUILDINFO` to the concrete PKGBUILD SHA256 before extraction. It compares
baseline public symbols for the loader and ten libc DSOs, preserving symbol
version/defaultness, type, binding, visibility and OBJECT/TLS size. This is a
bounded static compatibility check, not complete header/ABI or hardware proof.
Then the canonical smoke compiles with recorded bootstrap headers and executes
through the explicit candidate loader. Its complete native receipt, candidate
hashes, case set and adopted source identities are required. A zero process exit
alone cannot earn runtime credit. Bootstrap package inventories must stay exact.

Success additionally requires byte-identical pair archives and verified absence
of every owned container. Cancellation/error cleanup receives its own 900-second
budget, checks both token label and image ID, and never deletes foreign or
unknown containers. The work budget is 19,800 seconds, each build 8,400 seconds,
each ABI/runtime phase 900 seconds. Logs and bounded JSON receipts remain in the
private output, including failures. A daemon outage or uncatchable coordinator
termination can leave unknown owned state; no success may be claimed in that
case, and Root's external job owner must retire it before future mutation.
The 40 GiB reserve is a preflight measurement, not a disk quota.

## Inert controls

```sh
python3 -B -m unittest discover \
  -s /ABS/proposed/scripts/ci/glibc-owned-rebuild -p test_controls.py -v
bash -n /ABS/proposed/scripts/ci/glibc-owned-rebuild/build-entry.sh
bash -n /ABS/proposed/packages/core/cachy-asahi-glibc-rebuild/PKGBUILD.in
```

Controls use synthetic archives/statuses and a fake Docker/process facade.
They confer no ARM compilation, upstream test, candidate execution, hardware,
performance, installation or admission credit. The proposal's review directory
records actual results and the finite failed source acquisitions.
