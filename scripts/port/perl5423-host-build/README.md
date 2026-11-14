# Perl 5.42.3 clean host builds

This finite CLI builds the unchanged `perl5423-source-candidate` **5.42.3-1.2**
recipe in disposable x86_64 Arch containers. It preserves every candidate file,
including the 29 command aliases and POD retention changes. It installs no
package or dependency on the host. Historical r3, repack and signed-lifecycle
results remain separate; these newly compiled archives are not installed by
this route and inherit no earlier installed/ABI acceptance.

```sh
python3 -I -B scripts/port/perl5423-host-build/run.py \
  --source /absolute/path/to/retained/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603.tar.gz \
  --output /absolute/path/to/fresh-private-output --builds 2
python3 -I -B -Werror::ResourceWarning scripts/port/perl5423-host-build/test_host_build.py
python3 -I -B scripts/port/perl5423-host-build/test_actual_archive.py \
  /absolute/path/to/output/build-1/perl-5.42.3-1.2-x86_64.pkg.tar.zst
```

The build CLI requires host Python 3.14's `compression.zstd`; the DATA-only
controls also run under Python 3.12. `inputs.json` fixes the complete candidate namespace, source tarball, both
upstream patches and repository DB hashes. Missing, extra, changed or symlinked
input files fail before contacting Docker. The controller requires the cached
official `archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae`
image and the existing pinned FDK process/cleanup runtime. It copies only verified
inputs into its private snapshot, then mounts that snapshot read-only.

Provisioning alone has host networking, using the already demonstrated Python/Tk
acquisition route. It hashes frozen **2026/11/09 core/extra DBs** before dependency
resolution; official package signatures remain Required. DB authentication is
the pinned SHA256, not a claimed DB signature. `base-devel`, the exact runtime
dependencies, Python and procps-ng are installed only in the disposable image.
The complete installed inventory, frozen DBs, pacman configuration, acquired
archive/signature hashes and tool hashes are retained. Provisioning may run
ordinary package hooks; no host service/bus/device is mounted into it.

Each build starts in a new private work volume at the same `/work/recipe` path
and fixed hostname. Its inspected contract is UID/GID 1000, read-only root,
network-none, init, all capabilities dropped, no-new-privileges, 2 CPUs, 4 GiB
memory with zero swap allowance, and 256 PIDs. The only caller mounts are the
exact read-only input snapshot and its own writable work volume. `/tmp` and
`/run` are bounded noexec tmpfs mounts; executable temporary work stays under
`/work/tmp`. No native Actions dispatch or sealed role is involved.

The unchanged recipe runs ordinary
`makepkg --cleanbuild --nosign --noconfirm --log`, with dependency/integrity checks,
both zero-fuzz patches, Configure/make, the complete upstream test_harness target,
113 provider/five core C-extension checks, package staging and its exact layout
check. There is no dependency waiver, `--ignorearch`, test exclusion, or source
build cache. `SOURCE_DATE_EPOCH=1785628800`, two make jobs and two recipe harness
jobs are explicit inputs. Upstream default skips remain visible in full logs.

Exports include the unsigned archive, all makepkg phase logs and exit status,
`.PKGINFO`/`.BUILDINFO`, complete recipe and built-tree maps, generated config and
Makefile, actual patched regex sources, environment/cgroup/mount observations,
and staged candidate Config/eight-object XS readback. The DATA-only archive
reader reuses the existing bounded single-frame decoder, accepts only ordinary
files/directories/relative aliases and prior regular-file hardlinks, hashes the
whole payload, and verifies runtime/POD/notices, all 29 links, root ownership and
x86_64 ELF headers. It rejects truncation, trailing compressed bytes and unsafe
or changed payload. It extracts or executes no archive payload.

The normal controller automatically retains payload maps and archive/payload
comparisons. A successful pair means two successful clean builds; byte
reproducibility is a separate equality field. Perl's upstream Configure records
wall-clock `cf_time`, so fixed source epoch alone does not promise identical
packages. No recipe/time shim is introduced to force equality.

The existing Runner bounds the controller to 4,800 seconds, provisioning to 900,
commit/export to 120, and each full build to 1,500 seconds. A separate 180-second
cleanup budget, with deferred signals, owns only unique pre-registered names.
Optional partial-log harvesting has a separate 60-second budget so it cannot
consume the deletion/absence budget.
On SIGINT/SIGTERM or failure it stops any unexported actor, preserves available
partial output, then removes its actors, initializer, provisioning container,
volumes and derived image. Missing names are distinguished from errors, and the
final controller also verifies absence. Cleanup/input-recheck failures leave HOLD
and preserve the report; controlled cancellation returns 130 and accepts no build.

`RESULTS.md` and `validation.json` distinguish the actual executed controller
identities from later controller/DATA/cleanup refinements and record exact artifacts,
full-test outcomes, comparisons, controls and real cancellation evidence.
Native ARM/16K, M2, external XS/target ABI, installed behavior of these new
archives, performance, legal/policy and release acceptance remain separate gates.
