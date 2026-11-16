# Fish02 owned hosted domains successor v2

**Code and DATA controls only. No native build, sudo, service, cgroup, mount,
Docker, GPG, network, lease, dispatch, publication or runtime admission has run.**
This is a new capability requiring separate genuine Root review and issuance.
The original 32-file Source/map, all generic bootstrap/build helpers, recipe,
semantic finisher, comparator and historical acceptance remain unchanged.

`prepare.py --base <exact Source32 export> --workflow <new v2 workflow> --output
<fresh directory>` constructs a fresh closed Source containing the complete held
32-file tree under `held-source32/`, this finite owner closure, and only the new
`.github/workflows/native-arm-fish-config02-source-v2.yml` workflow at its root.
Its generated `source-map.json` pins the entire non-Git namespace. Its generated
`owner-program.json` pins all new code/policy/workflow bytes and the exact held
Source32 map. Source32 is 32 files/591897 bytes, map SHA256
`dfd91945cef9a3d3c7ffc73ac06252d6f54514f880071b2951b4e698fc5d6909`.
Actual public commit/ref, job/run, images, receipt hashes and grants remain NULL.

The workflow retains five inputs: external successor `source_map_sha256`, exact
`admission_sha256`/`admission_json` and `runtime_sha256`/`runtime_json`. Each JSON
has its independent whole-body 16KiB bound; the three digest inputs are small.
Use the existing Root once operator's custody, Main CAS, two complete repository
EMPTY sweeps, exact no-prior-run guard, single POST/no-retry, bounded natural
retirement and CLOSE_ONLY release. Rebind its fixed case, endpoint and five-input
schema after actual workflow registration and whole public readback. The old
LLVM/XS operator is not directly compatible with these new Fish inputs.

Runtime/admission templates retain their old unissued kind and old exact pair
resource object for the delegated entry. In the **new runtime**,
`external_supervision` must equal the whole `{bytes,sha256}` pin of generated
`owner-program.json`; `bootstrap_resource_domain` must equal the whole pin of
`policy.json`. The new wrapper actually loads and validates both documents.
Root's predispatch acceptance of those program/resource pins delegates future
measurement/enforcement; it does not attest a runner that has not started.
Root must review the new policy separately. No unknown future runtime hash is
required to issue these documents, so there is no circular admission dependency.

The proposed additional policy enforces three distinct kernel domains:

- Controller scope: 512MiB, 1CPU, 64 tasks, swap0, 256MiB Python AS, 1290s runtime.
- Ordinary Python owner and all acquisition/command descendants: 2GiB, 1CPU,
  256 tasks, swap0, 2GiB AS. NoNewPrivileges; writable host paths are confined to
  its work directory in the finite filesystem. Temporary files use that path.
- Dedicated root host dockerd service plus all its legacy build/ordinary builder
  containers: 6GiB, 4CPU, 768 tasks, swap0. `DelegateSubgroup=daemon` separates
  daemon processes from its delegated `containers` subtree. Explicit cgroupfs
  parent places every managed container below this finite parent. No global
  Docker service/socket/network/config/cache is stopped, changed or pruned.

A physically allocated 12GiB loop-backed ext4 filesystem contains all work,
cache/context, daemon data/exec/tmp/socket, and service logs. The wrapper requires
14GiB free before allocation and 10GiB MemAvailable: 2GiB owner + 6GiB daemon +
2GiB host reserve (including the 512MiB controller domain). These are fresh
admission observations plus kernel/storage bounds; they do not reserve host RAM.
Missing tools, unified cpu/memory/pids controllers, systemd254+ delegation,
namespace/mount support, finite limits, storage or ordinary runner IDs refuse.
No software installation, weaker profile or budget fallback is attempted.

The Docker backend is explicitly **legacy builder only**, via
`DOCKER_BUILDKIT=0`, with no fallback if that supported backend is unavailable.
This avoids a separately moving BuildKit worker escaping an inferred domain.
It is an additional reviewed execution-policy choice, not an assertion that the
old shared BuildKit daemon was bounded. The scratch Dockerfile, signed349 audit,
bootstrap transaction, architecture/inventory checks and ordinary two-build
semantics remain unchanged. Docker root/data/exec/socket/cgroup parent are all
fresh and exclusively owned. Host daemon writable paths are restricted to its
quota filesystem and owned cgroup subtree; host /tmp and /var/tmp are read-only.

The root controller records actual native context, kernel limit-file contents,
PID/starttime/PIDFD custody, cgroup paths, dedicated engine/storage identity and
socket owner/mode **after** the job/services start. Only then does it release a
marker to the ordinary payload. That payload independently checks its actual
PID/start/cgroup/limit files, the daemon's PID/start/cgroup/limits and socket,
Source/ref/run/job/attempt and exact program/resource pins before importing the
held entry or seeding secrets. Controller and payload live in separate bounded
process domains; the inherited threaded acquisition is inside the owner domain.

Two explicit adapters are reversible: one original entry line gains dedicated
Docker endpoint, TMPDIR and legacy-backend environment propagation; undoing this
single insertion restores every original entry byte. Its Source verifier is
explicitly delegated to recheck the whole outer successor namespace and the
unchanged held32 subtree before applying the original verifier to that subtree.
All generic builder/bootstrap/audit/comparator/finisher bodies are byte exact.
The existing Fish-only predetermined-name/nonce/swap4GiB projection is retained.
No native16K/M2, target lifecycle, project-package signature or release claim follows.

The controller's 1200-second deadline includes setup/acquisition/builds; cleanup
is bounded by90 seconds. Its external scope has a 1290-second kernel wall cap.
The old inner pair/build limits are not increased. The entire old pair must
succeed naturally, produce both real semantic check markers and strict archive/
payload/PKGINFO/BUILDINFO equality, and retire its ordinary containers/images.
The controller then requires no remaining owned-daemon containers, stops only
its exact nonce services, checks original PIDFD exit and cgroup emptiness twice,
and unmounts/detaches only its verified own loop backing file. Forced/uncertain
service retirement, cleanup failure or incomplete retention keeps HOLD. First
primary failure is preserved. The later retention step checks controller-scope
emptiness twice after the controller exits.

Only selected bounded owner/command/domain receipts and complete original public
pair evidence enter the existing free log encoder (unchanged 16MiB raw/8MiB gzip
bounds). Mounted daemon storage, cache, keyring homes, launch/config secrets and
loop image are excluded without traversing those trees. If safe cleanup cannot
finish, uncertain root-owned storage is retained privately for runner teardown;
it is not relabeled as cleaned. Root independently authenticates actual retained
receipts and the original pair before qualification.

Run `python3 -I -B scripts/ci/fish-config02-native-source/successor_v2/test_data.py`.
These fenced tests perform pure plan/JSON/inverse/namespace controls and tiny
local DATA copies only. Operational acceptance remains NOT RUN.
