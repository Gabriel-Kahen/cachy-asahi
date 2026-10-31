# Offline maintenance tool candidates

These three original MIT0.1.0-1 candidates package existing project code into
separate private runtime trees. All remain unselected development candidates.
They add no service, hook, boot configuration or shared Python-file ownership.
Asahi's platform stack is unchanged. Their versioned source exporters and finite
profiles preserve the original source closure; transported code is DATA until a
separate reviewed build is authorized.

| Candidate | Commands | Runtime prerequisites |
| --- | --- | --- |
| `cachy-asahi-platform-tools` | `plan`, `check`, `sources`, `prepare` | Python>=3.12, pacman/libALPM, gnupg, glibc; original libalpm16.0.1 gate remains |
| `cachy-asahi-source-tools` | `mirror-export`, `mirror-successor`, `mirror-verify`, `build-context`, `verify-context` | Python>=3.14, xz, zstd |
| `cachy-asahi-image-tools` | `plan`, `assemble`, `verify`, `resume` | Python>=3.14, libarchive, e2fsprogs, gnupg, glibc |

Platform preparation does not commit, download, execute hooks or read a host
package database. Keep its owned0700 report parent short enough for GPG Unix
sockets. Source tools do not download, execute retained recipes or start a
builder; held builder selectors remainNULL. Image tools admit only the existing
policy-signed recipe kind and preserve signature/time/revocation, input/tool and
source pins. Resume verifies completed output; it cannot continue a partial image.
These commands preserve FAIL, INCOMPLETE, UNKNOWN and NOT RUN distinctions.

## Retained actual host evidence

All real package builds used ordinary-user x86_64 Arch/Python3.14.7 and existing
host dependencies, rather than a clean ARM dependency-resolved environment.

| Candidate | Actual package archive SHA256 | Retained result |
| --- | --- | --- |
| Platform | `cb9252a4f078a530f0e3b64d4df747d7b125d64d996f360dffcee51c7eb78716` | 23-file payload;25 planner+15 private-ALPM+9 package+13 exporter controls; moved-prefix help/plan/check also on3.12.13; synthetic signatures refused before ALPM |
| Source | `2a0584f8c10abc5ea30871c9d3c1442f1d7087e9be7153ec378a94416aa79f33` | 17-file payload;24+11+19 original controls,14 exporter and17 moved-prefix CLI controls; real source transport/offline rebuild; same-host payload/PKGINFO match, archive reproducibility not established |
| Image | `2dd05d31a81aab29337632d37c80ae8f90ac461c6835096fbcd0f3b47e3e9e63` | 66-file payload;29+4+35 original and13 package+15 exporter controls; actual extracted/moved prefix10 synthetic TEST-signature image controls;16MiB ext4/readback/fsck0 |

Archive payload modes/root ownership and exact project sources were independently
checked as DATA for integration. File-removal inverses preserve caller data;
these are not ALPM installation/removal results. The image functional harness's
checkout denial covers Python file access, not namespace isolation. Its synthetic
TEST signing does not establish production signing authority. The complete real
signed platform-transition journey remains NOT RUN.

## CI and remaining evidence

The source-tools workflow is an exact manual-only proposal for a provisioned
ordinary-user Arch runner labelled `source-tools-host`, with base-devel,
Python>=3.14, xz/zstd and working bubblewrap namespaces. Workflow execution and
runner availability remain NOT RUN/UNKNOWN. The label is a required runner
contract, not evidence that such a runner exists. The image-tools CI guide is a
separate scoped proposal; no new native lane is included in this layer.

Inert exporter tests use their own fixture roots. The image installed-functional
harness runs only through its explicit CLI; generic unittest import does not
launch its filesystem/GPG actors. Integration checks were source syntax, exact
pins, manifest reconciliation and workflow syntax only. Host build, GPG,
namespace, VM and native actors were not repeated. Ubuntu namespace policy or
architecture is not inferred from retained Arch results, and no isolation,
privilege or host-policy fallback is added.

Clean native ARM pairs, signed disposable ALPM lifecycles and native16K work are
separately owned and not established here. Installed Asahi composition, both
physical M2 Air sizes, boot/recovery, production trust, measured performance and
release admission remain NOT RUN/unaccepted. Dependency metadata/license notices
are retained; complete corresponding-source redistribution approval is not asserted.
