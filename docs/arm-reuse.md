# Other-ARM reuse: read-only package inspection

Status on October 11, 2026: **procedure source-audited; x86 reference inspection passed; execution on another native ARM target (physical board or hosted ARM VM) NOT RUN**. The coordinator's read-only SSH inventory attempt against `gabepi` timed out, so its board model, userspace architecture and installed prerequisites are unverified. Do not infer these from its hostname. This document supplies the reuse part of [A10](acceptance.md); upstream submission and response evidence remain a separate requirement.

## Smallest useful demonstration

Run the existing [package inspector](../scripts/checks/package_checks.py) on another native ARM Linux target: an identified physical board or a provider-identified native ARM VM. Both can demonstrate reuse of this software component. A VM run makes no claim about physical Mac or board peripherals. Inspect a real retained original Fish configuration package without installing it. The result exposes package/build metadata, every payload member's hash/mode/owner/link, protected platform paths, hooks and ELF checks. This lets an ARM builder or package reviewer reuse the inspection boundary independently of Asahi desktop integration.

The chosen package was assembled on **x86_64**, declares `arch=any`, and contains no ELF. Inspecting it on ARM demonstrates execution of the inspector there; it supplies no native package build, Fish runtime, dependency-resolution, 16K-page execution, M2 support, performance or installation evidence. The inspector reads tar members into memory and does not extract them onto the filesystem. It does not verify signatures or the contents of `.MTREE`; those remain separate checks.

## Prerequisites and frozen inputs

- An identified native ARM Linux execution environment with aarch64/arm64 userspace, reached through an existing approved access path. For a physical board, record board/model and CPU plus the operator's execution attestation. For a hosted VM, record provider, runner/job identity, VM/image context and the corroborated native execution evidence below. `uname`, an ARM image or a runner label alone does not establish execution or exclude emulation.
- Already installed Python 3.11+ (stdlib only), `zstd`, Bash, and `sha256sum`; ordinary user access and free space for an input bundle and evidence directory. `diff` is optional. **No pacman, makepkg, Docker, libarchive/bsdtar, Fish, root access or package installation is needed for this inspector demonstration.** Missing prerequisites block this procedure; it does not install them.
- Retain the immutable bytes below, their MIT license and the package's assembly record. This source snapshot has not yet been committed by the coordinator; hashes identify the actual reviewed bytes. Add the coordinator's final source commit when available, and re-freeze if any hash changes.

| Bundle file | Source and SHA-256 |
| --- | --- |
| `package_checks.py` | `scripts/checks/package_checks.py`: `e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8` |
| `LICENSE` | Root original-project MIT text: `51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7` |
| `cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst` | `artifacts/reuse/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst`: `05489a9fdbea83423220cc257525dea83a6d3a2ccbab5155dd64a6c68a3678c8` |
| `host-validation.json` | `packages/shells/cachy-asahi-fish-config/host-validation.json`: `b0ce5882f96929057840ab3675cd28c784139812493877dfc3d4a4066045db2a` |

The coordinator retained and rehashed this exact archive under the local ignored `artifacts/reuse/` directory. It is not a published download or a file automatically available in a CI checkout. Preserve it in the transferable input bundle or supply it through a separately reviewed authorized transport. If missing at the destination, report a blocker or select and freeze another real artifact with its own reference result; do not assume rebuilding recreates this archive checksum. Its `.BUILDINFO` binds PKGBUILD SHA-256 `a3f0e5f693a48126086ff0e8279d8d833efb8e625dfa4644fdfd2c04ff0175fa` and records the x86 assembly environment. Included package payload hashes are:

| Payload | SHA-256 |
| --- | --- |
| `usr/share/cachy-asahi/fish/config.fish` | `223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c` |
| `usr/share/licenses/cachy-asahi-fish-config/NOTICE` | `19eb85ed65396056e59782ddf80fb5285ee26cad5ddf77ccb378936a2d5601c9` |
| `usr/share/licenses/cachy-asahi-fish-config/LICENSE` | `51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7` |

## Prepare a transferable bundle

These commands are a runbook, **not an executed transfer**. Run from the coordinator's frozen project checkout. All writes go into a newly created user-owned temporary directory. No sources are fetched, packages installed, services changed or trust distributed. Preserve the printed bundle location and copy the whole directory using the existing approved file-transfer path; destination/transport is deliberately unspecified until an identified board or native ARM VM is available.

```bash
set -eu
task_bundle=$(mktemp -d /tmp/cachy-asahi-arm-reuse-inputs.XXXXXXXX)
cp scripts/checks/package_checks.py LICENSE "$task_bundle/"
cp packages/shells/cachy-asahi-fish-config/host-validation.json "$task_bundle/"
cp artifacts/reuse/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst "$task_bundle/"
cd "$task_bundle"
cat > INPUTS.sha256 <<'HASHES'
e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8  package_checks.py
51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7  LICENSE
05489a9fdbea83423220cc257525dea83a6d3a2ccbab5155dd64a6c68a3678c8  cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst
b0ce5882f96929057840ab3675cd28c784139812493877dfc3d4a4066045db2a  host-validation.json
HASHES
sha256sum -c INPUTS.sha256
printf '%s\n' "$task_bundle"
```

These checksums detect changed bytes against this independently reviewed record. They are not authenticated release signatures, trust-bootstrap material or a substitute for inspecting code before execution. Retain the final committed source reference and this document with the bundle.

## Execute on the native ARM target

After the operator identifies the board or native ARM VM and transfers the frozen inputs, run the following Bash block **on that target**, from inside the transferred bundle. Do not run the build or provisioning runner for this demonstration. The evidence directory is newly created outside the inputs; failures retain diagnostics and prevent the later acceptance assertions from running.

```bash
set -eu
task_evidence=$(mktemp -d /tmp/cachy-asahi-arm-reuse-evidence.XXXXXXXX)
date -u +%FT%TZ > "$task_evidence/started-utc.txt"
uname -a > "$task_evidence/uname.txt"
cat /etc/os-release > "$task_evidence/os-release.txt"
if test -r /proc/device-tree/model; then
    tr -d '\000' < /proc/device-tree/model > "$task_evidence/device-model.txt"
fi
if test -r /proc/cpuinfo; then
    cat /proc/cpuinfo > "$task_evidence/cpuinfo.txt"
fi
python3 -I -c 'import json,os,platform,struct,sys; print(json.dumps({"python":sys.version,"executable":sys.executable,"machine":platform.machine(),"pointer_bits":struct.calcsize("P")*8,"page_size":os.sysconf("SC_PAGE_SIZE")},indent=2))' > "$task_evidence/python-environment.json"
python3 -I -c 'import platform,struct; assert platform.machine() in ("aarch64","arm64") and struct.calcsize("P")==8, "this procedure requires observed 64-bit ARM userspace"'
zstd --version > "$task_evidence/zstd-version.txt" 2>&1
sha256sum "$(command -v python3)" "$(command -v zstd)" > "$task_evidence/tool-binaries.sha256"
sha256sum -c INPUTS.sha256 > "$task_evidence/input-verification.txt" 2>&1
cp INPUTS.sha256 "$task_evidence/"
printf '%s\n' 'python3 -I package_checks.py artifacts ./cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst' > "$task_evidence/command.txt"
if python3 -I package_checks.py artifacts ./cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst > "$task_evidence/report.json" 2> "$task_evidence/stderr.txt"; then
    task_exit=0
else
    task_exit=$?
fi
printf '%s\n' "$task_exit" > "$task_evidence/exit-code.txt"
date -u +%FT%TZ > "$task_evidence/finished-utc.txt"
sha256sum "$task_evidence/report.json" > "$task_evidence/report.sha256"
printf '%s\n' "$task_evidence"
test "$task_exit" -eq 0
python3 -I - "$task_evidence/report.json" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
assert report['errors'] == [] and len(report['artifacts']) == 1
artifact = report['artifacts'][0]
assert artifact['status'] == 'artifact-static-pass' and artifact['errors'] == []
assert artifact['sha256'] == '05489a9fdbea83423220cc257525dea83a6d3a2ccbab5155dd64a6c68a3678c8'
assert len(artifact['members']) == 12 and artifact['elf'] == {}
assert artifact['members']['usr/share/cachy-asahi/fish/config.fish']['sha256'] == '223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c'
assert artifact['metadata']['.PKGINFO']['pkgname'] == ['cachy-asahi-fish-config']
assert artifact['metadata']['.PKGINFO']['pkgver'] == ['0.1.0-1']
assert artifact['metadata']['.PKGINFO']['arch'] == ['any']
assert artifact['metadata']['.PKGINFO']['license'] == ['MIT']
print('Inspection expectations matched; hardware/build/install gates unchanged.')
PY
```

Add a separate operator/reviewer record containing: run IDs, declared execution context (`native-physical-arm` or `native-hosted-arm-vm`), actual board/model/CPU or provider/VM/runner identity, evidence supporting native execution, access method, source commit (or the exact source-hash freeze), input-bundle location/hash, actual command/exit status, environment/evidence paths and hashes, result and limitations. Do not fabricate the missing fields from the proposed `gabepi` target. Preserve failures as FAIL with diagnostics; unreachable target or absent prerequisites are NOT RUN with blocker and next action.

## Native hosted ARM VM alternative (NOT RUN)

A separate native ARM builder is a valid other-ARM target for **component execution**. GitHub currently documents `ubuntu-24.04-arm` as a standard Arm64 Linux VM runner for public repositories; its general-availability announcement describes native ARM execution. This supplies a candidate provider route, not a completed run. The native ARM CI worker owns the workflow and provider/free-route audit; the coordinator owns any push, dispatch or input upload. This documentation task performs none of those actions. [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [native ARM availability](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-generally-available/)

For a reviewed, actually executed `ubuntu-24.04-arm` job:

1. Freeze the source/workflow commit and full action revisions. Retain the four inputs and their hashes from the table above. The local archive is ignored, so a checkout alone cannot provide it. The coordinator must provide a separately reviewed accessible input artifact/transport with the expected SHA-256. No hosted URL, completed upload or successful dispatch is invented here. Missing input or prerequisites leaves execution NOT RUN.
2. Run the same inspection block directly in the ARM VM's shell with preinstalled Python/zstd. Do not use an x86 runner plus QEMU/binfmt, cross execution, a remote x86 Docker daemon or a container whose architecture field is the only evidence. A successful runner probe or package-build job is not automatically an inspector run; retain this component's actual command/log/report.
3. Alongside the generic target evidence, preserve the job's setup log showing its requested runner, actual runner/image/VM identity and execution context. Corroborate with runtime CPU/kernel/interpreter architecture and the reviewed job source showing direct execution. Provider documentation establishes the native VM service; architecture observations and the actual run establish which environment executed these bytes. Record unsupported or uncertain facts honestly; do not name a physical CPU/board based only on a label.
4. Capture the allowlisted CI context below after `task_evidence` is set by the inspection block. Retain the source/workflow commit hash, run URL, job ID/attempt, provider/image versions, input hashes, exact command, stdout/stderr/exit status and report hash in an independently reviewed execution record. Missing direct-run evidence, a failed command, an input mismatch or unverifiable provider context cannot earn native reuse acceptance.
5. Coordinator records `execution_context: native-hosted-arm-vm` only after review confirms actual native execution. Record component reuse separately from native package builds, physical hardware validation and A10's upstream-return requirement. A second independently executed job can document repeatability; no physical board is a prerequisite for this software-only result.

Optional CI context capture, executed **inside the actual job**, after the generic block prints/sets its evidence directory:

```bash
python3 -I - "$task_evidence/hosted-context.json" <<'PY'
import json, os, sys
from pathlib import Path
names = ('GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_WORKFLOW',
         'GITHUB_JOB', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'RUNNER_NAME',
         'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_ENVIRONMENT', 'ImageOS', 'ImageVersion')
record = {name: os.environ.get(name) for name in names}
record['provider'] = 'GitHub Actions'
record['requested_runner'] = 'ubuntu-24.04-arm'
record['native_execution_acceptance'] = 'PENDING independent job/provider review'
if record['GITHUB_SERVER_URL'] and record['GITHUB_REPOSITORY'] and record['GITHUB_RUN_ID']:
    record['run_url'] = (record['GITHUB_SERVER_URL'] + '/' + record['GITHUB_REPOSITORY']
                         + '/actions/runs/' + record['GITHUB_RUN_ID'])
Path(sys.argv[1]).write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
assert os.environ.get('GITHUB_ACTIONS') == 'true', 'capture must come from the actual CI job'
assert record['RUNNER_ARCH'] == 'ARM64', 'unexpected runner architecture; retain diagnostics'
print('CI context captured; native acceptance still requires actual job/provider evidence.')
PY
sha256sum "$task_evidence/hosted-context.json" > "$task_evidence/hosted-context.sha256"
```

This block records a small explicit metadata allowlist; it does not dump the environment or expose credentials. Null values stay unavailable, rather than being filled from the example label. CI logs may expire, so the coordinator must retain the actual setup/command logs and output evidence through a reviewed local export or the CI worker's bounded evidence-retention interface. Hashes/URLs alone without retrievable logs are insufficient. Availability, quota/cost eligibility and the exact image/prerequisites are checked for the actual job; this task makes no reservation or billing change.

## Reference result and independent repeat

The original x86 reference inspection and the follow-up inspection of the retained archive both passed on the **x86_64 development host**, using Python 3.14.7 and zstd 1.5.7. The follow-up command was:

```bash
python3 -I scripts/checks/package_checks.py artifacts artifacts/reuse/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst
```

Observed exit 0, empty stderr, empty error/review lists, `artifact-static-pass`, 12 members and no ELF. Exact stdout SHA-256: `f2691de56f9b4a361a37f125cf7dc0701ac1c2dc7abecb44c3689ef63eba0ce0`. The report records the archive basename, so relocating this frozen archive does not change that field. Compare the ARM report hash against this reference; if serialization differs across supported Python versions, independently compare parsed JSON in full and document the byte difference rather than asserting identical reports. Never replace mismatched inputs or ignore validation errors to obtain a match.

An independent reviewer should verify the frozen inputs, actual native execution provenance and report. A second execution in a new target/job evidence directory is useful for confirming repeatability; retain its own board or provider/job context if performed. Compare complete parsed reports and input hashes, with exact stdout identity reported separately. A copied report or a second directory containing copied outputs is not an independent execution. One evidenced native ARM execution and usable instructions can supply the **component-reuse evidence** of A10; the coordinator records acceptance and links actual results. This does not satisfy A10's upstream-return part, second clean builds under A05 or any exact-M2 gate.

`compare.py` is inappropriate for these inspector runs: it expects successful isolated build records with retained inputs, artifacts, logs, package locks and distinct container IDs. If a later demonstration chooses `build.py --mode native` instead, it additionally requires an already provisioned pinned Linux/arm64 Docker image, a local native ARM Docker daemon (physical ARM or native ARM VM), makepkg/base-devel and complete locked dependencies/trusted keys in that image; follow [build-system.md](build-system.md). Those requirements are not prerequisites for the read-only inspector.

## Current blockers and next action

| Item | Status | Next action |
| --- | --- | --- |
| Frozen inspector and real package | Retained locally; x86 retained-archive inspection PASS | Preserve transferable bundle and add final source commit |
| Physical-board access/identity | NOT RUN; `gabepi` inventory timed out | Restore authorized access or choose the native hosted-VM alternative |
| Native hosted ARM VM | NOT RUN; runner route under CI-worker audit | Coordinator reviews provider/workflow/input transport, then records actual authorized job execution |
| Target prerequisites and first execution | NOT RUN | Inventory already installed tools; run the target block if prerequisites exist |
| Independent review and reuse acceptance | NOT RUN | Assign reviewer, retain actual job/target result; record a repeat separately if performed |
| Actual useful upstream submission/response | NOT RUN in this document | Review the separately prepared upstream draft and record its actual external status when submitted |

No ARM target was contacted by this documentation task. No package was installed, built or published by it, and no system configuration was changed. The local reference inspection is the only new execution evidence here.
