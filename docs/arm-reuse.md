# Other-ARM reuse: read-only package inspection

Status on October 11, 2026 local (October 12 UTC): **recipe/package inspection, native build/provenance capture and byte comparison EXECUTED on a separate hosted ARM VM in run 38189520114**. The original standalone CLI inspection of the old x86 Fish archive and physical-board execution remain NOT RUN. A10 upstream submission remains NOT RUN; full A10 is incomplete. The coordinator's read-only SSH inventory attempt against `gabepi` timed out, so its board model, userspace architecture and installed prerequisites are unverified. Do not infer these from its hostname. This document supplies the reuse part of [A10](acceptance.md); upstream submission and response evidence remain a separate requirement.

## Actual component reuse: native ARM CI run 38189520114

[The successful GitHub job](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38189520114) executed source commit `ebd5812640b0b69f5c09a47752b739e37e338754` on the standard `ubuntu-24.04-arm` hosted **native ARM VM**, separate from the intended Mac targets. Build execution was October 11, 2026, approximately 20:52–20:53 America/New_York; original UTC timestamps are retained in provenance. The coordinator dispatched the job and retained its logs/bundle. This documentation task checked the retained evidence; it did not dispatch or rerun the native job.

This is a useful executed alternative to the earlier proposed standalone inspector demonstration: the same portable recipe/artifact-inspection API, isolated build/provenance runner and build comparison component ran on another ARM target. **No standalone `package_checks.py artifacts` CLI command on the old x86 `.pkg.tar.zst` archive is claimed.** The executed inputs were the four reviewed original recipes and their newly produced native `.pkg.tar.xz` artifacts. In `build.py`, `recipe()` and `package()` are imported from `package_checks.py` and called on the ARM VM host; each resulting artifact inspection is retained in `validation.json`. `compare.py` also reinspects both actual outputs, verifies retained provenance/input hashes and requires byte equality.

### Executed environment and source

`runner.json` records Linux/aarch64, four observed Neoverse-N2 CPUs, Python 3.12.3, image `ubuntu24-arm64` version `20261004.142.1`, kernel `6.17.0-1022-azure`, UID/GID 1001 and local Docker UNIX socket `/var/run/docker.sock`, with aarch64 daemon. The containers record aarch64 and **4096-byte pages**, makepkg/pacman 7.1.0 and the frozen package inventory. No QEMU/binfmt setup was used. This is provider/job/runtime provenance; it does not attest physical Mac peripherals or 16K-page execution. `runner.json`'s `native_build: NOT RUN` is the pre-build probe snapshot; final `result.json` and eight completed build records establish the later execution. Preserve that chronology rather than modifying the original record.

The authenticated generic ALARM userspace image was `sha256:7a3a68aef1b1cbb2aa8ae81e05b08fd1e9c948c222053ae4957f57554fe4d4f0`. Input lock SHA-256 `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41`, corrected recipe lock `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`, actual 341-package lock `7f40e51da419514c3ffe4fc9ed5bd9d6f242e576a585347c4799cd20bfd32104`. Its bootstrap was confined to a disposable builder, with required signatures, scriptlets disabled and hooks masked; it is not an Asahi base installation or target transaction. Full trust/input details belong to [the CI contract](native-arm-ci.md) and [native execution record](validation/native-arm.md).

Component bytes were independently fetched from that immutable source commit and hashed during this documentation review:

| Component at executed commit | SHA-256 |
| --- | --- |
| [CI driver](https://github.com/Gabriel-Kahen/cachy-asahi/blob/ebd5812640b0b69f5c09a47752b739e37e338754/scripts/ci/native_arm.py) | `1a48dfe768fa40595d84648750b1ada3c2a0c56fb2f00fa961e0e6d8fa6034ef` |
| [Build/provenance runner](https://github.com/Gabriel-Kahen/cachy-asahi/blob/ebd5812640b0b69f5c09a47752b739e37e338754/scripts/build/build.py) | `e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45` |
| [Build comparison](https://github.com/Gabriel-Kahen/cachy-asahi/blob/ebd5812640b0b69f5c09a47752b739e37e338754/scripts/build/compare.py) | `d75d9177cb741d7ae8e13466aa4b9e96587470b88749735ef2923f9a4446748d` |
| [Recipe/artifact inspector](https://github.com/Gabriel-Kahen/cachy-asahi/blob/ebd5812640b0b69f5c09a47752b739e37e338754/scripts/checks/package_checks.py) | `e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8` |
| [Container entry](https://github.com/Gabriel-Kahen/cachy-asahi/blob/ebd5812640b0b69f5c09a47752b739e37e338754/scripts/build/container-entry.sh) | `89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24` |
| [Executed workflow](https://github.com/Gabriel-Kahen/cachy-asahi/blob/ebd5812640b0b69f5c09a47752b739e37e338754/.github/workflows/native-arm-build.yml) | `258a57b53a8a6cfe9490012daed7093d6940e83c4c37bb960e528249bee5ff5c` |

### Actual commands and inspection boundary

The workflow called `python3 scripts/ci/native_arm.py build` with the two reviewed lock digests above, cache `$RUNNER_TEMP/alarm-cache` and output `$RUNNER_TEMP/native-evidence`. The pinned driver calls `build.py` twice per recipe with `--mode native`, immutable image, `--source-date-epoch 1791748800`, recorded `packages.lock`, recipe-review JSON and `--timeout 300`; then calls `compare.py FIRST SECOND --require-bytes`. These high-level argument descriptions come from the executed pinned workflow/driver. The driver does not separately log its resolved `sys.executable` string, so no invented absolute Python executable is presented as a verbatim record.

For Fish attempt 1, the **actual captured Docker argv** from `provenance.json` is shown below, formatted with shell quoting. This is a historical record of the disposable runner paths, not a command to execute on the development host:

```text
docker run --rm --name cachy-asahi-4fb9be43014e1a8f --pull=never --platform linux/arm64 --user 1001:1001 --cap-drop=ALL --security-opt=no-new-privileges --read-only --pids-limit 512 --memory 4g --cpus 4 --network none --tmpfs /tmp:rw,nosuid,nodev,exec,size=4g --env CACHY_ASAHI_CONTAINER=1 --env SOURCE_DATE_EPOCH=1791748800 --mount type=bind,src=/home/runner/work/_temp/native-evidence/cachy-asahi-fish-config-1/inputs,dst=/inputs,readonly --mount type=bind,src=/home/runner/work/_temp/native-evidence/cachy-asahi-fish-config-1/artifacts,dst=/out --mount type=bind,src=/home/runner/work/cachy-asahi/cachy-asahi/scripts/build/container-entry.sh,dst=/builder-entry.sh,readonly --mount type=bind,src=/home/runner/work/_temp/native-evidence/cachy-asahi-fish-config-1/expected-packages.lock,dst=/expected-packages.lock,readonly --entrypoint /bin/bash sha256:7a3a68aef1b1cbb2aa8ae81e05b08fd1e9c948c222053ae4957f57554fe4d4f0 /builder-entry.sh
```

The container entry executed `makepkg --printsrcinfo`, `makepkg --verifysource --noconfirm`, and `makepkg --cleanbuild --clean --force --log --noconfirm` in its `/tmp/work` working directory, after checking native architecture/non-root identity and the exact package lock. The Fish build log records source checksum PASS, `check()` and `package()` execution and package creation. After that container exited, the ARM-host build runner performed its imported static recipe/artifact checks and wrote `validation.json`; it did not invoke a fabricated standalone inspector CLI. Build attempt 1/2 used distinct clean container IDs `cachy-asahi-4fb9be43014e1a8f` / `cachy-asahi-b987af2d88e44b7e`. All other packages likewise used distinct IDs. Both environments per package used the same immutable image and hosted VM; independent physical builder execution is not claimed.

### Native artifacts and reports actually retained

Every row below has two `built-package-static-pass` native records with exit 0, empty validation errors, and comparison flags `installed_contents_equal`, `pkginfo_equal`, `buildinfo_equal`, `bytes_equal` all true. These packages declare `arch=any` and contain no ELF; native execution is evidenced by the actual builder/provenance, not that declaration.

| Native archive (both attempts identical) | SHA-256 | Recipe PKGBUILD SHA-256 |
| --- | --- | --- |
| `cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz` | `6acf6de12396a0f9a6f37a192ea451eb42f7da1ad4d22b80ac84083a232fce79` | `4c55f488c5b886a88a277c058afde5266e4cefd3e348847f89801aef8d841bcc` |
| `cachy-asahi-setup-0.1.0-2-any.pkg.tar.xz` | `c2b51a0d1c7be0af726f2e03a877d87cef5f9b01188def2ae6c6a2f7512a4b26` | `1d4326ccfa5b0a68b4eb82351c29a99ca2c0ad8af7503e84aa01bcd3dd1cbe68` |
| `cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz` | `d2b18a1639c1062a56e5a796c27a4e7767edf1677eab745a8df72c45e6e3e9ce` | `a3f0e5f693a48126086ff0e8279d8d833efb8e625dfa4644fdfd2c04ff0175fa` |
| `cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz` | `4362eb85db3798b88addda4d6f4cc0fa94572dc4449b36aff37be521f230e9dc` | `a0d86c532654f01edac764ad39d1173bb981a13752ad0216ea49907cd49b53e1` |

Local raw evidence root: `artifacts/ci/38189520114/decoded/native-evidence/`. The decoded bundle and job logs are retained locally; these paths are not assumed publicly downloadable. The native-evidence archive SHA-256 is `8797f4f8b52d0f2a84dbbce3589f331b1a913f1fad413877bb1a861775f287e3`. Important raw record hashes:

| Record under evidence root | SHA-256 |
| --- | --- |
| `runner.json` | `d954427e1436b0a76909d2733c6168ccbc3cdc04ebf429e4fc0c11bc5b999eed` |
| `result.json` | `c3f6571e36159aff2595e63fc7b7d6d84121c92ad3ec00c4697aeec5209c9703` |
| `cachy-asahi-fish-config-1/provenance.json` | `5663b5043703423145ef7a30bca628680a3d8dc4ca698069d411769158400798` |
| `cachy-asahi-fish-config-2/provenance.json` | `3a1f885fa0e7c02aaa80ddb8bd3a4752feea48e7188856da172a661b7f015105` |
| `cachy-asahi-fish-config-1/validation.json` (same for attempt 2) | `9ab6a82aef06d38111db029ee0dd5bf22cf3cd6f4d2bfe8db99cef0f683f115f` |
| `cachy-asahi-fish-config-compare.json` | `b525b54dbffdfe7dd37a84d11bb3028719b1eb7f74803bc12dd18a8e501e60b7` |

The Fish native report contains 12 members and no ELF; its provenance binds the native archive, reviewed recipe inputs, `.BUILDINFO`, package lock, generated metadata, environment/configuration and build log. This documentation review independently rehashed **every retained file/input/artifact recorded by all eight build records**, matched the input maps to the immutable four-recipe lock, confirmed distinct container IDs/equal actual artifact hashes and checked all four comparison outputs. A bounded read-only peer review independently checked 230 recorded file/input/artifact hashes, all eight results, recipe-lock bindings, four comparisons, the captured Docker argv and local-date conversion. It corrected the documented container working directory and stale uncommitted-source wording. This does not replace the coordinator's broader independent source/trust/release review, which was underway when this record was written.

**A10 scope:** the component-execution portion now has concrete native-other-ARM evidence and usable source/contracts: original recipes were inspected, built and compared on a non-Mac ARM VM. The coordinator can record that narrow reuse subrequirement from this executed route after its review. Full A10 remains incomplete because useful upstream submission remains unexecuted. The old standalone inspection of the retained x86 Fish archive, physical-board execution, M2/16K-page behavior, target installation/removal, performance and stable-release acceptance are separate and are not earned by this job. Continued availability of retained source/input/artifact/log bytes remains an operator responsibility.

## Earlier standalone inspector runbook (NOT RUN on ARM)

The following procedure remains useful for a small standalone reuse exercise. Its old x86 Fish `.pkg.tar.zst` input is distinct from the successful job's newly built native `.pkg.tar.xz` artifacts. The successful job above supplies the actual executed reuse alternative; none of the commands below is retroactively reported as executed on ARM.

## Smallest useful demonstration

Run the existing [package inspector](../scripts/checks/package_checks.py) on another native ARM Linux target: an identified physical board or a provider-identified native ARM VM. Both can demonstrate reuse of this software component. A VM run makes no claim about physical Mac or board peripherals. Inspect a real retained original Fish configuration package without installing it. The result exposes package/build metadata, every payload member's hash/mode/owner/link, protected platform paths, hooks and ELF checks. This lets an ARM builder or package reviewer reuse the inspection boundary independently of Asahi desktop integration.

The chosen package was assembled on **x86_64**, declares `arch=any`, and contains no ELF. Inspecting it on ARM demonstrates execution of the inspector there; it supplies no native package build, Fish runtime, dependency-resolution, 16K-page execution, M2 support, performance or installation evidence. The inspector reads tar members into memory and does not extract them onto the filesystem. It does not verify signatures or the contents of `.MTREE`; those remain separate checks.

## Prerequisites and frozen inputs

- An identified native ARM Linux execution environment with aarch64/arm64 userspace, reached through an existing approved access path. For a physical board, record board/model and CPU plus the operator's execution attestation. For a hosted VM, record provider, runner/job identity, VM/image context and the corroborated native execution evidence below. `uname`, an ARM image or a runner label alone does not establish execution or exclude emulation.
- Already installed Python 3.11+ (stdlib only), `zstd`, Bash, and `sha256sum`; ordinary user access and free space for an input bundle and evidence directory. `diff` is optional. **No pacman, makepkg, Docker, libarchive/bsdtar, Fish, root access or package installation is needed for this inspector demonstration.** Missing prerequisites block this procedure; it does not install them.
- Retain the immutable bytes below, their MIT license and the package's assembly record. These inspector, LICENSE and assembly-record bytes are present at source commit `ebd5812640b0b69f5c09a47752b739e37e338754`; their listed hashes identify the reviewed inputs. The archive is retained separately as ignored local storage. Preserve that committed source reference and re-freeze if any input hash changes.

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

## Native hosted ARM VM alternative for standalone inspection (NOT RUN)

A separate native ARM builder is a valid other-ARM target for **component execution**. GitHub currently documents `ubuntu-24.04-arm` as a standard Arm64 Linux VM runner for public repositories; its general-availability announcement describes native ARM execution. This was the candidate provider route for the standalone inspection proposal; the separate native build/inspection/compare route above has now actually executed. Standalone execution of the old archive is still NOT RUN. The native ARM CI worker owns the workflow and provider/free-route audit; the coordinator owns any push, dispatch or input upload. This documentation task performs none of those actions. [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [native ARM availability](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-generally-available/)

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
| Frozen inspector and real package | Retained locally; source commit recorded; x86 inspection PASS | Preserve transferable bundle and committed source reference |
| Physical-board access/identity | NOT RUN; `gabepi` inventory timed out | Restore authorized access or choose the native hosted-VM alternative |
| Hosted VM build/inspection/compare reuse | EXECUTED in run 38189520114 | Coordinator and independent reviewer accepted source/provenance/artifact/comparison evidence; target/release gates unchanged |
| Standalone old-archive inspector CLI on ARM | NOT RUN | Optional additional demonstration; cannot be inferred from the native build route |
| Physical/standalone target execution | NOT RUN | Inventory tools and run the standalone block only if this additional exercise is chosen |
| Component reuse acceptance | PASS for hosted ARM build/inspection/compare components; independent review accepted | Retained records and final review in docs/validation/native-arm.md and docs/reviews/native-execution-review.md |
| Actual useful upstream submission/response | NOT RUN in this document | Review the separately prepared upstream draft and record its actual external status when submitted |

This documentation task did not contact an ARM target, dispatch CI, install/build/publish packages or change system configuration. The coordinator's actual hosted-ARM CI execution is now recorded above; this task newly checked its retained evidence. The earlier x86 reference and standalone proposal remain explicitly distinguished.

Coordinator signoff after worker handoff: independent final native review and
coordinator archive/evidence comparison accepted the executed build/inspection/compare
components on the identified hosted ARM VM. This supplies A10's component-reuse
portion. A10 overall remains incomplete because upstream submission is not executed;
the old-archive standalone proposal and both physical M2 records remain untested.
