# SPDX-License-Identifier: MIT
"""Prepare the Current606 virtio-input kernel inside the owning ARM CI job."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
from types import ModuleType

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REPO = 'Gabriel-Kahen/cachy-asahi'
INPUTS = {
    'scripts/ci/ksm2-kernel-native/runtime.py': '4d9aa954d95032ab9ea9085ced784efc81a5db42e2f1f3401e679ee861c16090',
    'scripts/ci/tools-generic16k/acquire_kernel.py': '4a372e1f4bfbd1f8604579873fc6fbdec91ac2555bb36f028646017b44b8c23f',
    'scripts/virtual/generic16k/fetch_inputs.py': '212a0a9efc7c386158526ce40683a3646a899a9c7fd2c3140d6e24a02d778043',
    'scripts/virtual/generic16k/inputs.json': 'bdfa44ed1d017c0d0e15c1f3af87bdf4a91923c20e812c861ca522d2cf428492',
}


def load(path, sha):
    import hashlib
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != sha:
        raise ValueError('held recipe source identity differs')
    module = ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(body, str(path), 'exec'), vars(module))
    return module


V = load(HERE/'verify.py', '35c95b1269d522317fb524fecc8194e59c2ddfd2e136177f6fe5ef290b35a6ae')


def preflight():
    pins, _, _, _ = V.source(HERE)
    for name, sha in INPUTS.items():
        V.need(V.pin(V.read(ROOT/name, 128 << 10))['sha256'] == sha, 'held KSM/Current604 acquisition and controller')
    return pins


def identity(env):
    source = env.get('GITHUB_SHA', '')
    run = env.get('GITHUB_RUN_ID', '')
    V.need(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_REPOSITORY') == REPO
           and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and env.get('GITHUB_RUN_ATTEMPT') == '1'
           and re.fullmatch(r'[a-f0-9]{40}', source) and source == env.get('KERNEL_SOURCE_SHA')
           and re.fullmatch(r'[1-9][0-9]{0,19}', run), 'exact first, manually selected owned CI source')
    return {'repository': REPO, 'source': source, 'run': run, 'attempt': 1}


def write(path, body):
    with path.open('xb') as output:
        output.write(body if isinstance(body, bytes) else (json.dumps(body, sort_keys=True, indent=2)+'\n').encode())


def build(work, archive):
    source = identity(os.environ)
    temp = Path(os.environ['RUNNER_TEMP'])
    V.need(os.uname().machine == 'aarch64' and 0 < os.geteuid() == os.getuid(), 'native ordinary AArch64 job only')
    V.need(temp.is_absolute() and temp.resolve() == temp and temp.is_dir() and work != temp and work.is_relative_to(temp)
           and work.parent.is_dir() and work.resolve() == work and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', work.name),
           'fresh owned directory inside RUNNER_TEMP required')
    sources = preflight()
    work.mkdir(mode=0o700)
    stage = 'SOURCE'
    try:
        info = work.stat()
        write(work/'owner.json', dict(source=source, work_inode=info.st_ino, work_device=info.st_dev, work_uid=info.st_uid))
        stage = 'TOOLS'
        H = load(HERE/'build_kernel.py', V.PINS['build_kernel.py'])
        tools = {name: H.identity(path) if (path := shutil.which(name, path='/usr/bin:/bin')) else None for name in H.TOOLS}
        write(work/'tools.json', tools)
        V.need(tools == H.expected_tools(), 'runner tool bytes differ from the exact R5 AArch64 receipts')
        stage = 'ARCHIVE'
        runtime_path, acquire_path, fetch_path, manifest_path = INPUTS
        acquire = load(ROOT/acquire_path, INPUTS[acquire_path])
        fetch = load(ROOT/fetch_path, INPUTS[fetch_path])
        manifest, manifest_sha = fetch.load_manifest(ROOT/manifest_path)
        inputs = work/'inputs'
        inputs.mkdir(mode=0o700)
        acquire.acquire(fetch, manifest['inputs'][0], inputs, manifest_sha, work/'acquisition.json', retained_archive=archive)
        stage = 'BUILD'
        for name in sources:
            write(work/name, V.read(HERE/name, 256 << 10))
        V.source(work)
        runtime = load(ROOT/runtime_path, INPUTS[runtime_path])
        argv = ['/usr/bin/python3', '-I', '-B', str(work/'build_kernel.py'), '--archive', str(inputs/'kernel.tar.gz'),
                '--output', str(work/'built'), '--build', '--boot-diagnostics']
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'TMPDIR': str(work), 'LC_ALL': 'C', 'TZ': 'UTC'}
        controller, stdout, stderr, error = runtime.run_command(argv, work, env, 3700, 16 << 20)
        write(work/'controller.json', controller)
        write(work/'controller.stdout', stdout)
        write(work/'controller.stderr', stderr)
        V.need(error is None and controller['exit_code'] == 0 and controller['group_absence_verified'] is True,
               'owned helper successful exit and process group absence required')
        stage = 'VERIFY'
        profile = V.complete(work/'built')
        write(work/'kernel-profile.json', profile)
        write(work/'result.json', {'status': 'BUILT_ONLY_CURRENT606_KSM_VIRTIO_INPUT', 'source': source,
                                    'profile': profile, 'controller': controller,
                                    'retention': 'OWNED_JOB_OUTPUT_ONLY', 'boot': 'NOT RUN',
                                    'hardware': 'NOT RUN', 'release': 'UNASSESSED'})
    except (Exception, KeyboardInterrupt) as error:
        write(work/'failure.json', {'status': 'HOLD_KERNEL_BUILD', 'stage': stage, 'type': type(error).__name__,
                                    'detail': str(error)[:1024], 'source': source})
        print('HOLD_KERNEL_BUILD_' + stage)
        return 1
    print('BUILT_ONLY_CURRENT606_KSM_VIRTIO_INPUT')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('preflight', 'build'))
    parser.add_argument('--work', type=Path)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    V.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, 'isolated unoptimized Python required')
    V.need((args.mode == 'build' and args.work is not None) or
           (args.mode == 'preflight' and args.work is None and args.archive is None), 'work is required only for build')
    if args.mode == 'preflight':
        preflight()
        print('PASS_KERNEL_SOURCE_ONLY')
        return 0
    os.umask(0o077)

    def stop(signum, frame):
        raise KeyboardInterrupt('owner stopped kernel build')

    signal.signal(signal.SIGTERM, stop)
    return build(args.work, args.archive)


if __name__ == '__main__':
    raise SystemExit(main())
