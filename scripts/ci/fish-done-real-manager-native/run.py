#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two registered consumers of the unchanged owned574 producer; no shared image mutation."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import closed as C


def command_for(root, image, name, output, phase, token, built=None):
    argv, label = C.held_docker(root, image, name, output)
    argv[0] = '/usr/bin/docker'
    argv += ['--label='+label+'='+token, '--env=CACHY_FISH_DONE_REAL_MANAGER=1',
             '--mount', 'type=bind,src='+str(root)+',dst=/source,readonly']
    if phase == 'build':
        argv += ['--read-only']
    else:
        C.need(phase == 'trial' and built is not None, 'exact separate delivery consumer required')
        # Docker's default filters can reject bwrap's unprivileged userns even
        # after its capabilities are dropped. This policy is per owned consumer.
        argv += ['--security-opt=seccomp=unconfined', '--security-opt=apparmor=unconfined',
                 '--mount', 'type=bind,src='+str(built)+',dst=/built,readonly']
    argv += ['--entrypoint=/usr/bin/python3', image, '-I', '-B',
             '/source/'+C.SLICE+'/container.py', '--phase', phase, '--source', '/source']
    return argv, label


def export_gate(directory):
    rows = json.loads(C.read(directory/'export-map.json'))
    C.need(type(rows) is dict and 1 <= len(rows) <= 768, 'finite consumer export map required')
    actual = {}
    for path in (directory/'export').rglob('*'):
        C.need(not path.is_symlink(), 'consumer export alias refused')
        if path.is_file():
            actual[str(path.relative_to(directory/'export'))] = C.pin(C.read(path))
    C.need(rows == actual, 'whole actual consumer export differs')
    return rows


def execute(root, base, output, proof_path):
    C.need(os.getuid() == os.geteuid() > 0 and platform.machine() == 'aarch64' and
           not any(n.startswith('DOCKER_') for n in os.environ), 'ordinary local native ARM runner required')
    proof = json.loads(C.read(proof_path))
    C.verify(root, proof['manifest_sha256'])
    C.need(not output.exists() and not output.is_relative_to(root) and not output.is_relative_to(base),
           'fresh separate runtime output required')
    producer = json.loads(C.read(base/'report.json'))
    image = C.read(base/'image-id').decode().strip()
    C.need(producer['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and
           producer['image'] == image and re.fullmatch('sha256:[0-9a-f]{64}', image) and
           producer['ownership']['token'] == proof['job_token'], 'exact owned original574 producer required')
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8', HOME=str(base/'home'), TZ='UTC')

    def capture(argv):
        result = subprocess.run(argv, env=env, capture_output=True, timeout=30)
        C.need(result.returncode == 0 and len(result.stdout)+len(result.stderr) <= 1024**2,
               'bounded local daemon observation failed')
        return result.stdout.decode().strip()

    C.need(capture(['/usr/bin/docker', 'context', 'show']) == 'default' and
           json.loads(capture(['/usr/bin/docker', 'context', 'inspect', 'default']))[0]['Endpoints']['docker']['Host'] ==
           'unix:///var/run/docker.sock' and capture(['/usr/bin/docker', 'info', '--format', '{{.Architecture}}']) in
           ('aarch64', 'arm64'), 'local native daemon required')
    actual = json.loads(capture(['/usr/bin/docker', 'image', 'inspect', image]))
    C.need(len(actual) == 1 and actual[0]['Id'] == image and actual[0]['Os'] == 'linux' and
           actual[0]['Architecture'] == 'arm64' and
           actual[0]['Config']['Labels']['org.cachy-asahi.bootstrap574.job'] == proof['job_token'],
           'actual owned native producer image differs')
    wanted = C.read(root/C.DATA/'inventory574.lock')
    C.need(C.read(base/'installed-packages.lock') == wanted, 'actual original574 inventory differs')
    output.mkdir(mode=0o755)
    lease = os.open(output/'consumer.lock', os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC, 0o600)
    fcntl.flock(lease, fcntl.LOCK_EX|fcntl.LOCK_NB)
    owner = dict(schema_version=1, token=proof['consumer_token'], image=image,
                 label=C.held_job(root).C.LABEL, containers=[])
    C.save(output/'owner.json', owner)
    report = dict(status='FAIL', image=image, ownership_token=proof['consumer_token'],
                  base_lock_sha256=C.digest(base/'installed-packages.lock'), phases=[],
                  physical_M2='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
    try:
        for phase, seconds in (('build', 1400), ('trial', 450)):
            directory = output/phase
            directory.mkdir(mode=0o755)
            name = 'cachy-asahi-product-'+('lifecycle-' if phase == 'trial' else '')+os.urandom(16).hex()
            owner['containers'].append(name)
            C.save(output/'owner.json', owner)  # Persist before any possible creation.
            argv, label = command_for(root, image, name, directory, phase, proof['consumer_token'],
                                      output/'build/export' if phase == 'trial' else None)
            C.need(label == owner['label'], 'accepted consumer label drift')
            C.save(directory/'command.json', dict(argv=argv, timeout_seconds=seconds, actual=None,
                policy='HELD_WELCOME_ROOT_POLICY_PLUS_BUILD_READONLY_OR_TRIAL_PRIVATE_USERNS',
                live_desktop='NO_MOUNTS', GPU='NO_DEVICES'))
            with (directory/'stdout').open('xb') as stdout, (directory/'stderr').open('xb') as stderr:
                result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, timeout=seconds)
            C.need(result.returncode == 0, 'native '+phase+' consumer failed')
            row = json.loads(C.read(directory/'report.json'))
            C.need(row['status'] == ('PASS_NATIVE_HEADLESS_BUILD' if phase == 'build' else
                   'PASS_NATIVE_INSTALLED_REAL_MANAGER_12_AND_OLD18') and row['phase'] == phase and
                   row['ordinary_uid'] == 1000 and row['ordinary_absent'] is True,
                   'actual ordinary native '+phase+' report differs')
            files = export_gate(directory)
            report['phases'].append(dict(phase=phase, container=name, report_sha256=C.digest(directory/'report.json'),
                                         export_map_sha256=C.digest(directory/'export-map.json'), files=len(files)))
        report['status'] = 'PASS_NATIVE_BUILD_AND_INSTALLED_REAL_MANAGER_PENDING_RETIREMENT'
    except BaseException as error:
        report.update(error_type=type(error).__name__, error=str(error)[:1024])
    finally:
        C.save(output/'report.json', report)
        os.close(lease)
    C.need(report['status'].startswith('PASS_'), 'native route incomplete; see retained report')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'base', 'output', 'proof'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(execute(*(C.safe(getattr(args, name).absolute()) for name in
                              ('source', 'base', 'output', 'proof'))), indent=2))
