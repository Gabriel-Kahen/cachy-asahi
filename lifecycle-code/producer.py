#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Root-only real execution entrypoint; no implicit trust/image/runtime authority."""
import argparse
import importlib.util
import io
import os
from pathlib import Path
import signal
import tarfile
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('perl_installed_common', HERE / 'common.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']


def labels(a, sha):
    return dict(a['base_labels'], **{'cachy-asahi.perl-lifecycle.operation':C.OPERATION,
        'cachy-asahi.perl-lifecycle.admission':sha,'cachy-asahi.perl-lifecycle.source':a['source_map_sha256']})


def image_identity(image, a):
    C.need(image['Id'] == a['image'] and image['Architecture'] == 'arm64' and image['Os'] == 'linux'
           and not image.get('Config',{}).get('Volumes') and not image.get('Config',{}).get('Healthcheck')
           and (image.get('Config',{}).get('Labels') or {}) == a['base_labels'],
           'exact native immutable baseline image/Root-reviewed inherited labels; no hidden mounts/health actor')


def options(a, admission_raw, admission_sha, domain):
    argv = DOCKER + ['create','--name',a['container'],'--hostname=perl-installed-lifecycle',
        '--cpus=2','--memory=2g','--memory-swap=2g','--pids-limit=128',
        '--init','--network=none','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--ulimit=nofile=1024:1024','--ulimit=core=0:0']
    for key, value in labels(a, admission_sha).items(): argv += ['--label',key + '=' + value]
    for cap in domain['cap_add']: argv.append('--cap-add=' + cap)
    for path, value in domain['tmpfs'].items(): argv.append('--tmpfs=' + path + ':' + value)
    return argv + ['--mount','type=bind,src=' + a['inputs'] + ',dst=/inputs,readonly',
        '--env','LIFECYCLE_ADMISSION_SHA256=' + admission_sha,
        '--env','LIFECYCLE_ADMISSION_JSON=' + admission_raw.decode(),
        '--entrypoint=/usr/bin/python3',a['image'],'-I','-B','/inputs/actor.py',
        '--admission-sha256',admission_sha,'--source-map-sha256',a['source_map_sha256']]


def inspect(row, a, sha, domain, container_id=None):
    C.need(row['Image'] == a['image'] and row['Name'] == '/' + a['container'], 'same immutable image/exact name')
    if container_id is not None: C.need(row['Id'] == container_id, 'owned container ID unchanged')
    config, host = row['Config'], row['HostConfig']
    C.need(config['User'] == '0:0' and config['Hostname'] == domain['hostname']
           and config['Labels'] == labels(a,sha), 'exact root user/hostname/inherited plus lifecycle labels')
    C.need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is False and host['Privileged'] is False
           and host['Init'] is True and host['Memory'] == domain['memory'] and host['MemorySwap'] == domain['memory_swap']
           and host['NanoCpus'] == 2 * 10**9 and host['PidsLimit'] == 128
           and host['CapDrop'] == ['ALL'] and set(host['CapAdd']) == set(domain['cap_add'])
           and host['SecurityOpt'] == ['no-new-privileges'], 'actual reviewed separate writable ALPM domain')
    C.need(host['Tmpfs'] == domain['tmpfs'] and not host.get('Binds') and not host.get('Devices')
           and not host.get('DeviceRequests') and not host.get('PublishAllPorts')
           and not host.get('PortBindings') and host.get('PidMode','') == ''
           and host.get('IpcMode') == 'private' and host.get('UsernsMode','') == '', 'no extra namespace/device/port authority')
    mounts = row['Mounts']
    C.need(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['Source'] == a['inputs']
           and mounts[0]['Destination'] == '/inputs' and mounts[0]['RW'] is False, 'one exact read-only inputs mount')


def unpack(raw, output):
    C.need(len(raw) <= 64 * 1024**2, 'bounded result tar')
    seen = set(); total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            parts = Path(member.name).parts
            C.need(parts and parts[0] == 'result' and len(parts) <= 2 and '..' not in parts,
                   'fixed shallow result DATA paths')
            if len(parts) == 1:
                C.need(member.isdir(), 'result root directory only'); continue
            name = parts[-1]
            C.need(name not in seen and member.isfile() and not member.sparse and 0 <= member.size <= 16 * 1024**2,
                   'ordinary unique result file only')
            C.need(name in ('report.json','upgraded-handoff.json') or name.endswith(('.stdout','.stderr')),
                   'fixed result DATA extensions')
            total += member.size
            C.need(total <= 64 * 1024**2 and len(seen) < 160, 'finite result DATA budget')
            body = archive.extractfile(member).read(member.size + 1)
            C.need(len(body) == member.size, 'complete result DATA')
            (output / name).write_bytes(body); seen.add(name)
    C.need('report.json' in seen, 'actual actor report required')


def execute(args):
    ar, qr = C.read(args.admission), C.read(args.qualification)
    C.need(C.pin(ar)['sha256'] == args.admission_sha256 and C.pin(qr)['sha256'] == args.qualification_sha256,
           'externally supplied Root operands/checksums')
    a, q = C.decode(ar), C.decode(qr)
    C.admission(a, args.source_map_sha256)
    C.need(a['root_qualification_sha256'] == args.qualification_sha256, 'same Root separate-domain qualification')
    C.need(q == dict(schema=1, operation=C.OPERATION, source_map_sha256=args.source_map_sha256,
                    image=a['image'], base_labels=a['base_labels'], baseline_source=C.SOURCE, baseline_inventory_sha256=C.EXPECTED_SHA,
                    native='aarch64', page_bytes=4096, runtime_domain='SEPARATE_ROOT_WRITABLE_NATIVE_ARM4K_ALPM_V1',
                    test_fingerprint=a['test_fingerprint'], baseline_fingerprint=a['baseline_fingerprint'],
                    signing_credentials='EXCLUDED; fresh Root TEST signing performed outside actors',
                    status='ROOT_ADMITTED_FOR_FINITE_COMPONENT_TRIAL'), 'concrete external Root qualification only')
    inputs = Path(a['inputs']); C.source(inputs, args.source_map_sha256)
    C.need(C.read(inputs / 'producer.py') == C.read(HERE / 'producer.py')
           and C.read(inputs / 'common.py') == C.read(HERE / 'common.py')
           and C.read(inputs / 'domain.json') == C.read(HERE / 'domain.json'), 'executing exact capsule Source/domain')
    domain = C.decode(C.read(inputs / 'domain.json'))
    output = Path(args.output)
    C.need(output.is_absolute() and str(output) == str(output.resolve()) and not output.exists()
           and not output.is_relative_to(inputs) and not inputs.is_relative_to(output), 'fresh disjoint output')
    C.need(output.parent.stat().st_uid == os.getuid() and not output.parent.stat().st_mode & 0o022,
           'caller-owned private output parent')
    output.mkdir(mode=0o700); (output / 'data').mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', operation=C.OPERATION, admission_sha256=args.admission_sha256,
                  source_map_sha256=args.source_map_sha256, qualification_sha256=args.qualification_sha256,
                  commands=[], container_id=None, cleanup=None, first_failure=None)
    owned = C.load('owned_child.py'); deadline = time.monotonic() + 660; cancelled = []
    def cancel(signum, frame): cancelled.append(signum)
    signal.signal(signal.SIGTERM, cancel); signal.signal(signal.SIGINT, cancel)
    def save(): (output / 'producer-report.json').write_bytes(C.encode(report))
    def command(step, argv, check=True, cleanup=False, cap=2*1024**2):
        C.need(cleanup or not cancelled, 'cancelled Root producer')
        row = dict(step=step, argv=argv, lifecycle={}, success=False)
        try:
            r = owned.run(argv, capture_output=True, env=dict(PATH='/usr/bin',HOME=str(output),LC_ALL='C',TZ='UTC'),
                          timeout=min(540 if step == 'run' else 45, max(1,deadline-time.monotonic())),
                          lifecycle=row['lifecycle'], stdout_limit=cap, stderr_limit=2*1024**2,
                          on_tick=None if cleanup else lambda: C.need(not cancelled, 'producer cancellation'))
            # Admission JSON is public DATA; no signing keys enter argv, logs, or capsule.
            (output / (step + '.stdout')).write_bytes(r.stdout)
            (output / (step + '.stderr')).write_bytes(r.stderr)
            row.update(returncode=r.returncode, stdout=C.pin(r.stdout), stderr=C.pin(r.stderr))
            C.need(C.natural(row['lifecycle']) and row['lifecycle']['exit'] == r.returncode
                   and (not check or r.returncode == 0), 'owned CLI natural exit/status')
            row['success'] = True
            return r
        finally: report['commands'].append(row); save()
    container_id = None; terminal = False; primary = None
    try:
        image = C.decode(command('image', DOCKER + ['image','inspect',a['image']]).stdout)[0]
        image_identity(image,a)
        arch = command('daemon-architecture', DOCKER + ['info','--format','{{.Architecture}}']).stdout.strip()
        C.need(arch in (b'arm64',b'aarch64'), 'actual native ARM daemon')
        storage = Path(command('daemon-storage', DOCKER + ['info','--format','{{.DockerRootDir}}']).stdout.decode().strip())
        C.need(storage.is_absolute() and str(storage) == str(storage.resolve()) and storage.is_dir(),
               'actual local-daemon storage directory visible to Root producer')
        fs = os.statvfs(storage)
        report['storage_before'] = dict(path=str(storage), free_bytes=fs.f_bavail*fs.f_frsize, free_inodes=fs.f_favail,
                                        admission_minimum_bytes=1024**3, admission_minimum_inodes=10000)
        C.need(fs.f_bavail*fs.f_frsize >= 1024**3 and fs.f_favail >= 10000,
               'finite ALPM trial actual Docker storage/inode headroom')
        raw = command('create', options(a, ar, args.admission_sha256, domain)).stdout.decode().strip()
        C.need(len(raw) == 64 and all(c in '0123456789abcdef' for c in raw), 'actual newly owned container ID')
        container_id = raw; report['container_id'] = raw
        row = C.decode(command('inspect-before', DOCKER + ['inspect',container_id]).stdout)[0]
        inspect(row,a,args.admission_sha256,domain,container_id)
        C.need(row['State']['Status'] == 'created', 'fresh never-started container')
        run = command('run', DOCKER + ['start','--attach',container_id], check=False)
        row = C.decode(command('inspect-after', DOCKER + ['inspect',container_id]).stdout)[0]
        inspect(row,a,args.admission_sha256,domain,container_id)
        C.need(row['State']['Running'] is False and row['State']['Status'] == 'exited'
               and row['State'].get('OOMKilled') is False and not row['State'].get('Error'), 'naturally exited non-OOM owned container')
        terminal = True
        data = command('export', DOCKER + ['cp',container_id + ':/work/result','-'], cap=64*1024**2)
        unpack(data.stdout, output / 'data')
        actor = C.decode(C.read(output / 'data/report.json',16*1024**2))
        C.need(run.returncode == row['State']['ExitCode'] == 0 and actor['first_failure'] is None
               and actor['status'] == 'PASS_FINITE_NATIVE_ARM4K_PERL_INSTALLED_LIFECYCLE'
               and actor['source_map_sha256'] == args.source_map_sha256
               and actor['admission_sha256'] == args.admission_sha256
               and actor['cleanup']['failures'] == [], 'complete same-Source successful actual lifecycle')
        report.update(status='PASS_PRODUCED_PERL_INSTALLED_LIFECYCLE_DATA_REQUIRES_INDEPENDENT_ROOT_REVIEW',
                      actor_report=C.pin(C.read(output / 'data/report.json',16*1024**2)))
    except BaseException as error:
        primary = error; report['first_failure'] = dict(type=type(error).__name__, message=str(error)[:1500])
    finally:
        try:
            if container_id is not None:
                row = C.decode(command('cleanup-inspect',DOCKER + ['inspect',container_id], cleanup=True).stdout)[0]
                inspect(row,a,args.admission_sha256,domain,container_id)
                if row['State']['Running']:
                    # Exact owned container graceful cancellation only; never rm -f or global cleanup.
                    command('cancel-owned', DOCKER + ['stop','--time=10',container_id], cleanup=True)
                    row = C.decode(command('inspect-cancelled',DOCKER + ['inspect',container_id], cleanup=True).stdout)[0]
                    inspect(row,a,args.admission_sha256,domain,container_id)
                    C.need(row['State']['Running'] is False, 'owned cancellation did not quiesce')
                    terminal = False
                    if primary is None: primary = ValueError('actor required cancellation; natural success disqualified')
                C.need(terminal or row['State']['Status'] in ('created','exited'), 'known quiescent owned container')
                command('remove-owned', DOCKER + ['rm',container_id], cleanup=True)
                fs = os.statvfs(storage)
                report['storage_after'] = dict(path=str(storage), free_bytes=fs.f_bavail*fs.f_frsize, free_inodes=fs.f_favail)
            report['cleanup'] = dict(status='OWNED_CONTAINER_REMOVED' if container_id else
                'NO_CONTAINER_ID_OWNERSHIP_NOT_ESTABLISHED', natural=terminal)
        except BaseException as error:
            report['cleanup'] = dict(status='UNKNOWN_OR_INCOMPLETE', error=str(error)[:1500])
            if primary is None: primary = error
        if primary is not None: report['status'] = 'FAIL'
        save()
    if primary is not None: raise primary
    return report


if __name__ == '__main__':
    C.need(__import__('sys').flags.isolated, 'isolated Python required')
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('admission','admission-sha256','qualification','qualification-sha256','source-map-sha256','output'):
        p.add_argument('--' + name, required=True)
    print(C.encode(execute(p.parse_args())).decode(), end='')
