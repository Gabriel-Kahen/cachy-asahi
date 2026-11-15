# SPDX-License-Identifier: MIT
"""Prospective owned native producer. Root admission is an external prerequisite.

This module never builds/pulls an image or admits a qualification. Its two cap0
actors use one already-admitted immutable image and one newly owned volume.
Explicit nocopy and pre-created actors precede final ownership initialization.
Copy-up is an unproven explanation for the earlier LLVM ownership failure.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import time

DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
OPERATION = 'rust199-source-reference-native-v1'
EXPORT_CAP = 4 * 1024**3
LOG_CAP = 64 * 1024**2
STAGE0 = 'build/stage0'
LABEL_PREFIX = 'cachy-asahi.'
_spec = importlib.util.spec_from_file_location('rust199_volume_successor', Path(__file__).with_name('volume.py'))
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw):
    need(type(raw) is bytes and len(raw) <= 8 * 1024**2, 'bounded Docker JSON bytes')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate Docker JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite Docker JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(c in str(path) for c in '\0\n\r,:') and
         all(not p.is_symlink() for p in (path, *path.parents)), 'ordinary canonical absolute path')
    need(path == path.resolve(), 'canonical absolute path required')
    return path


def pin(path, cap):
    path = ordinary(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= cap, 'bounded single-link ordinary input')
        result = dict(bytes=before.st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(key(before) == key(os.fstat(stream.fileno())) == key(path.lstat()), 'input changed while hashing')
    return result


def labels(binding, token, role):
    return {LABEL_PREFIX+'operation': OPERATION, LABEL_PREFIX+'source': binding['sha'],
            LABEL_PREFIX+'run': binding['run'], LABEL_PREFIX+'job': binding['job'],
            LABEL_PREFIX+'token': token, LABEL_PREFIX+'role': role}


def label_options(values):
    return [item for key, value in sorted(values.items()) for item in ('--label', key+'='+value)]


def mount_specs(volume, inputs, source, materials, phase):
    need(phase in ('prepare', 'makepkg') and len(materials) == 5, 'two fixed phases and five material mounts')
    mounts = [dict(Type='volume', Source=volume, Target='/work', ReadOnly=False, VolumeOptions=dict(NoCopy=True)),
              dict(Type='bind', Source=str(inputs), Target='/inputs', ReadOnly=True),
              dict(Type='bind', Source=str(source), Target='/source', ReadOnly=True)]
    for name, path in sorted(materials.items()):
        need(re.fullmatch('[A-Za-z0-9._+-]+', name) is not None, 'ordinary material basename')
        mounts.append(dict(Type='bind', Source=str(path), Target='/materials/'+name, ReadOnly=True))
    if phase == 'makepkg':
        for target in ('/stage0', '/work/build/stage0'):
            mounts.append(dict(Type='volume', Source=volume, Target=target, ReadOnly=True,
                               VolumeOptions=dict(Subpath=STAGE0, NoCopy=True)))
    return mounts


def mount_option(row):
    result = f"type={row['Type']},src={row['Source']},dst={row['Target']}"
    if row['ReadOnly']:
        result += ',readonly'
    if row.get('VolumeOptions', {}).get('NoCopy'):
        result += ',volume-nocopy'
    if 'Subpath' in row.get('VolumeOptions', {}):
        result += ',volume-subpath='+row['VolumeOptions']['Subpath']
    return result


def actor_options(name, volume, image, inputs, source, materials, phase, env, bindings):
    need(set(env) == {'ROOT_ADMISSION_SHA256', 'SOURCE_MAP_SHA256', 'CONTRACT_SHA256', 'WORK_VOLUME_ADMISSION_SHA256'} and
         all(re.fullmatch('[0-9a-f]{64}', v or '') for v in env.values()), 'exact four actor admission pins')
    args = DOCKER+['create', '--name', name, *label_options(bindings), '--cpus=2',
                  '--memory=8g', '--memory-swap=8g', '--pids-limit=512', '--init',
                  '--read-only', '--network=none', '--ipc=private', '--cgroupns=private',
                  '--restart=no', '--log-driver=none', '--hostname=rust199-native', '--cap-drop=ALL',
                  '--security-opt=no-new-privileges', '--user=1001:1001',
                  '--ulimit=nofile=1024:1024', '--ulimit=core=0:0', '--workdir=/work',
                  '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001',
                  '--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001']
    for row in mount_specs(volume, inputs, source, materials, phase):
        args += ['--mount', mount_option(row)]
    for key, value in sorted(env.items()):
        args += ['--env', key+'='+value]
    return args+['--entrypoint=/usr/bin/python', image, '-I', '-B', '/source/actor/entry.py', phase]


def init_options(name, volume, image, bindings, owner):
    return DOCKER+['create', '--name', name, *label_options(bindings), '--cpus=2',
                  '--memory=128m', '--memory-swap=128m', '--pids-limit=32', '--init',
                  '--network=none', '--ipc=private', '--cgroupns=private', '--restart=no', '--log-driver=none',
                  '--read-only', '--user=0:0', '--cap-drop=ALL', '--cap-add=CHOWN',
                  '--security-opt=no-new-privileges', '--ulimit=nofile=1024:1024', '--ulimit=core=0:0',
                  '--workdir=/', '--mount', f'type=volume,src={volume},dst=/work,volume-nocopy',
                  '--entrypoint=/usr/bin/python', image, '-I', '-B', '-c', V.INIT_CODE, encode(owner).decode()]


def inspect_identity(actor, name, image, bindings):
    need(actor['Name'] == '/'+name and re.fullmatch('[0-9a-f]{64}', actor['Id']) and actor['Image'] == image and
         all(actor['Config']['Labels'].get(key) == value for key, value in bindings.items()),
         'exact owned actor image/name/operation/source/run/job/token/role')


def exact_cap_add(raw, expected):
    # Docker28 may render CAP_CHOWN for the literal create flag CHOWN.
    if expected == []:
        return raw in (None, [])
    if expected != ['CHOWN']:
        return False
    return type(raw) is list and len(raw) == 1 and raw[0] in ('CHOWN', 'CAP_CHOWN')


def inspect_domain(actor, memory, pids, user, capadd):
    host, config = actor['HostConfig'], actor['Config']
    need(config['User'] == user and host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none' and
         host['CapDrop'] == ['ALL'] and exact_cap_add(host.get('CapAdd'), capadd) and
         host['SecurityOpt'] == ['no-new-privileges'] and host['Privileged'] is False and
         not host.get('Devices') and not host.get('DeviceRequests') and not host.get('Binds') and
         not host.get('VolumesFrom') and not host.get('Links') and not host.get('ExtraHosts') and
         host.get('UsernsMode', '') == '' and host.get('PidMode', '') == '' and
         host.get('IpcMode') == 'private' and host.get('CgroupnsMode') == 'private',
         'exact private cap/NNP/RO/no-network/no-device domain')
    need(host['Memory'] == host['MemorySwap'] == memory and host['NanoCpus'] == 2000000000 and
         host['PidsLimit'] == pids and host['Init'] is True, 'exact CPU/RAM/no-swap/PID/init operands')
    need({x['Name']: (x['Soft'], x['Hard']) for x in host['Ulimits']} ==
         {'nofile': (1024, 1024), 'core': (0, 0)}, 'exact actor ulimits')
    need(host.get('RestartPolicy', {}).get('Name') == 'no', 'no daemon actor restart policy')
    need(host.get('LogConfig') == {'Type': 'none', 'Config': {}}, 'no unbounded daemon logging')


def inspect_mounts(actor, expected, volume, volume_path):
    hostrows = actor['HostConfig']['Mounts']
    rows = actor['Mounts']
    need(len(hostrows) == len(rows) == len(expected), 'exact mount cardinality; no writable aliases')
    need(len({x['Target'] for x in hostrows}) == len(hostrows) and
         len({x['Destination'] for x in rows}) == len(rows), 'no duplicate mount targets')
    for want in expected:
        configured = next(x for x in hostrows if x['Target'] == want['Target'])
        need(all(configured.get(key) == value for key, value in want.items() if key != 'ReadOnly') and
             configured.get('ReadOnly', False) is want['ReadOnly'],
             'exact configured mount and volume-subpath required; no fallback')
        need(set(configured) <= {'Type', 'Source', 'Target', 'ReadOnly', 'Consistency',
                                'BindOptions', 'VolumeOptions'} and
             not configured.get('BindOptions') and configured.get('Consistency', '') in ('', 'default') and
             configured.get('VolumeOptions', {}) == want.get('VolumeOptions', {}),
             'no alternate mount options or volume driver behavior')
        actual = next(x for x in rows if x['Destination'] == want['Target'])
        need(actual['Type'] == want['Type'] and actual['RW'] is (not want['ReadOnly']) and
             actual.get('Propagation', '') in ('', 'rprivate'), 'actual mount type/access/propagation')
        if want['Type'] == 'bind':
            need(actual['Source'] == want['Source'], 'exact actual readonly DATA bind')
        else:
            path = str(volume_path / want.get('VolumeOptions', {}).get('Subpath', ''))
            need(actual['Name'] == volume and actual.get('Driver') == 'local' and
                 actual['Source'] == path, 'actual exact owned volume source/subpath')


def inspect_actor(actor, name, volume, image, inputs, source, materials, phase, env, bindings, volume_path):
    inspect_identity(actor, name, image, bindings)
    inspect_domain(actor, 8 * 1024**3, 512, '1001:1001', [])
    config, host = actor['Config'], actor['HostConfig']
    need(config['Hostname'] == 'rust199-native' and config['WorkingDir'] == '/work' and
         config['Entrypoint'] == ['/usr/bin/python'] and
         config['Cmd'] == ['-I', '-B', '/source/actor/entry.py', phase], 'exact actor entry/vector')
    actualenv = dict(item.split('=', 1) for item in config['Env'])
    need(all(actualenv.get(k) == v for k, v in env.items()) and
         not any(k.startswith(('LD_', 'DOCKER_', 'PYTHON', 'CACHY_OLD_', 'CACHY_RETAINED_')) for k in actualenv),
         'exact explicit admission pins; no ambient loader/cache overrides')
    need(host['Tmpfs'] == {'/tmp': 'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001',
                          '/run': 'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'}, 'exact bounded actor tmpfs')
    inspect_mounts(actor, mount_specs(volume, inputs, source, materials, phase), volume, volume_path)
    need(actor['State']['Status'] == 'created' and actor['State']['Running'] is False,
         'inspect exact unstarted actor before daemon execution')


def inspect_init(actor, name, volume, image, bindings, volume_path, owner, created=True):
    inspect_identity(actor, name, image, bindings)
    inspect_domain(actor, 128 * 1024**2, 32, '0:0', ['CHOWN'])
    need(actor['Config']['Entrypoint'] == ['/usr/bin/python'] and actor['Config']['WorkingDir'] == '/' and
         actor['Config']['Cmd'] == ['-I', '-B', '-c', V.INIT_CODE, encode(owner).decode()] and not actor['HostConfig'].get('Tmpfs'),
         'only exact nonrecursive chmod-before-CHOWN initialization')
    inspect_mounts(actor, [dict(Type='volume', Source=volume, Target='/work', ReadOnly=False,
                               VolumeOptions=dict(NoCopy=True))], volume, volume_path)
    need(not any(item.split('=', 1)[0].startswith(('LD_', 'PYTHON')) for item in actor['Config'].get('Env', [])),
         'no initializer loader overrides')
    if created:
        need(actor['State']['Status'] == 'created' and actor['State']['Running'] is False,
             'inspect exact unstarted CHOWN actor')


def natural(row):
    return (row.get('natural_exit') is True and row.get('forced_cleanup') is False and
            row.get('group_absent') is True and row.get('retirement') == 'REAPED' and
            row.get('ownership_lost') is False and row.get('leader_held_until_group_inspection') is True and
            row.get('exit_observed_via_waitpid') is True)


def finished(actor):
    row = actor['State']
    need(row['Status'] == 'exited' and row['ExitCode'] == 0 and row['OOMKilled'] is False and
         row['Running'] is False and row.get('Restarting') is False and not row.get('Error'),
         'natural zero-exit non-OOM daemon completion required')


def reserve(memory, rows):
    need(memory >= 4 * 1024**3, 'active host memory reserve exhausted')
    for row in rows:
        need(row['available_bytes'] >= 8 * 1024**3 and row['available_inodes'] >= 120000,
             'active host byte/inode reserve exhausted')


def diagnostic_action(state):
    if state['Status'] in ('running', 'restarting', 'paused'):
        return 'STOP_MARK_FAILED'
    need(state['Status'] == 'exited' and state['Running'] is False and state.get('Restarting') is False,
         'diagnostic export only from a stopped exited actor')
    return 'EXPORT_FAILED_EVIDENCE'


def completed(report):
    return bool(report.get('prepare_completed') and report.get('makepkg_completed') and report.get('export') and
                report.get('owned_resources_absent') and not report['errors'] and
                not report.get('cleanup_errors') and not report.get('forced_daemon_cleanup'))


def export_limit(previous):
    cap = min([EXPORT_CAP]+[value for value in previous if value != resource.RLIM_INFINITY])
    need(cap == EXPORT_CAP, 'inherited file-size limits cannot carry complete bounded export')
    return cap


def inspect_image(inspected, image):
    need(inspected['Id'] == image and inspected['Os'] == 'linux' and inspected['Architecture'] == 'arm64',
         'already-existing immutable native image; no build/pull fallback')
    need(not inspected['Config'].get('Volumes'),
         'image-declared volumes would allocate unowned anonymous resources')


def descriptors(value):
    """Project already-validated external descriptors without inventing paths."""
    result = []
    if type(value) is dict:
        if {'path', 'local_path', 'bytes', 'sha256'} <= set(value):
            result.append(value)
        else:
            for item in value.values():
                result.extend(descriptors(item))
    elif type(value) is list:
        for item in value:
            result.extend(descriptors(item))
    return result


def snapshot(root, inputs, a):
    candidate = root/'packages/port/rust199-source-reference'
    source_map = decode((root/'candidate-map.json').read_bytes())
    need(len(source_map['files']) == 9, 'exact frozen nine-file candidate')
    need({str(p.relative_to(candidate)) for p in candidate.rglob('*') if p.is_file()} ==
         set(source_map['files']), 'complete candidate snapshot namespace')
    target = inputs/'candidate'
    target.mkdir(mode=0o755)
    for name, expected in source_map['files'].items():
        need(all(part not in ('', '.', '..') for part in name.split('/')) and
             not Path(name).is_absolute(), 'ordinary candidate relative leaf')
        source = ordinary(candidate/name)
        need(dict(**pin(source, 4*1024**2), mode=stat.S_IMODE(source.stat().st_mode)) == expected,
             'frozen candidate source byte/mode pin')
        dest = target/name
        dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        need(dict(**pin(dest, 4*1024**2), mode=stat.S_IMODE(dest.stat().st_mode)) == expected,
             'copied candidate byte/mode pin')
    reserved = {'candidate', 'root-admission.json', 'actor-admission.json',
                'volume-admission.json', 'volume-initialization.json'}
    seen = set()
    for row in descriptors(a):
        actor = Path(row['path'])
        need(actor.is_absolute() and actor.parts[:2] == ('/', 'inputs') and
             all(x not in ('', '.', '..') for x in actor.parts[2:]) and len(actor.parts) > 2 and
             actor.parts[2] not in reserved and str(actor) not in seen,
             'unique preserved actor descriptor outside generated namespace')
        seen.add(str(actor))
        source = ordinary(row['local_path'])
        expected = {k: row[k] for k in ('bytes', 'sha256')}
        need(pin(source, row['bytes']) == expected, 'Root descriptor changed before snapshot')
        dest = inputs.joinpath(*actor.parts[2:])
        dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        need(not dest.exists(), 'no external descriptor overwrite')
        shutil.copy2(source, dest)
        dest.chmod(0o444)
        need(pin(dest, row['bytes']) == expected, 'Root descriptor snapshot changed')
    spec = importlib.util.spec_from_file_location('rust199_actor_normalize', root/'actor/entry.py')
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    raw = encode(a)
    (inputs/'root-admission.json').write_bytes(raw)
    (inputs/'actor-admission.json').write_bytes(encode(entry.normalize(a)))
    for name in ('root-admission.json', 'actor-admission.json'):
        (inputs/name).chmod(0o444)
    return dict(ROOT_ADMISSION_SHA256=hashlib.sha256(raw).hexdigest(),
                SOURCE_MAP_SHA256=a['source']['map_sha256'],
                CONTRACT_SHA256=pin(root/'contract.json', 4*1024**2)['sha256'])


def run(root, work, a, command):
    """Consume an actual Root-validated a; no qualification or material fetch here.

    command records natural owned CLI receipts, cancellation and its own deadline.
    Export streams through the same owned-child primitive with separate bounds.
    """
    root, work = ordinary(root), ordinary(work)
    source, image = a['source'], a['image']['id']
    need(re.fullmatch('sha256:[0-9a-f]{64}', image or '') is not None,
         'existing immutable Root-admitted image ID only')
    need(pin(root/'source-map.json', 4*1024**2)['sha256'] == source['map_sha256'],
         'actual Root Source map binding differs')
    out = work/'rust-build'
    out.mkdir(mode=0o700)
    inputs = out/'inputs'
    inputs.mkdir(mode=0o755)
    env = snapshot(root, inputs, a)
    materials = {row['name']: ordinary(row['local_path']) for row in a['materials']}
    need(len(materials) == 5 and all(row['transport'] == 'LOCAL_READONLY' for row in a['materials']),
         'all five actual Root material files must already exist locally')
    for row in a['materials']:
        need(pin(materials[row['name']], row['bytes']) == {k: row[k] for k in ('bytes', 'sha256')},
             'Root material changed before readonly bind')
    owner = V.binding(source, image, env['ROOT_ADMISSION_SHA256'])
    token = owner['token']
    actors = {role: owner[role] for role in ('init', 'prepare', 'makepkg')}
    volume = owner['volume']
    volume_raw = encode(V.admission(owner))
    (inputs/'volume-admission.json').write_bytes(volume_raw)
    (inputs/'volume-admission.json').chmod(0o444)
    env['WORK_VOLUME_ADMISSION_SHA256'] = hashlib.sha256(volume_raw).hexdigest()
    bindings = {role: labels(source, token, role) for role in (*actors, 'volume')}
    report = dict(schema=1, status='FAIL', operation=OPERATION, source=source, image=image,
                  actors=actors, volume=volume, root_admission_sha256=env['ROOT_ADMISSION_SHA256'],
                  intents=[], cleanup=[], errors=[], native_acceptance=False,
                  hardware_acceptance=False, release_acceptance=False, volume_binding=owner,
                  volume_admission_sha256=env['WORK_VOLUME_ADMISSION_SHA256'])
    report_path = out/'producer.json'
    def save():
        report_path.write_bytes(encode(report))
    def intent(kind, name, role):
        report['intents'].append(dict(kind=kind, name=name, role=role))
        save()
    def call(argv, timeout=60, check=True):
        result = command(argv, timeout=timeout, check=check)
        if check:
            need(result.returncode == 0, 'natural command returned nonzero')
        return result
    def one(argv):
        rows = decode(call(argv).stdout)
        need(type(rows) is list and len(rows) == 1, 'exact one Docker inspection')
        return rows[0]
    previous_tick, previous_cleaning, previous_deadline = command.on_tick, command.cleaning, command.deadline
    last_tick = [0.0]
    daemon = decode((work/'daemon.json').read_bytes())
    storage = ordinary(daemon['info']['DockerRootDir'])
    def watch():
        need(not command.cancelled[0] and time.monotonic() < command.deadline, 'Root cancellation/deadline')
        if time.monotonic()-last_tick[0] < 1:
            return
        last_tick[0] = time.monotonic()
        if previous_tick:
            previous_tick()
        memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                          if line.startswith('MemAvailable:')))*1024
        rows = []
        for path in (out, storage):
            data = os.statvfs(path)
            rows.append(dict(available_bytes=data.f_bavail*data.f_frsize, available_inodes=data.f_favail))
        reserve(memory, rows)
    command.on_tick = watch
    volume_path = None
    latest = None
    container_ids = {}
    def observe_finish(name, role):
        actual = one(DOCKER+['container', 'inspect', name])
        inspect_identity(actual, name, image, bindings[role])
        need(actual['Id'] == container_ids[role], 'same exact actor after natural retirement')
        (out/(role+'-finished.json')).write_bytes(encode(actual))
        finished(actual)
        return actual
    def export(name):
        lifecycle = {}
        path, error = out/'export.tar', out/'export-stderr.log'
        oldlimit = resource.getrlimit(resource.RLIMIT_FSIZE)
        cap = export_limit(oldlimit)
        try:
            timeout = min(900, command.deadline-time.monotonic()-300)
            need(timeout > 0 and cap == EXPORT_CAP, 'complete bounded export and cleanup deadline reserve')
            resource.setrlimit(resource.RLIMIT_FSIZE, (cap, oldlimit[1]))
            with path.open('xb') as output, error.open('xb') as stderr:
                result = command.owned.run(DOCKER+['cp', name+':/work/output', '-'], timeout=timeout,
                    cwd=work, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, stdout=output, stderr=stderr,
                    lifecycle=lifecycle, stdout_limit=EXPORT_CAP, stderr_limit=LOG_CAP, on_tick=watch)
            need(result.returncode == 0 and lifecycle.get('exit') == 0 and natural(lifecycle),
                 'natural owned export retirement required')
            report['export'] = dict(file='export.tar', **pin(path, EXPORT_CAP), lifecycle=lifecycle)
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, oldlimit)
            report['export_lifecycle'] = lifecycle
            save()
    save()
    try:
        # No actor/volume mutation until the complete operation namespace is absent.
        existing = call(DOCKER+['container', 'ls', '--all', '--format', '{{.Names}}']).stdout.decode().splitlines()
        existing_volumes = call(DOCKER+['volume', 'ls', '--quiet']).stdout.decode().splitlines()
        need(not set(actors.values()) & set(existing) and volume not in existing_volumes,
             'fresh complete owned actor/volume namespace required')
        inspected = one(DOCKER+['image', 'inspect', image])
        inspect_image(inspected, image)
        watch()
        intent('volume', volume, 'volume')
        call(DOCKER+['volume', 'create', '--driver=local', *label_options(bindings['volume']), volume])
        data = one(DOCKER+['volume', 'inspect', volume])
        need(data['Name'] == volume and data['Driver'] == 'local' and not data.get('Options') and
             all(data['Labels'].get(k) == v for k, v in bindings['volume'].items()), 'exact owned default local volume')
        volume_path = ordinary(data['Mountpoint'])
        (out/'volume-before.json').write_bytes(encode(data))
        # Prepare's mount and working directory exist BEFORE final initialization.
        # Main's stage0 subpaths cannot exist until prepare; every reference is nocopy.
        intent('container', actors['prepare'], 'prepare')
        call(actor_options(actors['prepare'], volume, image, inputs, root, materials, 'prepare', env, bindings['prepare']))
        actual = one(DOCKER+['container', 'inspect', actors['prepare']])
        inspect_actor(actual, actors['prepare'], volume, image, inputs, root, materials, 'prepare', env, bindings['prepare'], volume_path)
        container_ids['prepare'] = actual['Id']
        (out/'prepare-inspect.json').write_bytes(encode(actual))
        intent('container', actors['init'], 'init')
        call(init_options(actors['init'], volume, image, bindings['init'], owner))
        actual = one(DOCKER+['container', 'inspect', actors['init']])
        inspect_init(actual, actors['init'], volume, image, bindings['init'], volume_path, owner)
        container_ids['init'] = actual['Id']
        (out/'init-inspect.json').write_bytes(encode(actual))
        initialized = call(DOCKER+['start', '--attach', actors['init']], timeout=60)
        final_init = observe_finish(actors['init'], 'init')
        inspect_init(final_init, actors['init'], volume, image, bindings['init'], volume_path, owner, created=False)
        need(len(initialized.stdout) <= 16384, 'finite actual initializer receipt')
        initialized = decode(initialized.stdout)
        V.verify_receipt(initialized, owner)
        report['volume_initialization'] = initialized
        (out/'volume-initialization.json').write_bytes(encode(initialized))
        (inputs/'volume-initialization.json').write_bytes(encode(initialized))
        (inputs/'volume-initialization.json').chmod(0o444)
        save()
        for phase, budget in (('prepare', 900), ('makepkg', 16200)):
            name = actors[phase]
            if phase == 'makepkg':
                intent('container', name, phase)
                call(actor_options(name, volume, image, inputs, root, materials, phase, env, bindings[phase]))
            actual = one(DOCKER+['container', 'inspect', name])
            inspect_actor(actual, name, volume, image, inputs, root, materials, phase, env, bindings[phase], volume_path)
            need(phase not in container_ids or actual['Id'] == container_ids[phase], 'same pre-created prepare actor')
            container_ids[phase] = actual['Id']
            (out/(phase+'-inspect.json')).write_bytes(encode(actual))
            latest = name
            call(DOCKER+['start', '--attach', name], timeout=budget)
            observe_finish(name, phase)
            report[phase+'_completed'] = True
            save()
        export(latest)
    except BaseException as error:
        report['errors'].append(type(error).__name__+': '+str(error)[:2048])
        save()
        # Retain failed actor receipts when the original native deadline leaves
        # room. This can never clear the first failure or consume cleanup's
        # reserved 300 seconds. Cancellation/reserve refusal may prevent export.
        if latest is not None and time.monotonic() < command.deadline-300:
            was_cleaning = command.cleaning
            command.cleaning = True
            try:
                actual = one(DOCKER+['container', 'inspect', latest])
                phase = next(role for role, name in actors.items() if name == latest)
                inspect_identity(actual, latest, image, bindings[phase])
                need(actual['Id'] == container_ids[phase], 'same exact owned actor before diagnostic stop/export')
                if diagnostic_action(actual['State']) == 'STOP_MARK_FAILED':
                    report['forced_daemon_cleanup'] = True
                    save()
                    call(DOCKER+['stop', '--time=1', latest], timeout=15)
                    actual = one(DOCKER+['container', 'inspect', latest])
                    inspect_identity(actual, latest, image, bindings[phase])
                    need(actual['Id'] == container_ids[phase], 'same exact owned actor after diagnostic stop')
                need(diagnostic_action(actual['State']) == 'EXPORT_FAILED_EVIDENCE', 'stopped diagnostic actor required')
                export(latest)
                report['diagnostic_export_only'] = True
            except BaseException as diagnostic:
                report['diagnostic_export_error'] = type(diagnostic).__name__+': '+str(diagnostic)[:2048]
            finally:
                command.cleaning = was_cleaning
                save()
    finally:
        command.on_tick = None
        command.cleaning = True
        command.deadline = time.monotonic()+300
        try:
            for item in reversed(report['intents']):
                try:
                    kind, name, role = item['kind'], item['name'], item['role']
                    query = DOCKER+[kind, 'ls', '--all', '--format', '{{.Names}}'] if kind == 'container' else DOCKER+['volume', 'ls', '--quiet']
                    names = call(query).stdout.decode().splitlines()
                    if name not in names:
                        report['cleanup'].append(dict(name=name, already_absent=True))
                        continue
                    actual = one(DOCKER+[kind, 'inspect', name])
                    if kind == 'container':
                        inspect_identity(actual, name, image, bindings[role])
                        need(role not in container_ids or actual['Id'] == container_ids[role], 'same exact owned container during cleanup')
                        live = actual['State']['Status'] not in ('created', 'exited')
                        if live:
                            report['forced_daemon_cleanup'] = True
                        call(DOCKER+['container', 'rm']+(['--force'] if live else [])+[name], timeout=30)
                    else:
                        need(actual['Name'] == volume and actual['Driver'] == 'local' and
                             not actual.get('Options') and all(actual['Labels'].get(k) == v for k, v in bindings['volume'].items()) and
                             (volume_path is None or actual['Mountpoint'] == str(volume_path)), 'exact owned volume cleanup identity')
                        call(DOCKER+['volume', 'rm', name], timeout=30)
                    report['cleanup'].append(dict(name=name, removed=True))
                except BaseException as error:
                    report.setdefault('cleanup_errors', []).append(type(error).__name__+': '+str(error)[:2048])
                save()
            if report['intents']:
                remaining = call(DOCKER+['container', 'ls', '--all', '--format', '{{.Names}}']).stdout.decode().splitlines()
                remaining_volumes = call(DOCKER+['volume', 'ls', '--quiet']).stdout.decode().splitlines()
                need(not set(actors.values()) & set(remaining) and volume not in remaining_volumes,
                     'final actual owned-resource absence required')
                report['owned_resources_absent'] = True
        except BaseException as error:
            report.setdefault('cleanup_errors', []).append(type(error).__name__+': '+str(error)[:2048])
        finally:
            command.deadline, command.cleaning, command.on_tick = previous_deadline, previous_cleaning, previous_tick
            if completed(report):
                report['status'] = 'COMPLETED_EXPORTED_RETIRED'
            save()
    return report
