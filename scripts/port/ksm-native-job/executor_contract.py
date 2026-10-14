# SPDX-License-Identifier: MIT
"""Bound completed same-job observations to captured data; execute no native code.

The supervisor supplies observed exits and the broker's actual operation journal.
Neither package declarations nor these pure-data checks prove hardware acceptance.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType

INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
RECIPES_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
PACKAGES_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
PRODUCER_SHA = '7209d1f6a0a1acd38644a053d8956f3a1e17292122aef84d171368c984838924'
MAP_SHA = 'f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44'
ENTRY_SHA = '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24'
CONTRACT_SHA = 'bfce5d9a5e8a9626cdedb121f299dafd730b13e484d1c4be7ba917207e4d161b'
HASH = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
FILE_LIMIT, BUILD_LIMIT, TOTAL_LIMIT = 16 * 1024**2, 32 * 1024**2, 300 * 1024**2


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON field')
            value[key] = item
        return value
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda _: need(False, 'nonfinite JSON'))
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid bounded JSON') from error
    need(type(value) is dict, 'JSON object required')
    return value


def clean_exit(value):
    need(type(value) is int and value == 0, 'observed clean process exit required')


def first_journal(rows):
    need(type(rows) is list and 0 < len(rows) <= 4096 and type(rows[0]) is dict and rows[0].get('event') == 'opened',
         'actual opened broker journal required')
    return rows[0]


def canonical(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not re.search(r'[\x00-\x1f\x7f,]', str(path)), 'canonical absolute path required')
    return path


def directory(path):
    path = canonical(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def capture(path, limit=FILE_LIMIT):
    """Hash the bytes from one bounded, nofollow, single-link descriptor."""
    path = canonical(path)
    parent, fd = directory(path.parent), None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
             'bounded single-link regular data required')
        data = bytearray()
        while block := os.read(fd, min(65536, before.st_size - len(data) + 1)):
            data.extend(block)
            need(len(data) <= before.st_size, 'capture size changed')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
             'capture metadata changed')
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def capture_build(root):
    """Capture bounded build evidence, including nested original recipe inputs."""
    root = canonical(root)
    files, dirs, total = {}, {}, 0
    pending, count = [(root, 0)], 0
    while pending:
        path, depth = pending.pop()
        fd = directory(path)
        try:
            info = os.fstat(fd)
            dirs[str(path)] = info
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    need(count <= 256, 'build entry bound')
                    if entry.is_dir(follow_symlinks=False):
                        need(depth < 8 and (path != root or entry.name in {'inputs', 'artifacts'}),
                             'bounded build directory required')
                        pending.append((path / entry.name, depth + 1))
                        continue
                    need(entry.is_file(follow_symlinks=False), 'flat regular build evidence required')
                    data = capture(path / entry.name)
                    total += len(data)
                    need(total <= BUILD_LIMIT, 'build aggregate bound')
                    files[str(path / entry.name)] = data
        finally:
            os.close(fd)
    need(str(root / 'provenance.json') in files, 'build provenance missing')
    return MappingProxyType(files), MappingProxyType(dirs)


def relative(name):
    need(type(name) is str and 0 < len(name) <= 1024 and not name.startswith('/') and
         all(part not in {'', '.', '..'} for part in name.split('/')) and
         not re.search(r'[\x00-\x1f\x7f]', name), 'safe relative evidence name required')
    return name


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze(item) for item in value)
    return value


def plain(value):
    if isinstance(value, (dict, MappingProxyType)):
        return {key: plain(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [plain(item) for item in value]
    return value


def validate_binding(binding):
    fields = {'source_commit', 'run_id', 'uid', 'gid', 'runner_arch', 'docker_endpoint',
              'daemon_id', 'nonce', 'packet_sha256'}
    need(type(binding) is dict and set(binding) == fields, 'exact supervisor binding required')
    need(type(binding['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', binding['source_commit']) and
         type(binding['run_id']) is str and re.fullmatch(r'[1-9][0-9]{0,19}', binding['run_id']) and
         type(binding['nonce']) is str and re.fullmatch(r'[0-9a-f]{32}', binding['nonce']) and
         type(binding['packet_sha256']) is str and HASH.fullmatch(binding['packet_sha256']), 'job identity required')
    need(all(type(binding[key]) is int and 0 < binding[key] <= 65535 for key in ('uid', 'gid')) and
         binding['runner_arch'] == 'ARM64' and
         binding['docker_endpoint'] in {'unix:///run/docker.sock', 'unix:///var/run/docker.sock'} and
         type(binding['daemon_id']) is str and re.fullmatch(r'[A-Za-z0-9:-]{8,128}', binding['daemon_id']),
         'native local nonroot supervisor required')


def validate_journal(rows, binding, image, names, *, final=False):
    """Check actual broker JSONL transitions, never a synthetic ownership PASS."""
    validate_binding(binding)
    need(type(rows) is list and 0 < len(rows) <= 4096 and IMAGE.fullmatch(image), 'bounded actual broker rows required')
    need(type(final) is bool and len(set(names)) == len(names), 'exact journal context required')
    need(len(names) in {8, 10}, 'all eight originals and optional two KSM builds required')
    expected = set(names) | {'ksm-inventory-' + binding['nonce']}
    phases = {name: 'producer' if index < 8 else f'ksm-{index - 7}' for index, name in enumerate(names)}
    phases['ksm-inventory-' + binding['nonce']] = 'producer'
    containers, ids, opened = {}, set(), False
    phase_index = 0
    image_state, context, image_removed = None, None, False
    cleanup, pending_operation, operations, image_absence_verified = None, None, [], False
    prefix = ['docker', '--host=' + binding['docker_endpoint']]
    def operated(arguments, *, output=None):
        return any(argv == prefix + arguments and code == 0 and
                   (output is None or (size, digest) == (len(output), sha(output)))
                   for argv, code, size, digest in operations)
    allowed = {'opened', 'request', 'image-reserved', 'image-bound', 'container-reserved', 'container-bound',
               'container-start-reserved', 'container-exited', 'container-removal-reserved', 'container-absent',
               'image-removal-reserved', 'image-absent', 'cleanup-result',
               'docker-operation-reserved', 'docker-operation-completed'}
    for row in rows:
        need(type(row) is dict and row.get('event') in allowed and row.get('nonce') == binding['nonce'] and
             row.get('phase') in {'producer', 'ksm-1', 'ksm-2'}, 'unbound/failed broker event')
        event, phase = row['event'], row['phase']
        next_index = ('producer', 'ksm-1', 'ksm-2').index(phase)
        need(next_index >= phase_index and next_index <= phase_index + 1, 'monotonic broker phase required')
        phase_index = next_index
        if event == 'opened':
            need(phase == 'producer' and not opened and all(row.get(key) == binding[key] and type(row.get(key)) is type(binding[key])
                                           for key in ('source_commit', 'run_id', 'packet_sha256', 'uid', 'gid', 'docker_endpoint', 'daemon_id')),
                 'actual broker job identity required')
            need(type(row.get('docker_sha256')) is str and HASH.fullmatch(row['docker_sha256']) and
                 type(row.get('docker_socket_device')) is int and row['docker_socket_device'] >= 0 and
                 type(row.get('docker_socket_inode')) is int and row['docker_socket_inode'] > 0,
                 'captured Docker CLI/socket identity required')
            opened = True
            continue
        need(opened, 'broker event before opened')
        need(pending_operation is None or event == 'docker-operation-completed', 'incomplete broker operation')
        if event == 'docker-operation-reserved':
            need(set(row) == {'event', 'nonce', 'phase', 'argv'} and type(row['argv']) is list and
                 3 <= len(row['argv']) <= 256 and row['argv'][:2] == ['docker', '--host=' + binding['docker_endpoint']] and
                 all(type(arg) is str and '\x00' not in arg for arg in row['argv']) and
                 sum(len(arg.encode()) + 1 for arg in row['argv']) <= 65536, 'canonical bound Docker operation required')
            arguments = row['argv'][2:]
            need(not arguments[0].startswith('-'), 'canonical Docker command position required')
            if arguments[0] == 'image':
                selectors = {'reference=ksm-native-' + binding['nonce'],
                             'label=org.cachy-asahi.ksm-job=' + binding['nonce']}
                need(arguments in (['image', 'inspect', image], ['image', 'rm', '--no-prune', image]) or
                     len(arguments) == 6 and arguments[:5] == ['image', 'ls', '--quiet', '--no-trunc', '--filter']
                     and arguments[5] in selectors, 'exact scoped image command required')
            if arguments[0] == 'rmi' or arguments[:2] in (['image', 'rm'], ['image', 'remove']):
                need(arguments == ['image', 'rm', '--no-prune', image] and image_state == 'removing' and
                     not any(argv[2:4] == ['image', 'rm'] for argv, _, _, _ in operations),
                     'exact nonpruning owned image removal required')
            need(arguments[0] not in {'system', 'builder', 'buildx'} and arguments[:2] != ['image', 'prune'],
                 'unscoped pruning operation refused')
            pending_operation = (row['argv'], phase)
        elif event == 'docker-operation-completed':
            need(set(row) == {'event', 'nonce', 'phase', 'returncode', 'stdout_bytes', 'stdout_sha256'} and
                 pending_operation is not None and pending_operation[1] == phase and
                 type(row['returncode']) is int and type(row['stdout_bytes']) is int and
                 0 <= row['stdout_bytes'] <= 8 * 1024**2 and type(row['stdout_sha256']) is str and
                 HASH.fullmatch(row['stdout_sha256']), 'paired typed Docker operation required')
            if row['returncode'] != 0:
                variants = set()
                for separator in ('', ' '):
                    diagnostic = ('Error response from daemon: No such image:' + separator + image).encode()
                    for value in (diagnostic, b'[]\n' + diagnostic, diagnostic + b'\n[]'):
                        variants.update((value, value + b'\n'))
                need(row['returncode'] == 1 and image_state == 'removing' and
                     pending_operation[0] == ['docker', '--host=' + binding['docker_endpoint'], 'image', 'inspect', image] and
                     any((row['stdout_bytes'], row['stdout_sha256']) == (len(value), sha(value)) for value in variants),
                     'only exact bound-image absence may exit nonzero')
                image_absence_verified = True
            operations.append((pending_operation[0], row['returncode'], row['stdout_bytes'], row['stdout_sha256']))
            pending_operation = None
        elif event == 'request':
            need(type(row.get('argv')) is list and 0 < len(row['argv']) <= 256 and
                 all(type(arg) is str and len(arg) <= 65536 for arg in row['argv']), 'bounded broker request required')
        elif event == 'image-reserved':
            need(phase == 'producer' and image_state is None and row.get('tag') == 'ksm-native-' + binding['nonce'] and
                 type(row.get('context_sha256')) is str and HASH.fullmatch(row['context_sha256']), 'owned image reservation required')
            context, image_state = row['context_sha256'], 'reserved'
        elif event == 'image-bound':
            need(phase == 'producer' and image_state == 'reserved' and row.get('id') == image and
                 row.get('context_sha256') == context, 'owned immutable image binding required')
            need(sum(argv[2] == 'build' and code == 0 for argv, code, _, _ in operations) == 1,
                 'observed single successful bootstrap operation required')
            image_state = 'bound'
        elif event.startswith('container-'):
            name = row.get('name')
            need(name in expected and phase == phases[name] and image_state == 'bound' and not image_removed,
                 'unrequested owned container')
            if event == 'container-reserved':
                need(name not in containers and row.get('image') == image, 'fresh bound container reservation required')
                containers[name] = {'state': 'reserved', 'phase': phase}
                continue
            obj = containers.get(name)
            need(obj is not None and obj['phase'] == phase and type(row.get('id')) is str and
                 re.fullmatch(r'[0-9a-f]{64}', row['id']), 'immutable same-phase container binding required')
            if event == 'container-bound':
                need(obj['state'] == 'reserved' and row['id'] not in ids, 'distinct created container required')
                need(any(argv[2] == 'create' and '--name' in argv and argv[argv.index('--name') + 1] == name and
                         code == 0 and (size, digest) == (65, sha((row['id'] + '\n').encode()))
                         for argv, code, size, digest in operations), 'observed created container ID required')
                ids.add(row['id'])
                obj.update(state='bound', id=row['id'])
            else:
                need(row['id'] == obj.get('id'), 'container identity changed')
                if event == 'container-start-reserved':
                    need(obj['state'] == 'bound', 'fresh start reservation required')
                    obj['state'] = 'started'
                elif event == 'container-exited':
                    need(obj['state'] == 'started' and row.get('status') == 'exited' and
                         type(row.get('exit_code')) is int and row['exit_code'] == 0 and row.get('oom_killed') is False,
                         'observed clean owned container exit required')
                    need(operated(['start', '--attach', row['id']]), 'observed successful container start required')
                    obj['state'] = 'exited'
                elif event == 'container-removal-reserved':
                    need(obj['state'] == 'exited', 'removal before successful execution')
                    obj['state'] = 'removing'
                elif event == 'container-absent':
                    need(obj['state'] == 'removing', 'absence without removal reservation')
                    need(operated(['rm', '--force', '--volumes', row['id']]) and
                         all(operated(['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', selector], output=b'')
                             for selector in ('name=^/' + name + '$', 'id=' + row['id'])),
                         'observed owned removal and two absence selectors required')
                    obj['state'] = 'absent'
        elif event == 'image-removal-reserved':
            need(image_state == 'bound' and row.get('id') == image and
                 set(containers) == expected and all(obj['state'] == 'absent' for obj in containers.values()),
                 'image removal ownership required')
            image_state = 'removing'
        elif event == 'image-absent':
            need(image_state == 'removing' and row.get('id') == image and image_absence_verified and
                 operated(['image', 'rm', '--no-prune', image]) and
                 all(operated(['image', 'ls', '--quiet', '--no-trunc', '--filter', selector], output=b'')
                     for selector in ('reference=ksm-native-' + binding['nonce'], 'label=org.cachy-asahi.ksm-job=' + binding['nonce'])),
                 'image absence identity/operation required')
            image_removed, image_state = True, 'absent'
        elif event == 'cleanup-result':
            need(row.get('status') == 'PASS' and row.get('containers_absent') is True and
                 type(row.get('owned_image_absent')) is bool and
                 all(obj['state'] == 'absent' for obj in containers.values()), 'actual owned cleanup required')
            cleanup = row
    need(set(containers) == expected and all(obj['state'] == 'absent' for obj in containers.values()),
         'missing/pending owned operations')
    need(pending_operation is None and operations, 'complete actual Docker operation pairs required')
    need(image_state == ('absent' if final else 'bound') and
         (not final or cleanup is not None and cleanup['owned_image_absent'] is True), 'final owned image cleanup required')
    return {'status': 'PASS', 'containers_absent': True, 'image_absent': image_removed}


def validate_build(files, root, image, lock, recipe, *, uid, gid):
    record = decode(files[str(root / 'provenance.json')])
    wanted = {'schema_version': 1, 'status': 'built-package-static-pass', 'mode': 'native',
              'network': 'none', 'image': image, 'image_id': image, 'exit_code': 0,
              'hardware_status': 'NOT RUN', 'expected_packages_sha256': PACKAGES_SHA,
              'entry_script_sha256': ENTRY_SHA, 'recipe_inputs': recipe}
    need(all(type(record.get(key)) is type(value) and record[key] == value for key, value in wanted.items()),
         'completed native provenance required')
    need(record.get('builder_host_arch') in {'arm64', 'aarch64'} and
         type(record.get('source_date_epoch')) is int and record['source_date_epoch'] == 1791748800,
         'native build architecture/epoch required')
    name = record.get('clean_environment_id')
    need(type(name) is str and re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'clean builder name required')
    command = record.get('command')
    need(type(command) is list and all(type(x) is str for x in command) and
         command[:2] == ['docker', 'run'] and command[-2:] == [image, '/builder-entry.sh'] and
         command.count('--name') == command.count('--user') == 1 and
         command[command.index('--name') + 1] == name and
         command[command.index('--user') + 1] == f'{uid}:{gid}', 'bound build command required')
    need(type(record.get('files')) is dict and 0 < len(record['files']) <= 64 and
         type(record.get('artifacts')) is dict and len(record['artifacts']) == 1,
         'finite build evidence required')
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    need(required <= set(record['files']), 'complete build environment evidence required')
    for path, checksum in record['files'].items():
        relative(path)
        need(type(checksum) is str and HASH.fullmatch(checksum) and
             str(root / path) in files and sha(files[str(root / path)]) == checksum, 'build evidence drift')
    for path, checksum in recipe.items():
        relative(path)
        need(str(root / 'inputs' / path) in files and sha(files[str(root / 'inputs' / path)]) == checksum,
             'recipe snapshot drift')
    snapshots = {str(PurePosixPath(path).relative_to(root / 'inputs')) for path in files
                 if PurePosixPath(path).is_relative_to(root / 'inputs')}
    need(snapshots == set(recipe), 'exact recipe snapshot required')
    need(files.get(str(root / 'expected-packages.lock')) == files.get(str(root / 'artifacts/packages.lock')) == lock,
         'build inventory drift')
    validation = decode(files[str(root / 'validation.json')])
    need(validation.get('errors') == [] and type(validation.get('artifacts')) is list and
         len(validation['artifacts']) == 1 and validation['artifacts'][0].get('errors') == [],
         'static package validation required')
    filename, checksum = next(iter(record['artifacts'].items()))
    relative(filename)
    need('/' not in filename and type(checksum) is str and HASH.fullmatch(checksum) and
         record['files'].get('artifacts/' + filename) == checksum and
         sha(files[str(root / 'artifacts' / filename)]) == checksum, 'exact artifact binding required')
    actual_artifacts = {PurePosixPath(path).name for path in files if
                        PurePosixPath(path).parent == root / 'artifacts' and '.pkg.tar.' in PurePosixPath(path).name}
    need(actual_artifacts == {filename}, 'single recorded artifact required')
    return record, filename


def validate_producer(snapshot, producer_dir, observed_exit, binding, journal, *, consumer,
                      endpoint_observations=None):
    """Return immutable captured same-call base data after all eight build checks.

    The actual JSONL journal must include confirmed absence of owned containers.
    """
    clean_exit(observed_exit)
    validate_binding(binding)
    first_journal(journal)
    source = snapshot.files
    for path, pin in [('scripts/ci/inputs.lock.json', INPUTS_SHA),
                      ('scripts/ci/recipes.lock.json', RECIPES_SHA), ('scripts/ci/native_arm.py', PRODUCER_SHA)]:
        need(type(source.get(path)) is bytes and sha(source[path]) == pin, 'held producer input drift')
    need(snapshot.provenance['commit'] == binding['source_commit'] and
         snapshot.provenance['packet_sha256'] == binding['packet_sha256'], 'source packet job mismatch')
    root = canonical(producer_dir)
    data = {name: capture(root / name, 2 * 1024**2) for name in
            ('result.json', 'bootstrap.json', 'runner.json', 'image-id', 'inputs.lock.json', 'packages.lock')}
    result, boot, runner = (decode(data[name]) for name in ('result.json', 'bootstrap.json', 'runner.json'))
    image = data['image-id'].decode('ascii').strip()
    need(IMAGE.fullmatch(image) and sha(data['inputs.lock.json']) == INPUTS_SHA and
         sha(data['packages.lock']) == PACKAGES_SHA, 'accepted base image/inventory required')
    need(type(result.get('verified_signed_packages')) is int and result['verified_signed_packages'] == 248 and
         all(result.get(key) == value for key, value in {
             'mode': 'build', 'status': 'native-builds-and-byte-comparison-pass', 'native_build': 'PASS',
             'hardware_validation': 'NOT RUN', 'reviewed_inputs_sha256': INPUTS_SHA,
             'reviewed_recipes_sha256': RECIPES_SHA, 'bootstrap_script_sha256': PRODUCER_SHA}.items()),
         'completed signed original producer required')
    need(all(boot.get(key) == value for key, value in {'status': 'image-provisioned', 'image_id': image,
             'inputs_sha256': INPUTS_SHA, 'packages_lock_sha256': PACKAGES_SHA}.items()), 'bootstrap binding required')
    need(all(type(runner.get(key)) is type(value) and runner[key] == value for key, value in {
             'repository': 'Gabriel-Kahen/cachy-asahi', 'commit': binding['source_commit'], 'run_id': binding['run_id'],
             'uid': binding['uid'], 'gid': binding['gid'], 'runner_arch': 'ARM64', 'runner_os': 'Linux',
             'bootstrap_script_sha256': PRODUCER_SHA}.items()) and
         runner.get('docker_server_arch') in {'arm64', 'aarch64'} and type(runner.get('kernel')) is dict and
         runner['kernel'].get('system') == 'Linux' and runner['kernel'].get('machine') in {'arm64', 'aarch64'},
         'same-job native runner required')
    endpoint = runner.get('docker_endpoint')
    need(endpoint in {'unix:///run/docker.sock', 'unix:///var/run/docker.sock'}, 'held local runner endpoint required')
    if endpoint != binding['docker_endpoint']:
        observations = endpoint_observations
        need(type(observations) is dict and set(observations) == {endpoint, binding['docker_endpoint']} and
             all(type(row) is dict and set(row) == {'device', 'inode'} and
                 all(type(value) is int and value >= 0 for value in row.values()) and row['inode'] > 0
                 for row in observations.values()) and observations[endpoint] == observations[binding['docker_endpoint']],
             'observed same physical Docker socket aliases required')
        opened = first_journal(journal)
        need(observations[endpoint] == {'device': opened['docker_socket_device'], 'inode': opened['docker_socket_inode']},
             'runner alias differs from captured broker socket')
    recipes = decode(source['scripts/ci/recipes.lock.json'])
    need(len(recipes) == 4, 'four original recipes required')
    builds, names, total = [], [], sum(map(len, data.values()))
    for recipe_path, recipe in recipes.items():
        records, pair = [], []
        for index in (1, 2):
            path = root / (PurePosixPath(recipe_path).name + f'-{index}')
            files, _ = capture_build(path)
            total += sum(map(len, files.values()))
            need(total <= TOTAL_LIMIT, 'producer captured aggregate bound')
            record, filename = validate_build(files, path, image, data['packages.lock'], recipe,
                                              uid=binding['uid'], gid=binding['gid'])
            names.append(record['clean_environment_id'])
            records.append(record)
            pair.append((files, filename, path))
            builds.append({'directory': str(path), 'provenance': record,
                           'provenance_sha256': sha(files[str(path / 'provenance.json')]), 'files': files})
        need(names[-1] != names[-2] and pair[0][1] == pair[1][1], 'distinct original build pair required')
        filename = pair[0][1]
        need(pair[0][0][str(pair[0][2] / 'artifacts' / filename)] ==
             pair[1][0][str(pair[1][2] / 'artifacts' / filename)], 'original archive bytes differ')
        comparison_bytes = capture(root / (PurePosixPath(recipe_path).name + '-compare.json'), 2 * 1024**2)
        comparison = decode(comparison_bytes)
        consumer.validate_comparison(comparison, filename)
        data[PurePosixPath(recipe_path).name + '-compare.json'] = comparison_bytes
    need(len(set(names)) == 8, 'eight distinct original environments required')
    validate_journal(journal, binding, image, names, final=False)
    return freeze({'image_id': image, 'binding': dict(binding), 'runner_endpoint': endpoint, 'data': data,
                   'sha256': {key: sha(value) for key, value in data.items()}, 'builds': builds})


def validate_ksm_pair(snapshot, producer, build_dirs, observed_exits, approved_map, journal,
                      *, contract, consumer):
    """Use the captured held contract on the supervisor's private build namespace."""
    need(type(build_dirs) in (list, tuple) and len(build_dirs) == 2 and
         type(observed_exits) in (list, tuple) and len(observed_exits) == 2, 'two observed KSM builds required')
    for code in observed_exits:
        clean_exit(code)
    need(sha(snapshot.files['scripts/port/ksm-lifecycle/contract.py']) == CONTRACT_SHA,
         'held KSM contract pin required')
    roots = [canonical(path) for path in build_dirs]
    approved_map = canonical(approved_map)
    approved_bytes = capture(approved_map, 16384)
    need(sha(approved_bytes) == MAP_SHA, 'exact GPL15 recipe map required')
    approved = decode(approved_bytes)
    need(set(approved) == contract.INPUTS and all(sha(snapshot.files['packages/tools/cachy-asahi-ksmctl/' + name]) == pin
                                               for name, pin in approved.items()), 'captured GPL15 recipe drift')
    image, lock = producer['image_id'], producer['data']['packages.lock']
    files, records, names, hashes, dirs = [], [], [], [], []
    binding = plain(producer['binding'])
    for root in roots:
        captured, directory_info = capture_build(root)
        record, filename = validate_build(captured, root, image, lock, approved,
                                          uid=binding['uid'], gid=binding['gid'])
        files.append(captured)
        dirs.append(directory_info[str(root)])
        records.append(record)
        names.append(record['clean_environment_id'])
        hashes.append(sha(captured[str(root / 'provenance.json')]))
    need((dirs[0].st_dev, dirs[0].st_ino) != (dirs[1].st_dev, dirs[1].st_ino) and len(set(names)) == 2,
         'distinct real KSM builds required')
    need(set(names).isdisjoint({row['provenance']['clean_environment_id'] for row in producer['builds']}),
         'KSM build environment reused')
    all_names = [row['provenance']['clean_environment_id'] for row in producer['builds']] + names
    validate_journal(journal, binding, image, all_names, final=False)
    package, archive = contract.validate_build_pair(roots[0], roots[1], approved_map, image, lock)
    need(package['provenance_sha256'] == hashes and package['clean_environment_ids'] == names and
         package['approved_inputs_sha256'] == MAP_SHA and package['image_id'] == image and
         package['expected_packages_sha256'] == PACKAGES_SHA and package['source_date_epoch'] == 1791748800,
         'held pair/captured observation mismatch')
    filename = package['filename']
    need(all(captured[str(root / 'artifacts' / filename)] == archive for root, captured in zip(roots, files)) and
         sha(archive) == package['sha256'], 'captured KSM archives differ from validated pair')
    need(capture(approved_map, 16384) == approved_bytes, 'approved map changed during held validation')
    refs = [{'path': str(root / 'artifacts' / filename), 'size': len(archive), 'sha256': sha(archive)} for root in roots]
    return freeze({'package': package, 'archives': refs, 'archive_bytes': archive,
                   'provenance_sha256': hashes, 'environment_names': names})


def public_acceptance(snapshot, producer, pair, comparison, comparison_exit, lifecycle,
                      controller_exit, journal, *, consumer, public):
    """Construct the existing exact exporter schema after final observed cleanup."""
    clean_exit(comparison_exit)
    binding = plain(producer['binding'])
    package = plain(pair['package'])
    accepted_comparison = consumer.validate_comparison(comparison, package['filename'])
    source_names = ('scripts/client/stage.py', 'scripts/ci/source_suites.py',
                    'scripts/port/ksm-lifecycle/stage.py', 'scripts/port/ksm-lifecycle/worker.py',
                    'scripts/port/ksm-lifecycle/contract.py')
    pins = {name: sha(snapshot.files[name]) for name in source_names}
    lifecycle_binding = {key: binding[key] for key in ('source_commit', 'run_id', 'daemon_id')}
    lifecycle_binding['docker_endpoint'] = producer['runner_endpoint']
    lifecycle_binding['image_id'] = producer['image_id']
    accepted_lifecycle = consumer.validate_lifecycle(lifecycle, lifecycle_binding, pins, package,
                                                     controller_exit=controller_exit)
    need(lifecycle.get('coordinator_uid') == binding['uid'] and type(lifecycle.get('coordinator_uid')) is int and
         lifecycle.get('coordinator_gid') == binding['gid'] and type(lifecycle.get('coordinator_gid')) is int and
         lifecycle.get('runner_sha256') == producer['sha256']['runner.json'] and
         lifecycle.get('bootstrap_sha256') == producer['sha256']['bootstrap.json'] and
         lifecycle.get('packages_sha256') == PACKAGES_SHA and lifecycle.get('current_inputs_sha256') == INPUTS_SHA,
         'lifecycle accepted base binding required')
    opened = first_journal(journal)
    need(lifecycle.get('docker_cli_sha256') == opened.get('docker_sha256') and
         type(lifecycle.get('docker_socket_device')) is int and type(lifecycle.get('docker_socket_inode')) is int and
         lifecycle['docker_socket_device'] == opened.get('docker_socket_device') and
         lifecycle['docker_socket_inode'] == opened.get('docker_socket_inode'), 'same captured lifecycle CLI/socket required')
    names = [row['provenance']['clean_environment_id'] for row in producer['builds']] + list(pair['environment_names'])
    validate_journal(journal, binding, producer['image_id'], names, final=True)
    final_binding = {key: binding[key] for key in ('source_commit', 'run_id', 'packet_sha256')}
    final_binding.update(image_id=producer['image_id'], inputs_sha256=INPUTS_SHA,
                         packages_sha256=PACKAGES_SHA, recipe_map_sha256=MAP_SHA)
    value = {'schema_version': 1, 'status': 'PASS', 'scope': 'DEVELOPMENT TEST ONLY', 'binding': final_binding,
             'producer': {'status': 'PASS', 'cleanup': 'PASS'},
             'builds': [{'status': 'PASS', 'filename': package['filename'], 'sha256': package['sha256'],
                         'provenance_sha256': digest, 'container_cleanup': 'PASS'} for digest in pair['provenance_sha256']],
             'comparison': accepted_comparison, 'lifecycle': accepted_lifecycle,
             'source_notices': {'gpl15_recipe_snapshot': True, 'notice_preserved': True, 'license_preserved': True},
             'cleanup': {'status': 'PASS', 'absence_verified': True}}
    encoded = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    need(len(encoded) <= 65536, 'bounded consumer acceptance required')
    public.validate(encoded, final_binding, plain(pair['archives']))
    return encoded, final_binding
