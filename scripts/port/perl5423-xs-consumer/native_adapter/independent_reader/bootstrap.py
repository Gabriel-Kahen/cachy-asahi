# SPDX-License-Identifier: MIT
"""Passive joins for the hosted XS bootstrap, daemon and Docker evidence."""
import hashlib
import json
from pathlib import PurePosixPath as Path
import re
import stat
import types

MIB = 1024**2
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
OPERATION = 'perl5423-native-xs-v1'
HELD_MAP = '4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96'
INVENTORY = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
PAIR = dict(source='25dc3e65bdb6137c87a9409067fe9b2cf6e9763f', run='43692477455', job='132745843566')
DECISION = dict(bytes=5804, sha256='27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1')
NATIVE_SHA = '40c048fbbb6599bdb61ed8b105708b2d21db8ea2b2732258e1225a48c635d146'
RUNNER_SHA = 'bf2903fd1f72fe5c33a71bd00a15f71e7a4ae153d13522682af4f71d660e580e'
TMPFS = {'/run': 'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001',
         '/tmp': 'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001',
         '/xs-work': 'rw,exec,nosuid,nodev,size=256m,uid=1001,gid=1001,mode=0700'}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def native_path(value, io):
    io.need(type(value) is str and re.fullmatch('/[A-Za-z0-9._+/-]{1,4095}', value) and
            all(x not in ('', '.', '..') for x in value.split('/')[1:]), 'canonical observed native path')
    return Path(value)


def signed(status, io):
    io.need(type(status) is str and len(status) <= 65536, 'bounded GPG status')
    rows = [line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    io.need(not any(not r or r[0] in ('EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG',
                                    'NO_PUBKEY', 'FAILURE', 'ERROR') for r in rows), 'GPG failure/expiry status')
    valid = [r for r in rows if r[0] == 'VALIDSIG']
    io.need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == SIGNER,
            'one exact pinned primary GPG signer')


class Sequence:
    """Consume every captured operation once, in its immutable Source order."""
    def __init__(self, rows, captures, io):
        self.rows, self.captures, self.io, self.index = rows, captures, io, 0

    def take(self, argv, *, code=0, data=None, empty_error=True):
        self.io.tick()
        self.io.need(self.index < len(self.rows), 'missing ordered operation')
        row = self.rows[self.index]
        out, err = self.captures[self.index]
        self.io.need(row['argv'] == argv and row['returncode'] == code, 'ordered exact operation/exit differs')
        if empty_error:
            self.io.need(not err.strip(), 'unexpected operation stderr')
        if data is not None:
            self.io.need(out == data, 'actual raw operation body differs')
        self.index += 1
        return out, err

    def end(self):
        self.io.need(self.index == len(self.rows), 'unconsumed or unrelated operation')


def source_job(get, source_root, b, source_map, h, io):
    proof_raw = get('source-readback.json')
    proof = io.decode(proof_raw)
    io.need(io.pin(proof_raw)['sha256'] == h['source_readback_sha256'] and
            proof['schema'] == 1 and proof['status'] == 'PASS_EXACT_HOSTED_XS_SOURCE_READBACK' and
            proof['binding'] == {k: v for k, v in b.items() if k != 'job'}, 'actual same-Source readback')
    io.need(io.decode(get('binding.json')) == b, 'actual job binding differs')
    jobs = io.decode(get('job-metadata.json'))
    io.need(jobs['total_count'] == len(jobs['jobs']) == 1, 'one actual hosted job')
    job = jobs['jobs'][0]
    io.need(job['name'] == OPERATION and job['id'] == int(b['job']) and
            job['run_id'] == int(b['run']) and job['head_sha'] == b['source'], 'actual job/run/Source metadata join')
    expected = dict(source_map['files'])
    expected['source-map.json'] = dict(**io.pin(io.read(source_root, 'source-map.json', MIB)), mode=0o644)
    io.need(set(proof['files']) == set(expected), 'whole actual Source readback membership')
    for name, row in proof['files'].items():
        io.tick()
        io.need(set(row) == {'bytes', 'sha256', 'mode', 'blob'} and
                {k: row[k] for k in ('bytes', 'sha256', 'mode')} == expected[name], 'actual Source leaf pin/mode')
        body = io.read(source_root, name, 64 * MIB)
        io.need(hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == row['blob'],
                'actual Git blob/body join')
    actors = proof['actors']
    io.need(type(actors) is list and len(actors) == 2, 'exact two read-only Git actors')
    first = actors[0]['argv']
    io.need(type(first) is list and len(first) == 11 and type(first[3]) is str and
            first[3].startswith('--work-tree='), 'observed Git Source operand')
    native_source = native_path(first[3][len('--work-tree='):], io)
    git = ['/usr/bin/git', '--no-replace-objects', '--git-dir=' + str(native_source / '.git'),
           '--work-tree=' + str(native_source), '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false']
    io.need(io.decode(get('proof/operations.json')) == actors, 'whole Source proof operation index')
    bodies = []
    for index, (row, argv) in enumerate(zip(actors, [git + ['rev-parse', '--verify', 'HEAD'],
                                                  git + ['ls-tree', '-rz', '--full-tree', b['source']]])):
        io.need(row['argv'] == argv and type(row['returncode']) is int and row['returncode'] == 0 and
                io.natural(row['lifecycle'], max_seconds=60) == 0, 'natural exact Source Git command')
        for key in ('stdout', 'stderr'):
            io.need(row[key] == f'proof/operations/{index:03d}.{key}' and
                    io.pin(get(row[key])) == row[key + '_pin'], 'Source proof raw stream pin')
        io.need(not get(row['stderr']), 'Source Git stderr')
        bodies.append(get(row['stdout']))
    io.need(bodies[0].strip() == b['source'].encode(), 'actual published Source HEAD')
    found = {}
    for record in bodies[1].split(b'\0'):
        if not record:
            continue
        header, name = record.split(b'\t', 1)
        mode, kind, oid = header.decode().split()
        name = name.decode()
        io.need(name in expected and name not in found and kind == 'blob' and mode in ('100644', '100755'),
                'literal unique published Git tree leaf')
        found[name] = dict(mode=int(mode[-3:], 8), blob=oid)
    io.need(found == {n: {k: r[k] for k in ('mode', 'blob')} for n, r in proof['files'].items()},
            'raw Git tree joins whole Source table')
    return native_source


def passive_hosted(source_root, source_map, io):
    # This immutable module contains passive DATA classifiers only. Never import
    # the held entry/bootstrap/native producer or any actor implementation.
    name = 'held/hosted/reader.py'
    body = io.read(source_root, name, MIB)
    io.need(io.pin(body) == {k: source_map['files'][name][k] for k in ('bytes', 'sha256')},
            'immediately pinned passive daemon classifier')
    module = types.ModuleType('_xs_independent_held_data')
    module.__file__ = str(source_root) + '/' + name
    exec(compile(body, module.__file__, 'exec'), module.__dict__)
    return module


def boot_operations(get, h, io):
    raw = get('bootstrap/operations.json', 2 * MIB)
    io.need(io.pin(raw)['sha256'] == h['bootstrap_operations_sha256'], 'actual complete bootstrap operation index')
    rows = io.decode(raw)
    io.need(type(rows) is list and 1 <= len(rows) <= 600, 'bounded bootstrap operation count')
    captures, seconds = [], 0
    for index, row in enumerate(rows):
        io.tick()
        io.need(set(row) == {'argv', 'stdout', 'stderr', 'stdout_pin', 'stderr_pin', 'lifecycle', 'returncode'} and
                type(row['argv']) is list and 1 <= len(row['argv']) <= 64 and
                all(type(v) is str and 0 < len(v) <= 4096 for v in row['argv']), 'complete finite bootstrap operation row')
        code = io.natural(row['lifecycle'], zero=False, max_seconds=1800)
        io.need(type(row['returncode']) is int and code == row['returncode'], 'actual bootstrap direct exit join')
        seconds += row['lifecycle']['elapsed_seconds']
        for key in ('stdout', 'stderr'):
            io.need(row[key] == f'bootstrap/operations/{index:03d}.{key}', 'literal bootstrap raw stream path')
        out, err = get(row['stdout']), get(row['stderr'])
        io.need(io.pin(out) == row['stdout_pin'] and io.pin(err) == row['stderr_pin'], 'bootstrap whole raw stream pins')
        captures.append((out, err))
    io.need(seconds <= 5340, 'bootstrap/preparation/cleanup aggregate actor budget')
    return Sequence(rows, captures, io)


def policy(row, image, name, mounts, tmpfs, io, *, initializer=False):
    h, x = row['HostConfig'], row['Config']
    io.need(row['Name'] == '/' + name and row['Image'] == image and row['State']['Running'] is False and
            x['User'] == ('0:0' if initializer else '1001:1001'), 'actual stopped container image/name/user')
    io.need(h['NanoCpus'] == 2000000000 and h['Memory'] == h['MemorySwap'] == 4294967296 and
            h['PidsLimit'] == 256 and h['ReadonlyRootfs'] is True and h['NetworkMode'] == 'none' and
            h['CapDrop'] == ['ALL'] and (h.get('CapAdd') == ['CHOWN'] if initializer else not h.get('CapAdd')) and
            h['SecurityOpt'] == ['no-new-privileges'] and not h['Privileged'] and
            not h.get('Devices') and not h.get('DeviceRequests'), 'actual CPU/memory/swap/PID/capability/isolation policy')
    if not initializer:
        io.need(h['Init'] is True and h['CgroupnsMode'] == 'private' and h['Tmpfs'] == tmpfs and
                x['Hostname'] == 'perl5423-native', 'actual private init/cgroup/tmpfs/hostname policy')
    actual = {m['Destination']: m for m in row['Mounts']}
    io.need(len(row['Mounts']) == len(mounts) and set(actual) == set(mounts), 'exact container mounts')
    for destination, (kind, value, rw) in mounts.items():
        m = actual[destination]
        io.need(m['Type'] == kind and m['RW'] is rw and m['Name' if kind == 'volume' else 'Source'] == value,
                'actual mount type/source/write policy')


def stopped(row, image, io):
    io.need(row['Image'] == image and row['State']['Running'] is False and
            type(row['State']['Pid']) is int and row['State']['Pid'] == 0 and
            type(row['State']['ExitCode']) is int and row['State']['ExitCode'] == 0 and
            row['State']['OOMKilled'] is False, 'actual natural zero stopped container')


def preparation_argv(name, image, bundle, source, sha, b):
    return DOCKER + ['create', '--name', name, '--label', 'cachy-asahi.operation=' + OPERATION,
        '--label', 'cachy-asahi.admission=' + sha, '--label', 'cachy-asahi.hosted-perl.source=' + b['source'],
        '--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256', '--init', '--read-only',
        '--network=none', '--cgroupns=private', '--hostname=perl5423-native', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--user=1001:1001', '--ulimit=nofile=1024:1024', '--ulimit=core=0:0',
        *['--tmpfs=' + k + ':' + v for k, v in TMPFS.items()],
        '--mount', f'type=bind,src={source},dst=/source,readonly',
        '--mount', f'type=bind,src={bundle},dst=/inputs', '--workdir=/inputs',
        '--entrypoint=/usr/bin/python3', image, '-I', '-B', '/source/xs/prepare_inputs.py']


def image_data(raw, image, token, b, io):
    rows = io.decode(raw)
    io.need(type(rows) is list and len(rows) == 1, 'one actual image inspection')
    row = rows[0]
    io.need(row['Id'] == image and row['Architecture'] == 'arm64' and row['Os'] == 'linux' and
            not row['Config'].get('Volumes') and row['RepoTags'] == ['perl-native-base:' + token] and
            row['Config']['Labels'].get('cachy-asahi.hosted-perl') == token and
            row['Config']['Labels'].get('cachy-asahi.hosted-perl.source') == b['source'],
            'actual owned native image/no inherited volumes/aliases')
    return row


def signed_bootstrap(get, source_root, source_map, b, h, seq, daemon, source, helper, io):
    image = h['bootstrap']['image']
    io.need(re.fullmatch('sha256:[0-9a-f]{64}', image), 'actual immutable bootstrap image')
    token = hashlib.sha256((b['source'] + ':' + b['ref'] + ':' + b['run']).encode()).hexdigest()[:24]
    tag, label = 'perl-native-base:' + token, 'cachy-asahi.hosted-perl'
    for command, key in [('info', 'info'), ('version', 'version')]:
        out, _ = seq.take(DOCKER + [command, '--format', '{{json .}}'])
        io.need(io.decode(out) == daemon[key], 'actual daemon proof joins bootstrap raw metadata')
    original = io.decode(io.read(source_root, 'held/original/bootstrap/scripts/ci/inputs.lock.json', MIB))
    profile = io.decode(io.read(source_root, 'held/original/native/input-profile.json', MIB))
    combined = dict(original, packages=original['packages'] + profile['additions']['rows'])
    io.need(len(original['packages']) == 248 and len(profile['additions']['rows']) == 8 and
            original['signer_fingerprint'] == SIGNER and io.decode(get('bootstrap/inputs.lock.json')) == combined,
            'exact original248 plus fixed8 inputs and signer')
    proof = io.decode(get('bootstrap/proof.json'))
    io.need(proof['status'] == 'PASS_FRESH_SIGNED349_BOOTSTRAP' and
            proof['binding'] == dict(b, source_map_sha256=HELD_MAP, outer_source_map_sha256=b['source_map_sha256']) and
            h['bootstrap_binding'] == proof['binding'] and
            all(proof[k] == v for k, v in h['bootstrap'].items()), 'bootstrap proof/bindings join current Root operation')
    for filename, key in [('inputs.lock.json', 'inputs_sha256'), ('acquisition.json', 'acquisition_sha256'),
                          ('signatures.json', 'signatures_sha256'), ('input-data-preparation.json', 'preparation_sha256'),
                          ('fixed-eight-cache.json', 'cache_additions_sha256')]:
        io.need(io.pin(get('bootstrap/' + filename))['sha256'] == proof[key], 'whole bootstrap receipt pin')
    def signature(row):
        return dict(filename=row['filename'] + '.sig', url=row['url'] + '.sig',
                    size=row['signature_size'], sha256=row['signature_sha256'])
    payloads = [combined['rootfs'], *combined['packages']]
    items = combined['keyring_files'] + [r for item in payloads for r in (item, signature(item))]
    acquisition = io.decode(get('bootstrap/acquisition.json'))
    io.need(len(items) == 517 and len({r['filename'] for r in items}) == 517 and
            acquisition['schema_version'] == 1 and acquisition['acquisition'] == 'PASS' and
            acquisition['signature_authentication'] == 'NOT RUN', 'bounded exact acquisition receipt')
    io.need(acquisition['counts'] == {'total': 517, 'pass': 517, 'fail': 0, 'pending': 0} and
            all(type(v) is int for v in acquisition['counts'].values()) and
            set(acquisition['inputs']) == {r['filename'] for r in items}, 'actual complete PASS517 acquisition')
    for row in items:
        io.need(acquisition['inputs'][row['filename']] == dict(status='PASS', expected_sha256=row['sha256'],
                expected_bytes=row['size']), 'each acquired exact size/hash')
    signatures = io.decode(get('bootstrap/signatures.json'))
    io.need(set(signatures) == {r['filename'] for r in payloads}, 'all257 signed payloads')
    home = native_path(signatures[payloads[0]['filename']]['command'][4], io)
    io.need(home.name == 'gpg' and home.parent.name == 'bootstrap' and home.parent.parent.name == 'perl-hosted',
            'actual fixed private bootstrap GPG home')
    work, cache = home.parent.parent, home.parent.parent.parent / 'alarm-cache'
    io.need(not work.is_relative_to(source) and not source.is_relative_to(work), 'native work and Source paths are disjoint')
    seq.take(['gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve',
              '--import', str(cache / 'archlinuxarm.gpg')], empty_error=False)
    for item in payloads:
        row = signatures[item['filename']]
        signed(row['status'], io)
        argv = ['gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve',
                '--status-fd', '1', '--verify', str(cache / (item['filename'] + '.sig')), str(cache / item['filename'])]
        io.need(row['command'] == argv and type(row['exit_code']) is int and row['exit_code'] == 0,
                'actual exact zero GPG verification')
        out, err = seq.take(argv, empty_error=False)
        io.need((out, err) == (row['status'].encode(), row['diagnostic'].encode()), 'GPG receipt joins raw natural actor streams')
    lock = get('bootstrap/packages.lock')
    io.need(io.pin(lock)['sha256'] == INVENTORY == proof['expected349_sha256'] and
            lock == io.read(source_root, 'held/original/native/expected349.lock', MIB), 'actual complete signed349 inventory')
    for selector in ('reference=' + tag, 'label=' + label + '=' + token):
        out, _ = seq.take(DOCKER + ['image', 'ls', '--no-trunc', '-q', '--filter', selector])
        io.need(not out.strip(), 'empty owned image baseline')
    build = DOCKER + ['build', '--no-cache', '--tag', tag, '--label', label + '=' + token,
        '--label', label + '.source=' + b['source'], '--network=none', '--pull=false', '--platform=linux/arm64',
        '--iidfile', str(work / 'bootstrap/image-id'), str(work / 'bootstrap/context')]
    seq.take(build, empty_error=False)
    record = io.decode(get('bootstrap/bootstrap.json'))
    io.need(record['status'] == 'image-provisioned' and record['image_id'] == image and
            record['inputs_sha256'] == proof['inputs_sha256'] and record['packages_lock_sha256'] == INVENTORY,
            'actual bootstrap completion record')
    out, _ = seq.take(DOCKER + ['image', 'inspect', image])
    image_data(out, image, token, b, io)
    inventory = DOCKER + ['run', '--name', 'perl-bootstrap-inventory-' + token,
        '--label', label + '=' + token, '--label', label + '.source=' + b['source'],
        '--cpus=1', '--memory=128m', '--memory-swap=128m', '--pids-limit=32', '--rm', '--pull=never',
        '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
        '--entrypoint=/bin/cat', image, '/builder-packages.lock']
    seq.take(inventory, data=lock)
    out, _ = seq.take(DOCKER + ['image', 'inspect', image])
    actual = image_data(out, image, token, b, io)
    io.need(io.pin(encoded(actual))['sha256'] == proof['image_inspect_sha256'], 'actual image receipt hash')
    helper.daemon_data(daemon)
    io.need(daemon['storage']['work_filesystems'][1]['path'] == str(work), 'actual bootstrap/work filesystem continuity')
    return image, work, token, home


def preparation(get, source_root, source_map, b, h, image, work, source, seq, io):
    raw = get('preparation-delegation.json')
    delegation = io.decode(raw)
    sha = io.pin(raw)['sha256']
    expected = dict(schema=1, authorization='ROOT_ADMITTED_NATIVE_XS_DATA_PREPARATION', binding=b,
        image=image, accepted_pair=PAIR, accepted_reader_receipt=DECISION,
        generator_sha256=source_map['files']['xs/prepare_inputs.py']['sha256'],
        allowed_outputs=['prefix', 'xs-admission.json', 'xs-inputs.json', 'xs-plan.json', 'preparation.json'],
        roles=dict(Perl=0, make=0, compiler=0, XS=0), native_acceptance=False, XS_acceptance=False)
    io.need(delegation == expected and raw == encoded(expected), 'Root-bound DATA-only preparation delegation')
    name = h['preparation']['name']
    io.need(re.fullmatch('perl-xs-prep-' + re.escape(b['run']) + '-[0-9a-f]{12}', name) and
            h['preparation']['delegation_sha256'] == sha, 'actual unique delegated preparation name')
    bundle = work / 'bundle'
    out, _ = seq.take(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
    io.need(name not in out.decode().splitlines(), 'empty preparation container baseline')
    out, _ = seq.take(DOCKER + ['image', 'inspect', image])
    token = hashlib.sha256((b['source'] + ':' + b['ref'] + ':' + b['run']).encode()).hexdigest()[:24]
    image_data(out, image, token, b, io)
    seq.take(preparation_argv(name, image, bundle, source, sha, b))
    before_raw, _ = seq.take(DOCKER + ['inspect', name], data=get('preparation-before.json'))
    before = io.decode(before_raw)[0]
    policy(before, image, name, {'/source': ('bind', str(source), False), '/inputs': ('bind', str(bundle), True)}, TMPFS, io)
    io.need(before['Config']['Entrypoint'] == ['/usr/bin/python3'] and before['Config']['WorkingDir'] == '/inputs' and
            before['Config']['Cmd'] == ['-I', '-B', '/source/xs/prepare_inputs.py'] and
            before['Config']['Labels'].get('cachy-asahi.admission') == sha and
            before['Config']['Labels'].get('cachy-asahi.hosted-perl.source') == b['source'], 'actual fixed prep entry/delegation')
    body = get('preparation.json', 2 * MIB)
    seq.take(DOCKER + ['start', '--attach', name], data=body)
    after_raw, _ = seq.take(DOCKER + ['inspect', name], data=get('preparation-after.json'))
    after = io.decode(after_raw)[0]
    stopped(after, image, io)
    io.need(after['Id'] == before['Id'], 'same naturally retired preparation container')
    io.need(body == get('bundle/preparation.json', 2 * MIB) and
            io.pin(body) == {k: h['preparation'][k] for k in ('bytes', 'sha256')}, 'whole actual preparation receipt copies/pin')
    row = io.decode(body)
    io.need(row['schema'] == 1 and row['status'] == 'PREPARED_NATIVE_XS_DATA_ONLY' and row['planning_stage_removed'] is True and
            row['native_acceptance'] is row['XS_acceptance'] is False and
            all(type(row[k]) is int and row[k] == 0 for k in ('Perl_invocations', 'compiler_invocations', 'XS_loads')),
            'bounded DATA-only preparation, no acceptance/Perl/compiler/XS execution')
    runtime = row['runtime']
    io.need(runtime == dict(uid=1001, gid=1001, architecture='aarch64',
            limits={'cpu.max': '200000 100000', 'memory.max': '4294967296', 'memory.swap.max': '0', 'pids.max': '256'},
            capabilities='ZERO', NoNewPrivs=1, network='LO_ONLY'), 'actual DATA preparation resource observation')
    for filename, key in [('xs-inputs.json', 'inputs'), ('xs-admission.json', 'admission'), ('xs-plan.json', 'plan')]:
        io.need(io.pin(get('bundle/' + filename)) == row[key], 'actual generated preparation operand pin')
    seq.take(DOCKER + ['rm', name])
    out, _ = seq.take(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
    io.need(name not in out.decode().splitlines(), 'preparation retired before XS producer')
    return name


def bootstrap_cleanup(seq, h, image, token, home, prep, b, io):
    seq.take(['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'])
    for name in (prep, 'perl-bootstrap-inventory-' + token):
        out, _ = seq.take(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}', '--filter', 'name=^' + name + '$'])
        io.need(not out.strip() and h['cleanup'][name] == 'ABSENT', 'actual prep/inventory final absence')
    out, _ = seq.take(DOCKER + ['image', 'inspect', image])
    image_data(out, image, token, b, io)
    out, _ = seq.take(DOCKER + ['image', 'rm', image])
    io.need(('Deleted: ' + image).encode() in out.splitlines() and
            all(line.startswith((b'Deleted: ', b'Untagged: ')) for line in out.splitlines()), 'actual no-force owned image retirement')
    out, err = seq.take(DOCKER + ['image', 'inspect', image], code=1, empty_error=False)
    io.need(out.strip() in (b'', b'[]') and err.decode().strip() == 'Error response from daemon: No such image: ' + image,
            'actual exact image ID absence')
    for selector in ('reference=perl-native-base:' + token, 'label=cachy-asahi.hosted-perl=' + token):
        out, _ = seq.take(DOCKER + ['image', 'ls', '--no-trunc', '-q', '--filter', selector])
        io.need(not out.strip(), 'actual owned image alias absence')
    seq.end()
    io.need(h['cleanup']['gpg_agent_absent'] is True and h['cleanup']['image_absent'] is True and
            h['cleanup']['image'] == image and not h['cleanup'].get('errors'), 'bootstrap final absence/retirement receipt')


def actor_argv(name, volume, image, bundle, sha):
    return DOCKER + ['create', '--name', name, '--label', 'cachy-asahi.operation=' + OPERATION,
        '--label', 'cachy-asahi.admission=' + sha, '--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256',
        '--init', '--read-only', '--network=none', '--cgroupns=private', '--hostname=perl5423-native', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--user=1001:1001', '--ulimit=nofile=1024:1024', '--ulimit=core=0:0',
        *['--tmpfs=' + k + ':' + v for k, v in TMPFS.items()],
        '--mount', f'type=bind,src={bundle},dst=/inputs,readonly', '--mount', f'type=volume,src={volume},dst=/work',
        '--workdir=/work', '--entrypoint=/usr/bin/python3', image, '-I', '-B',
        '/inputs/consumer/native_adapter/native.py', 'actor', '--admission-sha256', sha]


def producer(get, image, work, h, b, daemon, io):
    op_raw = get('xs/operation.json')
    io.need(op_raw == get('bundle/operation.json') and io.pin(op_raw)['sha256'] == h['operation_sha256'], 'actual Root operation copies/pin')
    op = io.decode(op_raw)
    sha = io.pin(op_raw)['sha256']
    io.need(op['schema'] == 1 and op['operation'] == OPERATION and
            op['authorization'] == 'ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS' and
            op['source'] == dict(sha=b['source'], ref=b['ref'].removeprefix('refs/heads/')) and
            all(op[k] == b[k] for k in ('run', 'job', 'approval')) and op['pair'] == PAIR and op['image'] == image and
            op['source_readback_sha256'] == h['source_readback_sha256'] and
            op['native_daemon_identity_sha256'] == h['daemon_identity_sha256'] and
            op['input_signature_audit_sha256'] == h['bootstrap']['signatures_sha256'] and op['expected349_sha256'] == INVENTORY and
            op['runner_sha256'] == RUNNER_SHA and op['runtime_identity_generator_sha256'] == NATIVE_SHA and
            op['authorize_runtime_observation_only'] is True and
            op['accepted_reader_receipt'] == dict(path='/inputs/accepted-reader.json', **DECISION) and
            op['nested_invocation'] == 'NOT_INVOKED' and op['nested_qualification'] == 'NOT_QUALIFIED', 'exact delegated XS operation bindings')
    for name, key in [('xs-admission.json', 'xs_admission_sha256'), ('xs-inputs.json', 'inputs_sha256'),
                      ('xs-plan.json', 'plan_sha256'), ('bundle-map.json', 'bundle_map_sha256')]:
        io.need(io.pin(get('bundle/' + name))['sha256'] == op[key], 'prepared whole operand to Root operation join')
    report = io.decode(get('xs/producer-receipt.json'))
    io.need(report['schema'] == 1 and report['status'] == 'SMOKE_EVIDENCE_EXPORTED_PENDING_INDEPENDENT_READER' and
            report['operation_sha256'] == sha and report['native_acceptance'] is report['XS_acceptance'] is False and
            report['qualification'] == 'NOT_GRANTED' and report['owned_resources_absent'] is True and
            not any(k in report for k in ('error', 'actor_error', 'cleanup_error')), 'actual XS producer completion without acceptance')
    planned = report['planned']
    name, init, volume = (planned[k] for k in ('actor', 'init', 'volume'))
    io.need(re.fullmatch('perl-xs-' + re.escape(b['run']) + '-[0-9a-f]{12}', name) and
            init == name + '-init' and volume == name + '-work', 'exact unique owned XS resource names')
    rows = report['operations']
    io.need(type(rows) is list and len(rows) == 22, 'exact successful native XS operation count')
    captures, seconds = [], 0
    for index, row in enumerate(rows):
        io.tick()
        io.need(set(row) == {'argv', 'lifecycle', 'log', 'returncode', 'launched'} | ({'stdout'} if index == 13 else set()) and
                row['log'] == f'command-{index:03d}.log' and row['launched'] is True and
                type(row['returncode']) is int and row['returncode'] == 0 and
                io.natural(row['lifecycle'], max_seconds=300 if index == 11 else 120) == 0, 'natural bounded exact XS CLI row')
        captures.append((get('xs/' + row['log'], 8 * MIB), b''))
        seconds += row['lifecycle']['elapsed_seconds']
    io.need(seconds <= 600, 'complete XS producer actor budget')
    seq = Sequence(rows, captures, io)
    out, _ = seq.take(DOCKER + ['image', 'inspect', image], data=get('xs/image-inspect.json'))
    token = hashlib.sha256((b['source'] + ':' + b['ref'] + ':' + b['run']).encode()).hexdigest()[:24]
    image_data(out, image, token, b, io)
    actual = io.decode(get('xs/actual-daemon.json'))
    for command, key in [('info', 'info'), ('version', 'version')]:
        out, _ = seq.take(DOCKER + [command, '--format', '{{json .}}'])
        io.need(io.decode(out) == actual[key], 'actual XS daemon raw metadata join')
    io.need(get('xs/root-daemon-proof.json') == get('daemon.json'), 'unchanged Root daemon proof copy')
    for key in ('ID', 'OSType', 'Architecture', 'SecurityOptions', 'CgroupVersion', 'CpuCfsQuota',
                'MemoryLimit', 'SwapLimit', 'PidsLimit', 'DockerRootDir'):
        io.need(actual['info'][key] == daemon['info'][key], 'actual same Rootful unremapped daemon identity')
    socket = actual['socket_before']
    io.need(type(socket) is list and socket == actual['socket_after'] and len(socket) == 5 and
            all(type(v) is int and v >= 0 for v in socket) and socket[1] > 0 and socket[3] == 0 and
            stat.S_ISSOCK(socket[2]) and actual['version']['Server'] == daemon['version']['Server'], 'actual stable root-owned socket/native daemon version')
    out, _ = seq.take(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
    io.need(not {name, init} & set(out.decode().splitlines()), 'owned XS containers initially absent')
    out, _ = seq.take(DOCKER + ['volume', 'ls', '--quiet'])
    io.need(volume not in out.decode().splitlines(), 'owned XS volume initially absent')
    label = 'cachy-asahi.admission=' + sha
    seq.take(DOCKER + ['volume', 'create', '--label', label, volume])
    init_argv = DOCKER + ['create', '--name', init, '--label', label, '--cpus=2', '--memory=4g', '--memory-swap=4g',
        '--pids-limit=256', '--network=none', '--read-only', '--user=0:0', '--cap-drop=ALL', '--cap-add=CHOWN',
        '--security-opt=no-new-privileges', '--mount', f'type=volume,src={volume},dst=/work',
        '--entrypoint=/usr/bin/chown', image, '1001:1001', '/work']
    seq.take(init_argv)
    out, _ = seq.take(DOCKER + ['inspect', init], data=get('xs/init-before.json'))
    init_row = io.decode(out)[0]
    policy(init_row, image, init, {'/work': ('volume', volume, True)}, None, io, initializer=True)
    io.need(init_row['Config']['Entrypoint'] == ['/usr/bin/chown'] and init_row['Config']['Cmd'] == ['1001:1001', '/work'],
            'fixed CHOWN-only initializer argv')
    seq.take(DOCKER + ['start', '--attach', init])
    bundle = work / 'bundle'
    seq.take(actor_argv(name, volume, image, bundle, sha))
    out, _ = seq.take(DOCKER + ['inspect', name], data=get('xs/actor-before.json'))
    before = io.decode(out)[0]
    policy(before, image, name, {'/inputs': ('bind', str(bundle), False), '/work': ('volume', volume, True)}, TMPFS, io)
    io.need(before['Config']['Entrypoint'] == ['/usr/bin/python3'] and before['Config']['WorkingDir'] == '/work' and
            before['Config']['Cmd'] == ['-I', '-B', '/inputs/consumer/native_adapter/native.py', 'actor', '--admission-sha256', sha],
            'actual fixed native XS entry argv')
    seq.take(DOCKER + ['start', '--attach', name])
    out, _ = seq.take(DOCKER + ['inspect', name], data=get('xs/actor-after.json'))
    after = io.decode(out)[0]
    stopped(after, image, io)
    io.need(after['Id'] == before['Id'], 'same retired XS actor')
    seq.take(DOCKER + ['cp', name + ':/work/output', '-'])
    io.need(rows[13]['stdout'] == 'output.tar', 'captured bounded DATA tar path')
    exported = io.export(get('xs/output.tar', 256 * MIB))
    io.need(io.names('xs/exported') == set(exported), 'complete actual tar/exported namespace')
    for filename, (body, mode) in exported.items():
        io.tick()
        io.need(get('xs/exported/' + filename, 64 * MIB) == body, 'raw tar joins every exported file')
    evidence_map = io.decode(exported['evidence-map.json'][0])
    io.need(type(evidence_map) is dict and 1 <= len(evidence_map) <= 50, 'complete finite flattened runner map')
    membership = {'evidence-map.json', 'actor-result.json', 'runtime-observation.json',
                  'actual-packages.txt', 'operation.json', 'accepted-reader.json'}
    for relative, row in evidence_map.items():
        io.need(re.fullmatch('[A-Za-z0-9._+/-]+', relative) and all(x not in ('', '.', '..') for x in relative.split('/')) and
                re.fullmatch(r'evidence-[0-9]{3}\.data', row['file']) and row['file'] not in membership and
                io.pin(exported[row['file']][0]) == {k: row[k] for k in ('bytes', 'sha256')}, 'unique complete runner evidence map/raw pin')
        membership.add(row['file'])
    io.need(membership == set(exported), 'no missing or unaccounted exported DATA')
    io.need(exported['operation.json'][0] == op_raw and io.pin(exported['accepted-reader.json'][0]) == DECISION and
            io.pin(exported['actual-packages.txt'][0])['sha256'] == INVENTORY, 'actual actor operation/accepted decision/signed349 inventory')
    for kind, resource, expected_id in [('container', name, before['Id']), ('container', init, init_row['Id']), ('volume', volume, volume)]:
        out, _ = seq.take(DOCKER + [kind, 'inspect', resource])
        observed = io.decode(out)[0]
        labels = observed.get('Labels') if kind == 'volume' else observed['Config']['Labels']
        io.need(labels.get('cachy-asahi.admission') == sha, 'actual exact owned cleanup label')
        if kind == 'container':
            stopped(observed, image, io)
            io.need(observed['Id'] == expected_id, 'cleanup same stopped owned container')
        else:
            io.need(observed['Name'] == volume, 'cleanup same owned volume')
        seq.take(DOCKER + [kind, 'rm', *([] if kind == 'volume' else ['--force']), expected_id])
    out, _ = seq.take(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
    outv, _ = seq.take(DOCKER + ['volume', 'ls', '--quiet'])
    io.need(not {name, init} & set(out.decode().splitlines()) and volume not in outv.decode().splitlines(),
            'raw final XS container/volume absence')
    seq.end()
    io.need(report['cleanup'] == [dict(kind=k, name=n, removed=True) for k, n in
            [('container', name), ('container', init), ('volume', volume)]], 'exact owned cleanup receipt')
    result, observation = (io.decode(exported[n][0]) for n in ('actor-result.json', 'runtime-observation.json'))
    io.need(result['schema'] == 1 and result['status'] == 'RUNNER_COMPLETED' and result['failure'] is None and
            result['runner_status'] == 'FOUR_SMOKE_COMMANDS_COMPLETED' and result['operation_sha256'] == sha and
            result['native_acceptance'] is result['XS_acceptance'] is False and result['qualification'] == 'NOT_GRANTED' and
            result['nested_invocation'] == 'NOT_INVOKED' and result['nested_qualification'] == 'NOT_QUALIFIED', 'actual four-command actor receipt without acceptance')
    io.need(observation['schema'] == 1 and observation['operation_sha256'] == sha and
            observation['generator_sha256'] == NATIVE_SHA and
            observation['native_acceptance'] is observation['XS_acceptance'] is False,
            'runtime observation is bound delegated DATA, without acceptance')
    return op, report, result, observation


def validate(get, source_root, binding, source_map, io):
    """Root authenticates Source/once-role before these independent DATA joins."""
    io.tick()
    b = binding
    h = io.decode(get('hosted-xs.json'))
    io.need(h['schema'] == 1 and h['status'] == 'XS_SMOKE_EXPORTED_PENDING_ROOT_READER' and
            h['binding'] == b and h['native_acceptance'] is h['XS_acceptance'] is False and
            h['qualification'] == 'NOT_GRANTED' and type(h['producer_exit']) is int and h['producer_exit'] == 0 and
            not any(k in h for k in ('error', 'daemon_build_retirement')), 'actual hosted completion; no qualification granted')
    source = source_job(get, source_root, b, source_map, h, io)
    helper = passive_hosted(source_root, source_map, io)
    daemon_raw = get('daemon.json')
    io.need(io.pin(daemon_raw)['sha256'] == h['daemon_identity_sha256'], 'whole actual Rootful daemon proof')
    daemon = io.decode(daemon_raw)
    helper.daemon_data(daemon)
    seq = boot_operations(get, h, io)
    image, work, token, home = signed_bootstrap(get, source_root, source_map, b, h, seq, daemon, source, helper, io)
    prep = preparation(get, source_root, source_map, b, h, image, work, source, seq, io)
    op, report, result, observation = producer(get, image, work, h, b, daemon, io)
    bootstrap_cleanup(seq, h, image, token, home, prep, b, io)
    io.tick()
    return dict(image=image, operation=op, producer_report=report, actor_result=result, runtime_observation=observation)
