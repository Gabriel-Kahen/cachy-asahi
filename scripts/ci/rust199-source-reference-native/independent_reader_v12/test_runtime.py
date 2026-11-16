#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent finite MODEL runtime joins; never imports producer or Source code."""
import copy, importlib.util, sys, unittest
from pathlib import Path


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
        'os.system', 'os.exec', 'os.fork', 'os.posix_spawn',
        'fcntl.flock', 'resource.setrlimit',
    ):
        raise AssertionError('Reader12 MODEL forbids process/network/authority: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('independent_reader12_runtime_model', HERE / 'reader.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
S, E = R.S, R.E
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
IMAGE = 'sha256:' + 'a' * 64


def life():
    return dict(natural_exit=True, group_absent=True,
                leader_held_until_group_inspection=True, exit_observed_via_waitpid=True,
                retirement='REAPED', ownership_lost=False, forced_cleanup=False, exit=0)


class Corpus:
    def __init__(self):
        self.bodies = {}

    def member(self, name, cap=8 * S.MIB):
        raw = self.bodies[name]
        assert len(raw) <= cap
        return raw


def model(phase='build'):
    """All names, CIDs and paths are fenced MODEL values, never selectors."""
    selected = dict(source='1' * 40, ref='refs/heads/codex/rust199-source344-native-v12-MODEL',
                    run='100', bootstrap_job='101', build_job='102',
                    source_review_sha256='2' * 64, dispatch_sha256='3' * 64)
    binding = dict(sha=selected['source'], ref=selected['ref'], run=selected['run'],
                   job=selected[phase + '_job'])
    if phase == 'build':
        binding.update(map_sha256=S.SOURCE['map_sha256'], approval=selected['source_review_sha256'])
    token = S.pin(S.canonical(binding))['sha256'][:24]
    base = ('rust199-' if phase == 'build' else 'rust199-qual-') + token
    roles = ('init', 'prepare', 'makepkg') if phase == 'build' else ('init', 'data', 'probe')
    volume = base + '-work'
    rows, corpus, where = [], Corpus(), {}

    def labels(role):
        return {'cachy-asahi.' + k: v for k, v in dict(
            source=selected['source'], run=selected['run'], job=binding['job'],
            token=token, operation='rust199-source-reference-native-v1',
            role=role if phase == 'build' else 'qualification-' + role).items()}

    def operation(key, argv, stdout=b'', code=0):
        index = len(rows)
        streams = {}
        for kind, raw in (('stdout', stdout), ('stderr', b'')):
            name = f'operations/{index:03}.{kind}'
            corpus.bodies[phase + '/' + name] = raw
            streams[kind] = dict(file=name, **S.pin(raw))
        rows.append(dict(argv=DOCKER + argv, returncode=code, lifecycle=life(), **streams))
        where[key] = index

    operation('volume', ['volume', 'inspect', volume], S.canonical([dict(
        Name=volume, Driver='local', Options=None, Labels=labels('volume'), Mountpoint='/MODEL/volume')]))
    for index, role in enumerate(roles, 1):
        name, cid = base + '-' + role, str(index) * 64
        args = ['create', '--name', name]
        for key, value in sorted(labels(role).items()):
            args += ['--label', key + '=' + value]
        args += [IMAGE]
        operation(role + '_create', args, (cid + '\n').encode())
        actual = dict(Id=cid, Name='/' + name, Image=IMAGE, Config=dict(Labels=labels(role)),
                      State=dict(Status='created', Running=False, ExitCode=0, OOMKilled=False,
                                 Restarting=False, Error=''),
                      HostConfig=dict(Mounts=[dict(Type='volume', Source=volume, Target='/work',
                                                  ReadOnly=False, VolumeOptions=dict(NoCopy=True, DriverConfig={}))]),
                      Mounts=[dict(Type='volume', Name=volume, Source='/MODEL/volume',
                                   Destination='/work', Driver='local', RW=True, Propagation='')])
        if role != 'init':
            for target in ['/inputs', '/source'] + ['/materials/' + name for name in ('cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz',
                'llvm-project-23.1.1.src.tar.xz', 'rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz',
                'rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz', 'rustc-1.99.0-src.tar.xz')]:
                actual['HostConfig']['Mounts'].append(dict(Type='bind', Source='/MODEL' + target,
                                                          Target=target, ReadOnly=True))
                actual['Mounts'].append(dict(Type='bind', Source='/MODEL' + target,
                                            Destination=target, RW=False, Propagation='rprivate'))
        if role in ('makepkg', 'probe'):
            for target in ('/stage0', '/work/build/stage0'):
                actual['HostConfig']['Mounts'].append(dict(Type='volume', Source=volume, Target=target,
                    ReadOnly=True, VolumeOptions=dict(NoCopy=True, Subpath='build/stage0', DriverConfig={})))
                actual['Mounts'].append(dict(Type='volume', Name=volume, Source='/MODEL/volume/build/stage0',
                                            Destination=target, Driver='local', RW=False, Propagation=''))
        operation(role + '_inspect', ['container', 'inspect', name], S.canonical([actual]))
        operation(role + '_start', ['start', '--attach', name])
        actual['State']['Status'] = 'exited'
        operation(role + '_finished', ['container', 'inspect', name], S.canonical([actual]))
        operation(role + '_rm', ['container', 'rm', cid])
    return [rows, corpus, phase, selected, IMAGE], where


def add_rootfs_model(args, where):
    rows, corpus, phase, selected, image = args
    assert phase == 'bootstrap'
    binding = dict(source=selected['source'], ref=selected['ref'], run=selected['run'],
                   job=selected['bootstrap_job'], source_map_sha256=S.SOURCE['map_sha256'],
                   approval=selected['source_review_sha256'])
    token = S.pin(S.canonical(binding))['sha256'][:24]
    name, cid = 'rust199-rootfs-' + token, 'f' * 64
    labels = {'cachy-asahi.rust199-bootstrap': token,
              'cachy-asahi.rust199-bootstrap.source': selected['source']}
    create = ['create', '--name', name]
    for key, value in sorted(labels.items()):
        create += ['--label', key + '=' + value]
    create += [image]
    observed = dict(Id=cid, Name='/' + name, Image=image, Config=dict(Labels=labels),
                    State=dict(Status='created', Running=False), Mounts=[])
    for key, argv, stdout in (
        ('rootfs_create', create, (cid + '\n').encode()),
        ('rootfs_inspect', ['container', 'inspect', name], S.canonical([observed])),
        ('rootfs_rm', ['container', 'rm', cid], b''),
    ):
        index, streams = len(rows), {}
        for kind, body in (('stdout', stdout), ('stderr', b'')):
            member = f'operations/{index:03}.{kind}'
            corpus.bodies[phase + '/' + member] = body
            streams[kind] = dict(file=member, **S.pin(body))
        where[key] = index
        rows.append(dict(argv=DOCKER + argv, returncode=0, lifecycle=life(), **streams))


def raw(args, where, key):
    row = args[0][where[key]]
    return args[1].bodies[args[2] + '/' + row['stdout']['file']]


def replace_raw(args, where, key, value):
    row = args[0][where[key]]
    args[1].bodies[args[2] + '/' + row['stdout']['file']] = value
    row['stdout'].update(S.pin(value))


def inspect_mutation(args, where, key, mutate):
    value = S.decode(raw(args, where, key))
    mutate(value[0])
    replace_raw(args, where, key, S.canonical(value))


class RuntimeControls(unittest.TestCase):
    def setUp(self):
        S.END = None

    def refuses(self, args):
        with self.assertRaisesRegex(S.Hold, 'CUSTODY_'):
            E.custody_operations(*args)

    def test_default_driverconfig_absent_or_exact_empty_only(self):
        for options in ({'NoCopy': True}, {'NoCopy': True, 'DriverConfig': {}}):
            self.assertTrue(E.volume_options(options, {'NoCopy': True}))
        for value in (None, [], '', False, {'Name': 'local'}, {'Options': {}}, {'Unknown': True}):
            self.assertFalse(E.volume_options({'NoCopy': True, 'DriverConfig': value}, {'NoCopy': True}))

    def test_nocopy_exact_boolean_and_option_namespace(self):
        for value in (None, False, 0, 1, 'true'):
            self.assertFalse(E.volume_options({'NoCopy': value}, {'NoCopy': True}))
        for value in ({}, {'NoCopy': True, 'Unknown': 1}, {'NoCopy': True, 'Subpath': ''},
                      {'NoCopy': True, 'Subpath': 'build/stage0'}, {'DriverConfig': {}}):
            self.assertFalse(E.volume_options(value, {'NoCopy': True}))
        self.assertFalse(E.volume_options({'DriverConfig': {}}, {}))

    def test_exact_stage0_subpath_preserved(self):
        expected = dict(NoCopy=True, Subpath='build/stage0')
        self.assertTrue(E.volume_options(dict(expected, DriverConfig={}), expected))
        for path in (None, '', 'stage0', 'build//stage0', '../stage0', 'build/stage0/'):
            self.assertFalse(E.volume_options(dict(NoCopy=True, Subpath=path), expected))

    def test_three_build_and_bootstrap_custody_joins(self):
        for phase in ('bootstrap', 'build'):
            args, _ = model(phase)
            result = E.custody_operations(*args)
            roles = ('init', 'prepare', 'makepkg') if phase == 'build' else ('init', 'data', 'probe')
            self.assertEqual(result, {role: str(i) * 64 for i, role in enumerate(roles, 1)})

    def test_optional_rootfs_data_exporter_has_exact_passive_custody_only(self):
        args, where = model('bootstrap')
        add_rootfs_model(args, where)
        result = E.custody_operations(*args)
        self.assertEqual(set(result), {'init', 'data', 'probe'})
        self.assertNotIn('f' * 64, result.values())

    def test_rootfs_exporter_foreign_identity_missing_retirement_and_cid_reuse_refuse(self):
        for mutation in ('name', 'create_label', 'create_image', 'ack', 'inspect_cid',
                         'inspect_image', 'inspect_label', 'mount', 'running', 'missing_rm',
                         'rm_name', 'reuse_cid', 'start'):
            args, where = model('bootstrap')
            add_rootfs_model(args, where)
            create = args[0][where['rootfs_create']]['argv']
            if mutation == 'name':
                create[create.index('--name') + 1] = 'foreign'
            elif mutation == 'create_label':
                create[create.index('--label') + 1] = 'cachy-asahi.rust199-bootstrap=foreign'
            elif mutation == 'create_image':
                create[-1] = 'sha256:' + 'b' * 64
            elif mutation == 'ack':
                replace_raw(args, where, 'rootfs_create', b'f' * 12 + b'\n')
            elif mutation == 'inspect_cid':
                inspect_mutation(args, where, 'rootfs_inspect', lambda v: v.update(Id='e' * 64))
            elif mutation == 'inspect_image':
                inspect_mutation(args, where, 'rootfs_inspect', lambda v: v.update(Image='sha256:' + 'b' * 64))
            elif mutation == 'inspect_label':
                inspect_mutation(args, where, 'rootfs_inspect', lambda v: v['Config']['Labels'].update(
                    {'cachy-asahi.rust199-bootstrap.source': '0' * 40}))
            elif mutation == 'mount':
                inspect_mutation(args, where, 'rootfs_inspect', lambda v: v.update(Mounts=[{'MODEL': True}]))
            elif mutation == 'running':
                inspect_mutation(args, where, 'rootfs_inspect', lambda v: v['State'].update(Status='running', Running=True))
            elif mutation == 'missing_rm':
                args[0][where['rootfs_rm']]['argv'] = DOCKER + ['MODEL-ignored']
            elif mutation == 'rm_name':
                args[0][where['rootfs_rm']]['argv'][-1] = create[create.index('--name') + 1]
            elif mutation == 'reuse_cid':
                replace_raw(args, where, 'rootfs_create', b'1' * 64 + b'\n')
            else:
                args[0][where['rootfs_rm']]['argv'] = DOCKER + ['start', '--attach', create[create.index('--name') + 1]]
            with self.subTest(mutation=mutation):
                self.refuses(args)

    def test_full_acknowledged_cid_required(self):
        for value in (b'', b'1' * 12 + b'\n', b'1' * 64, b'1' * 64 + b'\n\n',
                      b'F' * 64 + b'\n', b'1' * 64 + b'\r\n', b' ' + b'1' * 64 + b'\n'):
            args, where = model()
            replace_raw(args, where, 'init_create', value)
            self.refuses(args)

    def test_failed_create_cannot_gain_custody_from_inspect(self):
        args, where = model()
        args[0][where['init_create']]['returncode'] = 1
        args[0][where['init_create']]['lifecycle']['exit'] = 1
        self.refuses(args)

    def test_duplicate_acknowledged_cid_refused(self):
        args, where = model()
        replace_raw(args, where, 'prepare_create', b'1' * 64 + b'\n')
        self.refuses(args)

    def test_inspect_identity_name_image_and_owner_labels_refused(self):
        mutations = [lambda v: v.update(Id='f' * 64), lambda v: v.update(Name='/foreign'),
                     lambda v: v.update(Image='sha256:' + 'f' * 64)]
        for key in ('source', 'run', 'job', 'token', 'role', 'operation'):
            mutations.append(lambda v, key=key: v['Config']['Labels'].update({'cachy-asahi.' + key: 'foreign'}))
        for mutate in mutations:
            args, where = model()
            inspect_mutation(args, where, 'prepare_inspect', mutate)
            self.refuses(args)

    def test_finish_cid_cannot_change_after_valid_start(self):
        args, where = model()
        inspect_mutation(args, where, 'makepkg_finished', lambda v: v.update(Id='f' * 64))
        self.refuses(args)

    def test_actual_mount_identity_access_and_subpath_refused(self):
        mutations = [lambda v: v['Mounts'][0].update(Name='foreign'),
                     lambda v: v['Mounts'][0].update(Source='/MODEL/foreign'),
                     lambda v: v['Mounts'][0].update(RW=False),
                     lambda v: v['Mounts'][0].update(Type='bind'),
                     lambda v: v['Mounts'][0].update(Driver='foreign'),
                     lambda v: v['HostConfig']['Mounts'][0].update(Source='foreign'),
                     lambda v: v['HostConfig']['Mounts'][0]['VolumeOptions'].update(NoCopy=1),
                     lambda v: v['HostConfig']['Mounts'][0]['VolumeOptions'].update(Subpath='build/stage0')]
        for mutate in mutations:
            args, where = model()
            inspect_mutation(args, where, 'prepare_inspect', mutate)
            self.refuses(args)

    def test_missing_extra_duplicate_and_writable_bind_mounts_refused(self):
        def missing(v):
            v['HostConfig']['Mounts'].pop()
            v['Mounts'].pop()
        def extra(v):
            v['HostConfig']['Mounts'].append(dict(Type='bind', Source='/MODEL/extra', Target='/extra', ReadOnly=True))
            v['Mounts'].append(dict(Type='bind', Source='/MODEL/extra', Destination='/extra', RW=False))
        def duplicate(v):
            v['HostConfig']['Mounts'].append(copy.deepcopy(v['HostConfig']['Mounts'][0]))
            v['Mounts'].append(copy.deepcopy(v['Mounts'][0]))
        def writable(v):
            v['HostConfig']['Mounts'][1]['ReadOnly'] = False
            v['Mounts'][1]['RW'] = True
        for mutate in (missing, extra, duplicate, writable):
            args, where = model()
            inspect_mutation(args, where, 'prepare_inspect', mutate)
            self.refuses(args)

    def test_stage0_actual_alias_source_subpath_and_readonly_refused(self):
        for mutate in (lambda v: v['Mounts'][-1].update(Source='/MODEL/volume'),
                       lambda v: v['HostConfig']['Mounts'][-1]['VolumeOptions'].update(Subpath='stage0'),
                       lambda v: v['HostConfig']['Mounts'][-1].update(ReadOnly=False),
                       lambda v: v['Mounts'][-1].update(RW=True)):
            args, where = model()
            inspect_mutation(args, where, 'makepkg_inspect', mutate)
            self.refuses(args)

    def test_unknown_mount_configuration_refused(self):
        for mutate in (lambda v: v['HostConfig']['Mounts'][0].update(Unknown=True),
                       lambda v: v['HostConfig']['Mounts'][0].update(Consistency='cached'),
                       lambda v: v['HostConfig']['Mounts'][1].update(VolumeOptions={'DriverConfig': {}})):
            args, where = model()
            inspect_mutation(args, where, 'prepare_inspect', mutate)
            self.refuses(args)

    def test_volume_owner_and_mountpoint_cannot_change(self):
        for mutate in (lambda v: v.update(Name='foreign'), lambda v: v.update(Driver='foreign'),
                       lambda v: v.update(Options={'device': '/MODEL/foreign'}),
                       lambda v: v['Labels'].update({'cachy-asahi.token': 'foreign'})):
            args, where = model()
            inspect_mutation(args, where, 'volume', mutate)
            self.refuses(args)

    def test_started_actor_requires_prestart_inspect(self):
        args, where = model()
        args[0][where['init_inspect']]['argv'] = DOCKER + ['MODEL-ignored']
        self.refuses(args)

    def test_name_only_or_forced_retirement_refused(self):
        for mutation in ('name', 'force', 'other'):
            args, where = model()
            row = args[0][where['init_rm']]
            if mutation == 'name':
                row['argv'][-1] = args[0][where['init_start']]['argv'][-1]
            elif mutation == 'force':
                row['argv'].insert(-1, '--force')
            else:
                row['argv'][-1] = 'f' * 64
            self.refuses(args)

    def test_retirement_requires_fresh_same_stopped_inspect(self):
        for state in (dict(Status='running', Running=True), dict(Status='exited', Running=False, ExitCode=134),
                      dict(Status='exited', Running=False, OOMKilled=True)):
            args, where = model()
            inspect_mutation(args, where, 'init_finished', lambda v: v['State'].update(state))
            self.refuses(args)

    def test_missing_ack_and_unset_data_id_cannot_be_repaired_by_pass_claim(self):
        args, where = model('bootstrap')
        replace_raw(args, where, 'data_create', b'')
        args[0][where['data_create']]['status'] = 'PASS'
        self.refuses(args)

    def test_missing_retirement_cannot_be_repaired_by_absence_claim(self):
        args, where = model()
        args[0][where['makepkg_rm']]['argv'] = DOCKER + ['MODEL-ignored']
        args[0][where['makepkg_rm']]['owned_resources_absent'] = True
        self.refuses(args)

    def test_failed_retirement_and_lifecycle_refuse(self):
        args, where = model()
        args[0][where['init_rm']]['returncode'] = 1
        args[0][where['init_rm']]['lifecycle']['exit'] = 1
        self.refuses(args)
        args, where = model()
        args[0][where['init_rm']]['lifecycle']['forced_cleanup'] = True
        # The Reader invokes existing operations() first; natural() is its
        # independent lifecycle guard, separate from the new identity replay.
        with self.assertRaisesRegex(S.Hold, 'CHILD_NATURAL_RETIREMENT'):
            E.natural(args[0][where['init_rm']]['lifecycle'], False)


if __name__ == '__main__':
    unittest.main()
