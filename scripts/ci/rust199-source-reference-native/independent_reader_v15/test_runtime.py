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
        raise AssertionError('Reader15 MODEL forbids process/network/authority: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('independent_reader15_runtime_model', HERE / 'reader.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
S, E = R.S, R.E
mspec=importlib.util.spec_from_file_location('reader13_custody_mount_model',HERE/'test_mounts.py')
M=importlib.util.module_from_spec(mspec);mspec.loader.exec_module(M);M.S=S;M.E=E
bspec=importlib.util.spec_from_file_location('reader15_runtime_owned_bind_model',HERE/'test_owned_bind.py')
B=importlib.util.module_from_spec(bspec);bspec.loader.exec_module(B);B.S=S;B.E=E
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
    selected = dict(source='1' * 40, ref='refs/heads/codex/rust199-source361-native-v15-MODEL',
                    run='100', bootstrap_job='101', build_job='102',
                    source_review_sha256='2' * 64, dispatch_sha256='3' * 64)
    binding = dict(sha=selected['source'], ref=selected['ref'], run=selected['run'],
                   job=selected[phase + '_job'])
    if phase in ('bootstrap','build'):
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

    work_bind, _, _, daemon = B.model(phase, binding)
    work = work_bind['work_source']
    operation('containers_absent_before', ['container', 'ls', '--all', '--format', '{{.Names}}'])
    operation('volume_absent_before', ['volume', 'ls', '--quiet'])
    operation('daemon', ['info', '--format', E.DAEMON_FORMAT], work_bind['daemon_inspect']['json'].encode())
    lifecycle=[dict(status='CREATED_HELD',after_operation_count=len(rows),workspace_node=work_bind['workspace_node'],nonce=work_bind['nonce'])]
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
                      HostConfig=dict(Mounts=[B.observed('/work',work,False)[0]]),
                      Mounts=[B.observed('/work',work,False)[1]])
        if role != 'init':
            for target in ['/inputs', '/source'] + ['/materials/' + name for name in ('cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz',
                'llvm-project-23.1.1.src.tar.xz', 'rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz',
                'rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz', 'rustc-1.99.0-src.tar.xz')]:
                configured, observed = B.observed(target, work_bind['job_root']+('/qualification/inputs'if phase=='bootstrap'else'/rust-build/inputs')if target=='/inputs'else'/MODEL'+target, True)
                actual['HostConfig']['Mounts'].append(configured)
                actual['Mounts'].append(observed)
        if role in ('makepkg', 'probe'):
            for target in ('/stage0', '/work/build/stage0'):
                configured, observed = B.observed(target, work + '/build/stage0', True)
                actual['HostConfig']['Mounts'].append(configured)
                actual['Mounts'].append(observed)
        if role=='init':
            owner=dict(source=binding,image=IMAGE,root_admission_sha256=selected['dispatch_sha256']if phase=='bootstrap'else'd'*64,token=token,init=base+'-init',prepare=base+('-data'if phase=='bootstrap'else'-prepare'),makepkg=base+('-probe'if phase=='bootstrap'else'-makepkg'),volume=volume,operation='rust199-source-reference-native-v1')
            actual['Config'].update(User='1001:1001',Entrypoint=['/usr/bin/python'],WorkingDir='/',Cmd=['-I','-B','-c',(HERE/'fixtures/initializer-code.DATA.txt').read_text(),S.canonical(owner).decode()])
            actual['HostConfig'].update(Memory=128*S.MIB,MemorySwap=128*S.MIB,PidsLimit=32,NanoCpus=2000000000,ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=None,Privileged=False,SecurityOpt=['no-new-privileges'],Init=True,IpcMode='private',CgroupnsMode='private',Cgroupns='private',RestartPolicy=dict(Name='no'),LogConfig=dict(Type='none',Config={}),Ulimits=[dict(Name='nofile',Soft=1024,Hard=1024),dict(Name='core',Soft=0,Hard=0)])
        if phase=='bootstrap'and role!='init':
            actual['Config'].update(User='1001:1001',Entrypoint=['/usr/bin/python'],Cmd=['-I','-B','/source/actor/qualify.py',role],Hostname='rust199-qualification',WorkingDir='/work',Env=['QUALIFICATION_SHA256='+'d'*64])
            actual['HostConfig'].update(Memory=8*S.GIB,MemorySwap=8*S.GIB,PidsLimit=512,NanoCpus=2000000000,ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=None,Privileged=False,SecurityOpt=['no-new-privileges'],Init=True,IpcMode='private',CgroupnsMode='private',RestartPolicy=dict(Name='no'),LogConfig=dict(Type='none',Config={}),Ulimits=[dict(Name='nofile',Soft=1024,Hard=1024),dict(Name='core',Soft=0,Hard=0)],Tmpfs={'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'})
        operation(role + '_inspect', ['container', 'inspect', name], S.canonical([actual]))
        operation(role + '_start', ['start', '--attach', name],S.canonical(dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=owner,before=work_bind['workspace_node'],after=work_bind['workspace_node'],limits={'cpu.max':'200000 100000','memory.max':'134217728','memory.swap.max':'0','pids.max':'32'},capabilities='NO_CAPS_NO_MUTATION_OWNED_DIRECTORY',recursive=False))if role=='init'else b'')
        actual['State']['Status'] = 'exited'
        operation(role + '_finished', ['container', 'inspect', name], S.canonical([actual]))
        operation(role + '_rm', ['container', 'rm', cid])
    operation('containers_absent_after', ['container', 'ls', '--all', '--format', '{{.Names}}'])
    operation('volume_absent_after', ['volume', 'ls', '--quiet'])
    lifecycle.append(dict(status='RETIRED_ABSENT',after_operation_count=len(rows),workspace_node=work_bind['workspace_node'],nonce=work_bind['nonce'],nodes=20,fd_held_until_absence=True))
    kernels={}
    actions=('qualification-data','qualification-probe')if phase=='bootstrap'else('prepare','makepkg','build','package')
    for action in actions:
        context=dict(source=binding,dispatch_sha256=selected['dispatch_sha256'],input_admission_sha256='d'*64,image_id=IMAGE,volume_token=token,phase=action)
        kernels[action]=M.verify(M.proof_model(action,context=context))
    return [rows, corpus, phase, selected, IMAGE, kernels, work_bind, daemon, lifecycle], where


def add_rootfs_model(args, where):
    rows, corpus, phase, selected, image = args[:5]
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
        with self.assertRaisesRegex(S.Hold, 'CUSTODY_|MOUNTINFO_|OWNED_BIND_|INITIALIZER_|ACTOR_'):
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

    def test_bind_aliases_cannot_use_old_volume_root_source_even_with_kernel_proof(self):
        for phase, role in (('bootstrap', 'probe'), ('build', 'makepkg')):
            args, where = model(phase)
            def root_source(row):
                for mount in row['Mounts']:
                    if mount['Destination'] in ('/stage0', '/work/build/stage0'):
                        mount['Source'] = args[6]['work_source']
            for key in (role + '_inspect', role + '_finished'):
                inspect_mutation(args, where, key, root_source)
            self.refuses(args)

    def test_every_directory_lifecycle_observation_is_required(self):
        for phase in('bootstrap','build'):
            for key in('containers_absent_before','volume_absent_before','daemon','containers_absent_after','volume_absent_after'):
                args,where=model(phase);args[0][where[key]]['argv']=DOCKER+['MODEL-ignored']
                with self.subTest(phase=phase,missing=key):self.refuses(args)
    def test_owned_compatibility_name_must_never_be_a_docker_volume(self):
        for key in('volume_absent_before','volume_absent_after'):
            args,where=model();replace_raw(args,where,key,(args[6]['volume']+'\n').encode());self.refuses(args)
        for args_tail in(['volume','create','MODEL'],['volume','inspect','MODEL'],['volume','rm','MODEL']):
            args,where=model();args[0][where['volume_absent_before']]['argv']=DOCKER+args_tail;self.refuses(args)
    def test_fresh_and_final_actor_namespaces_are_actually_empty(self):
        for key in('containers_absent_before','containers_absent_after'):
            args,where=model();name=S.decode(raw(args,where,'prepare_inspect'))[0]['Name'][1:]
            replace_raw(args,where,key,(name+'\n').encode());self.refuses(args)
    def test_lifecycle_rows_exact_source_nonce_inode_bounds_and_fd_custody(self):
        changes=[lambda r:r.clear(),lambda r:r.reverse(),lambda r:r[0].update(status='PASS'),lambda r:r[1].update(status='PASS'),lambda r:r[0].update(nonce='f'*64),lambda r:r[1].update(nonce='f'*64),lambda r:r[1].update(workspace_node={}),lambda r:r[1].update(nodes=-1),lambda r:r[1].update(nodes=2000001),lambda r:r[1].update(nodes=True),lambda r:r[1].update(fd_held_until_absence=False),lambda r:r[1].update(extra=True)]
        for change in changes:
            args,_=model();change(args[8]);self.refuses(args)
    def test_lifecycle_counts_cannot_shift_before_create_or_retirement(self):
        for position in(0,1):
            for count in(0,True,-1,999999):
                args,_=model();args[8][position]['after_operation_count']=count;self.refuses(args)
        args,where=model();args[8][0]['after_operation_count']=where['init_create']+1;self.refuses(args)
        args,where=model();args[8][1]['after_operation_count']=where['makepkg_rm'];self.refuses(args)
    def test_exact_whole_daemon_snapshot_precedes_held_workspace_creation(self):
        args,where=model();replace_raw(args,where,'daemon',raw(args,where,'daemon')+b'\n');self.refuses(args)
        args,where=model();args[0][where['daemon']],args[0][where['init_create']]=args[0][where['init_create']],args[0][where['daemon']];self.refuses(args)
    def test_fixed_job_input_child_and_source_root_disjointness(self):
        for phase,role in(('bootstrap','data'),('build','prepare')):
            for source in('/MODEL/foreign','/MODEL/private-job/rust199-hosted'):
                args,where=model(phase)
                inspect_mutation(args,where,role+'_inspect',lambda v:v['HostConfig']['Mounts'][1].update(Source=source))
                self.refuses(args)
            args,where=model(phase)
            def shadow(v):
                for row in v['HostConfig']['Mounts']:
                    if row['Target']=='/source':row['Source']=args[6]['job_root']+'/shadow'
                for row in v['Mounts']:
                    if row['Destination']=='/source':row['Source']=args[6]['job_root']+'/shadow'
            inspect_mutation(args,where,role+'_inspect',shadow);self.refuses(args)

    def test_all_phase_kernel_records_mandatory(self):
        for phase in('bootstrap','build'):
            original,_=model(phase)
            for missing in original[5]:
                args,_=model(phase);args[5].pop(missing)
                with self.subTest(phase=phase,missing=missing):self.refuses(args)

    def test_kernel_context_cannot_move_to_another_actor_or_source(self):
        for field in('source','dispatch_sha256','image_id','volume_token','phase'):
            args,_=model('bootstrap');proof=args[5]['qualification-probe']
            proof['context'][field]='MODEL_FOREIGN'
            with self.subTest(field=field):self.refuses(args)

    def test_kernel_work_identity_stable_across_all_actor_phases(self):
        args,_=model();args[5]['build']['mounts']['/work']['root']='/MODEL/FOREIGN'
        self.refuses(args)

    def test_bootstrap_token_includes_map_and_approval_fields(self):
        args,_=model('bootstrap');context=args[5]['qualification-data']['context']
        short={k:v for k,v in context['source'].items()if k not in('map_sha256','approval')}
        self.assertNotEqual(S.pin(S.canonical(short))['sha256'][:24],context['volume_token'])
        args[5]['qualification-data']['context']['volume_token']=S.pin(S.canonical(short))['sha256'][:24]
        self.refuses(args)

    def test_qualifier_kernel_proof_requires_exact_trusted_entry_and_plan(self):
        mutations=[lambda row:row['Config'].update(User='0:0'),
                   lambda row:row['Config'].update(Entrypoint=['/bin/sh']),
                   lambda row:row['Config'].update(Cmd=['-I','-B','/source/actor/qualify.py','probe']),
                   lambda row:row['Config'].update(Env=['QUALIFICATION_SHA256='+'e'*64]),
                   lambda row:row['Config']['Env'].append('GITHUB_TOKEN=MODEL_FORBIDDEN')]
        for mutate in mutations:
            args,where=model('bootstrap');inspect_mutation(args,where,'data_inspect',mutate)
            self.refuses(args)

    def test_qualifier_kernel_proof_preserves_isolation_and_resources(self):
        for field,value in(('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),
                           ('MemorySwap',9*S.GIB),('CapAdd',['SYS_ADMIN'])):
            args,where=model('bootstrap')
            inspect_mutation(args,where,'data_inspect',lambda row:row['HostConfig'].update({field:value}))
            with self.subTest(field=field):self.refuses(args)

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
                     lambda v: v['Mounts'][0].update(Type='volume'),
                     lambda v: v['Mounts'][0].update(Driver='foreign'),
                     lambda v: v['Mounts'][0].update(Propagation='rslave'),
                     lambda v: v['HostConfig']['Mounts'][0].update(Source='foreign'),
                     lambda v: v['HostConfig']['Mounts'][0].update(VolumeOptions=dict(NoCopy=True)),
                     lambda v: v['HostConfig']['Mounts'][0]['BindOptions'].update(Propagation='rslave')]
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
        for mutate in (lambda v: v['Mounts'][-1].update(Source='/MODEL/volume/FOREIGN'),
                       lambda v: v['HostConfig']['Mounts'][-1].update(Source='/MODEL/foreign/stage0'),
                       lambda v: v['HostConfig']['Mounts'][-1].update(ReadOnly=False),
                       lambda v: v['Mounts'][-1].update(RW=True)):
            args, where = model()
            inspect_mutation(args, where, 'makepkg_inspect', mutate)
            self.refuses(args)

    def test_unknown_mount_configuration_refused(self):
        for mutate in (lambda v: v['HostConfig']['Mounts'][0].update(Unknown=True),
                       lambda v: v['HostConfig']['Mounts'][0]['BindOptions'].update(NonRecursive=True),
                       lambda v: v['HostConfig']['Mounts'][1].update(VolumeOptions={'DriverConfig': {}})):
            args, where = model()
            inspect_mutation(args, where, 'prepare_inspect', mutate)
            self.refuses(args)

    def test_workspace_owner_inode_and_source_cannot_change(self):
        for mutate in(lambda v:v['workspace_node'].update(uid=0),lambda v:v['workspace_node'].update(inode=0),lambda v:v['labels'].update({'cachy-asahi.token':'foreign'}),lambda v:v.update(work_source='/MODEL/foreign')):
            args,_=model();mutate(args[6]);self.refuses(args)

    def test_initializer_nonroot_no_caps_and_exact_resources_both_phases(self):
        mutations=[lambda v:v['Config'].update(User='0:0'),lambda v:v['HostConfig'].update(CapAdd=['CHOWN']),lambda v:v['HostConfig'].update(CapAdd=['DAC_OVERRIDE']),lambda v:v['HostConfig'].update(Memory=129*S.MIB),lambda v:v['HostConfig'].update(PidsLimit=33),lambda v:v['Config'].update(WorkingDir='/work'),lambda v:v['Config']['Cmd'].__setitem__(3,'MODEL_CODE')]
        for phase in('bootstrap','build'):
            for mutate in mutations:
                args,where=model(phase);inspect_mutation(args,where,'init_inspect',mutate);self.refuses(args)
    def test_initializer_runtime_receipt_is_same_inode_without_mutation(self):
        for phase in('bootstrap','build'):
            for mutate in(lambda v:v.update(capabilities='CHOWN_ONLY_CHMOD_BEFORE_CHOWN'),lambda v:v['before'].update(uid=0),lambda v:v['after'].update(inode=999),lambda v:v['limits'].update(**{'pids.max':'33'}),lambda v:v.update(schema=True),lambda v:v.update(recursive=True),lambda v:v['binding'].update(token='f'*24)):
                args,where=model(phase);value=S.decode(raw(args,where,'init_start'));mutate(value);replace_raw(args,where,'init_start',S.canonical(value));self.refuses(args)

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
