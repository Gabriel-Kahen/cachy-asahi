# SPDX-License-Identifier: MIT
import copy
import itertools
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import broker


FAKE_CLI = r'''#!/usr/bin/python3
import json,os,signal,sys,time
from pathlib import Path
root=Path(os.environ['HOME']);path=root/'state.json';state=json.loads(path.read_text())
args=sys.argv[1:];assert args[:2]==['--host','unix:///run/docker.sock'];args=args[2:]
state['calls'].append(args)
def save():path.write_text(json.dumps(state))
save()
if args[:2]==['image','inspect']:
 assert args[2]==state['item']['Image']
 print(json.dumps([{'Id':args[2],'Architecture':'arm64','Os':'linux',
                   'Config':{'Env':['PATH=/usr/bin:/bin'],'Labels':{}}}]))
elif args[:2]==['container','ls']:
 item=state.get('container')
 if item and args[-1] in ('id='+item['Id'],'name=^'+item['Name']+'$'):
  print(json.dumps({'ID':item['Id'],'Names':item['Name'][1:]}))
elif args[:1]==['create']:
 assert args==state['create']
 row=json.loads((root/'journal-build').read_text())['containers'][0]
 assert row['create_attempted'] and row['id'] is None
 state['container']=state['item'];save();print(state['item']['Id'])
elif args[:2]==['container','inspect']:
 assert state['container']['Id']==args[2];print(json.dumps([state['container']]))
elif args[:1]==['start']:
 if args!=['start','--attach',state['item']['Id']]:
  print('unknown start flag');raise SystemExit(125)
 assert state['container']['Id']==args[2]
 if state['stop']!='success':
  pid=os.fork()
  if pid==0:
   signal.signal(signal.SIGTERM,signal.SIG_IGN)
   (root/'descendant-ready').write_text(str(os.getpid()));time.sleep(60);os._exit(0)
  def forward(number,frame):
   (root/'forwarded').write_text(str(number));os.kill(pid,number)
  signal.signal(signal.SIGTERM,forward)
  while not (root/'descendant-ready').exists():time.sleep(.01)
  (root/'start-ready').write_text(str(os.getpid()));time.sleep(60)
 print('kernel fixture output')
elif args[:3]==['container','rm','--force']:
 assert args[3]==state['container']['Id'];del state['container'];save();print(args[3])
else:raise SystemExit(9)
'''


class BrokerPolicy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.mounts = {}
        for name in ('code', 'inputs', 'out'):
            p = self.root / name; p.mkdir(); self.mounts['/' + name] = str(p)
        self.runner = Mock(deadline=time.monotonic() + 60)
        self.nonce = 'a' * 32

    def instance(self, role='build'):
        value = broker.Broker(self.runner, self.runner, str(self.root / 'docker'), 'b' * 64,
            'unix:///run/docker.sock', 'sha256:' + 'c' * 64, 1000, 1000, self.root / ('journal-' + role), self.nonce,
            expected_mounts=self.mounts, role=role)
        value.image_config = {'Env': ['PATH=/usr/bin:/bin'], 'Labels': {}}
        return value

    def env(self, action):
        return {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp/home', 'KERNEL_STAGE_NONCE': self.nonce,
                'KERNEL_STAGE_ACTION': action, 'KERNEL_STAGE_CONTRACT_SHA256': 'd' * 64}

    def test_build_options_are_nonroot_network_off_readonly_and_bounded(self):
        value = self.instance(); options = value._options('name', {}, self.mounts)
        for item in ('--read-only', '--network=none', '--memory=14g', '--memory-swap=14g', '--cpus=2', '--pids-limit=512'):
            self.assertIn(item, options)
        self.assertIn('1000:1000', options)
        self.assertIn('/tmp:rw,nosuid,nodev,exec,size=12g', options)
        self.assertNotIn('--cap-add=CHOWN', options)

    def test_provision_identity_is_command_bound_without_commit_env_label_leak(self):
        value = self.instance('provision'); options = value._options('name', {}, self.mounts)
        self.assertNotIn('--read-only', options); self.assertNotIn('--label', options)
        self.assertIn('0:0', options)
        self.assertEqual({item for item in options if item.startswith('--cap-add=')},
                         {'--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER'})
        with patch.object(value, '_launch', return_value=None) as launched:
            value.launch('provision', self.mounts, self.env('provision'), 900, persist=True)
        args = launched.call_args.args
        self.assertEqual(args[1], {})
        self.assertEqual(args[3][-2:], [self.nonce, 'd' * 64])

    def test_role_action_persist_and_mount_drift_refused(self):
        value = self.instance()
        for action, mounts, persist in (('provision', self.mounts, True), ('baseline', {**self.mounts, '/host': '/'}, False),
                                        ('baseline', self.mounts, True), ('unknown', self.mounts, False)):
            with self.assertRaises(ValueError): value.launch(action, mounts, self.env(action), 900, persist)

    def test_docker_remote_and_identity_overrides_refused(self):
        for endpoint in ('tcp://localhost:2375', 'unix:///tmp/fake.sock', 'ssh://machine', 'unix:///run/user/1000/docker.sock'):
            with self.assertRaises(ValueError): broker.validate_endpoint(endpoint, 1000)
        value = self.instance()
        with self.assertRaises(ValueError): value.launch('baseline', self.mounts, {**self.env('baseline'), 'DOCKER_HOST': 'tcp://evil'}, 900)

    def test_uid_remapping_daemons_refused(self):
        value = self.instance()
        for security in (['name=rootless'], ['name=userns'], None):
            data = {'ID': 'native-daemon-id', 'Architecture': 'aarch64', 'OSType': 'linux', 'SecurityOptions': security}
            with patch.object(value, '_local'), patch.object(broker, 'daemon_http', return_value=data):
                with self.assertRaises(ValueError): value._info(self.runner)
        data['SecurityOptions'] = ['name=seccomp,profile=builtin', 'name=cgroupns']
        with patch.object(value, '_local'), patch.object(broker, 'daemon_http', return_value=data):
            self.assertEqual(value._info(self.runner)['id'], data['ID'])

    def inspect_row(self, value):
        row = {'name': 'cachy-asahi-kernel-' + self.nonce + '-baseline', 'id': 'e' * 64,
               'mounts': self.mounts, 'env': self.env('baseline'), 'cmd': ['-I', '-B', 'worker.py', 'baseline']}
        item = {'Id': row['id'], 'Name': '/' + row['name'], 'Image': value.image,
            'Config': {'User': value.user, 'Labels': {broker.LABEL: self.nonce},
                       'Env': [key + '=' + text for key, text in row['env'].items()],
                       'Entrypoint': ['/usr/bin/python3'], 'Cmd': row['cmd']},
            'HostConfig': {'AutoRemove': False, 'Privileged': False, 'ReadonlyRootfs': True, 'NetworkMode': 'none',
                'IpcMode': 'private', 'PidMode': '', 'CgroupnsMode': 'private', 'Memory': 14 * 1024**3,
                'MemorySwap': 14 * 1024**3, 'NanoCpus': 2 * 10**9, 'PidsLimit': 512, 'CapDrop': ['ALL'],
                'SecurityOpt': ['no-new-privileges'], 'Tmpfs': {'/tmp': 'rw,nosuid,nodev,exec,size=12g'}},
            'Mounts': [{'Type': 'bind', 'Destination': key, 'Source': source, 'RW': not broker.DESTINATIONS[key]}
                       for key, source in self.mounts.items()]}
        return row, item

    def test_exact_actual_inspect_accepts_only_bounded_profile(self):
        value = self.instance(); row, item = self.inspect_row(value)
        with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
            self.assertEqual(value._inspect(row['id'], row), row['id'])
        for key, changed in (('Privileged', True), ('NetworkMode', 'host'), ('Memory', 0), ('Devices', ['disk']), ('CapAdd', ['SYS_ADMIN'])):
            altered = {**item, 'HostConfig': {**item['HostConfig'], key: changed}}
            with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([altered]).encode())):
                with self.assertRaises(ValueError): value._inspect(row['id'], row)

    def provision_inspect(self):
        value = self.instance('provision'); row, item = self.inspect_row(value)
        row.update(name='cachy-asahi-kernel-' + self.nonce + '-provision', env={},
                   cmd=['-I', '-B', '/code/scripts/port/kernel-native-stage/worker.py',
                        'provision', self.nonce, 'd' * 64])
        item['Name'] = '/' + row['name']
        item['Config'].update(Labels={}, Env=value.image_config['Env'], Cmd=row['cmd'])
        item['HostConfig'].update(ReadonlyRootfs=False, CapAdd=['CHOWN', 'DAC_OVERRIDE', 'FOWNER'])
        return value, row, item

    def test_provision_null_empty_and_absent_labels_preserve_raw_base(self):
        for base, actual in ((None, {}), ({}, None), (None, None), ({}, {}),
                             ({'upstream': 'fixed'}, {'upstream': 'fixed'})):
            with self.subTest(base=base, actual=actual):
                value, row, item = self.provision_inspect()
                value.image_config['Labels'] = base; item['Config']['Labels'] = actual
                original = copy.deepcopy(value.image_config)
                with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
                    self.assertEqual(value._inspect(row['id'], row), row['id'])
                self.assertEqual(value.image_config, original)
        value, row, item = self.provision_inspect(); del value.image_config['Labels']
        with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
            self.assertEqual(value._inspect(row['id'], row), row['id'])
        self.assertNotIn('Labels', value.image_config)

    def test_provision_labels_cannot_hide_nonempty_drift_or_malformed_maps(self):
        for base, actual in ((None, {'extra': 'value'}), ({'upstream': 'fixed'}, {}),
                             ({'upstream': 'fixed'}, {'upstream': 'changed'}),
                             ({'upstream': 'fixed'}, {'upstream': 'fixed', 'extra': 'value'})):
            value, row, item = self.provision_inspect()
            value.image_config['Labels'] = base; item['Config']['Labels'] = actual
            with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
                with self.assertRaisesRegex(ValueError, '^docker-container-ownership$'):
                    value._inspect(row['id'], row)
        for bad in (False, [], ['label'], '', 0, {'x': None}, {'x': 1}):
            for side in ('base', 'container'):
                with self.subTest(bad=bad, side=side):
                    value, row, item = self.provision_inspect()
                    if side == 'base': value.image_config['Labels'] = bad
                    else: item['Config']['Labels'] = bad
                    with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
                        with self.assertRaisesRegex(ValueError, '^docker-container-ownership$'):
                            value._inspect(row['id'], row)
        value, row, item = self.provision_inspect(); value.image_config['Labels'] = {1: 'x'}
        with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
            with self.assertRaisesRegex(ValueError, '^docker-container-ownership$'):
                value._inspect(row['id'], row)

    def test_null_label_compatibility_keeps_every_other_ownership_gate(self):
        changes = (lambda r, i: i.update(Id='e' * 63), lambda r, i: i.update(Name='/foreign'),
                   lambda r, i: r.update(id='f' * 64), lambda r, i: i.update(Image='sha256:' + 'f' * 64),
                   lambda r, i: i['Config'].update(User='1000:1000'))
        for change in changes:
            value, row, item = self.provision_inspect(); value.image_config['Labels'] = None
            change(row, item)
            with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
                with self.assertRaisesRegex(ValueError, '^docker-container-ownership$'):
                    value._inspect(row['id'], row)

    def test_build_nonce_label_equality_stays_required_with_strict_map_types(self):
        for labels in ({broker.LABEL: self.nonce, 'extra': 'fixed'}, {}, None,
                       {broker.LABEL: 'wrong'}, {broker.LABEL: self.nonce, 'extra': False}):
            value = self.instance(); row, item = self.inspect_row(value); item['Config']['Labels'] = labels
            with patch.object(value, '_operation', return_value=subprocess.CompletedProcess([], 0, json.dumps([item]).encode())):
                if labels == {broker.LABEL: self.nonce, 'extra': 'fixed'}:
                    self.assertEqual(value._inspect(row['id'], row), row['id'])
                else:
                    with self.assertRaisesRegex(ValueError, '^docker-container-ownership$'):
                        value._inspect(row['id'], row)

    def test_unknown_create_cancellation_never_claims_absence(self):
        value = self.instance()
        row = {'name': 'cachy-asahi-kernel-' + self.nonce, 'id': None, 'create_attempted': True}
        value.cleanup_runner.env = {}; value.cleanup_runner.log_dir = self.root
        with (patch.object(broker, 'Runner', return_value=self.runner),
              patch.object(value, '_journal', return_value={'containers': [row]}),
              patch.object(value, '_find', return_value=None)):
            result = value.cleanup()
        self.assertEqual((result['status'], result['absence_verified']), ('FAIL', False))

    def attached_start(self, stop, observed=False):
        # Only CLI process lifetime is real; daemon identity/local checks are fixture-bound.
        self.mounts['/out'] = str(self.root / 'output-baseline')
        Path(self.mounts['/out']).mkdir()
        value = self.instance(); row, item = self.inspect_row(value)
        row['cmd'] = ['-I', '-B', '/code/scripts/port/kernel-native-stage/worker.py', 'baseline']
        item['Config']['Cmd'] = row['cmd']
        binary = self.root / 'fake-docker'; binary.write_text(FAKE_CLI); binary.chmod(0o755)
        create = ['create', *value._options(row['name'], row['env'], self.mounts), value.image, *row['cmd']]
        state_path = self.root / 'state.json'
        state_path.write_text(json.dumps({'calls': [], 'item': item, 'create': create, 'stop': str(stop)}))
        config = self.root / 'config'; config.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'DOCKER_CONFIG': str(config)}
        result_path = self.root / 'attached-result.json'
        helper = '''import json,sys
from pathlib import Path
sys.path.insert(0,%r)
import broker
from runtime import Runner,Cancelled,cancellation_handlers
root=Path(%r);env=%r
value=broker.Broker(Runner(20,env,root/'logs'),Runner(1,env,root/'cleanup-logs'),
 %r,'b'*64,'unix:///run/docker.sock',%r,1000,1000,root/'journal-build',%r,expected_mounts=%r)
if %r:
 value.observer=broker.Trace();value.observer.action('baseline')
value._local=lambda runner:{}
value._info=lambda runner:{'id':'native-fixture-daemon','architecture':'aarch64'}
value.initialize()
with cancellation_handlers():
 try:
  result=value.launch('baseline',%r,%r,%r);failure=None;rc=result.returncode
 except Cancelled:failure='cancelled';rc=None
 except ValueError as error:failure=str(error);rc=None
Path(%r).write_text(json.dumps({'failure':failure,'returncode':rc,'cleanup':value.last_cleanup,'operation':value.observer.snapshot() if isinstance(value.observer,broker.Trace) else None}))
''' % (str(Path(broker.__file__).parent), str(self.root), env, str(binary), value.image,
       self.nonce, self.mounts, observed, self.mounts, self.env('baseline'), 1 if stop == 'timeout' else 15,
       str(result_path))
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', helper], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            if stop != 'success':
                end = time.monotonic() + 5
                while not (self.root / 'start-ready').exists():
                    self.assertIsNone(process.poll()); self.assertLess(time.monotonic(), end)
                    time.sleep(.01)
                if stop != 'timeout':
                    os.kill(process.pid, stop)
            output = process.communicate(timeout=10)[0]
            self.assertEqual(process.returncode, 0, output)
            result = json.loads(result_path.read_bytes())
            expected = None if stop == 'success' else 'command-timeout' if stop == 'timeout' else 'cancelled'
            self.assertEqual(result['failure'], expected)
            if stop == 'success':
                self.assertEqual(result['returncode'], 0)
            self.assertEqual(result['cleanup']['status'], 'PASS')
            self.assertIs(result['cleanup']['absence_verified'], True)
            if observed:
                from evidence import validate_operation
                validate_operation(result['operation'])
                first=result['operation']['first_failure']
                if stop=='success': self.assertIsNone(first)
                else:
                    self.assertEqual(first['gate'],'QUERY_EXEC')
                    self.assertEqual(first['query'],'START')
                    self.assertEqual(first['start'],'UNKNOWN')
                    self.assertEqual(first['query_return'],{'kind':'UNOBSERVED','code':None})
                    self.assertEqual(first['category'],'TIMEOUT' if stop=='timeout' else 'CANCELLED')
                self.assertIsNone(result['operation']['cleanup_failure'])
            state = json.loads(state_path.read_bytes())
            self.assertNotIn('container', state)
            self.assertEqual([call for call in state['calls'] if call[0] == 'start'],
                             [['start', '--attach', item['Id']]])
            self.assertEqual([call for call in state['calls'] if call[:2] == ['container', 'rm']],
                             [['container', 'rm', '--force', item['Id']]])
            if stop != 'success':
                self.assertEqual(int((self.root / 'forwarded').read_text()), signal.SIGTERM)
                for marker in ('start-ready', 'descendant-ready'):
                    with self.assertRaises(ProcessLookupError):
                        os.kill(int((self.root / marker).read_text()), 0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=2)
            process.stdout.close()

    def test_observer_real_owned_return_cancel_timeout_retains_first_and_same_cleanup(self):
        for stop in ('success',signal.SIGTERM,'timeout'):
            with self.subTest(stop=stop):
                with tempfile.TemporaryDirectory() as temporary:
                    original=self.root;self.root=Path(temporary);self.mounts={}
                    for name in ('code','inputs','out'):
                        path=self.root/name;path.mkdir();self.mounts['/'+name]=str(path)
                    try:self.attached_start(stop,True)
                    finally:self.root=original

    def test_attached_start_accepts_exact_cli_profile_and_removes_owned_container(self):
        self.attached_start('success')

    def test_fake_cli_rejects_unsupported_start_flag(self):
        self.attached_start('success')
        result = subprocess.run([str(self.root / 'fake-docker'), '--host', 'unix:///run/docker.sock',
                                 'start', '--attach', '--sig-proxy=false', 'e' * 64],
                                env={'HOME': str(self.root)}, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=2)
        self.assertEqual((result.returncode, result.stdout), (125, b'unknown start flag\n'))

    def test_attached_start_sigint_reaps_cli_descendant_and_removes_owned_container(self):
        self.attached_start(signal.SIGINT)

    def test_attached_start_sigterm_reaps_cli_descendant_and_removes_owned_container(self):
        self.attached_start(signal.SIGTERM)

    def test_attached_start_timeout_reaps_cli_descendant_and_removes_owned_container(self):
        self.attached_start('timeout')



class OperationDiagnostics(unittest.TestCase):
    setUp = BrokerPolicy.setUp
    instance = BrokerPolicy.instance
    env = BrokerPolicy.env
    inspect_row = BrokerPolicy.inspect_row

    def traced(self):
        value=self.instance('provision'); value.observer=broker.Trace()
        value.observer.current['action']='provision';value.daemon={'id':'native-daemon'}
        return value

    def test_every_existing_query_boundary_preserves_observed_exit_before_postchecks(self):
        from types import SimpleNamespace
        cases = [('pre-info','DAEMON_PRE',False),('pre-local','LOCAL_PRE',False),
                 ('exec','QUERY_EXEC',False),('post-local','LOCAL_POST',True),('post-info','DAEMON_POST',True)]
        for fault, gate, returned in cases:
            with self.subTest(fault=fault):
                value=self.traced();self.runner.run.reset_mock()
                self.runner.run.side_effect=ValueError('private runner') if fault=='exec' else None
                self.runner.run.return_value=SimpleNamespace(returncode=125)
                infos=[ValueError('docker-daemon-drift'),None] if fault=='pre-info' else [None,ValueError('docker-daemon-drift')] if fault=='post-info' else [None,None]
                locals_=[ValueError('docker-local-pin-drift'),None] if fault=='pre-local' else [None,ValueError('docker-local-pin-drift')] if fault=='post-local' else [None,None]
                with patch.object(value,'_info',side_effect=infos),patch.object(value,'_local',side_effect=locals_):
                    with self.assertRaises(ValueError):value._operation(['create'])
                first=value.observer.snapshot()['first_failure']
                self.assertEqual(first['gate'],gate);self.assertEqual(first['query'],'CREATE')
                self.assertEqual(first['create'],'UNKNOWN')
                self.assertEqual(first['query_return'], {'kind':'EXIT_NONZERO','code':125} if returned else {'kind':'UNOBSERVED','code':None})
                self.assertEqual(self.runner.run.call_count, int(fault not in ('pre-info','pre-local')))

    def test_returned_start_not_worker_acceptance_or_owned_completion(self):
        from types import SimpleNamespace
        value=self.traced()
        with patch.object(value,'_info',side_effect=[None,ValueError('docker-daemon-drift')]),patch.object(value,'_local'):
            self.runner.run.return_value=SimpleNamespace(returncode=-15)
            with self.assertRaises(ValueError):value._operation(['start','--attach','private-id'])
        first=value.observer.snapshot()['first_failure']
        self.assertEqual(first['query_return'],{'kind':'EXIT_SIGNAL','code':-15})
        self.assertEqual(first['start'],'EXIT_OBSERVED')
        self.assertNotIn('private-id',json.dumps(first))

    def test_actual_info_metadata_retains_http_status_and_prior_process_exit(self):
        value=self.traced();value.observer.begin('CREATE');value.observer.returned(0)
        def response(path,deadline,observer):
            observer.returned(200,daemon=True,http=True)
            return {'ID':'wrong-daemon-id','Architecture':'arm64','OSType':'linux','SecurityOptions':[]}
        with patch.object(value,'_local'),patch.object(broker,'daemon_http',side_effect=response):
            with self.assertRaises(ValueError):value._info(self.runner)
        first=value.observer.snapshot()['first_failure']
        self.assertEqual((first['gate'],first['predicate']),('DAEMON_METADATA','docker-daemon-drift'))
        self.assertEqual(first['daemon_return'],{'kind':'HTTP_STATUS','code':200})
        self.assertEqual(first['query_return'],{'kind':'EXIT_ZERO','code':0})

    def test_actual_inspect_fixed_source_gates_do_not_export_payload(self):
        from types import SimpleNamespace
        for gate, key in [('INSPECT_OWNERSHIP','owner'),('INSPECT_RESOURCES','resources'),
                          ('INSPECT_MOUNTS','mounts'),('INSPECT_COMMAND','command')]:
            value=self.instance();value.observer=broker.Trace();row,item=self.inspect_row(value)
            if key=='owner':item['Config']['User']='0:0'
            if key=='resources':item['HostConfig']['Privileged']=True
            if key=='mounts':item['Mounts'][0]['Source']='/private-secret-path'
            if key=='command':item['Config']['Cmd']=['secret']
            with patch.object(value,'_operation',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([item]).encode())):
                with self.assertRaises(ValueError):value._inspect(row['id'],row)
            first=value.observer.snapshot()['first_failure']
            self.assertEqual(first['gate'],gate);self.assertNotIn('secret',json.dumps(first))

    def test_create_journal_cid_parse_start_and_cleanup_first_failure_schedules(self):
        from types import SimpleNamespace
        for fault, expected in [('attempt','CREATE_ATTEMPT'),('cid','CREATE_ID'),('journal','JOURNAL_WRITE'),('inspect','INSPECT_OWNERSHIP'),('start','QUERY_EXEC')]:
            value=self.traced();row={'schema_version':1,'containers':[]}
            writes=[]
            def write(record):
                writes.append(len(writes))
                if fault=='attempt' and len(writes)==2:raise OSError('private attempt path')
                if fault=='journal' and len(writes)==3:
                    with broker.scope(value.observer,'JOURNAL_WRITE'):raise OSError('private journal path')
            def operation(args,**kwargs):
                value.observer.begin(value.query_kind(args))
                if args[0]=='start' and fault=='start':
                    with broker.scope(value.observer,'QUERY_EXEC'):raise ValueError('command-timeout')
                value.observer.returned(0)
                return SimpleNamespace(returncode=0,stdout=(b'bad' if fault=='cid' else b'e'*64))
            def inspect(*args):
                if fault=='inspect':
                    with broker.scope(value.observer,'INSPECT_OWNERSHIP'):raise ValueError('docker-container-ownership')
            def cleanup():
                with broker.scope(value.observer,'CLEANUP_REMOVE','cleanup'):
                    try:raise ValueError('docker-owned-remove')
                    except ValueError as error:value.observer.fail(error)
                return {'status':'FAIL','absence_verified':False}
            with patch.object(value,'_journal',return_value=row),patch.object(value,'_write',side_effect=write),                 patch.object(value,'_find',return_value=None),patch.object(value,'_operation',side_effect=operation),                 patch.object(value,'_inspect',side_effect=inspect),patch.object(value,'cleanup',side_effect=cleanup):
                with self.assertRaises((OSError,ValueError)):value._launch('name',{},self.mounts,[],900,True)
            snap=value.observer.snapshot();self.assertEqual(snap['first_failure']['gate'],expected)
            self.assertEqual(snap['cleanup_failure']['gate'],'CLEANUP_REMOVE')
            self.assertEqual(snap['first_failure']['create'],'UNKNOWN' if fault in ('attempt','cid') else 'CID_OBSERVED')
            self.assertEqual(snap['first_failure']['start'],'UNKNOWN' if fault=='start' else 'NOT_ATTEMPTED')



class ReturnedNonzeroDiagnostics(unittest.TestCase):
    setUp = BrokerPolicy.setUp
    instance = BrokerPolicy.instance

    def test_returned_create_failure_is_frozen_before_failing_cleanup(self):
        from types import SimpleNamespace
        value=self.instance();value.observer=broker.Trace();value.observer.current['action']='baseline'
        def operation(args,**kwargs):
            value.observer.begin('CREATE');value.observer.returned(125)
            return SimpleNamespace(returncode=125)
        def cleanup():
            with value.observer.scope('CLEANUP_REMOVE','cleanup'):
                value.observer.fail(ValueError('docker-owned-remove'))
            return {'status':'FAIL','absence_verified':False}
        with patch.object(value,'_journal',return_value={'containers':[]}),patch.object(value,'_write'),             patch.object(value,'_find',return_value=None),patch.object(value,'_operation',side_effect=operation),             patch.object(value,'cleanup',side_effect=cleanup):
            with self.assertRaisesRegex(ValueError,'docker-cleanup-failed'):
                value._launch('name',{},self.mounts,[],900)
        result=value.observer.snapshot()
        self.assertEqual(result['first_failure']['category'],'COMMAND_NONZERO')
        self.assertEqual(result['first_failure']['query_return'],{'kind':'EXIT_NONZERO','code':125})
        self.assertEqual(result['cleanup_failure']['predicate'],'docker-owned-remove')



class ResourceMismatchObservations(unittest.TestCase):
    setUp = BrokerPolicy.setUp
    instance = BrokerPolicy.instance
    env = BrokerPolicy.env
    inspect_row = BrokerPolicy.inspect_row
    provision_inspect = BrokerPolicy.provision_inspect

    def refused(self, field, kind, *, cleanup=False, value=None, remove=False):
        subject,row,item=self.provision_inspect();item=__import__('copy').deepcopy(item)
        subject.observer=broker.Trace();subject.observer.current['action']='cleanup' if cleanup else 'provision'
        if remove:del item['HostConfig'][field]
        else:item['HostConfig'][field]=value
        with patch.object(subject,'_operation',return_value=subprocess.CompletedProcess([],0,json.dumps([item]).encode())) as query:
            with self.assertRaisesRegex(ValueError,'^docker-container-resources$'):subject._inspect(row['id'],row,cleanup=cleanup)
        self.assertEqual(query.call_count,1);snapshot=subject.observer.snapshot()
        target='cleanup_failure' if cleanup else 'first_failure'
        self.assertEqual(snapshot[target]['resource_mismatch'],{'field':field,'kind':kind})
        self.assertNotIn('private-secret',json.dumps(snapshot));return subject,snapshot

    def test_all_required_missing_type_value_labels_are_closed(self):
        _,_,item=self.provision_inspect()
        for field,expected in item['HostConfig'].items():
            with self.subTest(field=field):
                self.refused(field,'MISSING',remove=True)
                self.refused(field,'TYPE',value=None)
                changed=(not expected if type(expected) is bool else expected+1 if type(expected) is int
                         else 'private-secret' if type(expected) is str else ['private-secret'] if type(expected) is list
                         else {'private-secret':'private-secret'})
                self.refused(field,'VALUE',value=changed)

    def test_forbidden_presence_and_build_capadd_are_observations_not_permission(self):
        for field in ('Devices','DeviceRequests','Binds','VolumesFrom','Links','PortBindings','GroupAdd'):
            self.refused(field,'PRESENT',value=['private-secret'])
        subject=self.instance();subject.observer=broker.Trace();subject.observer.current['action']='baseline'
        row,item=self.inspect_row(subject);item['HostConfig']['CapAdd']=['private-secret']
        with patch.object(subject,'_operation',return_value=subprocess.CompletedProcess([],0,json.dumps([item]).encode())):
            with self.assertRaisesRegex(ValueError,'^docker-container-resources$'):subject._inspect(row['id'],row)
        self.assertEqual(subject.observer.snapshot()['first_failure']['resource_mismatch'],{'field':'CapAdd','kind':'PRESENT'})

    def test_only_original_refusal_annotates_and_first_conjunct_order_is_preserved(self):
        subject,row,item=self.provision_inspect();subject.observer=broker.Trace()
        item['HostConfig']['AutoRemove']=0  # Existing equality accepts bool/int representation; no new type gate.
        item['HostConfig']['Devices']=[]
        with patch.object(subject,'_operation',return_value=subprocess.CompletedProcess([],0,json.dumps([item]).encode())),\
             patch.object(subject.observer,'resources_refused') as annotate:
            self.assertEqual(subject._inspect(row['id'],row),row['id']);annotate.assert_not_called()
        self.assertIsNone(subject.observer.snapshot()['current']['resource_mismatch'])
        subject,row,item=self.provision_inspect();subject.observer=broker.Trace();subject.observer.current['action']='provision'
        del item['HostConfig']['AutoRemove'];item['HostConfig']['Devices']=['private-secret']
        with patch.object(subject,'_operation',return_value=subprocess.CompletedProcess([],0,json.dumps([item]).encode())):
            with self.assertRaises(ValueError):subject._inspect(row['id'],row)
        self.assertEqual(subject.observer.snapshot()['first_failure']['resource_mismatch'],{'field':'AutoRemove','kind':'MISSING'})

    def test_first_last_and_cleanup_are_independent_and_later_scope_clears_only_current(self):
        subject,first=self.refused('Memory','TYPE',value='private-secret')
        with broker.scope(subject.observer,'CHECKPOINT_WRITE'):
            self.assertIsNone(subject.observer.snapshot()['current']['resource_mismatch'])
        row,item=self.provision_inspect()[1:];item['HostConfig']['PidsLimit']=1
        subject.observer.current['action']='cleanup'
        with patch.object(subject,'_operation',return_value=subprocess.CompletedProcess([],0,json.dumps([item]).encode())):
            with self.assertRaises(ValueError):subject._inspect(row['id'],row,cleanup=True)
        final=subject.observer.snapshot()
        self.assertEqual(final['first_failure'],first['first_failure'])
        self.assertEqual(final['cleanup_failure']['resource_mismatch'],{'field':'PidsLimit','kind':'VALUE'})
        self.assertIsNone(final['current']['resource_mismatch'])  # Existing outer scope is no longer the resource leaf.


class ProvisionCapabilityEquivalence(unittest.TestCase):
    setUp = BrokerPolicy.setUp
    instance = BrokerPolicy.instance
    env = BrokerPolicy.env
    inspect_row = BrokerPolicy.inspect_row
    provision_inspect = BrokerPolicy.provision_inspect

    @staticmethod
    def variants():
        names = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER')
        return [list(order) for prefixes in itertools.product(('', 'CAP_'), repeat=3)
                for order in itertools.permutations([prefix + name for prefix, name in zip(prefixes, names)])]

    def inspect(self, subject, row, item, cleanup=False, error=None):
        original = copy.deepcopy(item)
        decoded = []
        decode = broker.decode
        def capture(raw):
            result = decode(raw)
            decoded.append((result, copy.deepcopy(result)))
            return result
        with patch.object(subject, '_operation', return_value=subprocess.CompletedProcess(
                [], 0, json.dumps([item]).encode())) as query, patch.object(broker, 'decode', side_effect=capture):
            if error:
                with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                    subject._inspect(row['id'], row, cleanup=cleanup)
            else:
                self.assertEqual(subject._inspect(row['id'], row, cleanup=cleanup), row['id'])
        query.assert_called_once_with(['container', 'inspect', row['id']], cleanup=cleanup)
        self.assertEqual(item, original)
        self.assertEqual(len(decoded), 1)
        self.assertEqual(decoded[0][0], decoded[0][1])

    def traced(self, cleanup=False):
        subject, row, item = self.provision_inspect()
        subject.observer = broker.Trace()
        subject.observer.current['action'] = 'cleanup' if cleanup else 'provision'
        return subject, row, item

    def mismatch(self, subject, field, kind, cleanup=False):
        snapshot = subject.observer.snapshot()
        target = 'cleanup_failure' if cleanup else 'first_failure'
        self.assertEqual(snapshot[target]['resource_mismatch'], {'field': field, 'kind': kind})
        self.assertEqual(snapshot[target]['gate'], 'INSPECT_RESOURCES')
        self.assertNotIn('private-secret', json.dumps(snapshot))

    def test_all_48_spellings_and_orders_accept_in_provision_and_cleanup_without_mutation(self):
        variants = self.variants()
        self.assertEqual(len(variants), 48)
        self.assertEqual(len({tuple(value) for value in variants}), 48)
        for cleanup, caps in itertools.product((False, True), variants):
            with self.subTest(cleanup=cleanup, caps=caps):
                subject, row, item = self.traced(cleanup)
                item['HostConfig']['CapAdd'] = caps
                self.inspect(subject, row, item, cleanup)
                snapshot = subject.observer.snapshot()
                self.assertIsNone(snapshot['first_failure'])
                self.assertIsNone(snapshot['cleanup_failure'])

    def test_exact_helper_types_and_closed_capability_set(self):
        class ListSubclass(list): pass
        class StringSubclass(str): pass
        valid = ['CHOWN', 'DAC_OVERRIDE', 'FOWNER']
        for caps in self.variants():
            self.assertIs(broker.provision_capabilities(caps), True)
        for caps in (tuple(valid), ListSubclass(valid), [StringSubclass('CHOWN'), *valid[1:]],
                     None, False, True, 0, 3, '', 'CHOWN', {}, set(valid),
                     ['CHOWN', 'DAC_OVERRIDE', None], ['CHOWN', 'DAC_OVERRIDE', 1]):
            with self.subTest(caps=repr(caps)):
                self.assertIs(broker.provision_capabilities(caps), False)

    def test_invalid_json_capadd_values_refuse_with_closed_diagnostics(self):
        invalid = [None, False, True, 0, 3, '', 'CHOWN', {}, {'CHOWN': True}, [],
                   ['CHOWN'], ['CHOWN', 'DAC_OVERRIDE'], ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SYS_ADMIN'],
                   ['CHOWN', 'CHOWN', 'FOWNER'], ['CHOWN', 'CAP_CHOWN', 'FOWNER'],
                   ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_DAC_OVERRIDE']]
        for bad in ('ALL', 'CAP_ALL', 'SYS_ADMIN', 'private-secret', 'chown', 'cap_CHOWN',
                    'CAP_chown', ' CHOWN', 'CHOWN ', 'CAP_CAP_CHOWN', '', None, False, 0, [], {}):
            invalid.append([bad, 'DAC_OVERRIDE', 'FOWNER'])
        for cleanup, caps in itertools.product((False, True), invalid):
            with self.subTest(cleanup=cleanup, caps=caps):
                subject, row, item = self.traced(cleanup)
                item['HostConfig']['CapAdd'] = caps
                self.inspect(subject, row, item, cleanup, 'docker-container-resources')
                self.mismatch(subject, 'CapAdd', 'VALUE' if type(caps) is list else 'TYPE', cleanup)
        for cleanup in (False, True):
            subject, row, item = self.traced(cleanup)
            del item['HostConfig']['CapAdd']
            self.inspect(subject, row, item, cleanup, 'docker-container-resources')
            self.mismatch(subject, 'CapAdd', 'MISSING', cleanup)

    def test_build_role_forbids_every_equivalent_nonempty_capadd(self):
        for cleanup, caps in itertools.product((False, True), self.variants()):
            with self.subTest(cleanup=cleanup, caps=caps):
                subject = self.instance()
                subject.observer = broker.Trace()
                subject.observer.current['action'] = 'cleanup' if cleanup else 'baseline'
                row, item = self.inspect_row(subject)
                item['HostConfig']['CapAdd'] = caps
                self.inspect(subject, row, item, cleanup, 'docker-container-resources')
                self.mismatch(subject, 'CapAdd', 'PRESENT', cleanup)

    def test_accepted_alias_preserves_every_required_and_forbidden_diagnostic(self):
        _, _, reference = self.provision_inspect()
        for cleanup in (False, True):
            for field, expected in reference['HostConfig'].items():
                if field == 'CapAdd': continue
                changed = (not expected if type(expected) is bool else expected + 1 if type(expected) is int
                           else 'private-secret' if type(expected) is str else ['private-secret'] if type(expected) is list
                           else {'private-secret': 'private-secret'})
                for kind, replacement in (('MISSING', None), ('TYPE', None), ('VALUE', changed)):
                    with self.subTest(cleanup=cleanup, field=field, kind=kind):
                        subject, row, item = self.traced(cleanup)
                        item['HostConfig']['CapAdd'] = ['CAP_FOWNER', 'CHOWN', 'CAP_DAC_OVERRIDE']
                        if kind == 'MISSING': del item['HostConfig'][field]
                        else: item['HostConfig'][field] = replacement
                        self.inspect(subject, row, item, cleanup, 'docker-container-resources')
                        self.mismatch(subject, field, kind, cleanup)
            for field in ('Devices', 'DeviceRequests', 'Binds', 'VolumesFrom', 'Links', 'PortBindings', 'GroupAdd'):
                with self.subTest(cleanup=cleanup, field=field):
                    subject, row, item = self.traced(cleanup)
                    item['HostConfig'].update(CapAdd=['CAP_FOWNER', 'CAP_DAC_OVERRIDE', 'CAP_CHOWN'])
                    item['HostConfig'][field] = ['private-secret']
                    self.inspect(subject, row, item, cleanup, 'docker-container-resources')
                    self.mismatch(subject, field, 'PRESENT', cleanup)

    def test_first_resource_conjunct_and_sticky_independent_cleanup_failure(self):
        subject, row, item = self.traced()
        item['HostConfig'].update(CapAdd=['CAP_FOWNER', 'CHOWN', 'CAP_DAC_OVERRIDE'],
                                  AutoRemove=True, Tmpfs={}, Devices=['private-secret'])
        self.inspect(subject, row, item, error='docker-container-resources')
        self.mismatch(subject, 'AutoRemove', 'VALUE')
        first = subject.observer.snapshot()['first_failure']
        subject.observer.current['action'] = 'cleanup'
        _, row, item = self.provision_inspect()
        item['HostConfig'].update(CapAdd=['CAP_FOWNER', 'CHOWN', 'CAP_DAC_OVERRIDE'],
                                  Devices=['private-secret'])
        self.inspect(subject, row, item, True, 'docker-container-resources')
        self.mismatch(subject, 'Devices', 'PRESENT', True)
        self.assertEqual(subject.observer.snapshot()['first_failure'], first)
        subject, row, item = self.traced()
        item['HostConfig'].update(CapAdd=['CAP_ALL', 'CHOWN', 'FOWNER'], Devices=['private-secret'])
        self.inspect(subject, row, item, error='docker-container-resources')
        self.mismatch(subject, 'CapAdd', 'VALUE')

    def test_alias_does_not_bypass_ownership_mount_or_command_gates(self):
        changes = [('docker-container-ownership', lambda item: item.update(Name='/foreign')),
                   ('docker-container-mounts', lambda item: item['Mounts'][0].update(Source='/foreign')),
                   ('docker-container-command', lambda item: item['Config'].update(Cmd=['foreign'])),
                   ('docker-container-command', lambda item: item['Config'].update(Entrypoint=['/bin/sh'])),
                   ('docker-container-command', lambda item: item['Config'].update(Env=['PATH=/foreign']))]
        for error, change in changes:
            subject, row, item = self.traced()
            item['HostConfig']['CapAdd'] = ['CAP_FOWNER', 'CAP_DAC_OVERRIDE', 'CAP_CHOWN']
            change(item)
            self.inspect(subject, row, item, error=error)
            self.assertIsNone(subject.observer.snapshot()['first_failure']['resource_mismatch'])

    def test_literal_capability_flags_and_other_options_remain_unchanged(self):
        for role in ('build', 'provision'):
            subject = self.instance(role)
            options = subject._options('name', {}, self.mounts)
            self.assertEqual([arg for arg in options if arg.startswith('--cap-add=')],
                             ['--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER']
                             if role == 'provision' else [])
            for arg in ('--cap-drop=ALL', '--security-opt=no-new-privileges', '--network=none',
                        '--ipc=private', '--cgroupns=private', '--memory=14g', '--memory-swap=14g',
                        '--cpus=2', '--pids-limit=512', '--pull=never', '--platform=linux/arm64'):
                self.assertEqual(options.count(arg), 1)

    def test_malformed_hostconfig_keeps_original_exception_and_resource_gate(self):
        for cleanup, host in itertools.product((False, True), (None, [], 'private-secret', 1)):
            with self.subTest(cleanup=cleanup, host=host):
                subject, row, item = self.traced(cleanup)
                item['HostConfig'] = host
                original = copy.deepcopy(item)
                with patch.object(subject, '_operation', return_value=subprocess.CompletedProcess(
                        [], 0, json.dumps([item]).encode())) as query:
                    with self.assertRaises(AttributeError) as caught:
                        subject._inspect(row['id'], row, cleanup=cleanup)
                self.assertIs(type(caught.exception), AttributeError)
                self.assertEqual(caught.exception.args, (f"'{type(host).__name__}' object has no attribute 'get'",))
                query.assert_called_once_with(['container', 'inspect', row['id']], cleanup=cleanup)
                self.assertEqual(item, original)
                snapshot = subject.observer.snapshot()
                target = 'cleanup_failure' if cleanup else 'first_failure'
                self.assertEqual(snapshot[target]['gate'], 'INSPECT_RESOURCES')
                self.assertIsNone(snapshot[target]['resource_mismatch'])
                self.assertNotIn('private-secret', json.dumps(snapshot))


if __name__ == '__main__':
    unittest.main()
