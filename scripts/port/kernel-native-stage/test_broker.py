# SPDX-License-Identifier: MIT
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

    def test_unknown_create_cancellation_never_claims_absence(self):
        value = self.instance()
        row = {'name': 'cachy-asahi-kernel-' + self.nonce, 'id': None, 'create_attempted': True}
        value.cleanup_runner.env = {}; value.cleanup_runner.log_dir = self.root
        with (patch.object(broker, 'Runner', return_value=self.runner),
              patch.object(value, '_journal', return_value={'containers': [row]}),
              patch.object(value, '_find', return_value=None)):
            result = value.cleanup()
        self.assertEqual((result['status'], result['absence_verified']), ('FAIL', False))

    def attached_start(self, stop):
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
value._local=lambda runner:{}
value._info=lambda runner:{'id':'native-fixture-daemon','architecture':'aarch64'}
value.initialize()
with cancellation_handlers():
 try:
  result=value.launch('baseline',%r,%r,%r);failure=None;rc=result.returncode
 except Cancelled:failure='cancelled';rc=None
 except ValueError as error:failure=str(error);rc=None
Path(%r).write_text(json.dumps({'failure':failure,'returncode':rc,'cleanup':value.last_cleanup}))
''' % (str(Path(broker.__file__).parent), str(self.root), env, str(binary), value.image,
       self.nonce, self.mounts, self.mounts, self.env('baseline'), 1 if stop == 'timeout' else 15,
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


if __name__ == '__main__':
    unittest.main()
