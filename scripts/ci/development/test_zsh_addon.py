# SPDX-License-Identifier: MIT
"""Inert source/command/container-data fixtures; no Docker or package actors."""
import ast
import copy
from contextlib import ExitStack, nullcontext
import importlib
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import sys
import signal
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('zsh_addon_fixture', HERE / 'zsh_addon.py')
zsh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(zsh)

# Writer cancellation masking is now part of the private save API. Keep every
# test's signal installation/query/mask inert; narrower case models override it.
_SIGNAL_STACK = None


def setUpModule():
    global _SIGNAL_STACK
    handlers = {number: (lambda *_: None) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
    def install(number, handler):
        previous = handlers[number]
        handlers[number] = handler
        return previous
    _SIGNAL_STACK = ExitStack()
    _SIGNAL_STACK.enter_context(patch.object(zsh.signal, 'signal', side_effect=install))
    _SIGNAL_STACK.enter_context(patch.object(zsh.signal, 'getsignal', side_effect=lambda number: handlers[number]))
    _SIGNAL_STACK.enter_context(patch.object(zsh.signal, 'pthread_sigmask', return_value=set()))


def tearDownModule():
    global _SIGNAL_STACK
    if _SIGNAL_STACK is not None:
        _SIGNAL_STACK.close()
        _SIGNAL_STACK = None


# Independent closed selected-package goldens; no artifact-directory dependency.
FIXTURE_PACKAGE = {'arch': 'any',
 'build_helper_reviewed_inputs': {'.SRCINFO': 'fd7ce4ce1c33534b1b168bfe6166463cd8d74ce602f0469b62d5f9d475081504',
                                  'LICENSE.project': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7',
                                  'LICENSE.upstream': '4598a6be0b8d7f2b708da5259d2a30d4e15e59b3c66781bab9e27744a9f859d8',
                                  'NOTICE': '9171e9a773c8b7c60ae8e489608f7ef4a4dba3a762156aa57e4673960ab2c921',
                                  'PKGBUILD': 'dbcd109f38f75e8bda2c79a5b368961319a57ea7c618987d242cb90b79185408',
                                  'README.md': '775d480926b42496f937aaa019978ae26db6d21cbfa331ef33999f1874c1e4fd',
                                  'check-module.py': 'fa81e94383b3d7caa1522ea6be165579ba7a4d0775f6cc7f1e14c343fb6946bc',
                                  'integration-proposal.json': '40949e6667a2859c7fbc8ce82b78183db3bf353669e2ea1291ff47c2551d6c3d',
                                  'opt-in.zsh': '692bca1e9ba1a2e9bd32de08cb6ffa5d15b19f85b48e1c08d85a48e41fe6f768',
                                  'source-provenance.json': '0e46b589fefba600766591e8cc02897111c5f45e17415f4a2aac004d46418f36',
                                  'usage.md': '3b43dee6a8f3c20796bb6e0965fd60b3b2e7b7e8c2d508efc011ba36aada6760',
                                  'zsh-autosuggestions.zsh': 'eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a'},
 'depends': ['zsh>=4.3.11'],
 'expected_payloads': {'usr/share/cachy-asahi/zsh-autosuggestions/README.md': {'bytes': 2776,
                                                                               'gid': 0,
                                                                               'mode': 420,
                                                                               'sha256': '3b43dee6a8f3c20796bb6e0965fd60b3b2e7b7e8c2d508efc011ba36aada6760',
                                                                               'source': 'usage.md',
                                                                               'type': 'regular',
                                                                               'uid': 0},
                       'usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh': {'bytes': 253,
                                                                                'gid': 0,
                                                                                'mode': 420,
                                                                                'sha256': '692bca1e9ba1a2e9bd32de08cb6ffa5d15b19f85b48e1c08d85a48e41fe6f768',
                                                                                'source': 'opt-in.zsh',
                                                                                'type': 'regular',
                                                                                'uid': 0},
                       'usr/share/cachy-asahi/zsh-autosuggestions/zsh-autosuggestions.zsh': {'bytes': 27017,
                                                                                             'gid': 0,
                                                                                             'mode': 420,
                                                                                             'sha256': 'eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a',
                                                                                             'source': 'zsh-autosuggestions.zsh',
                                                                                             'type': 'regular',
                                                                                             'uid': 0},
                       'usr/share/licenses/cachy-asahi-zsh-autosuggestions/LICENSE.project': {'bytes': 1081,
                                                                                              'gid': 0,
                                                                                              'mode': 420,
                                                                                              'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7',
                                                                                              'source': 'LICENSE.project',
                                                                                              'type': 'regular',
                                                                                              'uid': 0},
                       'usr/share/licenses/cachy-asahi-zsh-autosuggestions/LICENSE.upstream': {'bytes': 1096,
                                                                                               'gid': 0,
                                                                                               'mode': 420,
                                                                                               'sha256': '4598a6be0b8d7f2b708da5259d2a30d4e15e59b3c66781bab9e27744a9f859d8',
                                                                                               'source': 'LICENSE.upstream',
                                                                                               'type': 'regular',
                                                                                               'uid': 0},
                       'usr/share/licenses/cachy-asahi-zsh-autosuggestions/NOTICE': {'bytes': 633,
                                                                                     'gid': 0,
                                                                                     'mode': 420,
                                                                                     'sha256': '9171e9a773c8b7c60ae8e489608f7ef4a4dba3a762156aa57e4673960ab2c921',
                                                                                     'source': 'NOTICE',
                                                                                     'type': 'regular',
                                                                                     'uid': 0}},
 'license': ['MIT'],
 'local_makepkg_sources': ['zsh-autosuggestions.zsh',
                           'opt-in.zsh',
                           'usage.md',
                           'NOTICE',
                           'LICENSE.upstream',
                           'LICENSE.project'],
 'name': 'cachy-asahi-zsh-autosuggestions',
 'optdepends': ['coreutils: stty for upstream optional completion suggestions'],
 'source_files': {'.SRCINFO': {'bytes': 981,
                               'mode': 420,
                               'sha256': 'fd7ce4ce1c33534b1b168bfe6166463cd8d74ce602f0469b62d5f9d475081504'},
                  'LICENSE.project': {'bytes': 1081,
                                      'mode': 420,
                                      'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'},
                  'LICENSE.upstream': {'bytes': 1096,
                                       'mode': 420,
                                       'sha256': '4598a6be0b8d7f2b708da5259d2a30d4e15e59b3c66781bab9e27744a9f859d8'},
                  'NOTICE': {'bytes': 633,
                             'mode': 420,
                             'sha256': '9171e9a773c8b7c60ae8e489608f7ef4a4dba3a762156aa57e4673960ab2c921'},
                  'PKGBUILD': {'bytes': 1745,
                               'mode': 420,
                               'sha256': 'dbcd109f38f75e8bda2c79a5b368961319a57ea7c618987d242cb90b79185408'},
                  'README.md': {'bytes': 3269,
                                'mode': 420,
                                'sha256': '775d480926b42496f937aaa019978ae26db6d21cbfa331ef33999f1874c1e4fd'},
                  'check-module.py': {'bytes': 13447,
                                      'mode': 420,
                                      'sha256': 'fa81e94383b3d7caa1522ea6be165579ba7a4d0775f6cc7f1e14c343fb6946bc'},
                  'integration-proposal.json': {'bytes': 1130,
                                                'mode': 420,
                                                'sha256': '40949e6667a2859c7fbc8ce82b78183db3bf353669e2ea1291ff47c2551d6c3d'},
                  'opt-in.zsh': {'bytes': 253,
                                 'mode': 420,
                                 'sha256': '692bca1e9ba1a2e9bd32de08cb6ffa5d15b19f85b48e1c08d85a48e41fe6f768'},
                  'source-provenance.json': {'bytes': 1482,
                                             'mode': 420,
                                             'sha256': '0e46b589fefba600766591e8cc02897111c5f45e17415f4a2aac004d46418f36'},
                  'usage.md': {'bytes': 2776,
                               'mode': 420,
                               'sha256': '3b43dee6a8f3c20796bb6e0965fd60b3b2e7b7e8c2d508efc011ba36aada6760'},
                  'zsh-autosuggestions.zsh': {'bytes': 27017,
                                              'mode': 420,
                                              'sha256': 'eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a'}},
 'source_root': 'packages/shells/cachy-asahi-zsh-autosuggestions',
 'upstream_revision': '85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5',
 'version': '0.7.1-1'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class DeadlineTests(unittest.TestCase):
    def test_work_cutoff_preserves_nonrenewable_cleanup_reserve(self):
        tick = [50.0]
        deadline = zsh.Deadline(clock=lambda: tick[0])
        self.assertEqual(deadline.remaining(360), 360)
        tick[0] = 50 + 1070
        self.assertEqual(deadline.remaining(360), 10)
        tick[0] = 50 + 1080
        with self.assertRaises(zsh.Refusal): deadline.remaining(30)
        self.assertEqual(deadline.remaining(120, cleanup=True), 120)
        tick[0] = 50 + 1190
        self.assertEqual(deadline.remaining(60, cleanup=True), 10)
        tick[0] = 50 + 1200
        with self.assertRaises(zsh.Refusal): deadline.remaining(1, cleanup=True)

    def test_repeated_remaining_does_not_restart_work_budget(self):
        tick = [0]
        deadline = zsh.Deadline(clock=lambda: tick[0])
        tick[0] = 1079
        self.assertEqual(deadline.remaining(360), 1)
        self.assertEqual(deadline.remaining(360), 1)
        tick[0] += 1
        with self.assertRaises(zsh.Refusal): deadline.remaining(360)
        self.assertEqual(deadline.remaining(60, cleanup=True), 60)

    def test_nonpositive_nonfinite_or_boolean_operation_caps_refused(self):
        deadline = zsh.Deadline(clock=lambda: 0)
        for cap in (0, -1, True, float('inf'), float('nan')):
            with self.subTest(cap=cap), self.assertRaises(zsh.Refusal): deadline.remaining(cap)

    def test_constructor_refuses_ambiguous_or_unbounded_stage_limits(self):
        for total, work in ((True, 1), (1200, True), (float('nan'), 1),
                            (1200, float('inf')), (1201, 1080), (1200, 1200), (1200, 0)):
            with self.subTest(total=total, work=work), self.assertRaises(zsh.Refusal):
                zsh.Deadline(clock=lambda: 0, total=total, work=work)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config = {'image': 'sha256:' + 'a' * 64, 'uid': 1000, 'gid': 1001, 'epoch': 1791748800,
                       'attempt': str(root / 'attempt-1'), 'entry': str(root / 'container-entry.sh'),
                       'cidfile': str(root / 'lane/cid')}
        attempt = Path(self.config['attempt']); attempt.mkdir()
        (attempt / 'inputs').mkdir(); (attempt / 'artifacts').mkdir()
        (attempt / 'expected-packages.lock').write_text('zsh 5.9-1\n')
        Path(self.config['entry']).write_bytes(b'# inert fixture entry; never executed\n')
        Path(self.config['cidfile']).parent.mkdir(mode=0o700)
        self.name = 'cachy-asahi-' + 'b' * 16
        self.argv = ['run', '--rm', '--name', self.name, '--pull=never', '--platform', 'linux/arm64',
                     '--user', '1000:1001', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                     '--pids-limit', '512', '--memory', '4g', '--cpus', '4', '--network', 'none',
                     '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g', '--env', 'CACHY_ASAHI_CONTAINER=1',
                     '--env', 'SOURCE_DATE_EPOCH=1791748800',
                     '--mount', f'type=bind,src={self.config["attempt"]}/inputs,dst=/inputs,readonly',
                     '--mount', f'type=bind,src={self.config["attempt"]}/artifacts,dst=/out',
                     '--mount', f'type=bind,src={self.config["entry"]},dst=/builder-entry.sh,readonly',
                     '--mount', f'type=bind,src={self.config["attempt"]}/expected-packages.lock,dst=/expected-packages.lock,readonly',
                     '--entrypoint', '/bin/bash', self.config['image'], '/builder-entry.sh']

    def test_exact_original_command_becomes_owned_create_without_changing_helper_name(self):
        original = list(self.argv)
        result = zsh.exact_run(self.config, self.argv)
        self.assertEqual(result['name'], self.name)
        self.assertEqual(result['original'], original)
        self.assertEqual(self.argv, original)
        create = result['create']
        self.assertEqual(create[0], 'create')
        self.assertNotIn('--rm', create)
        self.assertEqual(create[create.index('--cidfile') + 1], self.config['cidfile'])
        self.assertEqual(create[create.index('--name') + 1], self.name)
        restored = [item for index, item in enumerate(create)
                    if index not in {create.index('--cidfile'), create.index('--cidfile') + 1}]
        self.assertEqual(restored, ['create', *original[2:]])

    def test_privileged_host_network_extra_mount_and_helper_removal_refused(self):
        candidates = (['rm', '-f', self.name], ['docker', *self.argv], ['run', '--privileged', *self.argv[1:]],
                      [x if x != 'none' else 'host' for x in self.argv],
                      [x.replace('src=' + self.config['attempt'] + '/inputs', 'src=/') for x in self.argv],
                      self.argv[:-2] + ['--mount', 'type=bind,src=/,dst=/host', *self.argv[-2:]])
        for argv in candidates:
            with self.subTest(argv=argv[:4]), self.assertRaises(zsh.Refusal): zsh.exact_run(self.config, argv)

    def test_changed_resource_user_env_image_and_entrypoint_refused(self):
        for old, new in (('512', '513'), ('4g', '8g'), ('4', '8'), ('1000:1001', '0:0'),
                         ('linux/arm64', 'linux/amd64'), ('--cap-drop=ALL', '--cap-add=SYS_ADMIN'),
                         ('--security-opt=no-new-privileges', '--security-opt=seccomp=unconfined'),
                         ('SOURCE_DATE_EPOCH=1791748800', 'SOURCE_DATE_EPOCH=1'),
                         ('CACHY_ASAHI_CONTAINER=1', 'CACHY_ASAHI_CONTAINER=0'),
                         ('/bin/bash', '/bin/sh'), (self.config['image'], 'latest')):
            argv = [new if value == old else value for value in self.argv]
            with self.subTest(old=old), self.assertRaises(zsh.Refusal): zsh.exact_run(self.config, argv)

    def test_missing_readonly_duplicate_option_and_invalid_names_refused(self):
        for argv in ([value for value in self.argv if value != '--read-only'],
                     self.argv[:4] + ['--name', self.name] + self.argv[4:],
                     [value if value != self.name else 'foreign-container' for value in self.argv],
                     [value.replace('/inputs,readonly', '/inputs') for value in self.argv],
                     self.argv + ['extra-command']):
            with self.subTest(argv=argv[:6]), self.assertRaises(zsh.Refusal): zsh.exact_run(self.config, argv)


class ContainerTests(unittest.TestCase):
    def setUp(self):
        CommandTests.setUp(self)
        self.config['base_config'] = {'Env': [], 'WorkingDir': '/tmp'}
        self.cid = 'c' * 64
        mounts = [('/inputs', self.config['attempt'] + '/inputs', True),
                  ('/out', self.config['attempt'] + '/artifacts', False),
                  ('/builder-entry.sh', self.config['entry'], True),
                  ('/expected-packages.lock', self.config['attempt'] + '/expected-packages.lock', True)]
        self.info = {'Id': self.cid, 'Name': '/' + self.name, 'Image': self.config['image'],
                     'Config': {'Image': self.config['image'], 'User': '1000:1001', 'WorkingDir': '/tmp',
                                'Entrypoint': ['/bin/bash'], 'Cmd': ['/builder-entry.sh'],
                                'Env': ['CACHY_ASAHI_CONTAINER=1', 'SOURCE_DATE_EPOCH=1791748800'],
                                'Tty': False, 'OpenStdin': False, 'StdinOnce': False},
                     'HostConfig': {'AutoRemove': False, 'NetworkMode': 'none', 'Privileged': False,
                                    'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': None,
                                    'SecurityOpt': ['no-new-privileges'], 'Memory': 4 * 1024**3,
                                    'MemorySwap': 0, 'NanoCpus': 4 * 10**9, 'PidsLimit': 512,
                                    'Tmpfs': {'/tmp': 'rw,nosuid,nodev,exec,size=4g'},
                                    'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private', 'Runtime': 'runc', 'UsernsMode': '',
                                    'Binds': None, 'Devices': [], 'DeviceRequests': None,
                                    'ContainerIDFile': self.config['cidfile'], 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                                    'Mounts': [{'Type': 'bind', 'Source': source, 'Target': target, 'ReadOnly': readonly}
                                               for target, source, readonly in mounts]},
                     'Mounts': [{'Type': 'bind', 'Source': source, 'Destination': target, 'RW': not readonly,
                                 'Propagation': 'rprivate'} for target, source, readonly in mounts],
                     'State': {'Status': 'created', 'Running': False, 'Paused': False, 'Restarting': False,
                               'Dead': False, 'OOMKilled': False, 'Error': '', 'ExitCode': 0}}

    def test_exact_observed_created_container_accepted_without_actor(self):
        self.assertIsNone(zsh.validate_container(self.config, self.info, self.name, self.cid))

    def test_foreign_cid_name_image_or_root_user_cannot_be_cleanup_authority(self):
        for area, field, value in (('', 'Id', 'd' * 64), ('', 'Name', '/foreign'),
                                   ('', 'Image', 'sha256:' + 'd' * 64), ('Config', 'User', '0:0'),
                                   ('Config', 'Entrypoint', ['/bin/sh']), ('Config', 'Cmd', ['unreviewed-script'])):
            candidate = copy.deepcopy(self.info)
            (candidate[area] if area else candidate)[field] = value
            with self.subTest(area=area, field=field), self.assertRaises(zsh.Refusal):
                zsh.validate_container(self.config, candidate, self.name, self.cid)

    def test_daemon_resource_privilege_or_namespace_drift_refused(self):
        for field, value in (('AutoRemove', True), ('Privileged', True), ('ReadonlyRootfs', False),
                             ('NetworkMode', 'host'), ('CapDrop', []), ('CapAdd', ['SYS_ADMIN']),
                             ('SecurityOpt', ['seccomp=unconfined']), ('Memory', 8 * 1024**3),
                             ('NanoCpus', 8 * 10**9), ('PidsLimit', -1), ('PidMode', 'host')):
            candidate = copy.deepcopy(self.info); candidate['HostConfig'][field] = value
            with self.subTest(field=field), self.assertRaises(zsh.Refusal):
                zsh.validate_container(self.config, candidate, self.name, self.cid)

    def test_changed_bind_source_readonly_type_and_extra_mount_refused(self):
        for field, value in (('Source', '/'), ('RW', True), ('Type', 'volume')):
            candidate = copy.deepcopy(self.info); candidate['Mounts'][0][field] = value
            with self.subTest(field=field), self.assertRaises(zsh.Refusal):
                zsh.validate_container(self.config, candidate, self.name, self.cid)
        candidate = copy.deepcopy(self.info)
        candidate['Mounts'].append({'Type': 'bind', 'Source': '/', 'Destination': '/host', 'RW': True})
        with self.assertRaises(zsh.Refusal): zsh.validate_container(self.config, candidate, self.name, self.cid)


class GateTests(unittest.TestCase):
    def setUp(self):
        ContainerTests.setUp(self)
        self.config.update(owned=str(Path(self.config['cidfile']).parent / 'owned.json'),
                           endpoint='unix:///run/docker.sock', daemon_id='inert-daemon',
                           stage_end=time.monotonic() + 1200, work_end=time.monotonic() + 1080, gate_end=time.monotonic() + 270,
                           docker='/usr/bin/inert-docker-never-executed')
        self.operations, self.inspect_mutation = [], None
        fixture = self
        class FakeDocker:
            env = {'PATH': '/inert', 'LC_ALL': 'C'}
            def binding(self, cleanup=False): fixture.operations.append(('binding', cleanup))
            def absence(self, name, cid=None, cleanup=False): fixture.operations.append(('absence', name, cid))
            def call(self, argv, cap=30, cleanup=False):
                fixture.operations.append(('call', list(argv)))
                if argv[0] == 'create':
                    intent = json.loads(Path(fixture.config['owned']).read_bytes())
                    fixture.assertEqual(intent['status'], 'INTENT')
                    fixture.assertIsNone(intent['cid'])
                    fixture.assertEqual(intent['create'], argv)
                    Path(fixture.config['cidfile']).write_text(fixture.cid + '\n')
                    return (fixture.cid + '\n').encode()
                return b''
            def execute(self, argv, cap=30, cleanup=False):
                return zsh.supervised([fixture.config['docker'], '--host', fixture.config['endpoint'], *argv],
                                      self.env, zsh.Deadline(), cap, cleanup=cleanup)
            def inspect(self, cid, cleanup=False):
                fixture.operations.append(('inspect', cid))
                result = copy.deepcopy(fixture.info)
                if fixture.inspect_mutation: fixture.inspect_mutation(result)
                return result
        self.fake = FakeDocker()
        self.docker_patch = patch.object(zsh, 'Docker', return_value=self.fake)
        self.docker_patch.start(); self.addCleanup(self.docker_patch.stop)

    def attached(self, argv, env, deadline, cap, *args, **kwargs):
        self.operations.append(('start', list(argv)))
        intent = json.loads(Path(self.config['owned']).read_bytes())
        self.assertEqual(intent['status'], 'OBSERVED_BEFORE_START')
        self.assertIs(intent['observed'], True)
        self.assertEqual(intent['cid'], self.cid)
        self.info['State'].update(Status='exited', Running=False, ExitCode=0, OOMKilled=False, Error='')
        return 0, b'inert attached stdout\n'

    def test_durable_create_inspect_and_observed_intent_precede_start(self):
        with patch.object(zsh, 'supervised', side_effect=self.attached):
            code, output = zsh.gate(self.config, self.argv)
        self.assertEqual((code, output), (0, b'inert attached stdout\n'))
        events = [operation[0] for operation in self.operations]
        self.assertLess(events.index('call'), events.index('inspect'))
        self.assertLess(events.index('inspect'), events.index('start'))
        intent = json.loads(Path(self.config['owned']).read_bytes())
        self.assertEqual(intent['status'], 'EXITED')
        self.assertEqual(intent['exit_code'], 0)

    def test_foreign_inspected_cid_or_prestared_state_never_starts(self):
        for mutation in ('foreign-cid', 'already-running'):
            for name in ('owned', 'cidfile'): Path(self.config[name]).unlink(missing_ok=True)
            self.operations.clear()
            def drift(info):
                if mutation == 'foreign-cid': info['Id'] = 'f' * 64
                else: info['State'].update(Status='running', Running=True)
            self.inspect_mutation = drift
            with self.subTest(mutation=mutation), patch.object(zsh, 'supervised') as start:
                with self.assertRaises(zsh.Refusal): zsh.gate(self.config, self.argv)
                start.assert_not_called()
            intent = json.loads(Path(self.config['owned']).read_bytes())
            self.assertEqual(intent['status'], 'CREATED')
            self.assertIs(intent['observed'], False)

    def test_create_reply_and_cidfile_mismatch_keeps_unknown_commit_unstarted(self):
        original = self.fake.call
        def mismatch(argv, *args, **kwargs):
            reply = original(argv, *args, **kwargs)
            return ('f' * 64).encode() if argv[0] == 'create' else reply
        self.fake.call = mismatch
        with patch.object(zsh, 'supervised') as start, self.assertRaises(zsh.Refusal):
            zsh.gate(self.config, self.argv)
        start.assert_not_called()
        intent = json.loads(Path(self.config['owned']).read_bytes())
        self.assertEqual(intent['status'], 'INTENT')
        self.assertIsNone(intent['cid'])

    def test_nonzero_container_exit_is_forwarded_from_terminal_inspection(self):
        def attached(*args, **kwargs):
            _, output = self.attached(*args, **kwargs)
            self.info['State']['ExitCode'] = 7
            return 0, output
        with patch.object(zsh, 'supervised', side_effect=attached):
            code, _ = zsh.gate(self.config, self.argv)
        self.assertEqual(code, 7)
        self.assertEqual(json.loads(Path(self.config['owned']).read_bytes())['exit_code'], 7)

    def test_owned_cleanup_refuses_foreign_cid_configuration_and_no_remove(self):
        with patch.object(zsh, 'supervised', side_effect=self.attached): zsh.gate(self.config, self.argv)
        self.operations.clear()
        self.inspect_mutation = lambda info: info['Config'].update(User='0:0')
        with self.assertRaises(zsh.Refusal): zsh.cleanup_attempt(self.config, zsh.Deadline())
        self.assertFalse(any(operation[0] == 'call' and operation[1][:2] == ['container', 'rm']
                             for operation in self.operations))


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.contract = copy.deepcopy(FIXTURE_PACKAGE)
        self.recipe = self.root / self.contract['source_root']
        self.recipe.mkdir(parents=True)
        for name in self.contract['source_files']:
            source = REPO / self.contract['source_root'] / name
            (self.recipe / name).write_bytes(source.read_bytes())
            (self.recipe / name).chmod(self.contract['source_files'][name]['mode'])

    def test_actual_twelve_sources_and_six_payload_contract_are_accepted_inertly(self):
        self.assertEqual(len(self.contract['source_files']), 12)
        self.assertEqual(len(self.contract['build_helper_reviewed_inputs']), 12)
        self.assertEqual(len(self.contract['expected_payloads']), 6)
        self.assertIsNone(zsh.validate_contract(self.root, self.contract))

    def test_source_bytes_modes_and_missing_notice_refused(self):
        for mutation in ('bytes', 'mode', 'missing'):
            name = 'NOTICE'
            path = self.recipe / name
            data, mode = path.read_bytes(), path.stat().st_mode & 0o777
            if mutation == 'bytes': path.write_bytes(b'X' * len(data))
            elif mutation == 'mode': path.chmod(0o755)
            else: path.unlink()
            with self.subTest(mutation=mutation), self.assertRaises((zsh.Refusal, OSError)):
                zsh.validate_contract(self.root, self.contract)
            path.write_bytes(data); path.chmod(mode)

    def test_unreviewed_recipe_file_symlink_or_hardlink_refused(self):
        extra = self.recipe / 'extra-unreviewed'
        extra.write_bytes(b'inert source')
        with self.assertRaises(zsh.Refusal): zsh.validate_contract(self.root, self.contract)
        extra.unlink()
        notice = self.recipe / 'NOTICE'; data = notice.read_bytes(); notice.unlink()
        notice.symlink_to(self.recipe / 'LICENSE.project')
        with self.assertRaises((zsh.Refusal, OSError)): zsh.validate_contract(self.root, self.contract)
        notice.unlink(); notice.write_bytes(data)
        alias = self.root / 'linked-notice'; os.link(notice, alias)
        with self.assertRaises(zsh.Refusal): zsh.validate_contract(self.root, self.contract)

    def test_six_entry_local_source_subset_cannot_replace_twelve_entry_input_authority(self):
        candidate = copy.deepcopy(self.contract)
        candidate['build_helper_reviewed_inputs'] = {name: candidate['build_helper_reviewed_inputs'][name]
                                                    for name in candidate['local_makepkg_sources']}
        with self.assertRaises(zsh.Refusal): zsh.validate_contract(self.root, candidate)

    def test_contract_payload_hash_mode_or_missing_file_refused(self):
        for field, value in (('sha256', '0' * 64), ('mode', 0o755), ('bytes', 1), ('uid', 1000), ('type', 'symlink')):
            candidate = copy.deepcopy(self.contract)
            candidate['expected_payloads'][next(iter(candidate['expected_payloads']))][field] = value
            with self.subTest(field=field), self.assertRaises(zsh.Refusal): zsh.validate_contract(self.root, candidate)
        candidate = copy.deepcopy(self.contract)
        candidate['expected_payloads'].pop(next(iter(candidate['expected_payloads'])))
        with self.assertRaises(zsh.Refusal): zsh.validate_contract(self.root, candidate)


class PairTests(unittest.TestCase):
    def setUp(self):
        self.comparison = {'status': 'contents-reproduced', 'errors': [],
                           'packages': {'cachy-asahi-zsh-autosuggestions-0.7.1-1-any.pkg.tar.xz': {
                               'installed_contents_equal': True, 'pkginfo_equal': True, 'bytes_equal': True,
                               'buildinfo_equal': True}}, 'hardware_status': 'NOT RUN',
                           'independence_limit': 'same native hosted builder'}

    def test_exact_byte_equal_pair_accepted_buildinfo_result_remains_separate_boolean(self):
        self.assertIsNone(zsh.validate_pair(self.comparison))
        next(iter(self.comparison['packages'].values()))['buildinfo_equal'] = False
        self.assertIsNone(zsh.validate_pair(self.comparison))

    def test_host_content_equal_but_archive_byte_false_cannot_pass(self):
        next(iter(self.comparison['packages'].values()))['bytes_equal'] = False
        with self.assertRaises(zsh.Refusal): zsh.validate_pair(self.comparison)

    def test_missing_failed_multiple_wrong_package_and_boolean_ambiguity_refused(self):
        original = copy.deepcopy(self.comparison)
        for field in ('installed_contents_equal', 'pkginfo_equal', 'bytes_equal', 'buildinfo_equal'):
            for value in (1, 'true', None):
                candidate = copy.deepcopy(original)
                next(iter(candidate['packages'].values()))[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(zsh.Refusal): zsh.validate_pair(candidate)
        for candidate in ({**original, 'status': 'FAIL'}, {**original, 'errors': ['fixture failure']},
                          {**original, 'packages': {}}, {**original, 'packages': {**original['packages'], 'foreign.pkg.tar.xz': {}}}):
            with self.assertRaises(zsh.Refusal): zsh.validate_pair(candidate)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.full, self.target = base / 'full', base / 'original-only'
        self.full.mkdir()
        self.packet = json.loads((REPO / 'scripts/ci/development/packet.lock.json').read_bytes())
        self.initial_path = 'scripts/ci/integration.lock.json'
        selected = set(self.packet['initial_source_files']) | {self.initial_path}
        self.assertEqual(len(selected), 160)
        for name in selected:
            source = REPO / name; target = self.full / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes()); target.chmod(source.stat().st_mode & 0o777)
        addon = self.full / 'packages/shells/cachy-asahi-zsh-autosuggestions/PKGBUILD'
        addon.parent.mkdir(parents=True); addon.write_bytes(b'# inert excluded addon\n')

    def test_original_view_is_exact_159_sources_plus_lock_and_never_addon(self):
        self.assertEqual(zsh.prepare_initial_view(self.full, self.target, self.packet), self.target)
        files = {str(path.relative_to(self.target)) for path in self.target.rglob('*') if path.is_file()}
        self.assertEqual(files, set(self.packet['initial_source_files']) | {self.initial_path})
        self.assertEqual(len(files), 160)
        self.assertFalse((self.target / 'packages/shells/cachy-asahi-zsh-autosuggestions').exists())
        for name, row in self.packet['initial_source_files'].items():
            path = self.target / name
            self.assertEqual(digest(path.read_bytes()), row['sha256'])
            self.assertEqual(path.stat().st_mode & 0o777, row['mode'])

    def test_wrong_initial_cardinality_or_fifth_recipe_authority_refused(self):
        for mutation in ('missing', 'extra', 'replacement'):
            candidate = copy.deepcopy(self.packet)
            names = candidate['initial_source_files']
            if mutation != 'extra': names.pop(next(iter(names)))
            if mutation != 'missing': names['packages/shells/cachy-asahi-zsh-autosuggestions/PKGBUILD'] = {
                'sha256': digest(b'# inert excluded addon\n'), 'mode': 0o644}
            with self.subTest(mutation=mutation), self.assertRaises(zsh.Refusal):
                zsh.prepare_initial_view(self.full, self.target.with_name('bad-' + mutation), candidate)

    def test_initial_lock_pin_source_same_size_mutation_and_existing_target_refused(self):
        candidate = copy.deepcopy(self.packet)
        candidate['metadata_pins'][self.initial_path] = '0' * 64
        with self.assertRaises(zsh.Refusal): zsh.prepare_initial_view(self.full, self.target, candidate)
        path = self.full / next(iter(self.packet['initial_source_files']))
        path.write_bytes(b'X' * path.stat().st_size)
        with self.assertRaises(zsh.Refusal):
            zsh.prepare_initial_view(self.full, self.target.with_name('changed-source'), self.packet)
        self.target.mkdir(exist_ok=True)
        with self.assertRaises(zsh.Refusal): zsh.prepare_initial_view(self.full, self.target, self.packet)


class SourceAuthorityTests(unittest.TestCase):
    """Synthetic marker modules exercise loaders; no real producer is imported."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.full, self.view = base / 'full', base / 'view'
        self.full.mkdir(); self.view.mkdir()
        name = 'scripts/ci/integration.py'
        data = ('from pathlib import Path\nfrom contextlib import contextmanager\nROOT=Path(' + repr(str(self.view)) + ')\n'
                'MARKER="captured"\n@contextmanager\ndef boundary():\n yield "accepted-body"\n'
                'class Controller:\n def __init__(self): self.source=ROOT\n').encode()
        row = {'sha256': digest(data), 'mode': 0o644}
        lock_data = json.dumps({'source_files': {name: row}, 'generated_fixture_files': {}}).encode()
        lock_row = {'sha256': digest(lock_data), 'mode': 0o644}
        rows = {name: row, zsh.INITIAL: lock_row,
                'scripts/ci/development/common.py': {'sha256': digest(b'MARKER="common-captured"\n'), 'mode': 0o644}}
        for root in (self.full, self.view):
            for path_name, content in ((name, data), (zsh.INITIAL, lock_data)):
                path = root / path_name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content); path.chmod(0o644)
        common = self.full / 'scripts/ci/development/common.py'; common.parent.mkdir(parents=True)
        common.write_bytes(b'MARKER="common-captured"\n'); common.chmod(0o644)
        packet = {'source_files': rows, 'initial_source_files': {name: row},
                  'metadata_pins': {zsh.INITIAL: lock_row['sha256']}}
        path = self.full / zsh.LOCK; path.write_text(json.dumps(packet)); path.chmod(0o644)
        self.pin = digest(path.read_bytes())
        self.authority = zsh.SourceAuthority(self.full, self.pin, self.view)
        self.modules = patch.dict(sys.modules)
        self.modules.start(); self.addCleanup(self.modules.stop)
        for name in ('integration', 'common'): sys.modules.pop(name, None)

    def test_captured_loader_ignores_valid_poisoned_bytecode_and_restores_import_hooks(self):
        source = self.view / 'scripts/ci/integration.py'
        cached = Path(importlib.util.cache_from_source(str(source))); cached.parent.mkdir()
        poison = compile('raise AssertionError("foreign PYC executed")', str(source), 'exec')
        header = importlib.util.MAGIC_NUMBER + (0).to_bytes(4, 'little')
        header += int(source.stat().st_mtime).to_bytes(4, 'little') + source.stat().st_size.to_bytes(4, 'little')
        cached.write_bytes(header + marshal.dumps(poison))
        original_spec, original_path = importlib.util.spec_from_file_location, list(sys.path)
        with self.authority:
            module = importlib.import_module('integration')
            self.assertEqual(module.MARKER, 'captured')
            self.assertEqual(module.__file__, str(source))
            self.assertIsNone(module.__cached__)
            with self.assertRaisesRegex(zsh.Refusal, 'real-initial-controller'):
                self.authority.controller(module.Controller())
            common = importlib.import_module('common')
            self.assertEqual(common.MARKER, 'common-captured')
            self.assertIs(self.authority.loaded['common'], common)
        self.assertIs(importlib.util.spec_from_file_location, original_spec)
        self.assertEqual(sys.path, original_path)
        self.assertNotIn('integration', sys.modules)

    def test_preloaded_module_is_refused_even_with_correct_file_attribute(self):
        fake = ModuleType('integration'); fake.__file__ = str(self.view / 'scripts/ci/integration.py')
        sys.modules['integration'] = fake
        with self.assertRaisesRegex(zsh.Refusal, 'preloaded'):
            with self.authority: pass
        self.assertFalse(self.authority.active)

    def test_controller_imitation_or_canonical_module_replacement_refused(self):
        with self.authority:
            module = importlib.import_module('integration')
            with self.assertRaisesRegex(zsh.Refusal, 'real-initial-controller'):
                self.authority.controller(SimpleNamespace(source=self.view))
            actual = module.Controller()
            sys.modules['integration'] = ModuleType('integration')
            with self.assertRaises(zsh.Refusal): self.authority.controller(actual)
            sys.modules['integration'] = module

    def test_same_size_source_drift_between_authority_and_import_is_refused(self):
        source = self.view / 'scripts/ci/integration.py'
        source.write_bytes(b'X' * source.stat().st_size)
        with self.authority, self.assertRaises(zsh.Refusal): importlib.import_module('integration')

    def test_contextmanager_hidden_body_code_replacement_is_refused(self):
        with self.authority:
            module = importlib.import_module('integration')
            with module.boundary() as value: self.assertEqual(value, 'accepted-body')
            wrapper = module.boundary
            def replacement(): yield 'foreign-body'
            wrapper.__wrapped__.__code__ = replacement.__code__
            self.assertIs(module.boundary, wrapper)
            with self.assertRaisesRegex(zsh.Refusal, 'loaded-code-identity-drift'):
                self.authority.verify_loaded()

    def test_unknown_project_import_or_unreviewed_direct_alias_refused(self):
        foreign = self.view / 'scripts/ci/unregistered_probe.py'
        foreign.write_bytes(b'raise AssertionError("unregistered source executed")\n')
        with self.authority:
            sys.path.insert(0, str(foreign.parent))
            with self.assertRaises(zsh.Refusal): importlib.import_module('unregistered_probe')
            with self.assertRaises(zsh.Refusal):
                importlib.util.spec_from_file_location('arbitrary_alias', self.view / 'scripts/ci/integration.py')

    def test_child_bootstrap_embeds_closed_captured_bytes_with_no_pyc_or_path_loader(self):
        mapping = {name: self.view / 'scripts/ci' / (name + '.py')
                   for name in ('build', 'compare', 'package_checks')}
        captured = {path: ('MARKER=' + repr(name) + '\n').encode() for name, path in mapping.items()}
        script = mapping['build']
        model = SimpleNamespace(mapping=mapping, bytes=lambda path: captured[Path(path)],
                                root=self.full, view=self.view)
        output = self.full.parent / 'inert-bootstrap.py'
        zsh.write_bootstrap(output, model, script)
        content = output.read_text(); parsed = ast.parse(content)
        self.assertIn('exec(compile(self.r["data"],p,"exec")', content)
        self.assertIn('m.__cached__=None', content)
        self.assertNotIn('SourceFileLoader', content)
        self.assertNotIn('spec_from_file_location', content)
        self.assertNotIn('read_bytes', content)
        table = ast.literal_eval(next(item.value for item in parsed.body if isinstance(item, ast.Assign)
                                     and any(isinstance(target, ast.Name) and target.id == 'M' for target in item.targets)))
        self.assertEqual(set(table), set(mapping))
        self.assertEqual(table['build']['path'], str(script))
        self.assertEqual({name: row['data'] for name, row in table.items()},
                         {name: captured[path] for name, path in mapping.items()})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


class AbsenceTests(unittest.TestCase):
    def check(self, data, name='owned-fixture', cid='a' * 64, cleanup=False):
        docker = object.__new__(zsh.Docker)
        calls = []
        docker.call = lambda argv, **kwargs: calls.append((argv, kwargs)) or data
        docker.absence(name, cid, cleanup=cleanup)
        self.assertEqual(calls, [(['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}} {{.Names}}'],
                                 {'cleanup': cleanup})])

    def test_empty_and_exact_foreign_inventory_are_valid_absence_observations(self):
        self.check(b'')
        self.check(('b' * 64 + ' valid_foreign-name.1\n').encode(), cleanup=True)

    def test_malformed_duplicate_or_present_identity_refuses_absence(self):
        rows = [b'bad-id foreign\n', ('B' * 64 + ' foreign\n').encode(),
                ('b' * 64 + ' foreign extra\n').encode(),
                ('b' * 64 + ' comma,name\n').encode(), b'\n',
                (('b' * 64 + ' foreign\n') * 2).encode(),
                ('a' * 64 + ' foreign\n').encode(),
                ('b' * 64 + ' owned-fixture\n').encode(),
                (('b' * 64 + ' foreign\n') * 4097).encode()]
        for row in rows:
            with self.subTest(row=row[:80]), self.assertRaises(zsh.Refusal): self.check(row)


class TraversalTests(unittest.TestCase):
    def test_wide_directory_charges_node_before_stat_without_materializing_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            charged = []
            def entries():
                for number in range(1025):
                    def metadata(number=number):
                        charged.append(number)
                        return SimpleNamespace(st_mode=0o100644, st_nlink=1)
                    yield SimpleNamespace(name=str(number), stat=lambda follow_symlinks, f=metadata: f())
            with patch.object(zsh.os, 'scandir', side_effect=lambda _: nullcontext(entries())):
                with self.assertRaisesRegex(zsh.Refusal, 'tree-node-bound'):
                    list(zsh.nodes(temporary))
            self.assertEqual(charged, list(range(1024)))

    def test_deep_directory_refuses_before_descending_beyond_24(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            for _ in range(25): path = path / 'directory'; path.mkdir()
            with self.assertRaisesRegex(zsh.Refusal, 'tree-node-bound'): list(zsh.nodes(temporary))

    def test_expired_traversal_stops_before_entry_metadata_is_consumed(self):
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / 'entry').write_bytes(b'inert')
            deadline = zsh.Deadline(clock=lambda: 0)
            deadline.work_end = 0
            with self.assertRaisesRegex(zsh.Refusal, 'deadline-expired'):
                list(zsh.nodes(temporary, deadline))


class DockerSupervisionModelTests(unittest.TestCase):
    def test_cleanup_skips_live_workspace_quota_but_keeps_tool_and_daemon_binding(self):
        docker = object.__new__(zsh.Docker)
        docker.config = {'docker': '/inert-docker', 'endpoint': 'unix:///inert/socket',
                         'docker_config': '/inert/config', 'quota_root': '/inert/quota',
                         'inside_helper': True, 'daemon_binding': {'ID': 'inert'}}
        docker.env, docker.deadline = {}, zsh.Deadline(clock=lambda: 0)
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup), patch.object(docker, 'tools') as tools, \
                 patch.object(docker, 'binding') as binding, \
                 patch.object(zsh, 'supervised', return_value=(0, b'inert')) as run:
                self.assertEqual(docker.execute(['container', 'ls'], cleanup=cleanup), (0, b'inert'))
                self.assertEqual([call.args for call in tools.call_args_list], [(cleanup,), (cleanup,)])
                self.assertEqual([call.args for call in binding.call_args_list], [(cleanup,), (cleanup,)])
                self.assertIs(run.call_args.kwargs['new_group'], False)
                self.assertEqual(run.call_args.kwargs['quota_root'], None if cleanup else '/inert/quota')


class SupervisionTests(unittest.TestCase):
    """All process, selector, signal-mask, and group operations are inert models."""
    def setUp(self):
        # New cleanup-proof API has sticky private failure state. Restore only
        # this inert fixture's prior state after its modeled resources close.
        prior = list(zsh._PROCESS_DISPOSAL_UNCERTAIN)
        self.addCleanup(lambda: zsh._PROCESS_DISPOSAL_UNCERTAIN.__setitem__(slice(None), prior))
        self.tick, self.signals, self.waits = [0], [], []
        self.blocks = [b'fixture-output', b'']
        self.state, self.group, self.stubborn = 0, False, False
        self.stdout = SimpleNamespace(closed=False)
        self.stdout.close = lambda: setattr(self.stdout, 'closed', True)
        self.process = SimpleNamespace(pid=987654321, stdout=self.stdout,
                                       poll=lambda: self.state, wait=self.wait,
                                       send_signal=self.send_signal)
        self.deadline = zsh.Deadline(clock=lambda: self.tick[0])
        self.selector = SimpleNamespace(active=True)
        self.selector.register = lambda *_: None
        self.selector.unregister = lambda *_: setattr(self.selector, 'active', False)
        self.selector.get_map = lambda: {9: self.stdout} if self.selector.active else {}
        self.selector.select = self.select
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.popen = self.stack.enter_context(patch.object(zsh.subprocess, 'Popen', return_value=self.process))
        self.stack.enter_context(patch.object(zsh.selectors, 'DefaultSelector',
                                            side_effect=lambda: nullcontext(self.selector)))
        self.stack.enter_context(patch.object(zsh.os, 'read', side_effect=self.read))
        self.group_signal = self.stack.enter_context(patch.object(zsh.os, 'killpg', side_effect=self.killpg))
        self.mask = self.stack.enter_context(patch.object(zsh.signal, 'pthread_sigmask', return_value=set()))
        self.stack.enter_context(patch.object(zsh, 'defer_cancel', side_effect=lambda: nullcontext([])))

    def select(self, timeout):
        self.assertGreaterEqual(timeout, 0)
        self.assertLessEqual(timeout, .1)
        return [(SimpleNamespace(fd=9, fileobj=self.stdout), 1)] if self.selector.active else []

    def read(self, fd, limit):
        self.assertEqual((fd, limit), (9, 65536))
        return self.blocks.pop(0)

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.state is None:
            raise zsh.subprocess.TimeoutExpired('inert-fixture', timeout)
        return self.state

    def killpg(self, pid, signum):
        self.assertEqual(pid, self.process.pid)
        self.signals.append(signum)
        if signum == 0:
            if not self.group: raise ProcessLookupError()
        elif signum == signal.SIGKILL and not self.stubborn:
            self.state, self.group = -9, False

    def send_signal(self, signum):
        self.signals.append(signum)
        if signum == signal.SIGKILL and not self.stubborn: self.state = -9

    def run_model(self, **kwargs):
        return zsh.supervised(['/inert-never-executed', 'fixture'], {'PATH': '/inert'},
                              self.deadline, 1, **kwargs)

    def test_success_captures_exact_output_and_checks_group_absence(self):
        self.assertEqual(self.run_model(), (0, b'fixture-output'))
        self.assertEqual(self.signals, [0])
        self.assertTrue(self.stdout.closed)
        _, options = self.popen.call_args
        self.assertTrue(options['start_new_session'])
        self.assertTrue(options['close_fds'])
        self.assertEqual(options['env'], {'PATH': '/inert'})
        self.assertEqual(self.mask.call_args_list[0].args[0], signal.SIG_BLOCK)
        self.assertEqual(self.mask.call_args_list[1].args[0], signal.SIG_SETMASK)

    def test_exited_leader_with_live_group_is_disposed_before_success(self):
        self.group = True
        self.assertEqual(self.run_model(), (0, b'fixture-output'))
        self.assertEqual(self.signals, [0, signal.SIGTERM, signal.SIGKILL, 0])
        self.assertFalse(self.group)

    def test_timeout_kills_and_reaps_with_finite_remaining_cleanup_budget(self):
        self.state, self.group = None, True
        def advance(timeout):
            self.tick[0] = 1199
            return []
        self.selector.select = advance
        with self.assertRaisesRegex(zsh.Refusal, 'process-timeout'): self.run_model()
        self.assertEqual(self.signals, [signal.SIGTERM, signal.SIGKILL, 0])
        self.assertEqual(self.waits, [1, 1])
        self.assertTrue(self.stdout.closed)

    def test_expired_stage_still_sends_kill_without_renewing_wait_budget(self):
        self.state, self.group = None, True
        self.selector.select = lambda _: self.tick.__setitem__(0, 1201) or []
        with self.assertRaisesRegex(zsh.Refusal, 'process-timeout'): self.run_model()
        self.assertEqual(self.waits, [0, 0])
        self.assertIn(signal.SIGKILL, self.signals)
        self.assertTrue(self.stdout.closed)

    def test_output_bound_refuses_and_disposes_before_returning_partial_data(self):
        self.blocks = [b'x' * 65536] * 65
        self.state, self.group = None, True
        with self.assertRaisesRegex(zsh.Refusal, 'process-output-bound'): self.run_model()
        self.assertEqual(self.signals, [signal.SIGTERM, signal.SIGKILL, 0])
        self.assertTrue(self.stdout.closed)

    def test_output_read_error_closes_stream_and_disposes_group(self):
        self.state, self.group = None, True
        with patch.object(zsh.os, 'read', side_effect=OSError('inert read failure')):
            with self.assertRaisesRegex(OSError, 'inert read failure'): self.run_model()
        self.assertEqual(self.signals, [signal.SIGTERM, signal.SIGKILL, 0])
        self.assertTrue(self.stdout.closed)

    def test_unproved_group_disposal_refuses_even_after_exited_leader(self):
        self.group, self.stubborn = True, True
        with self.assertRaisesRegex(zsh.Refusal, 'process-group-disposal-unproved'): self.run_model()
        self.assertTrue(self.stdout.closed)
        self.assertIn(signal.SIGKILL, self.signals)

    def test_pending_cancel_on_spawn_mask_restore_retains_child_for_disposal(self):
        self.state, self.group = None, True
        self.mask.side_effect = [set(), KeyboardInterrupt('inert pending cancel')]
        with self.assertRaises(KeyboardInterrupt): self.run_model()
        self.popen.assert_called_once()
        self.assertEqual(self.signals, [signal.SIGTERM, signal.SIGKILL, 0])
        self.assertTrue(self.stdout.closed)

    def test_inner_gate_cli_keeps_outer_owned_group_and_creates_no_new_session(self):
        self.assertEqual(self.run_model(new_group=False), (0, b'fixture-output'))
        self.assertIs(self.popen.call_args.kwargs['start_new_session'], False)
        self.group_signal.assert_not_called()
        self.assertTrue(self.stdout.closed)

    def test_inner_gate_failure_signals_only_direct_child_and_preserves_outer_group(self):
        self.state = None
        with patch.object(zsh.os, 'read', side_effect=OSError('inert inner read error')):
            with self.assertRaises(OSError): self.run_model(new_group=False)
        self.assertEqual(self.signals, [signal.SIGTERM, signal.SIGKILL])
        self.group_signal.assert_not_called()
        self.assertTrue(self.stdout.closed)

    def test_live_workspace_quota_failure_disposes_child_without_returning_success(self):
        self.state, self.group = None, True
        with patch.object(zsh, 'quota', side_effect=zsh.Refusal('workspace-quota-refused')) as quota:
            with self.assertRaisesRegex(zsh.Refusal, 'workspace-quota-refused'):
                self.run_model(quota_root='/inert-not-traversed')
        quota.assert_called_once_with('/inert-not-traversed', self.deadline)
        self.assertEqual(self.signals, [signal.SIGTERM, signal.SIGKILL, 0])
        self.assertTrue(self.stdout.closed)


class CancellationModelTests(unittest.TestCase):
    def test_remembered_finalization_event_is_forwarded_to_restored_owner(self):
        outer_events, handlers = [], {}
        def outer(signum, frame): outer_events.append(signum)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): handlers[signum] = outer
        def installed(signum, handler):
            previous = handlers[signum]
            handlers[signum] = handler
            return previous
        with patch.object(zsh.signal, 'signal', side_effect=installed), \
             patch.object(zsh.signal, 'getsignal', side_effect=lambda sig: handlers[sig]), \
             patch.object(zsh.signal, 'pthread_sigmask', return_value=set()):
            with zsh.defer_cancel() as remembered:
                handlers[signal.SIGTERM](signal.SIGTERM, None)
                self.assertEqual(remembered, [signal.SIGTERM])
                self.assertEqual(outer_events, [])
            self.assertEqual(outer_events, [signal.SIGTERM])
            self.assertTrue(all(handler is outer for handler in handlers.values()))


class FinalizationTests(unittest.TestCase):
    """Exercise the pure finalization seam; producer/actor dispatch is inert."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root, self.view, self.native = (base / name for name in ('root', 'view', 'native'))
        for path in (self.root, self.view, self.native): path.mkdir()
        self.output = base / 'output'
        self.controller = SimpleNamespace(native_out=self.native)
        # Private API correction: no unregistered SourceAuthority or shadowed
        # guard grants. Original test bodies dispatch only this pure seam.
        self.authority = SimpleNamespace(root=self.root, view=self.view, pin='0' * 64, verify=lambda: None)
        self.records = ('adapter-status/result.json', 'public/receipt.json', 'result.json')
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        def finalize_model(controller, root, output, *, authority):
            self.assertIs(controller, self.controller)
            self.assertIs(authority, self.authority)
            self.assertEqual(Path(root), self.root)
            output = Path(output); output.mkdir(mode=0o700)
            result = {'stage': 'zsh-addon', 'status': 'PASS', 'provisional': True,
                      'cleanup': {'status': 'UNKNOWN'}, 'attempts': [], 'comparison': None,
                      'hardware_status': 'NOT RUN', 'installation': 'NOT RUN',
                      'selected_for_release': False, 'public': [], 'source_packet_sha256': authority.pin}
            return zsh.finalize_stage(output, result, [], zsh.Deadline(clock=lambda: 0), authority)
        self.stack.enter_context(patch.object(zsh, 'run_zsh', side_effect=finalize_model))
        self.outer = lambda *_: None
        self.stack.enter_context(patch.object(zsh.signal, 'getsignal', return_value=self.outer))
        self.signal = self.stack.enter_context(patch.object(zsh.signal, 'signal', return_value=self.outer))
        self.stack.enter_context(patch.object(zsh.signal, 'pthread_sigmask', return_value=set()))
        real_finish = zsh.finish
        def provisional_finish(output, result):
            # Model the successful actor outcome at the receipt boundary only.
            result['status'] = 'PASS'
            real_finish(output, result)
        self.stack.enter_context(patch.object(zsh, 'finish', side_effect=provisional_finish))

    def statuses(self):
        return [json.loads((self.output / path).read_bytes())['status'] for path in self.records]

    def test_restoration_keyboardinterrupt_rewrites_all_three_real_pass_receipts(self):
        observed = []
        def restore(signum, handler):
            if handler is self.outer and (self.output / 'result.json').exists() and not observed:
                observed.append(self.statuses())
                raise KeyboardInterrupt('inert restoration cancellation')
            return self.outer
        self.signal.side_effect = restore
        with self.assertRaises(KeyboardInterrupt):
            zsh.run_zsh(self.controller, self.root, self.output, authority=self.authority)
        self.assertEqual(observed, [['PASS', 'PASS', 'PASS']])
        self.assertEqual(self.statuses(), ['FAIL', 'FAIL', 'FAIL'])
        for path in self.records:
            self.assertEqual(json.loads((self.output / path).read_bytes())['cleanup']['status'], 'PASS')

    def test_partial_receipt_write_failure_is_reconciled_to_three_real_fail_records(self):
        real_save, failed = zsh.save, []
        def write(path, value):
            if Path(path) == self.output / 'public/receipt.json' and not failed:
                failed.append(json.loads((self.output / 'adapter-status/result.json').read_bytes())['status'])
                raise OSError('inert one-shot receipt write failure')
            return real_save(path, value)
        with patch.object(zsh, 'save', side_effect=write):
            result = zsh.run_zsh(self.controller, self.root, self.output, authority=self.authority)
        self.assertEqual(failed, ['PASS'])
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(self.statuses(), ['FAIL', 'FAIL', 'FAIL'])


class DisposalCorrectionTests(unittest.TestCase):
    def setUp(self):
        SupervisionTests.setUp(self)

    # Bind only inert model helpers, avoiding duplicate inherited test methods.
    select = SupervisionTests.select
    read = SupervisionTests.read
    wait = SupervisionTests.wait
    killpg = SupervisionTests.killpg
    send_signal = SupervisionTests.send_signal
    run_model = SupervisionTests.run_model

    def test_term_error_continues_owned_group_kill_and_preserves_exact_business_error(self):
        self.state, self.group = None, True
        original = zsh.Refusal('process-timeout')
        def signaling(pid, number):
            if number == signal.SIGTERM:
                self.signals.append(number)
                raise OSError(5, 'inert TERM failure')
            return self.killpg(pid, number)
        with patch.object(zsh.os, 'read', side_effect=original), \
             patch.object(zsh.os, 'killpg', side_effect=signaling):
            with self.assertRaises(zsh.Refusal) as caught: self.run_model()
        self.assertIs(caught.exception, original)
        self.assertIn(signal.SIGKILL, self.signals)
        self.assertTrue(self.waits)
        self.assertFalse(self.group)
        self.assertTrue(self.stdout.closed)

    def test_inner_term_error_continues_direct_kill_and_preserves_exact_interrupt(self):
        self.state = None
        original = KeyboardInterrupt('inert original cancellation')
        def signaling(number):
            if number == signal.SIGTERM:
                self.signals.append(number)
                raise OSError(5, 'inert inner TERM failure')
            return self.send_signal(number)
        self.process.send_signal = signaling
        with patch.object(zsh.os, 'read', side_effect=original):
            with self.assertRaises(KeyboardInterrupt) as caught: self.run_model(new_group=False)
        self.assertIs(caught.exception, original)
        self.assertEqual(self.signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(self.waits)
        self.group_signal.assert_not_called()
        self.assertTrue(self.stdout.closed)

    def test_disposal_mask_entry_error_still_kills_reaps_closes_and_keeps_first_timeout(self):
        self.state, self.group = None, True
        original = zsh.Refusal('process-timeout')
        with patch.object(zsh.os, 'read', side_effect=original), \
             patch.object(zsh, 'defer_cancel', side_effect=OSError(5, 'inert disposal mask entry')):
            with self.assertRaises(zsh.Refusal) as caught: self.run_model()
        self.assertIs(caught.exception, original)
        self.assertIn(signal.SIGTERM, self.signals)
        self.assertIn(signal.SIGKILL, self.signals)
        self.assertTrue(self.waits)
        self.assertFalse(self.group)
        self.assertTrue(self.stdout.closed)


class CleanupCustodyCorrectionTests(unittest.TestCase):
    def setUp(self):
        GateTests.setUp(self)

    def test_missing_intent_with_present_cid_cannot_pass_or_authorize_removal(self):
        Path(self.config['cidfile']).write_text(self.cid + '\n')
        self.assertFalse(Path(self.config['owned']).exists())
        self.operations.clear()
        try:
            result = zsh.cleanup_attempt(self.config, zsh.Deadline())
        except zsh.Refusal:
            pass
        else:
            self.assertNotEqual(result.get('status'), 'PASS')
        self.assertFalse(any(op[0] == 'call' and op[1][:2] == ['container', 'rm'] for op in self.operations))
        self.assertTrue(Path(self.config['cidfile']).exists())


class AuthorityCorrectionTests(unittest.TestCase):
    """Closed synthetic module graph; every executed body is inert fixture code."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root, self.view, self.snapshot = (base / name for name in ('root', 'view', 'controller-source'))
        for directory in (self.root, self.view, self.snapshot): directory.mkdir()
        integration = ('import hashlib\nfrom pathlib import Path\nROOT=Path(' + repr(str(self.view)) + ')\n'
                       'SOURCE=Path(' + repr(str(self.snapshot)) + ')\nPOLICY=True\nCANCEL_REQUESTED=False\n'
                       'def global_policy(): return POLICY\n'
                       'def kw_policy(*, policy=True): return policy\n'
                       'def list_policy(policy=[True]): return policy[0]\n'
                       'def imported_digest(data): return hashlib.sha256(data).hexdigest()\n'
                       'class Controller:\n def __init__(self): self.source=SOURCE;self.native_out=SOURCE\n'
                       ' def run(self,integration_consumers): return integration_consumers(self)\n'
                       ' @property\n def token(self): return "accepted-property"\n').encode()
        native = ('from pathlib import Path\nROOT=Path(' + repr(str(self.view)) + ')\n'
                  'def main(argv,integration_consumers=None):\n from integration import Controller\n'
                  ' return Controller().run(integration_consumers)\n').encode()
        sources = {'scripts/ci/integration.py': integration, 'scripts/ci/native_arm.py': native}
        rows = {name: {'sha256': digest(data), 'mode': 0o644} for name, data in sources.items()}
        lock = json.dumps({'source_files': rows, 'generated_fixture_files': {}}).encode()
        for directory in (self.root, self.view, self.snapshot):
            for name, data in sources.items():
                path = directory / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data); path.chmod(0o644)
        for directory in (self.root, self.view):
            path = directory / zsh.INITIAL; path.write_bytes(lock); path.chmod(0o644)
        # Same actual common source authenticated in the blocked root review;
        # pin its repo bytes so this fixture has no artifact dependency.
        common = (HERE / 'common.py').read_bytes()
        self.assertEqual(digest(common), 'b62ec5f3c106589ff431af5ae88733cc30a0819a8a884257d75af3db8a52307d')
        path = self.root / 'scripts/ci/development/common.py'
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(common); path.chmod(0o644)
        checker = b'CHECKER_MARKER="inert-declared-alias"\n'
        path = self.root / 'scripts/checks/package_checks.py'
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(checker); path.chmod(0o644)
        packet = {'source_files': {**rows, zsh.INITIAL: {'sha256': digest(lock), 'mode': 0o644},
                                  'scripts/ci/development/common.py': {'sha256': digest(common), 'mode': 0o644},
                                  'scripts/checks/package_checks.py': {'sha256': digest(checker), 'mode': 0o644}},
                  'initial_source_files': rows, 'metadata_pins': {zsh.INITIAL: digest(lock)}}
        data = json.dumps(packet).encode()
        path = self.root / zsh.LOCK; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(0o644)
        self.modules = patch.dict(sys.modules); self.modules.start(); self.addCleanup(self.modules.stop)
        for name in ('integration', 'native_arm', 'common', 'package_checks', 'development_package_checks'):
            sys.modules.pop(name, None)
        self.authority = zsh.SourceAuthority(self.root, digest(data), self.view)

    def test_keyword_default_content_mutation_is_refused(self):
        with self.authority:
            module = importlib.import_module('integration')
            self.assertIs(module.kw_policy(), True)
            module.kw_policy.__kwdefaults__['policy'] = False
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_mutable_positional_default_content_mutation_is_refused(self):
        with self.authority:
            module = importlib.import_module('integration')
            self.assertIs(module.list_policy(), True)
            module.list_policy.__defaults__[0][0] = False
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_property_descriptor_replacement_is_refused(self):
        with self.authority:
            module = importlib.import_module('integration')
            self.assertEqual(module.Controller().token, 'accepted-property')
            module.Controller.token = property(lambda _: 'foreign-property')
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_imported_hashlib_binding_replacement_is_refused(self):
        with self.authority:
            module = importlib.import_module('integration')
            self.assertEqual(module.imported_digest(b'inert'), digest(b'inert'))
            module.hashlib = SimpleNamespace(sha256=lambda _: SimpleNamespace(hexdigest=lambda: '0' * 64))
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_execution_global_policy_replacement_is_refused(self):
        with self.authority:
            module = importlib.import_module('integration')
            module.POLICY = False
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_decoded_packet_paths_and_buffers_cannot_redefine_pinned_source(self):
        name = 'scripts/ci/integration.py'
        original = (self.root / name).read_bytes()
        changed = original.replace(b'POLICY=True', b'POLICY=None')
        self.assertEqual(len(original), len(changed))
        serialized_pin = digest((self.root / zsh.LOCK).read_bytes())
        for directory in (self.root, self.view): (directory / name).write_bytes(changed)
        row = {'sha256': digest(changed), 'mode': 0o644}
        try:
            self.authority.packet['source_files'][name] = row
            self.authority.packet['initial_source_files'][name] = row
            for directory in (self.root, self.view):
                path = str(directory / name)
                self.authority.paths[path] = row
                self.authority.buffers[path] = changed
        except (TypeError, AttributeError, zsh.Refusal):
            pass
        self.assertEqual(digest((self.root / zsh.LOCK).read_bytes()), serialized_pin)
        with self.assertRaises(zsh.Refusal): self.authority.verify()
        with self.assertRaises(zsh.Refusal): self.authority.bytes(self.view / name)

    def test_instance_controller_shadow_cannot_create_run_output(self):
        output = self.root.parent / 'unauthorized-output'
        with self.authority:
            module = importlib.import_module('integration')
            try:
                self.authority.controller = lambda _: None
            except (AttributeError, TypeError, zsh.Refusal):
                self.assertFalse(output.exists())
                return
            with patch.object(zsh.signal, 'signal', return_value=lambda *_: None), \
                 patch.object(zsh.signal, 'getsignal', return_value=lambda *_: None), \
                 patch.object(zsh.signal, 'pthread_sigmask', return_value=set()), \
                 self.assertRaises(zsh.Refusal):
                zsh.run_zsh(module.Controller(), self.root, output, authority=self.authority)
        self.assertFalse(output.exists())

    def test_writable_controller_flags_do_not_forge_callback_custody(self):
        with self.authority:
            module = importlib.import_module('integration')
            controller = module.Controller()
            try:
                self.authority.current_controller, self.authority.native_running = controller, True
            except (AttributeError, TypeError, zsh.Refusal):
                return
            with self.assertRaises(zsh.Refusal): self.authority.controller(controller)

    def test_loader_class_poison_cannot_recapture_foreign_module_as_baseline(self):
        original = zsh.BytesLoader.exec_module
        def poisoned(loader, module):
            original(loader, module)
            module.global_policy = lambda: False
            loader.authority.states[module.__name__] = loader.authority.state(module)
        with patch.object(zsh.BytesLoader, 'exec_module', poisoned):
            with self.assertRaises(zsh.Refusal):
                with self.authority:
                    importlib.import_module('integration')
                    self.authority.verify_loaded()

    def test_actual_retained_common_digest_positive_and_hashlib_poison_refusal(self):
        with self.authority:
            module = importlib.import_module('common')
            path = self.root.parent / 'inert-digest'; path.write_bytes(b'actual-common-data')
            self.assertEqual(module.digest(path), digest(b'actual-common-data'))
            self.authority.verify_loaded()
            class FakeHash:
                def update(self, data): pass
                def hexdigest(self): return '0' * 64
            module.hashlib = SimpleNamespace(sha256=lambda: FakeHash())
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_actual_common_keyword_default_poison_refused_without_command_actor(self):
        with self.authority:
            module = importlib.import_module('common')
            self.authority.verify_loaded()
            module.command.__kwdefaults__['cleanup_grace'] = 0
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_cancellation_exact_boolean_can_become_sticky_true_but_cannot_reset(self):
        with self.authority:
            module = importlib.import_module('integration')
            self.authority.verify_loaded()
            module.CANCEL_REQUESTED = True
            self.authority.verify_loaded()
            self.authority.verify_loaded()
            module.CANCEL_REQUESTED = False
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_integer_cancellation_flag_cannot_impersonate_exact_boolean(self):
        with self.authority:
            module = importlib.import_module('integration')
            module.CANCEL_REQUESTED = 1
            with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_actual_captured_inert_native_and_controller_frames_grant_only_callback(self):
        observed = []
        with self.authority:
            def consume(controller):
                self.authority.controller(controller)
                observed.append(controller)
                return 'inert-callback'
            self.assertEqual(self.authority.run_native([], consume), 'inert-callback')
            self.assertEqual(len(observed), 1)
            with self.assertRaises(zsh.Refusal): self.authority.controller(observed[0])

    def test_instance_dict_shadow_cannot_bypass_callback_guard(self):
        output = self.root.parent / 'dict-shadow-output'
        with self.authority:
            module = importlib.import_module('integration')
            try:
                namespace = self.authority.__dict__
            except AttributeError:
                return
            namespace['controller'] = lambda _: None
            namespace['verify'] = lambda: None
            try:
                with patch.object(zsh.signal, 'signal', return_value=lambda *_: None), \
                     patch.object(zsh.signal, 'getsignal', return_value=lambda *_: None), \
                     patch.object(zsh.signal, 'pthread_sigmask', return_value=set()), \
                     self.assertRaises(zsh.Refusal):
                    zsh.run_zsh(module.Controller(), self.root, output, authority=self.authority)
            finally:
                namespace.pop('controller', None)
                namespace.pop('verify', None)
        self.assertFalse(output.exists())

    def test_loader_code_identity_change_is_refused_before_module_acceptance(self):
        loader = zsh.BytesLoader.exec_module
        original = loader.__code__
        try:
            loader.__code__ = original.replace(co_filename='foreign-loader-code')
            with self.assertRaises(zsh.Refusal):
                with self.authority:
                    importlib.import_module('integration')
                    self.authority.verify_loaded()
        finally:
            loader.__code__ = original

    def test_loader_path_cannot_switch_to_another_registered_module_before_exec(self):
        with self.authority:
            loader = zsh.BytesLoader(self.authority, self.authority.mapping['integration'])
            foreign = ModuleType('integration')
            try:
                loader.path = self.authority.mapping['native_arm']
            except (AttributeError, TypeError, zsh.Refusal):
                return
            with self.assertRaises(zsh.Refusal): loader.exec_module(foreign)
            self.assertNotIn('main', foreign.__dict__)

    def test_loader_authority_cannot_be_replaced_by_caller_byte_provider(self):
        with self.authority:
            loader = zsh.BytesLoader(self.authority, self.authority.mapping['integration'])
            foreign = ModuleType('integration')
            replacement = SimpleNamespace(loaded={}, states={}, verify_loaded=lambda: None,
                                          bytes=lambda _: b'FOREIGN_EXECUTED=True\n', state=lambda _: {})
            try:
                loader.authority = replacement
            except (AttributeError, TypeError, zsh.Refusal):
                return
            with self.assertRaises(zsh.Refusal): loader.exec_module(foreign)
            self.assertNotIn('FOREIGN_EXECUTED', foreign.__dict__)

    def test_added_authority_getattribute_descriptor_is_refused(self):
        with self.authority:
            with patch.object(zsh.SourceAuthority, '__getattribute__',
                              lambda owner, name: object.__getattribute__(owner, name), create=True):
                with self.assertRaises(zsh.Refusal): self.authority.verify_loaded()

    def test_legitimate_authority_context_reentry_reloads_closed_modules_and_restores_hooks(self):
        modules, controllers = [], []
        original_meta, original_spec, original_path = list(sys.meta_path), importlib.util.spec_from_file_location, list(sys.path)
        for _ in range(2):
            with self.authority:
                modules.append(importlib.import_module('integration'))
                def consume(controller):
                    self.authority.controller(controller)
                    controllers.append(controller)
                    return 'inert-reentry'
                self.assertEqual(self.authority.run_native([], consume), 'inert-reentry')
                self.authority.verify_loaded()
            self.assertEqual(sys.meta_path, original_meta)
            self.assertIs(importlib.util.spec_from_file_location, original_spec)
            self.assertEqual(sys.path, original_path)
            self.assertNotIn('integration', sys.modules)
        self.assertIsNot(modules[0], modules[1])
        self.assertIsNot(type(controllers[0]), type(controllers[1]))

    def test_cached_loader_path_raw_mutation_cannot_select_registered_common_source(self):
        with self.authority:
            loader = zsh.BytesLoader(self.authority, self.authority.mapping['integration'])
            path = loader.path
            cached = str(path)
            foreign = str(self.authority.mapping['common'])
            # The selected runtime uses _raw_paths; older supported pathlib uses
            # _parts. Retain the cached original rendering while replacing raw
            # input, so a str(path)-only identity check cannot notice the drift.
            if hasattr(path, '_raw_paths'):
                object.__setattr__(path, '_raw_paths', [foreign])
            else:
                object.__setattr__(path, '_parts', list(Path(foreign).parts))
            self.assertEqual(str(path), cached)
            module = ModuleType('integration')
            with self.assertRaises(zsh.Refusal): loader.exec_module(module)
            self.assertNotIn('digest', module.__dict__)

    def test_canonical_module_name_cannot_bind_another_registered_source_path(self):
        with self.authority:
            with self.assertRaises(zsh.Refusal):
                self.authority.spec('integration', self.authority.mapping['common'])
            self.assertNotIn('integration', self.authority.loaded)

    def test_declared_direct_checker_alias_loads_only_its_captured_inert_source(self):
        with self.authority:
            path = self.root / 'scripts/checks/package_checks.py'
            spec = importlib.util.spec_from_file_location('development_package_checks', path)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            self.assertEqual(module.CHECKER_MARKER, 'inert-declared-alias')
            self.assertEqual(Path(module.__file__), path)
            self.authority.verify_loaded()

    def test_cached_native_main_replacement_is_refused_before_foreign_dispatch(self):
        effects = []
        with self.authority:
            native = importlib.import_module('native_arm')
            original = native.main
            native.main = lambda *args, **kwargs: effects.append('foreign-dispatch')
            try:
                with self.assertRaises(zsh.Refusal): self.authority.run_native([], lambda _: None)
            finally:
                native.main = original
        self.assertEqual(effects, [])


class RevocationCorrectionTests(unittest.TestCase):
    def setUp(self):
        FinalizationTests.setUp(self)

    statuses = FinalizationTests.statuses

    def cancel_after_pass(self, control):
        interrupted, initial = [], []
        def restoration(signum, handler):
            if handler is self.outer and (self.output / 'result.json').exists() and not interrupted:
                initial.append(self.statuses()); interrupted.append(True)
                raise control
            return self.outer
        self.signal.side_effect = restoration
        return interrupted, initial

    def test_one_shot_revocation_fsync_failure_retries_and_keeps_exact_interrupt(self):
        control = KeyboardInterrupt('inert restoration interrupt')
        interrupted, initial = self.cancel_after_pass(control)
        real_sync, failed = zsh.os.fsync, []
        def sync(fd):
            if interrupted and not failed:
                failed.append(True)
                raise OSError(5, 'one-shot revocation fsync')
            return real_sync(fd)
        with patch.object(zsh.os, 'fsync', side_effect=sync):
            with self.assertRaises(KeyboardInterrupt) as caught:
                zsh.run_zsh(self.controller, self.root, self.output, authority=self.authority)
        self.assertIs(caught.exception, control)
        self.assertEqual(initial, [['PASS'] * 3])
        self.assertEqual(self.statuses(), ['FAIL'] * 3)
        self.assertFalse(list(self.output.rglob('*.partial')))
        zsh.revoke(self.output, {'status': 'FAIL', 'public': []})
        self.assertEqual(self.statuses(), ['FAIL'] * 3)

    def test_persistent_revocation_write_failure_invalidates_every_pass_selector(self):
        control = KeyboardInterrupt('inert persistent revocation interrupt')
        interrupted, initial = self.cancel_after_pass(control)
        real_sync = zsh.os.fsync
        def sync(fd):
            if interrupted: raise OSError(5, 'persistent revocation fsync')
            return real_sync(fd)
        with patch.object(zsh.os, 'fsync', side_effect=sync):
            with self.assertRaises(KeyboardInterrupt) as caught:
                zsh.run_zsh(self.controller, self.root, self.output, authority=self.authority)
        self.assertIs(caught.exception, control)
        self.assertEqual(initial, [['PASS'] * 3])
        for name in self.records:
            path = self.output / name
            if path.exists():
                try: value = json.loads(path.read_bytes())
                except (ValueError, OSError): continue
                self.assertNotEqual(value.get('status'), 'PASS', name)

    def test_failed_owned_temporary_write_does_not_block_subsequent_save(self):
        path = self.root.parent / 'inert-save.json'
        real_sync, failed = zsh.os.fsync, []
        def sync(fd):
            if not failed:
                failed.append(True)
                raise OSError(5, 'one-shot private save fsync')
            return real_sync(fd)
        with patch.object(zsh.os, 'fsync', side_effect=sync):
            try: zsh.save(path, {'status': 'FAIL'})
            except OSError: pass
        zsh.save(path, {'status': 'FAIL', 'retry': True})
        self.assertEqual(json.loads(path.read_bytes()), {'status': 'FAIL', 'retry': True})
        self.assertFalse(path.with_name(path.name + '.partial').exists())


class ReceiptCustodyCorrectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_foreign_destination_is_refused_without_overwrite(self):
        path = self.root / 'receipt.json'
        foreign = b'{"status":"PASS","foreign":true}\n'; path.write_bytes(foreign)
        with self.assertRaises(zsh.Refusal): zsh.save(path, {'status': 'FAIL'})
        self.assertEqual(path.read_bytes(), foreign)

    def test_foreign_fixed_partial_name_is_neither_deleted_nor_reused(self):
        path = self.root / 'receipt.json'
        foreign = path.with_name(path.name + '.partial'); foreign.write_bytes(b'foreign-temporary')
        zsh.save(path, {'status': 'FAIL'})
        self.assertEqual(json.loads(path.read_bytes()), {'status': 'FAIL'})
        self.assertEqual(foreign.read_bytes(), b'foreign-temporary')

    def test_foreign_replacement_of_owned_temp_is_retained_and_not_unlinked(self):
        path, displaced, replacements = self.root / 'receipt.json', self.root / 'displaced-owned', []
        real_sync = zsh.os.fsync
        def sync(fd):
            if not replacements:
                candidates = list(self.root.glob('*.partial-*'))
                self.assertEqual(len(candidates), 1)
                temporary = candidates[0]; temporary.rename(displaced)
                temporary.write_bytes(b'foreign-replacement')
                replacements.append(temporary)
                raise OSError(5, 'inert temp namespace replacement')
            return real_sync(fd)
        try:
            with patch.object(zsh.os, 'fsync', side_effect=sync), self.assertRaises(OSError):
                zsh.save(path, {'status': 'FAIL'})
            self.assertEqual(replacements[0].read_bytes(), b'foreign-replacement')
            self.assertEqual(json.loads(displaced.read_bytes()), {'status': 'FAIL'})
            self.assertFalse(path.exists())
        finally:
            # The owned descriptor was closed; explicitly dispose the private
            # fixture namespace before resetting only its uncertainty entries.
            for filename in replacements:
                filename.unlink(missing_ok=True)
                for key in list(zsh._RECEIPT_UNCERTAIN):
                    if key[1] == filename.name: zsh._RECEIPT_UNCERTAIN.pop(key)
            displaced.unlink(missing_ok=True)

    def test_initial_fstat_failure_retains_unknown_fd_without_adopting_or_closing(self):
        path = self.root / 'inert-record'; path.write_bytes(b'inert')
        first, descriptors = OSError(5, 'inert first fstat'), []
        real_query, real_close = zsh.os.fstat, zsh.os.close
        def query(fd):
            descriptors.append(fd)
            raise first
        try:
            with patch.object(zsh.os, 'fstat', side_effect=query):
                with self.assertRaises(OSError) as caught: zsh.receipt_open(path, os.O_RDONLY)
            self.assertIs(caught.exception, first)
            self.assertEqual(len(descriptors), 1)
            fd = descriptors[0]
            self.assertIs(zsh._RECEIPT_FDS[fd], None)
            self.assertEqual(real_query(fd).st_ino, path.stat().st_ino)
            with patch.object(zsh.os, 'close', side_effect=AssertionError('unknown close forbidden')):
                self.assertIsInstance(zsh.receipt_close(fd), zsh.Refusal)
            self.assertEqual(real_query(fd).st_ino, path.stat().st_ino)
        finally:
            for fd in descriptors:
                real_close(fd)
                with self.assertRaises(OSError): real_query(fd)
                zsh._RECEIPT_FDS.pop(fd, None)


class ProcessProofCorrectionTests(unittest.TestCase):
    setUp = DisposalCorrectionTests.setUp
    select = SupervisionTests.select
    read = SupervisionTests.read
    wait = SupervisionTests.wait
    killpg = SupervisionTests.killpg
    send_signal = SupervisionTests.send_signal
    run_model = SupervisionTests.run_model

    def test_permanent_group_query_error_preserves_timeout_and_reports_unknown_cleanup(self):
        self.state, self.group = None, True
        original = zsh.Refusal('process-timeout')
        def query(pid, number):
            if number == 0: raise OSError(5, 'inert unavailable group query')
            return self.killpg(pid, number)
        with patch.object(zsh.os, 'read', side_effect=original), patch.object(zsh.os, 'killpg', side_effect=query):
            with self.assertRaises(zsh.Refusal) as caught: self.run_model()
        self.assertIs(caught.exception, original)
        self.assertEqual(zsh.process_cleanup_status(original), 'UNKNOWN')
        self.assertTrue(zsh._PROCESS_DISPOSAL_UNCERTAIN)
        self.assertIn(signal.SIGKILL, self.signals)
        self.assertTrue(self.stdout.closed)

    def test_permanent_poll_error_preserves_timeout_and_cannot_claim_cleanup_pass(self):
        self.state, self.group = None, True
        original = zsh.Refusal('process-timeout')
        self.process.poll = lambda: (_ for _ in ()).throw(OSError(5, 'inert unavailable poll'))
        with patch.object(zsh.os, 'read', side_effect=original):
            with self.assertRaises(zsh.Refusal) as caught: self.run_model()
        self.assertIs(caught.exception, original)
        self.assertEqual(zsh.process_cleanup_status(original), 'UNKNOWN')
        self.assertTrue(zsh._PROCESS_DISPOSAL_UNCERTAIN)
        self.assertTrue(self.stdout.closed)

    def test_term_fault_with_eventual_proved_absence_keeps_failure_and_reports_cleanup_pass(self):
        self.state, self.group = None, True
        original = zsh.Refusal('process-timeout')
        def signaling(pid, number):
            if number == signal.SIGTERM: raise OSError(5, 'inert TERM failure')
            return self.killpg(pid, number)
        with patch.object(zsh.os, 'read', side_effect=original), patch.object(zsh.os, 'killpg', side_effect=signaling):
            with self.assertRaises(zsh.Refusal) as caught: self.run_model()
        self.assertIs(caught.exception, original)
        self.assertEqual(zsh.process_cleanup_status(original), 'PASS')
        self.assertFalse(zsh._PROCESS_DISPOSAL_UNCERTAIN)
        self.assertTrue(self.stdout.closed)

    def test_cleanup_proof_attribute_is_a_closed_typed_status(self):
        for value in (True, 1, None, 'foreign', [], {}):
            error = zsh.Refusal('inert-typed-proof')
            error.process_cleanup_status = value
            with self.subTest(value=value): self.assertEqual(zsh.process_cleanup_status(error), 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
