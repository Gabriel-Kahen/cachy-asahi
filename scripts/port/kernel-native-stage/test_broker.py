# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import broker


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


if __name__ == '__main__':
    unittest.main()
