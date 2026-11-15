#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Pure DATA refusal controls; no job evidence or operational Reader invocation."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('xs_bootstrap_controls', HERE / 'bootstrap.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('actor forbidden in DATA controls: ' + event)


sys.addaudithook(fence)


class IO:
    @staticmethod
    def need(value, why):
        if not value:
            raise ValueError(why)

    @staticmethod
    def tick():
        pass

    @staticmethod
    def decode(raw):
        return json.loads(raw)


def policy_fixture():
    return dict(Name='/MODELED', Image='MODELED_IMAGE', State=dict(Running=False),
        Config=dict(User='1001:1001', Hostname='perl5423-native'),
        HostConfig=dict(NanoCpus=2000000000, Memory=4294967296, MemorySwap=4294967296,
            PidsLimit=256, ReadonlyRootfs=True, NetworkMode='none', CapDrop=['ALL'], CapAdd=None,
            SecurityOpt=['no-new-privileges'], Privileged=False, Devices=[], DeviceRequests=None,
            Init=True, CgroupnsMode='private', Tmpfs=b.TMPFS),
        Mounts=[dict(Destination='/inputs', Type='bind', Source='/MODELED/bundle', RW=False)])


class Controls(unittest.TestCase):
    def test_refuses_unrelated_reordered_or_nonzero_operations(self):
        rows = [dict(argv=['MODELED_A'], returncode=0), dict(argv=['MODELED_B'], returncode=0)]
        sequence = b.Sequence(rows, [(b'A', b''), (b'B', b'')], IO)
        with self.assertRaises(ValueError):
            sequence.take(['MODELED_B'])
        sequence.take(['MODELED_A'], data=b'A')
        with self.assertRaises(ValueError):
            sequence.end()
        with self.assertRaises(ValueError):
            sequence.take(['MODELED_B'], code=1)
        sequence.take(['MODELED_B'], data=b'B')
        sequence.end()
        with self.assertRaises(ValueError):
            sequence.take(['MODELED_EXTRA'])

    def test_signature_status_rejects_expiry_foreign_and_duplicate_primary(self):
        status = '[GNUPG:] VALIDSIG ' + b.SIGNER + ' ' + ' '.join(['0'] * 8) + ' ' + b.SIGNER + '\n'
        b.signed(status, IO)  # Syntax/fingerprint classifier, never cryptographic verification.
        for changed in (status + '[GNUPG:] EXPKEYSIG X\n', status.replace(b.SIGNER, '0' * 40), status + status):
            with self.subTest(status=changed), self.assertRaises(ValueError):
                b.signed(changed, IO)

    def test_policy_rejects_resource_capability_or_mount_expansion(self):
        original = policy_fixture()
        mounts = {'/inputs': ('bind', '/MODELED/bundle', False)}
        b.policy(original, 'MODELED_IMAGE', 'MODELED', mounts, b.TMPFS, IO)
        for key, value in [('MemorySwap', 8589934592), ('PidsLimit', 512), ('CapAdd', ['SYS_ADMIN']),
                           ('ReadonlyRootfs', False), ('NetworkMode', 'host'), ('CgroupnsMode', 'host')]:
            row = copy.deepcopy(original)
            row['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                b.policy(row, 'MODELED_IMAGE', 'MODELED', mounts, b.TMPFS, IO)
        row = copy.deepcopy(original)
        row['Mounts'].append(dict(Destination='/foreign', Type='volume', Name='FOREIGN', RW=True))
        with self.assertRaises(ValueError):
            b.policy(row, 'MODELED_IMAGE', 'MODELED', mounts, b.TMPFS, IO)

    def test_stopped_receipt_requires_zero_pid_exit_and_no_oom(self):
        original = dict(Image='MODELED_IMAGE', State=dict(Running=False, Pid=0, ExitCode=0, OOMKilled=False))
        for key, value in [('Running', True), ('Pid', 42), ('ExitCode', 1), ('ExitCode', False), ('OOMKilled', True)]:
            row = copy.deepcopy(original)
            row['State'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                b.stopped(row, 'MODELED_IMAGE', IO)


if __name__ == '__main__':
    unittest.main(verbosity=2)
