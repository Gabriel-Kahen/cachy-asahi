# SPDX-License-Identifier: MIT
"""Inert transport controls for the owned updater entry."""

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('q3_owner', Path(__file__).with_name('q3-owner.py'))
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
CID = 'a' * 64
NOW = 1795710000


def fence(event, _args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.posix_spawn', 'os.system')):
        raise AssertionError('external actor forbidden: ' + event)


class FakeDocker:
    def __init__(self, out, *, interrupt_create=False, unsafe_mount=False):
        self.out, self.present, self.exited = out, False, False
        self.interrupt_create, self.unsafe_mount = interrupt_create, unsafe_mount
        self.mutations = []

    def runtime(self):
        pass

    def attach(self, attempt, cid):
        assert cid == CID
        self.exited = True
        (attempt / 'serial.log').write_bytes(b'inert serial\n')
        (attempt / 'runner.stderr').touch()
        work = attempt / 'work'
        for name, data in (('overlay.qcow2', b'inert qcow'), ('host-utc', f'{NOW}\n'.encode()),
                           ('overlay-before.size', b'8\n'), ('overlay-before.json', b'[]'),
                           ('overlay-after.json', b'[]')):
            (work / name).write_bytes(data)
        return 0

    def command(self, *args, **_):
        action = args[1]
        if action == 'ls':
            return (CID + '\n').encode() if self.present else b''
        if action == 'create':
            self.mutations.append(action)
            self.present = True
            self.name = args[args.index('--name') + 1]
            self.label = args[args.index('--label') + 1].split('=', 1)[1]
            self.argv = list(args[args.index(owner.IMAGE) + 1:])
            if self.interrupt_create:
                raise subprocess.TimeoutExpired([], 1)
            (self.out / 'run.cid').write_text(CID + '\n')
            return (CID + '\n').encode()
        if action == 'rm':
            assert args[2] == CID
            self.mutations.append(action)
            self.present = False
            return (CID + '\n').encode()
        assert action == 'inspect' and args[2] == CID
        host = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False, 'Init': False,
                'AutoRemove': False, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                'Memory': 6 << 30, 'MemorySwap': 6 << 30, 'NanoCpus': 4000000000, 'PidsLimit': 64,
                'LogConfig': {'Type': 'none'}}
        mounts = [{'Type': 'bind', 'Propagation': 'rprivate', 'Source': str(self.out / leaf),
                   'Destination': dest, 'RW': rw} for leaf, dest, rw in
                  (('inputs', '/inputs', self.unsafe_mount), ('work', '/out', True))]
        state = {'Status': 'exited' if self.exited else 'created', 'Pid': 0, 'Running': False,
                 'OOMKilled': False, 'ExitCode': 0, 'Error': '',
                 'StartedAt': datetime.fromtimestamp(NOW - 10, timezone.utc).isoformat(),
                 'FinishedAt': datetime.fromtimestamp(NOW + 30, timezone.utc).isoformat()}
        return owner.encoded([{'Id': CID, 'Name': '/' + self.name, 'Image': owner.IMAGE,
                               'Path': '/usr/bin/bash', 'Args': self.argv,
                               'Config': {'Labels': {owner.CLAIM_LABEL: self.label}},
                               'HostConfig': host, 'Mounts': mounts, 'State': state}])


class OwnerTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.packet, self.media = self.root / 'packet', self.root / 'media'
        for path in (self.packet, self.packet / 'inputs', self.media):
            path.mkdir(mode=0o700)
        self.args = SimpleNamespace(packet=self.packet, media=self.media, output=self.root / 'attempt',
                                    admission=self.root / 'admission.json')
        sizes = {}
        self.inputs = {}
        for name in owner.INPUTS:
            path = (self.media if name == 'media.raw' else self.packet / 'inputs') / name
            owner.P.new(path, name.encode())
            sizes[name] = len(name)
            self.inputs[name] = (path, owner.P.observe(path, 64)[1])
        self.addCleanup(patch.stopall)
        patch.object(owner, 'INPUTS', sizes).start()
        nonce = '0a' * 16
        self.prep = {'kind': 'UPDATER_Q3_PREPARATION_UNISSUED', 'authority': None, 'base_inventory': 356,
                     'target_inventory': 362, 'nonce': nonce, 'case': 'update',
                     'inputs': {n: v[1] for n,v in self.inputs.items() if n != 'media.raw'},
                     'input_ext4': {'bytes': sizes['media.raw'], 'label': 'UPDATER16K',
                                    'uuid': owner.P.result_uuid(nonce)},
                     'qemu_argv_template': owner.argv_template(nonce, 'update')}
        self.args.preparation_sha256 = self.put(self.packet / 'PLAN.UNISSUED.json', self.prep)
        self.plan = {'case': 'update', 'valid_from': NOW - 100, 'expires': NOW + 3000}
        pin = self.put(self.media / 'plan.json', self.plan)
        self.seal = {'kind': 'UPDATER_Q3_MEDIA_V1', 'preparation_sha256': self.args.preparation_sha256,
                     'case': 'update', 'media': self.inputs['media.raw'][1],
                     'plan': {'bytes': (self.media / 'plan.json').stat().st_size, 'sha256': pin}}
        self.args.media_manifest_sha256 = self.put(self.media / 'media.json', self.seal)
        grant = owner.binding(self.args, self.prep, self.seal) | {'valid_from': NOW - 50, 'expires': NOW + 2500}
        self.args.admission_sha256 = self.put(self.args.admission, grant)

    def put(self, path, row):
        raw = owner.encoded(row)
        owner.P.new(path, raw)
        return owner.P.sha(raw)

    def test_preflight_accepts_bound_case_without_launch(self):
        self.assertEqual(owner.preflight(self.args), (self.prep, self.seal, self.plan, self.inputs))
        self.assertEqual(owner.admit(self.args, self.prep, self.seal, self.plan, NOW), NOW + 2500)
        with self.assertRaisesRegex(ValueError, 'current owner admission'):
            owner.admit(self.args, self.prep, self.seal, self.plan, NOW + 2490)
        self.args.admission_sha256 = 'b' * 64
        with self.assertRaises(ValueError):
            owner.admit(self.args, self.prep, self.seal, self.plan, NOW)

    def test_foreign_case_and_mutated_media_refused(self):
        self.seal['case'] = 'signature-refusal'
        other = self.media / 'different.json'
        self.args.media_manifest_sha256 = self.put(other, self.seal)
        other.replace(self.media / 'media.json')
        with self.assertRaisesRegex(ValueError, 'case differs'):
            owner.preflight(self.args)
        self.seal['case'] = 'update'
        self.args.media_manifest_sha256 = self.put(other, self.seal)
        other.replace(self.media / 'media.json')
        target = self.media / 'media.raw'
        target.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'sealed input'):
            owner.preflight(self.args)

    def test_shared_backing_reference_uses_the_same_sealed_pin(self):
        scratch, pin = self.inputs['scratch.raw']
        shared = self.root / 'shared'
        shared.mkdir(mode=0o700)
        shared /= 'scratch.raw'
        scratch.rename(shared)
        self.prep['originals'] = {'scratch.raw': {'path': str(shared), **pin}}
        forwarded = self.packet / 'new.json'
        self.args.preparation_sha256 = self.put(forwarded, self.prep)
        forwarded.replace(self.packet / 'PLAN.UNISSUED.json')
        self.seal['preparation_sha256'] = self.args.preparation_sha256
        forwarded = self.media / 'new.json'
        self.args.media_manifest_sha256 = self.put(forwarded, self.seal)
        forwarded.replace(self.media / 'media.json')
        self.assertEqual(owner.preflight(self.args)[3]['scratch.raw'], (shared, pin))
        shared.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'sealed input'):
            owner.preflight(self.args)

    def execute(self, actor):
        def overlay(work):
            path = work / 'overlay.qcow2'
            return owner.P.observe(path, 64)[1], owner.P.identity(path.lstat())

        with (patch.object(owner, 'capacity'), patch.object(owner.time, 'time', return_value=NOW),
              patch.object(owner.P, 'clone', side_effect=shutil.copyfile), patch.object(owner, 'overlay_pin', side_effect=overlay)):
            return owner.execute(self.args, *owner.preflight(self.args), docker_factory=lambda _: actor)

    def test_mock_normal_entry_retires_exact_clone_and_owner(self):
        actor = FakeDocker(self.args.output)
        row = self.execute(actor)
        self.assertEqual(row['retirement'], 'PASS')
        self.assertEqual(row['host_utc'], NOW)
        self.assertEqual(actor.mutations, ['create', 'rm'])
        self.assertFalse(actor.present)
        self.assertFalse((self.args.output / 'inputs').exists())
        self.assertFalse((self.args.output / 'work/overlay.qcow2').exists())
        self.assertEqual(row['evidence']['absence-1']['bytes'], 0)
        with self.assertRaisesRegex(ValueError, 'fresh owned attempt'):
            self.execute(actor)

    def test_create_interruption_recovers_only_exact_owned_name(self):
        actor = FakeDocker(self.args.output, interrupt_create=True)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.execute(actor)
        self.assertFalse(actor.present)
        self.assertEqual(actor.mutations, ['create', 'rm'])
        self.assertTrue((self.args.output / 'absence-2').is_file())
        self.assertFalse((self.args.output / 'owner.json').exists())

    def test_unexpected_mount_never_attaches_or_removes_ambiguous_container(self):
        actor = FakeDocker(self.args.output, unsafe_mount=True)
        with self.assertRaisesRegex(ValueError, 'isolated output mounts'):
            self.execute(actor)
        self.assertEqual(actor.mutations, ['create'])
        self.assertFalse((self.args.output / 'serial.log').exists())


if __name__ == '__main__':
    sys.addaudithook(fence)
    unittest.main()
