# SPDX-License-Identifier: MIT
"""FENCED MODEL controls: public inspect DATA and mocked controllers, no actors."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
LANE = HERE.parent
VOLUME = LANE / 'successor_v2/payload/hosted/volume.py'
CID = '16aa9ada533b4d6f5938b7b6cedf8571ba2a059d636c7a2c80f6762a0128513e'
IMAGE = 'sha256:' + 'd' * 64


def load(name, path):
    # Import the maintained volume implementation through its import seam;
    # no copied actor, Source tree or runtime directory is constructed.
    original = importlib.util.spec_from_file_location
    def spec(module, location, *args, **kwargs):
        if Path(location).name == 'volume.py':
            location = VOLUME
        return original(module, location, *args, **kwargs)
    with mock.patch.object(importlib.util, 'spec_from_file_location', side_effect=spec):
        definition = original(name, path)
        value = importlib.util.module_from_spec(definition)
        definition.loader.exec_module(value)
    return value


def fixture():
    return json.loads((HERE / 'fixtures/actual287-inspect.json').read_bytes())


def expected_mounts(P, row):
    configured = row['HostConfig']['Mounts']
    binds = {r['Target']: Path(r['Source']) for r in configured if r['Type'] == 'bind'}
    materials = {Path(k).name: v for k, v in binds.items() if k.startswith('/materials/')}
    volume = configured[0]['Source']
    return P.mount_specs(volume, binds['/inputs'], binds['/source'], materials, 'prepare'), volume, Path(row['Mounts'][0]['Source'])


class ModelDaemon:
    """Finite in-memory command seam; unknown commands always refuse."""
    def __init__(self, P, foreign=None):
        self.P, self.foreign = P, foreign
        self.deadline, self.cleaning, self.cancelled, self.on_tick = time.monotonic() + 300, False, [False], None
        self.events, self.actor, self.volume, self.images = [], None, None, {}

    def __call__(self, argv, timeout=60, check=True):
        assert argv[:len(self.P.DOCKER)] == self.P.DOCKER, 'MODEL Docker seam only'
        args = argv[len(self.P.DOCKER):]
        self.events.append(tuple(args))
        def answer(value=b'', code=0, stderr=b''):
            return SimpleNamespace(stdout=value, returncode=code, stderr=stderr)
        def rows(value):
            return answer(json.dumps([value]).encode())
        if args[:2] == ['container', 'ls']:
            return answer((self.actor['Name'][1:] + '\n').encode() if self.actor else b'')
        if args[:2] == ['volume', 'ls']:
            return answer((self.volume['Name'] + '\n').encode() if self.volume else b'')
        if args[:2] == ['volume', 'create']:
            labels = dict(args[i+1].split('=', 1) for i, a in enumerate(args) if a == '--label')
            name = args[-1]
            self.volume = dict(Name=name, Driver='local', Options=None, Labels=labels, Mountpoint='/MODEL/volume')
            return answer((name + '\n').encode())
        if args[:2] == ['volume', 'inspect']:
            assert self.volume and args[-1] == self.volume['Name']
            return rows(self.volume)
        if args[0] == 'create':
            assert self.actor is None
            labels = dict(args[i+1].split('=', 1) for i, a in enumerate(args) if a == '--label')
            self.actor = dict(Id=CID, Name='/' + args[args.index('--name')+1], Image=IMAGE,
                              Config=dict(Labels=labels), State=dict(Status='created', Running=False))
            return answer((CID + '\n').encode())
        if args[:2] == ['container', 'inspect']:
            assert self.actor and args[-1] == self.actor['Name'][1:]
            value = copy.deepcopy(self.actor)
            if self.cleaning and self.foreign:
                self.foreign(value)
            return rows(value)
        if args[:2] == ['container', 'rm']:
            assert self.actor and args == ['container', 'rm', CID], 'exact acknowledged MODEL CID only'
            self.actor = None
            return answer()
        if args[:2] == ['volume', 'rm']:
            assert self.volume and args[-1] == self.volume['Name']
            if self.actor:
                raise ValueError('MODEL volume still in use')
            self.volume = None
            return answer()
        if args[:2] == ['image', 'inspect']:
            if args[-1] in self.images:
                return rows(self.images[args[-1]])
            return answer(code=1, stderr=('Error response from daemon: No such image: ' + args[-1]).encode())
        if args[:2] == ['image', 'rm']:
            assert not self.actor and not self.volume, 'MODEL images must follow CID and volume retirement'
            del self.images[args[-1]]
            return answer()
        if args[:2] == ['image', 'ls']:
            return answer(b'\n'.join(k.encode() for k in self.images))
        raise AssertionError('Unexpected MODEL command: ' + repr(args))


class RuntimeControls(unittest.TestCase):
    def setUp(self):
        for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen', 'os.system'):
            guard = mock.patch(name, side_effect=AssertionError('FENCED no network/process'))
            guard.start()
            self.addCleanup(guard.stop)
        self.P = load('runtime_v12_model', HERE / 'payload/hosted/producer.py')
        self.Q = load('qualification_v12_model', HERE / 'payload/hosted/qualification.py')

    def inspect(self, row):
        mounts, volume, path = expected_mounts(self.P, fixture())
        self.P.inspect_mounts(row, mounts, volume, path)

    def test_actual287_fixture_is_pinned_allowlisted_public_projection(self):
        raw = (HERE / 'fixtures/actual287-inspect.json').read_bytes()
        provenance = json.loads((HERE / 'fixtures/actual287-provenance.json').read_bytes())
        self.assertEqual(len(raw), 5198)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '94b04d74b274ef5fdfb089ea9ae712d6ef06341541b6ec438fd98eb0464e1b55')
        self.assertEqual(provenance['source_sha256'], '3049a973c26c02fbfdec6ea0300b518addd10b48e5b3de76c204b6c61e53189d')
        row = fixture()
        self.assertEqual(set(row), {'Id', 'Name', 'Image', 'Config', 'State', 'HostConfig', 'Mounts'})
        self.assertEqual(set(row['Config']), {'Labels'})
        self.assertEqual(set(row['HostConfig']), {'Mounts'})
        self.assertEqual(row['Id'], CID)
        self.assertFalse(provenance['acceptance'])

    def test_actual287_old_rejects_and_new_accepts_empty_driverconfig(self):
        row = fixture()
        old = load('runtime_v7_model', LANE / 'successor_v7/payload/hosted/producer.py')
        mounts, volume, path = expected_mounts(old, row)
        with self.assertRaises(ValueError):
            old.inspect_mounts(row, mounts, volume, path)
        self.inspect(row)
        del row['HostConfig']['Mounts'][0]['VolumeOptions']['DriverConfig']
        self.inspect(row)

    def test_named_nonempty_unknown_and_null_driverconfig_refuse(self):
        for value in (None, [], '', {'Name': 'local'}, {'Options': {}}, {'Unknown': True}):
            row = fixture()
            row['HostConfig']['Mounts'][0]['VolumeOptions']['DriverConfig'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.inspect(row)

    def test_nocopy_must_be_present_exact_true_boolean(self):
        for value in (None, False, 1, 0, 'true'):
            row = fixture()
            row['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.inspect(row)
        row = fixture()
        del row['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy']
        with self.assertRaises(ValueError):
            self.inspect(row)

    def test_unknown_volume_options_and_bind_driver_normalization_refuse(self):
        for key, value in (('Unknown', True), ('Subpath', 'build/stage0')):
            row = fixture()
            row['HostConfig']['Mounts'][0]['VolumeOptions'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.inspect(row)
        row = fixture()
        row['HostConfig']['Mounts'][1]['VolumeOptions'] = {'DriverConfig': {}}
        with self.assertRaises(ValueError):
            self.inspect(row)

    def test_work_readonly_source_and_mount_alias_substitutions_refuse(self):
        changes = [lambda r: r['HostConfig']['Mounts'][0].update(ReadOnly=True),
                   lambda r: r['HostConfig']['Mounts'][0].update(Source='foreign-volume'),
                   lambda r: r['Mounts'][0].update(RW=False),
                   lambda r: r['Mounts'][0].update(Source='/MODEL/foreign'),
                   lambda r: r['Mounts'][1].update(RW=True),
                   lambda r: r['Mounts'][1].update(Source='/MODEL/foreign'),
                   lambda r: r['HostConfig']['Mounts'].append(copy.deepcopy(r['HostConfig']['Mounts'][0])),
                   lambda r: r['Mounts'][1].update(Destination='/work'),
                   lambda r: r['HostConfig']['Mounts'][1].update(Target='/work')]
        for index, change in enumerate(changes):
            row = fixture()
            change(row)
            with self.subTest(index=index), self.assertRaises((ValueError, StopIteration)):
                self.inspect(row)

    def test_readonly_stage0_subpaths_remain_exact(self):
        row = fixture()
        expected, volume, path = expected_mounts(self.P, row)
        for target in ('/stage0', '/work/build/stage0'):
            options = dict(Subpath='build/stage0', NoCopy=True)
            expected.append(dict(Type='volume', Source=volume, Target=target, ReadOnly=True, VolumeOptions=options))
            row['HostConfig']['Mounts'].append(dict(Type='volume', Source=volume, Target=target, ReadOnly=True, VolumeOptions=dict(options, DriverConfig={})))
            row['Mounts'].append(dict(Type='volume', Name=volume, Destination=target, RW=False, Driver='local', Source=str(path / 'build/stage0')))
        self.P.inspect_mounts(row, expected, volume, path)
        for change in (lambda r: r['HostConfig']['Mounts'][-1]['VolumeOptions'].update(Subpath='build/other'),
                       lambda r: r['HostConfig']['Mounts'][-1].update(ReadOnly=False),
                       lambda r: r['Mounts'][-1].update(Source=str(path)),
                       lambda r: r['Mounts'][-1].update(RW=True)):
            bad = copy.deepcopy(row)
            change(bad)
            with self.assertRaises(ValueError):
                self.P.inspect_mounts(bad, expected, volume, path)

    def test_created_id_accepts_only_full_lowercase_hex_plus_one_lf(self):
        self.assertEqual(self.P.created_id((CID + '\n').encode()), CID)
        for value in (CID.encode(), (CID + '\r\n').encode(), (CID + '\n\n').encode(), (CID.upper() + '\n').encode(), b'a'*63+b'\n', b'g'*64+b'\n', CID + '\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.P.created_id(value)

    def qualification_failure(self, root, foreign=None):
        provider = dict(schema=4, status='ACTUAL_PROVIDER_BINDING_ONLY', phase='bootstrap', run_attempt=1, manual_dispatch=True,
                        dispatch_sha256='b'*64, source=dict(sha='a'*40, ref='refs/heads/codex/FENCED', run='1', job='2', map_sha256='c'*64, approval='e'*64))
        audit = dict(status='FENCED_MODEL_SOURCE_AUDIT')
        audit_path = root / 'audit.json'
        audit_path.write_bytes(self.Q.encode(audit))
        plan = dict(reviews=dict(stage0=True, source=True, llvm_material=True), source_audit=audit, holds_preserved=True)
        delivered = dict(files=dict(source_audit=dict(local_path=str(audit_path))), materials=[dict(name='MODEL-'+str(i), local_path=str(root / str(i)), bytes=1, sha256='f'*64) for i in range(5)])
        boot = dict(image=IMAGE, rootfs_tree_sha256='f'*64)
        command = ModelDaemon(self.P, foreign)
        def fail_after_create(*args):
            report = json.loads((root / 'qualification/controller.json').read_bytes())
            self.assertEqual(report['container_ids'], {'data': CID})
            raise ValueError('FENCED validation failure after acknowledged create')
        with mock.patch.object(self.Q, 'load', return_value=self.P), mock.patch.object(self.Q, 'inspect_actor', side_effect=fail_after_create):
            with self.assertRaisesRegex(ValueError, 'FENCED validation failure'):
                self.Q.run(root, root, provider, plan, delivered, boot, command)
        return command, json.loads((root / 'qualification/controller.json').read_bytes()), provider, boot

    def test_qualification_validation_failure_retires_acknowledged_cid_then_volume(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-custody-') as temporary:
            command, report, _, _ = self.qualification_failure(Path(temporary))
            removed = [r for r in command.events if r[:2] in (('container', 'rm'), ('volume', 'rm'))]
            self.assertEqual([r[:2] for r in removed], [('container', 'rm'), ('volume', 'rm')])
            self.assertEqual(removed[0][-1], CID)
            self.assertEqual(report['container_ids'], {'data': CID})
            self.assertTrue(report['owned_resources_absent'])
            self.assertEqual(report['status'], 'FAIL')
            self.assertFalse(report['native_acceptance'])
            self.assertFalse(any('KeyError' in r or "'data'" == r for r in report['errors']))
            self.assertIsNone(command.actor)
            self.assertIsNone(command.volume)

    def test_foreign_cleanup_labels_image_and_changed_cid_cannot_remove_container(self):
        changes = [lambda r: r.update(Image='sha256:'+'0'*64), lambda r: r.update(Id='0'*64)]
        for key in ('operation', 'source', 'run', 'job', 'token', 'role'):
            changes.append(lambda r, key=key: r['Config']['Labels'].update({'cachy-asahi.'+key: 'foreign'}))
        for index, change in enumerate(changes):
            with self.subTest(index=index), tempfile.TemporaryDirectory(prefix='FENCED-foreign-') as temporary:
                command, report, _, _ = self.qualification_failure(Path(temporary), change)
                self.assertFalse(any(r[:2] == ('container', 'rm') for r in command.events))
                self.assertIsNotNone(command.actor)
                self.assertIsNotNone(command.volume)
                self.assertNotIn('owned_resources_absent', report)
                self.assertTrue(any(r.startswith('cleanup: ') for r in report['errors']))

    def test_actual_bootstrap_retire_follows_qualification_cid_and_volume(self):
        B = load('bootstrap_v11_model', LANE / 'successor_v11/payload/hosted/bootstrap.py')
        with tempfile.TemporaryDirectory(prefix='FENCED-image-order-') as temporary:
            root = Path(temporary)
            command, report, provider, boot = self.qualification_failure(root)
            owner = B.owner(B.provider_source(provider))
            base_image = 'sha256:'+'e'*64
            boot['base_image'] = base_image
            for image, tag in ((IMAGE, owner['tag']), (base_image, owner['base_tag'])):
                command.images[image] = dict(Id=image, Os='linux', Architecture='arm64', RepoTags=[tag], Config=dict(Labels={B.LABEL: owner['token'], B.LABEL+'.source': owner['source']}))
            retired = B.retire(root, root, provider, boot, command)
            self.assertEqual(retired['status'], 'PASS_RETIRED')
            removals = [r[:2] for r in command.events if r[:2] in (('container', 'rm'), ('volume', 'rm'), ('image', 'rm'))]
            self.assertEqual(removals, [('container', 'rm'), ('volume', 'rm'), ('image', 'rm'), ('image', 'rm')])
            self.assertFalse(command.images)
            self.assertEqual(report['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main(verbosity=2)
