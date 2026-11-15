# SPDX-License-Identifier: MIT
"""Synthetic refusal DATA only; any subprocess/network/FFI actor is forbidden."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import stat

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('native_xs_controls', HERE / 'native.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('actor forbidden in native XS source controls: ' + event)


sys.addaudithook(fence)


def modeled_operation():
    a = dict(schema=1, operation=n.OPERATION, authorization='ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS',
             source=dict(sha='1' * 40, ref='codex/MODELED_SOURCE_NOT_ACTUAL'), run='1', job='2',
             pair=dict(source='2' * 40, run='3', job='4'), image='sha256:' + '3' * 64,
             runner_sha256=n.RUNNER_SHA, authorize_runtime_observation_only=True,
             expected349_sha256=n.INVENTORY, nested_invocation='NOT_INVOKED', nested_qualification='NOT_QUALIFIED',
             accepted_reader_receipt=dict(path='/inputs/accepted-reader.json', bytes=1, sha256='4' * 64))
    for key in ('approval', 'source_readback_sha256', 'native_daemon_identity_sha256',
                'input_signature_audit_sha256', 'bundle_map_sha256', 'xs_admission_sha256',
                'inputs_sha256', 'plan_sha256'):
        a[key] = '5' * 64
    a['runtime_identity_generator_sha256'] = n.c.pin(n.c.read(HERE / 'native.py'))['sha256']
    return a


class Refusals(unittest.TestCase):
    def test_pending_pair_reader_or_runtime_authority_refuses(self):
        for change in (lambda a: a.update(authorization='PENDING_READER'),
                       lambda a: a.update(accepted_reader_receipt=None),
                       lambda a: a['pair'].update(source=None),
                       lambda a: a.update(authorize_runtime_observation_only=False),
                       lambda a: a.update(runtime_identity_generator_sha256='0' * 64),
                       lambda a: a.update(nested_qualification='QUALIFIED')):
            a = modeled_operation()
            change(a)
            with self.assertRaises((ValueError, TypeError)):
                n.operation(a)

    def test_missing_actual_inputs_refuses_before_any_actor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'MODELED_DATA').write_bytes(b'MODELED; NO RUNTIME OR RECEIPTS\n')
            raw = n.p.encode(dict(files={'MODELED_DATA': n.c.pin((bundle / 'MODELED_DATA').read_bytes())}))
            (bundle / 'bundle-map.json').write_bytes(raw)
            a = modeled_operation()
            a['bundle_map_sha256'] = n.c.pin(raw)['sha256']
            ar = n.p.encode(a)
            (bundle / 'operation.json').write_bytes(ar)
            with self.assertRaises(FileNotFoundError):
                n.producer(bundle, n.c.pin(ar)['sha256'], root / 'must-not-exist')
            self.assertFalse((root / 'must-not-exist').exists())

    def test_wrong_architecture_or_pair_refuses_before_prefix_or_actor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for artifact, arch in ((dict(kind='host', source=None, run=None, job=None), 'x86_64'),
                                   (dict(kind='native', source=None, run='3', job='4'), 'aarch64')):
                a = modeled_operation()
                daemon = b'MODELED daemon DATA, never an actual observation\n'
                (root / 'daemon.json').write_bytes(daemon)
                a['native_daemon_identity_sha256'] = n.c.pin(daemon)['sha256']
                xs = dict(schema=1, candidate=n.p.CANDIDATE, target_arch=arch, artifact=artifact)
                for filename, key, body in (('xs-admission.json', 'xs_admission_sha256', n.p.encode(xs)),
                                             ('xs-inputs.json', 'inputs_sha256', b'{}\n'),
                                             ('xs-plan.json', 'plan_sha256', b'{}\n')):
                    (root / filename).write_bytes(body)
                    a[key] = n.c.pin(body)['sha256']
                with self.assertRaisesRegex(ValueError, 'candidate/accepted pair'):
                    n.inputs(root, a)

    def test_rootless_remapped_or_stale_daemon_and_wrong_socket_refuse(self):
        version = dict(Server=dict(Os='linux', Arch='arm64'))
        socket = (1, 2, stat.S_IFSOCK | 0o660, 0, 0)
        info = dict(ID='MODELED_DAEMON', OSType='linux', Architecture='aarch64', SecurityOptions=[],
                    CgroupVersion='2', CpuCfsQuota=True, MemoryLimit=True, SwapLimit=True, PidsLimit=True,
                    DockerRootDir='/MODELED/docker')
        proof = dict(schema=1, status='OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS', native_acceptance=False,
                     info=copy.deepcopy(info), version=version,
                     socket=dict(path='/var/run/docker.sock', uid=0, socket=True, stable=True))
        for option in ('name=rootless', 'name=userns'):
            actual, pinned = copy.deepcopy(info), copy.deepcopy(proof)
            actual['SecurityOptions'] = pinned['info']['SecurityOptions'] = [option]
            with self.assertRaisesRegex(ValueError, 'Rootful unremapped'):
                n.daemon_join(pinned, actual, version, socket, socket)
        actual = dict(info, ID='OTHER_DAEMON')
        with self.assertRaisesRegex(ValueError, 'current daemon differs'):
            n.daemon_join(proof, actual, version, socket, socket)
        with self.assertRaisesRegex(ValueError, 'root-owned local daemon socket'):
            n.daemon_join(proof, info, version, socket, (1, 3, socket[2], 1001, 0))

    def test_substituted_export_leaf_refuses(self):
        body = b'MODELED source DATA, no runtime claim'
        rows = {'MODELED_DATA': dict(file='evidence-000.data', **n.c.pin(body))}
        exported = {name: (b'MODELED DATA', 0o600) for name in
                    ('actor-result.json', 'runtime-observation.json', 'actual-packages.txt',
                     'operation.json', 'accepted-reader.json')}
        exported['evidence-map.json'] = (n.c.encode(rows), 0o600)
        exported['evidence-000.data'] = (b'SUBSTITUTED DATA', 0o600)
        with self.assertRaisesRegex(ValueError, 'leaf differs'):
            n.export_join(exported)

    def test_create_argv_is_fixed_local_and_bounded(self):
        argv = n.create_argv('owned', 'owned-work', 'sha256:' + '1' * 64, Path('/MODEL'), '2' * 64)
        self.assertEqual(argv[:5], n.DOCKER + ['create', '--name', 'owned'])
        self.assertIn('--cpus=2', argv)
        self.assertIn('--network=none', argv)
        self.assertIn('--user=1001:1001', argv)
        self.assertIn('--tmpfs=/xs-work:rw,exec,nosuid,nodev,size=256m,uid=1001,gid=1001,mode=0700', argv)
        self.assertEqual(argv[-6:], ['-I', '-B', '/inputs/consumer/native_adapter/native.py', 'actor',
                                    '--admission-sha256', '2' * 64])

    def test_inspect_refuses_privileged_alias_mount_and_substituted_command(self):
        a = modeled_operation()
        row = dict(Name='/owned', Image=a['image'], State=dict(Running=False),
                   Config=dict(User='1001:1001', Hostname='perl5423-native', Entrypoint=['/usr/bin/python3'],
                               WorkingDir='/work', Cmd=['-I', '-B', '/inputs/consumer/native_adapter/native.py',
                                                       'actor', '--admission-sha256', '2' * 64]),
                   HostConfig=dict(NanoCpus=2000000000, Memory=4294967296, MemorySwap=4294967296,
                                   PidsLimit=256, ReadonlyRootfs=True, Init=True, NetworkMode='none',
                                   CgroupnsMode='private', CapDrop=['ALL'], CapAdd=[], SecurityOpt=['no-new-privileges'],
                                   Privileged=False, Tmpfs=n.TMPFS),
                   Mounts=[dict(Destination='/inputs', Type='bind', RW=False, Source='/MODEL'),
                           dict(Destination='/work', Type='volume', RW=True, Name='owned-work')])
        for change in (lambda x: x['HostConfig'].update(Privileged=True),
                       lambda x: x['HostConfig'].update(Tmpfs=dict(n.TMPFS, **{'/xs-work': 'rw,noexec,size=256m'})),
                       lambda x: x['Mounts'].append(dict(Destination='/usr', Type='bind', RW=True)),
                       lambda x: x['Config'].update(Cmd=['OTHER_COMMAND'])):
            altered = copy.deepcopy(row)
            change(altered)
            with self.assertRaises(ValueError):
                n.inspect_actor(altered, a, 'owned', 'owned-work', Path('/MODEL'), '2' * 64)


if __name__ == '__main__':
    unittest.main(verbosity=2)
