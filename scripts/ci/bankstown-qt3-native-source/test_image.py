#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fenced MODEL controls for actual maintained Build/DRIVER and finite projection."""
import ast
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


F = load('qt3_input_fixture', HERE / 'test_inputs.py')  # Installs pre-role fence.
J = load('qt3_image_model', HERE / 'image.py')


class Executor:
    """Fictional Docker replies only. Real held Build validates every vector."""
    def __init__(self, module, fixture, mutation=None):
        self.M, self.f, self.mutation = module, fixture, mutation
        self.facts = dict(uid=1000, gid=1000, docker_endpoint='unix:///MODEL/private-docker.sock')
        self.containers, self.images, self.commands = {}, {}, []

    def result(self, step, argv, timeout, stdout, expected):
        row = dict(step=step, argv=argv, expected=expected, exit=expected,
                   timeout_seconds=timeout, supervision_cap_seconds=timeout,
                   output_pin=self.M.pin(stdout), stderr_pin=self.M.pin(b''),
                   supervision=dict(reaped=True, ownership='REAPED', group_census='EMPTY_TWICE',
                       output_complete=True, signals=[], timeout=False, error=None, exit=expected, seconds=0.001))
        if self.mutation:
            self.mutation(step, row, self)
        return dict(stdout=stdout, stderr=b'', receipt=row)

    def run(self, step, argv, timeout, expected=0):
        self.commands.append((step, argv))
        assert argv[:2] == ['/usr/bin/docker', '--host=' + self.facts['docker_endpoint']]
        a, output = argv[2:], b''
        if a[:2] == ['container', 'create']:
            name = a[a.index('--name') + 1]
            cid = self.M.pin(name.encode())['sha256']
            index = a.index('--entrypoint=/bin/bash')
            image, command = a[index + 1], a[index + 2:]
            labels = dict(a[i + 1].split('=', 1) for i, v in enumerate(a[:-1]) if v == '--label')
            probe = name.endswith('-probe')
            self.containers[cid] = dict(Id=cid, Name='/' + name, Image=image,
                Config=dict(Labels=labels, User=a[a.index('--user') + 1], Entrypoint=['/bin/bash'], Cmd=command),
                HostConfig=dict(NetworkMode='none', Privileged=False, Devices=[], CapDrop=['ALL'],
                    CapAdd=[] if probe else self.M.CAPS, Memory=4 * 1024**3, MemorySwap=4 * 1024**3,
                    NanoCpus=4 * 10**9, PidsLimit=512, ReadonlyRootfs=probe, SecurityOpt=['no-new-privileges']),
                Mounts=[], State=dict(Running=False, ExitCode=0, OOMKilled=False))
            output = (cid + '\n').encode()
        elif a[:2] == ['container', 'inspect']:
            output = self.M.encoded([self.containers[a[2]]])
        elif a[:2] == ['container', 'start']:
            row = self.containers[a[-1]]
            output = self.M.lock(self.f.expected) if row['Name'].endswith('-probe') else b'MODEL normal ALPM output\n'
        elif a[0] == 'cp' and ':/image-facts/' in a[1]:
            cid = a[1].split(':', 1)[0]
            p = Path(a[2])
            inventory = self.f.baseline if self.containers[cid]['Name'].endswith('-base') else self.f.expected
            for name, body in {
                'inventory.lock': self.M.lock(inventory), 'package-file-check.log': b'MODEL actual-Qkk channel\n',
                'payload.tsv': b'', 'package-files.txt': b'', 'alarm.passwd': b'alarm:x:1000:1000::/home/alarm:/bin/bash\n',
                'alarm.group': b'alarm:x:1000:\n'}.items():
                (p / name).write_bytes(body)
        elif a[:2] == ['container', 'commit']:
            cid = a[-2]
            image = 'sha256:' + self.M.pin(a[-1].encode())['sha256']
            self.images[image] = dict(Id=image, Os='linux', Architecture='arm64',
                                     Config=dict(Labels=self.containers[cid]['Config']['Labels']))
            output = (image + '\n').encode()
        elif a[:2] == ['image', 'inspect']:
            output = self.M.encoded([self.images[a[2]]])
        elif a[:2] == ['image', 'ls']:
            output = ''.join(v + '\n' for v in sorted(self.images)).encode()
        elif a[:2] == ['image', 'rm']:
            del self.images[a[2]]
        elif a[:2] == ['container', 'rm']:
            del self.containers[a[2]]
        elif a[0] == 'ps':
            name = a[-1].split('name=^/', 1)[-1].removesuffix('$')
            output = ''.join(cid + '\n' for cid, row in self.containers.items() if row['Name'] == '/' + name).encode()
        elif a[0] != 'cp':
            raise AssertionError('Unexpected MODEL Docker vector: ' + repr(a))
        return self.result(step, argv, timeout, output, expected)


class ImageControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qt3-image-MODEL-')
        self.addCleanup(self.tmp.cleanup)
        self.f = F.Fixture(Path(self.tmp.name))
        self.M = F.I.held(self.f.root, 'image_current_v3.py')
        self.M.OP, self.M.COUNTS = J.OPERATION, {'qt3': 477}

    def build(self, mutation=None):
        e = Executor(self.M, self.f, mutation)
        out = Path(self.tmp.name) / 'build'
        out.mkdir()
        d = dict(capability=dict(total_seconds=600, max_command_seconds=300, command_rows=512),
                 expires_epoch=int(time.time()) + 600)
        c = dict(nonce='a' * 64, stage='qt3', binding={'source': 'b' * 40})
        b = self.M.Build(e, d, c, {}, out)
        labels = {self.M.LABEL + '.nonce': c['nonce'], self.M.LABEL + '.source': c['binding']['source'],
                  self.M.LABEL + '.stage': 'qt3'}
        seed = 'sha256:' + 'c' * 64
        e.images[seed] = dict(Id=seed, Os='linux', Architecture='arm64', Config=dict(Labels=labels))
        b.images.append(dict(id=seed, tag=None, labels=labels))
        return b, e, labels, seed

    def test_real_build_actor_commit_probe_and_cleanup(self):
        b, e, labels, seed = self.build()
        base = b.actor('base', seed, labels, Path(self.tmp.name), [], self.f.baseline, {})
        image = b.commit(base, 'base349')
        stage = b.actor('qt3', image, labels, Path(self.tmp.name), [], self.f.expected, {})
        target = b.commit(stage, '477')
        b.actor('probe', target, labels, None, [], self.f.expected, {})
        b.target = target
        receipt = b.cleanup()
        self.assertEqual(receipt['errors'], [])
        self.assertEqual(e.containers, {})
        self.assertEqual(set(e.images), {target})
        self.assertEqual(receipt['retained_target_image_unqualified'], target)
        self.assertLess(len(b.rows) + J.SIGNATURE_ROWS, 512)
        self.assertTrue(any(self.M.DRIVER in argv for _, argv in e.commands))

    def test_projection_changes_only_two_reviewed_stage_seams(self):
        old = self.M.build_stage
        identities = {n: getattr(self.M, n) for n in ('Build', 'admit', 'DRIVER', 'protected_state', 'stage_materials')}
        raw = (self.f.root / F.I.NATIVE / 'image_current_v3.py').read_bytes()
        stage = J.projected_stage(self.M, raw)
        self.assertIsNot(stage, old)
        for n, value in identities.items():
            self.assertIs(getattr(self.M, n), value)
        constants = repr(stage.__code__.co_consts)
        self.assertIn(J.TRUST_SCOPE, constants)
        self.assertNotIn('CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY', constants)
        self.assertNotIn('/usr/bin/bsdtar', constants)

    def test_changed_held_program_refuses_before_projection(self):
        raw = (self.f.root / F.I.NATIVE / 'image_current_v3.py').read_bytes() + b'\n# changed\n'
        with self.assertRaisesRegex(ValueError, 'EXACT_HELD_IMAGE_PROGRAM'):
            J.projected_stage(self.M, raw)

    def test_null_root_refuses_before_module_roles(self):
        with patch.object(J, 'local', side_effect=AssertionError('role imported')):
            with self.assertRaisesRegex(ValueError, 'GENUINE_EXTERNAL_ROOT'):
                J.build_qt3_image(delegation_raw=b'null', delegation_sha256=J.pin(b'null')['sha256'],
                    context=None, source_root=self.f.root, inputs=None, executor=None, output=None)

    def test_actual_build_non_natural_start_is_hold(self):
        def mutate(step, row, e):
            if step == 'start-qt3':
                row['supervision']['signals'] = ['TERM']
        b, e, labels, seed = self.build(mutate)
        with self.assertRaisesRegex(ValueError, 'natural owned command'):
            b.actor('qt3', seed, labels, Path(self.tmp.name), [], self.f.expected, {})
        self.assertEqual(b.cleanup()['errors'], [])
        self.assertEqual(e.containers, {})

    def test_wrong_immutable_container_limits_refuse_before_removal(self):
        def mutate(step, row, e):
            if step == 'create-qt3':
                next(iter(e.containers.values()))['HostConfig']['MemorySwap'] += 1
        b, e, labels, seed = self.build(mutate)
        with self.assertRaisesRegex(ValueError, 'finite offline image actor'):
            b.actor('qt3', seed, labels, Path(self.tmp.name), [], self.f.expected, {})
        self.assertTrue(b.cleanup()['errors'])
        self.assertNotEqual(e.containers, {})

    def test_wrong_probe_inventory_refuses(self):
        b, e, labels, seed = self.build()
        wrong = dict(self.f.expected)
        wrong['rust'] = '1:1.98.0-1'
        with self.assertRaisesRegex(ValueError, 'actual inventory'):
            b.actor('probe', seed, labels, None, [], wrong, {})
        self.assertEqual(b.cleanup()['errors'], [])

    def test_finite_row_budget_fits_all385_signatures(self):
        self.assertEqual(J.SIGNATURE_ROWS, 257 + 128)
        self.assertLessEqual(J.SIGNATURE_ROWS + J.RESERVED_CONTROL_ROWS, J.COMMAND_ROWS)
        self.assertEqual(J.COMMAND_ROWS, 512)

    def test_actual_context_original_admit_and_selected_input_contract_join(self):
        """Real context/source/admit predicates; kernel observations are MODEL."""
        CF = load('qt3_real_context_fixture', HERE / 'test_context.py')
        f = CF.Fixture(self.f.root)
        context_member = 'scripts/ci/bankstown-qt3-native-source/context.py'
        image_member = 'scripts/ci/bankstown-qt3-native-source/image.py'
        held_context = 'scripts/ci/first-login-enrollment-native-source/payload/native/delegated_context_v3.py'
        self.f.copy(held_context)
        self.f.copy(image_member)
        C = load('qt3_closed_context_model', self.f.root / context_member)
        policy = json.loads((F.ROOT / F.I.NATIVE / 'owned_current_v3.policy.PROPOSAL.json').read_bytes())
        policy.update(context=f.limits, stage_capabilities={'qt3': f.ceiling})
        (self.f.root / 'inputs/policy.json').write_bytes(C.encoded(policy))
        f.d['policy'] = dict(member='inputs/policy.json', **C.pin(C.encoded(policy)))
        f.d['programs']['image'] = dict(member=image_member, **C.pin((self.f.root / image_member).read_bytes()))
        f.d['inputs_pin'] = C.pin(C.encoded(self.f.request))
        rows = {str(p.relative_to(self.f.root)): dict(C.pin(p.read_bytes()), mode=0o644)
                for p in self.f.root.rglob('*') if p.is_file() and p.name not in ('source-map.json', 'source.lock.json')}
        source_map = C.encoded(dict(schema=1, kind=C.SOURCE_KIND, operation=C.OPERATION,
            actual=dict(source=None, ref=None, run=None, job=None), files=rows))
        for name in ('source-map.json', 'source.lock.json'):
            (self.f.root / name).write_bytes(source_map)
        f.d['binding']['source_lock'] = C.pin(source_map)
        raw = C.encoded(f.d)
        with patch.object(self.M.time, 'time', return_value=CF.NOW):
            c = C.capture_context(raw, C.pin(raw)['sha256'], self.f.root,
                                  environ=f.env, jobs_response=f.response, now=CF.NOW)
            domains = {role: dict(pid=12345 + i, starttime=1, cgroup='/MODEL/' + c['nonce'] + '/' + role,
                                  limits=policy['image_domains'][role], executable='dockerd' if role == 'daemon' else 'python3')
                       for i, role in enumerate(('owner', 'daemon'))}
            facts = dict(api=self.M.API, binding=c['binding'], nonce=c['nonce'], stage='qt3',
                code_pin={k: f.d['programs']['image_executor'][k] for k in ('bytes', 'sha256')},
                domain_policy_pin=C.pin(C.encoded(policy)), native_architecture='aarch64',
                owner_domain=domains['owner'], daemon_domain=domains['daemon'], uid=1000, gid=1000,
                daemon_pidfd_held=True, whole_owner_deadline_enforced=True, daemon_deadline_enforced=True,
                exclusive_daemon=True, docker_endpoint=policy['image_endpoint_template'].format(nonce=c['nonce']),
                storage=dict(quota_bytes=policy['image_storage_bytes'], kernel_enforced=True,
                             scope='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES'))
            self.M.context_contract, self.M.__file__ = C.context_contract, str(self.f.root / image_member)
            with patch.object(self.M, 'native_identity', return_value=dict(system='Linux', machine='aarch64',
                    uid=1000, gid=1000, pid=domains['owner']['pid'])), \
                 patch.object(self.M, 'actual_domain', side_effect=lambda pid: next(v for v in domains.values() if v['pid'] == pid)):
                d, actual_c, p, actual_H = self.M.admit(raw, C.pin(raw)['sha256'], c,
                    self.f.root, types.SimpleNamespace(facts=facts), context_program=C)
                self.assertIs(actual_H, C)
                plan = J.bind_inputs(F.I, C, self.f.request, 'qt3', self.f.root, actual_H, d, actual_c,
                                     verify_archives=False)
                self.assertEqual(len(plan['expected']), 477)
                self.assertNotIn('operation', d)  # Operation lives in the real capability.
                wrong = dict(self.f.request, official_trust={'MODEL': True})
                with self.assertRaisesRegex(ValueError, 'ROOT_SELECTED_INPUT_REQUEST_PIN'):
                    J.bind_inputs(F.I, C, wrong, 'qt3', self.f.root, actual_H, d, actual_c, verify_archives=False)

    def tar_metadata(self, count=1):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for _ in range(count):
                body = b'pkgname = MODEL\npkgver = 1-1\narch = aarch64\n'
                member = tarfile.TarInfo('.PKGINFO')
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        return buffer.getvalue()

    def test_passive_decoder_uses_actual_held_metadata_parser(self):
        T = self.M.tools(self.f.root)
        raw = self.tar_metadata()
        observed = J.zstd_package_metadata(Path('/MODEL/unopened'), T._metadata,
            deadline=time.monotonic() + 10, opener=lambda *args: io.BytesIO(raw))
        self.assertEqual(observed, dict(pkgname=['MODEL'], pkgver=['1-1'], arch=['aarch64']))

    def test_duplicate_or_expired_metadata_refused(self):
        T = self.M.tools(self.f.root)
        for count, deadline, message in ((2, time.monotonic() + 10, 'ONE_ACTUAL_PKGINFO'),
                                         (1, 0, 'METADATA_DEADLINE')):
            with self.subTest(count=count, deadline=deadline):
                with self.assertRaisesRegex(ValueError, message):
                    J.zstd_package_metadata(Path('/MODEL/unopened'), T._metadata,
                        deadline=deadline, opener=lambda *args: io.BytesIO(self.tar_metadata(count)))

    def test_real_stdlib_zstd_synthetic_data_or_explicit_unsupported_hold(self):
        T = self.M.tools(self.f.root)
        try:
            from compression import zstd
        except ImportError:
            with self.assertRaisesRegex(ValueError, 'PYTHON314_ZSTD_DATA_READER_REQUIRED'):
                J.zstd_package_metadata(Path('/MODEL/unopened'), T._metadata, deadline=time.monotonic() + 10)
            return
        path = Path(self.tmp.name) / 'MODEL-metadata.zst'
        path.write_bytes(zstd.compress(self.tar_metadata(), level=1))
        result = J.zstd_package_metadata(path, T._metadata, deadline=time.monotonic() + 10)
        self.assertEqual(result['pkgname'], ['MODEL'])


if __name__ == '__main__':
    unittest.main()
