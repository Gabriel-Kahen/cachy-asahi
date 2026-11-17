# SPDX-License-Identifier: MIT
"""MODEL Root/native/signature seams, real policy/source/context/image predicates."""
import base64
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in ('os.system', 'fcntl.flock'):
        ACTORS.append(event)
        raise AssertionError('BRIDGE_DATA_NO_ACTOR: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


B = load('project_bridge_controls', HERE / 'payload/hosted/project_provider.py')
F = load('project_bridge_admission_models', HERE.parent / 'project_test_provider_v1/test_admission.py')
A = F.A; D = A.D


class Bridge(unittest.TestCase):
    def setUp(self):
        self.f = F.Controls(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        p = self.f.put(B.PATHS['policy'], A.encode(self.f.p))
        decision = self.f.put(B.PATHS['decision'], A.encode(self.f.decision()))
        self.config = dict(schema=19, kind='RUST19_PROJECT_TEST_PROVIDER_BINDING_V1', policy=p, decision=decision)
        self.f.put(B.CONFIG, A.encode(self.config))
        self.addCleanup(patch.stopall)
        patch.object(B, 'CONFIG_PIN', B.pin(A.encode(self.config))).start()
        patch.object(B, 'interface', return_value=A).start()
        original = A.module
        def modules(path, *args):
            if Path(path).name == 'native.py':
                return SimpleNamespace(validate=lambda *args: {'MODEL_NATIVE_BOUNDARY_NOT_AUTHORITY': True})
            return original(path, *args)
        patch.object(A, 'module', side_effect=modules).start()
        self.base = self.f.base

    def selected(self): return B.policy(self.root, now=1000)

    def outputs(self):
        context, output = self.base / 'context', self.base / 'out'
        context.mkdir(mode=0o700); output.mkdir(mode=0o700)
        return context, output

    def signature(self, argv, timeout):
        self.assertEqual(timeout, 30); self.assertEqual(argv[0], '/usr/bin/gpgv')
        raw = ('[GNUPG:] VALIDSIG ' + F.FPR + ' 2026-11-17 900 0 4 0 1 10 00 ' + F.FPR + '\n').encode()
        return SimpleNamespace(returncode=0, stdout=raw)

    def prepared(self):
        state = self.selected(); context, output = self.outputs()
        receipt = B.prepare_context(self.root, context, output, state, self.signature, now=1000)
        return state, context, output, receipt

    def test_config_fresh_admission_and_complete_signature_audit_dockerfile_chain(self):
        state, context, output, receipt = self.prepared()
        self.assertEqual(len(receipt['gpgv_evidence']), 2)
        self.assertEqual((output / 'build-dependency-audit.json').read_bytes(), B.encode(receipt))
        self.assertFalse(receipt['ALARM_authentication']); self.assertFalse(receipt['native_acceptance'])
        docker = B.extend_dockerfile(b'MODEL_PARENT\nUSER alarm\nWORKDIR /tmp\n', state, receipt, now=1000)
        self.assertIn(b'SigLevel = Required', docker); self.assertIn(b'LocalFileSigLevel = Required', docker)
        self.assertIn(b' -T ', docker); self.assertIn(b'--noscriptlet', docker)
        self.assertNotIn(b'--nodeps', docker); self.assertNotIn(b'/etc/pacman.d/gnupg', docker)

    def test_unbound_changed_or_wrong_path_config_refuses_before_any_call(self):
        with patch.object(B, 'CONFIG_PIN', None), self.assertRaisesRegex(ValueError, 'UNBOUND'): self.selected()
        path = self.root / B.CONFIG; raw = path.read_bytes(); path.write_bytes(raw + b'\n')
        with self.assertRaisesRegex(ValueError, 'constructor-selected'): self.selected()
        value = copy.deepcopy(self.config); value['decision']['path'] = 'project-test/other.json'
        path.write_bytes(B.encode(value))
        with patch.object(B, 'CONFIG_PIN', B.pin(path.read_bytes())), self.assertRaisesRegex(ValueError, 'fixed separate'): self.selected()

    def test_expiry_and_policy_decision_mutation_checked_at_every_boundary(self):
        state, context, output, receipt = self.prepared()
        for call in (lambda: B.checked(state, now=1100),
                     lambda: B.extend_dockerfile(b'USER alarm\nWORKDIR /tmp\n', state, receipt, now=1100),
                     lambda: B.observe(self.base, self.root, state, image_id='sha256:' + 'a' * 64, now=1100)):
            with self.assertRaisesRegex(ValueError, 'fresh finite'): call()
        (self.root / B.PATHS['decision']).write_bytes(b'{}')
        with self.assertRaises(ValueError): B.checked(state, now=1000)

    def test_full_gpgv_argv_status_bound_and_math_refuse_after_receipt_rehash(self):
        state, context, output, receipt = self.prepared()
        name = next(iter(receipt['gpgv_evidence']))
        for mutate in (lambda r: r['gpgv_evidence'][name]['argv'].__setitem__(5, '--import'),
                       lambda r: r['gpgv_evidence'][name]['argv'].__setitem__(-1, '/OTHER/package.xz'),
                       lambda r: r['gpgv_evidence'][name].update(returncode=False),
                       lambda r: r['gpgv_evidence'][name].update(status_base64='x' * 87385),
                       lambda r: r['gpgv_evidence'].pop(name)):
            value = copy.deepcopy(receipt); mutate(value)
            with self.assertRaises(ValueError): B.extend_dockerfile(b'USER alarm\nWORKDIR /tmp\n', state, value, now=1000)
        value = copy.deepcopy(receipt); raw = b'[GNUPG:] BADSIG MODEL\n'
        value['gpgv_evidence'][name].update(status=B.pin(raw), status_base64=base64.b64encode(raw).decode())
        value['verified_signatures'][name]['gpgv_status'] = B.pin(raw)
        with self.assertRaisesRegex(ValueError, 'one valid'): B.extend_dockerfile(b'USER alarm\nWORKDIR /tmp\n', state, value, now=1000)

    def test_scoped_verifier_failure_and_cancellation_cannot_produce_audit(self):
        state = self.selected(); context, output = self.outputs()
        def fail(argv, timeout): return SimpleNamespace(returncode=1, stdout=b'[GNUPG:] ERRSIG MODEL')
        with self.assertRaises(ValueError): B.prepare_context(self.root, context, output, state, fail, now=1000)
        self.assertFalse((output / 'build-dependency-audit.json').exists())
        def cancel(): raise ValueError('MODEL cancelled')
        with self.assertRaisesRegex(ValueError, 'cancelled'): B.checked(state, now=1000, tick=cancel)

    def image(self, p):
        image = self.base / 'image'; db = image / 'var/lib/pacman/local'; db.mkdir(parents=True)
        rows = D.inventory(D.expected_inventory(self.root, p)); packages = {r['name']: r for r in p['packages']}
        keys = dict(pkgname='%NAME%', pkgver='%VERSION%', arch='%ARCH%', license='%LICENSE%', depend='%DEPENDS%',
                    provides='%PROVIDES%', conflict='%CONFLICTS%', replaces='%REPLACES%')
        for name, version in rows.items():
            folder = db / (name + '-' + version.replace(':', '_')); folder.mkdir()
            meta = packages[name]['metadata'] if name in packages else dict(pkgname=[name], pkgver=[version])
            (folder / 'desc').write_text(''.join(keys[k] + '\n' + '\n'.join(v) + '\n\n' for k, v in meta.items() if v))
            if name in packages: (folder / 'files').write_text('%FILES%\n' + '\n'.join(packages[name]['providers']) + '\n')
        for package in p['packages']:
            for name, row in package['providers'].items():
                path = image / name; path.parent.mkdir(parents=True, exist_ok=True)
                if row['kind'] == 'file': path.write_bytes(F.ELF); path.chmod(row['mode'])
                else: path.symlink_to(row['target'])
        return image

    def test_real_complete_image_observation_same_image_and_provider_gates(self):
        state = self.selected(); image = self.image(state['policy']); iid = 'sha256:' + 'a' * 64
        observed = B.observe(image, self.root, state, image_id=iid, now=1000)
        B.validate_observation(observed, self.root, state, image_id=iid, native=False, now=1000)
        self.assertEqual(observed['image_id'], iid); self.assertFalse(observed['native_acceptance'])
        with self.assertRaises(ValueError): B.validate_observation(observed, self.root, state, image_id='sha256:' + 'b' * 64, native=False, now=1000)
        row = state['policy']['packages'][0]; name = next(n for n, r in row['providers'].items() if r['kind'] == 'file')
        (image / name).write_bytes(b'OTHER')
        with self.assertRaises(ValueError): B.observe(image, self.root, state, image_id=iid, now=1000)

    def test_real_embedded_interface_pin_and_no_operational_attempts(self):
        with patch.object(B, 'interface', wraps=load('bridge_real_template', HERE / 'payload/hosted/project_provider.py').interface):
            actual = B.interface(ROOT)
        self.assertEqual(actual.PREDECESSOR, '8128cd73c85d533092d081f0b9131b2ca9893ecd')
        self.assertEqual(ACTORS, [])


if __name__ == '__main__': unittest.main(verbosity=2)
