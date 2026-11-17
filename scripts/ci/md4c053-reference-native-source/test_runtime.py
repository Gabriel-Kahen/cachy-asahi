# SPDX-License-Identifier: MIT
"""Actor-free MODEL checks of the actual admitted provider hook."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('md4c_provider_runtime', HERE/'runtime.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


def bundle():
    raw = {name: b'MODEL\n' for name in R.FILES}
    raw['finish_pair.py'] = b'VALUE = "MODEL_FINISHER_ONLY"\n'
    raw['reviewed-inputs.json'] = json.dumps({name[7:]: hashlib.sha256(value).hexdigest()
        for name, value in raw.items() if name.startswith('recipe/')}).encode()
    return {name: dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest(),
        mode=0o644, body_base64=base64.b64encode(value).decode())
        for name, value in raw.items()}


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='md4c-runtime-', dir='/dev/shm')
        self.addCleanup(self.tmp.cleanup)
        self.area = Path(self.tmp.name)
        self.root = self.area/'source'
        self.here = self.root/R.BASE
        self.here.mkdir(parents=True)
        (self.here/'expected349.lock').write_bytes(b'MODEL\n')
        self.forwarded = Mock(return_value='ORIGINAL_MODULE_RESULT')
        self.contract = SimpleNamespace(module=self.forwarded, plans=Mock())
        self.namespace = dict(HERE=self.here, C=self.contract)
        self.inputs = bundle()
        self.out = self.area/'quota-work-output'
        self.image = 'sha256:'+'a'*64
        self.addCleanup(patch.stopall)
        patch('subprocess.Popen', side_effect=AssertionError('native actor fenced')).start()
        patch('subprocess.run', side_effect=AssertionError('native actor fenced')).start()
        patch('subprocess.check_output', side_effect=AssertionError('native actor fenced')).start()
        patch('socket.socket', side_effect=AssertionError('network actor fenced')).start()

    def installed(self):
        R.install(self.namespace, self.root, self.inputs)
        return self.contract

    def stage(self):
        c = self.installed()
        self.out.mkdir(mode=0o700)
        plans = c.plans(self.here, self.out, self.image)
        return c, plans

    def test_install_no_staging_and_finisher_requires_post_bootstrap_plans(self):
        before = {p.relative_to(self.area) for p in self.area.rglob('*')}
        c = self.installed()
        self.assertEqual(before, {p.relative_to(self.area) for p in self.area.rglob('*')})
        self.assertFalse(self.out.exists())
        with self.assertRaises(ValueError):
            c.module(self.here/'finish_pair.py', 'MODEL_FINISHER')
        self.assertEqual(c.module(self.here/'runtime/owned_process.py', 'ordinary'),
                         'ORIGINAL_MODULE_RESULT')
        self.forwarded.assert_called_once_with(self.here/'runtime/owned_process.py', 'ordinary')

    def test_actual_plans_keep_native_two_clean_outputs_and_all_required_gates(self):
        c, (builds, compare) = self.stage()
        self.assertEqual(len(builds), 2)
        stage = self.out/'md4c-provider-inputs'
        R.verify_stage(stage, R.decode_bundle(self.inputs))
        for i, argv in enumerate(builds, 1):
            self.assertEqual(argv[:4], ['/usr/bin/python3', '-I', '-B',
                str(self.here/'runtime/scripts/build/build_llhttp-reference.py')])
            self.assertEqual(argv[4], str(stage/'recipe'))
            for key, value in [('--image', self.image), ('--mode', 'native'),
                ('--network', 'none'), ('--timeout', '300'),
                ('--source-date-epoch', '1776685420'),
                ('--expected-packages', str(self.here/'expected349.lock')),
                ('--reviewed-inputs', str(stage/'reviewed-inputs.json')),
                ('--output', str(self.out/('build-'+str(i))))]:
                self.assertEqual(argv[argv.index(key)+1], value)
            self.assertFalse(any(x in argv for x in ('--nodeps', '--nocheck', '--ignorearch')))
        self.assertEqual(compare, ['/usr/bin/python3', '-I', '-B',
            str(self.here/'runtime/scripts/build/compare_llhttp.py'),
            str(self.out/'build-1'), str(self.out/'build-2'), '--require-bytes'])
        self.assertEqual(c.module(self.here/'finish_pair.py', 'MODEL_FINISHER').VALUE,
                         'MODEL_FINISHER_ONLY')

    def test_wrong_bundle_closure_hash_mode_and_review_refuse_before_staging(self):
        variants = []
        v = copy.deepcopy(self.inputs); v['unexpected'] = v['recipe/PKGBUILD']; variants.append(v)
        v = copy.deepcopy(self.inputs); v.pop('recipe/smoke.c'); variants.append(v)
        v = copy.deepcopy(self.inputs); v['recipe/smoke.c']['mode'] = 0o755; variants.append(v)
        v = copy.deepcopy(self.inputs); v['recipe/smoke.c']['sha256'] = 'f'*64; variants.append(v)
        v = copy.deepcopy(self.inputs); v['recipe/smoke.c']['bytes'] = True; variants.append(v)
        v = copy.deepcopy(self.inputs); v['recipe/smoke.c']['body_base64'] = '!'; variants.append(v)
        v = copy.deepcopy(self.inputs); raw = b'{}'; v['reviewed-inputs.json'] = dict(bytes=2,
            sha256=hashlib.sha256(raw).hexdigest(), mode=0o644, body_base64='e30='); variants.append(v)
        for value in variants:
            with self.subTest(value=value.keys()):
                with self.assertRaises(ValueError):
                    R.install(self.namespace, self.root, value)
                self.assertNotIn('_md4c053_provider', self.namespace)
                self.assertFalse(self.out.exists())

    def test_ordinary_lock_paths_and_single_use_are_required(self):
        alias = self.area/'alias'; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            R.install(self.namespace, alias, self.inputs)
        (self.here/'expected349.lock').write_bytes(b'DRIFT\n')
        with self.assertRaises(ValueError):
            R.install(self.namespace, self.root, self.inputs)
        (self.here/'expected349.lock').write_bytes(b'MODEL\n')
        c, _ = self.stage()
        with self.assertRaises(ValueError):
            R.install(self.namespace, self.root, self.inputs)
        with self.assertRaises(ValueError):
            c.plans(self.here, self.out, self.image)

    def test_stage_drift_extra_alias_and_early_reuse_do_not_import_finisher(self):
        c, _ = self.stage()
        stage = self.out/'md4c-provider-inputs'
        target = stage/'recipe/smoke.c'
        target.write_bytes(b'DRIFT\n')
        with self.assertRaises(ValueError):
            c.module(self.here/'finish_pair.py', 'MODEL_FINISHER')
        target.unlink(); target.symlink_to(self.here/'expected349.lock')
        with self.assertRaises(ValueError):
            c.module(self.here/'finish_pair.py', 'MODEL_FINISHER')

    def test_staging_refuses_source_output_and_preexisting_stage_without_overwrite(self):
        c = self.installed()
        inside = self.root/'quota'; inside.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            c.plans(self.here, inside, self.image)
        self.out.mkdir(mode=0o700)
        stage = self.out/'md4c-provider-inputs'; stage.mkdir(mode=0o700)
        marker = stage/'unchanged'; marker.write_bytes(b'NO_OVERWRITE')
        with self.assertRaises(FileExistsError):
            c.plans(self.here, self.out, self.image)
        self.assertEqual(marker.read_bytes(), b'NO_OVERWRITE')
        with self.assertRaises(ValueError):
            c.plans(self.here, self.out, self.image)


if __name__ == '__main__':
    unittest.main(verbosity=2)
