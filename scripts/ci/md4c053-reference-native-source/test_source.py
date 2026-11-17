#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actual packed Source/payload/provider integration, with all actors fenced."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load(HERE/'prepare.py', 'md4c_source_constructor')
PARENT, RECIPE, ARCHIVE = (Path(os.environ[name]) for name in ('MD4C_PARENT', 'MD4C_RECIPE', 'MD4C_ARCHIVE'))


def rehash(bodies):
    bodies = dict(bodies)
    prior = json.loads(bodies[P.PREFIX+'owner-program.json'])
    mapping = json.loads(bodies['source-map.json'])
    bodies.pop('source-map.json'); bodies.pop(P.PREFIX+'owner-program.json')
    bodies[P.PREFIX+'owner-program.json'] = P.P.encode(dict(schema=1,
        base_source_map_sha256=prior['base_source_map_sha256'],
        files={n:dict(P.pin(raw), mode=0o644) for n,raw in sorted(bodies.items())
               if not n.startswith('held-source/')}))
    bodies['source-map.json'] = P.P.encode(dict(mapping,
        files={n:dict(P.pin(raw), mode=0o644) for n,raw in sorted(bodies.items())}))
    return bodies


class Controls(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='md4c-source-control-')
        self.addCleanup(temp.cleanup)
        self.area = Path(temp.name).resolve()
        for actor in ('subprocess.Popen', 'socket.socket', 'os.system', 'os.fork', 'os.kill',
                      'os.posix_spawn', 'os.chown', 'resource.setrlimit'):
            guard = patch(actor, side_effect=AssertionError('unexpected native actor: '+actor))
            guard.start()
            self.addCleanup(guard.stop)

    @classmethod
    def setUpClass(cls):
        cls.old = P.P.physical(PARENT)
        cls.bundle = P.bundle_for(cls.old, RECIPE, ARCHIVE)
        cls.new = P.assemble(cls.old, cls.bundle)

    def source(self, bodies=None):
        root = self.area/'Source'
        root.mkdir(mode=0o700)
        for name, raw in (self.new if bodies is None else bodies).items():
            path = root/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(0o644)
        return root

    def test_actual_constructor_full_inverse_and_unchanged_source_bounds(self):
        output = self.area/'constructed'
        result = P.construct(PARENT, RECIPE, ARCHIVE, output)
        bodies = P.P.physical(output)
        self.assertEqual(bodies, self.new)
        self.assertEqual(P.inverse(bodies), self.old)
        self.assertEqual(result['files'], 95)
        self.assertLess(result['bytes'], 2*1024**2)
        self.assertTrue(result['full_fixed241_and_predecessor_inverse'])
        self.assertEqual(result, P.verify_source(output))
        self.assertEqual(result['source_map'], P.FIXED['factory']['source']['map'])
        self.assertTrue(all(v is None for v in result['actual'].values()))
        for name in ('Root_authority', 'Root_registration', 'Root_acceptance', 'native_pair', 'signing'):
            self.assertIsNone(result[name])
        self.assertEqual(set(self.new)-set(self.old), {P.NEW_WF})
        self.assertEqual(set(self.old)-set(self.new), {P.OLD_WF})

    def test_all501_expected349_private182_cadence_source_ro_and_resources_preserved(self):
        for name, raw in self.old.items():
            if name.startswith('held-source/'):
                self.assertEqual(self.new[name], raw, name)
        for name in (P.PREFIX+'native349_carrier.py', P.PREFIX+'source_readonly.py', P.PREFIX+'data.py'):
            self.assertEqual(self.new[name], self.old[name])
        self.assertEqual(P.pin(self.new[P.BASE+'runtime/scripts/ci/inputs.lock.json']), P.FIXED['all501'])
        self.assertEqual(P.pin(self.new[P.BASE+'expected349.lock']), P.FIXED['expected349'])
        old, new = [json.loads(b[P.PREFIX+'policy.json']) for b in (self.old, self.new)]
        new.pop('md4c_provider_case'); new['inner_public_retention'] = old['inner_public_retention']
        self.assertEqual(new, old)
        self.assertEqual(old['finite_command_case']['inner_limit'], 512)
        self.assertEqual(old['finite_command_case']['outer_limit_unchanged'], 512)
        self.assertEqual(old['finite_command_case']['startup_status_seconds'], 1)
        self.assertEqual(old['finite_command_case']['running_status_seconds'], 10)
        methods = lambda raw: {n.name:ast.dump(n, include_attributes=False)
            for c in ast.parse(raw).body if isinstance(c, ast.ClassDef) and c.name == 'Controller'
            for n in c.body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(methods(self.old[P.PREFIX+'hosted_owner.py']),
                         methods(self.new[P.PREFIX+'hosted_owner.py']))
        for token in (b'E.preserve(', b'owner.cleanup()', b'ordinary payload natural success required'):
            self.assertIn(token, self.new[P.PREFIX+'hosted_owner.py'])

    def test_actual_generated_payload_unpacks_installs_and_stages_real_provider(self):
        root = self.source()
        data = load(root/P.PREFIX/'data.py', 'md4c_integrated_data')
        carrier = load(root/P.PREFIX/'native349_carrier.py', 'md4c_integrated_carrier')
        payload = ast.parse(self.new[P.PREFIX+'payload.py'])
        main = next(n for n in payload.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        start = next(i for i,n in enumerate(main.body) if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'base' for t in n.targets))
        stop = next(i for i,n in enumerate(main.body) if isinstance(n, ast.Expr)
                    and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
                    and isinstance(n.value.func.value, ast.Name) and n.value.func.value.id == 'hook'
                    and n.value.func.attr == 'install')
        code = ast.Module(body=main.body[start:stop+1], type_ignores=[])
        phases = Mock()
        env = dict(root=root, D=data, N=carrier, Path=Path,
            config=dict(pinned_inputs=str(self.area/'MODEL-pinned-inputs')),
            map_sha=P.pin(self.new['source-map.json'])['sha256'], X=SimpleNamespace(phase=phases))
        exec(compile(code, '<actual-source-md4c-payload-segment>', 'exec'), env)
        self.assertFalse((self.area/'native-output').exists())
        namespace = env['namespace']; contract = namespace['C']; here = namespace['HERE']
        entry = env['entry']
        self.assertEqual(entry.count(b'PASS_CURRENT_MD4C053_REFERENCE'), 4)
        self.assertNotIn(b'PASS_CURRENT_LLHTTP_REFERENCE', entry)
        self.assertIn(b'len(self.rows)<512', entry)
        self.assertLess(entry.index(b'PINNED_CARRIER.seed'), entry.index(b'native.audit('))
        contract.verify_source(root/'held-source', env['map_sha'])
        output = self.area/'native-output'; output.mkdir(mode=0o700)
        image = 'sha256:'+'a'*64
        builds, compare = contract.plans(here, output, image)
        for i, argv in enumerate(builds, 1):
            self.assertEqual(argv[4], str(output/'md4c-provider-inputs/recipe'))
            for name, value in (('--mode','native'), ('--network','none'),
                ('--source-date-epoch','1776685420'), ('--timeout','300'),
                ('--expected-packages',str(here/'expected349.lock')),
                ('--output',str(output/('build-'+str(i))))):
                self.assertEqual(argv[argv.index(name)+1], value)
            self.assertFalse({'--nodeps','--nocheck','--ignorearch'} & set(argv))
        self.assertEqual(len(builds), 2); self.assertEqual(compare[-1], '--require-bytes')
        finisher = contract.module(here/'finish_pair.py', 'md4c_integrated_finisher')
        self.assertEqual(finisher.PACKAGE, 'md4c-0.5.3-1-aarch64.pkg.tar.xz')
        original = contract.module(here/'contract.py', 'md4c_forwarded_legacy_contract')
        self.assertEqual(Path(original.__file__), here/'contract.py')
        self.assertEqual((output/'md4c-provider-inputs/recipe/PKGBUILD').read_bytes(),
                         (RECIPE/'PKGBUILD').read_bytes())
        with self.assertRaises(ValueError): contract.plans(here, output, image)

    def test_actual_recipe_archive_license_and_required_checks_are_frozen(self):
        bodies = P.validate_bundle(self.bundle, self.old)
        self.assertEqual(len(bodies), 9)
        for name in P.RECIPE_FILES:
            self.assertEqual(bodies['recipe/'+name], (RECIPE/name).read_bytes())
        self.assertEqual(P.pin(bodies['recipe/'+P.FIXED['archive']['filename']]),
                         {k:P.FIXED['archive'][k] for k in ('bytes','sha256')})
        self.assertEqual(P.pin(P.license_body(ARCHIVE.read_bytes())),
            {k:json.loads(bodies['recipe-pin.json'])['license'][k] for k in ('bytes','sha256')})
        recipe = bodies['recipe/PKGBUILD']
        self.assertIn(b'for suite in spec regressions', recipe)
        self.assertIn(b'bash "$srcdir/smoke.sh"', recipe)
        self.assertIn(b"depends=('glibc')", recipe)
        self.assertNotIn(b'--nodeps', recipe)
        for marker in (b'652 passed, 0 failed, 0 errored, 0 skipped',
                       b'65 passed, 0 failed, 0 errored, 0 skipped',
                       b'md4c 0.5.3 staged CLI, C API, pkg-config, CMake and SONAME smoke PASS'):
            self.assertIn(marker, bodies['finish_pair.py'])

    def test_new_manual_workflow_keeps_five_inputs_secret_isolation_and_serialization(self):
        text = self.new[P.NEW_WF].decode()
        self.assertEqual(text.count('required: true'), 5)
        self.assertEqual(text.count('${{ secrets.CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY }}'), 1)
        fetch, controller = text.split('- name: Admitted existing-host', 1)
        self.assertIn('CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY', fetch)
        self.assertNotIn('CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY', controller)
        self.assertIn('group: native-arm-llhttp-reference-source', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertIn('name: native-arm-md4c053-reference-source', text)
        for bad in ('apt-get', 'apt install', 'ssh-agent', 'set -x', '--nodeps', '--nocheck'):
            self.assertNotIn(bad, text)
        self.assertEqual(self.new[P.NEW_WF], self.old[P.OLD_WF].replace(
            b'name: native-arm-llhttp-pinned-input-source', b'name: native-arm-md4c053-reference-source').replace(
            b'Admitted existing-host XZ-only llhttp reference pair',
            b'Admitted existing-host XZ-only md4c 0.5.3 provider pair'))

    def test_rehashed_source_bundle_and_before_body_tampering_refuse(self):
        for name in (P.PREFIX+'payload.py', P.PREFIX+'public_evidence.py', P.NEW_WF):
            changed = rehash(dict(self.new, **{name:self.new[name]+b'\n# MODEL drift\n'}))
            with self.subTest(name=name), self.assertRaises(ValueError): P.inverse(changed)
        changed = copy.deepcopy(self.bundle)
        changed['recipe/PKGBUILD'] = P.row(b'MODEL rehashed replacement')
        with self.assertRaises(ValueError): P.assemble(self.old, changed)
        original_pin = json.loads(P.unpack(self.bundle['recipe-pin.json']))
        for forged in (dict(original_pin, origin='OFFICIAL_ALARM_BINARY'),
                       dict(original_pin, extra='MODEL_FORGED_AUTHORITY')):
            changed = copy.deepcopy(self.bundle)
            changed['recipe-pin.json'] = P.row(P.P.encode(forged))
            with self.assertRaises(ValueError): P.assemble(self.old, changed)
        root = self.source(); data = load(root/P.PREFIX/'data.py', 'md4c_drift_data')
        path = root/P.PREFIX/'payload.py'; path.write_bytes(path.read_bytes()+b'\n# MODEL drift\n')
        with self.assertRaises(ValueError): data.source(root, P.pin(self.new['source-map.json'])['sha256'])

    def test_strict_md4c_public_catalog_exports_hold_without_other_package_or_private_reads(self):
        root = self.source(); exporter = load(root/P.PREFIX/'public_evidence.py', 'md4c_source_exporter')
        self.assertEqual(exporter.PACKAGE, 'md4c-0.5.3-1-aarch64')
        self.assertEqual(exporter.MAX_BYTES, 16*1024**2)
        self.assertIn('commands/511.stdout', exporter.PUBLIC_LEAVES)
        self.assertNotIn('commands/512.stdout', exporter.PUBLIC_LEAVES)
        inner = self.area/'owner/volume/work/llhttp-reference-native'; inner.mkdir(parents=True, mode=0o700)
        expected = dict(source='a'*40, ref='refs/heads/codex/MODEL', source_map_sha256='b'*64,
                        run='123', attempt=1, job='pair', nonce='c'*32)
        report = dict(expected, status='HOLD', Root_acceptance=None, hardware='NOT RUN', release='NOT ADMITTED')
        (inner/'report.json').write_bytes(exporter.encode(report)); (inner/'cleanup.json').write_text('{}')
        logs = inner/'build-1/artifacts'; logs.mkdir(parents=True, mode=0o700)
        new_log = 'md4c-0.5.3-1-aarch64-check.log'; (logs/new_log).write_bytes(b'MODEL PUBLIC HOLD')
        old_log = 'cachy-asahi-llhttp-reference-9.3.1-1-aarch64-check.log'
        (logs/old_log).write_bytes(b'MODEL NEVER READ')
        (inner/'private-key').write_bytes(b'MODEL NEVER READ')
        seen = []; leaf = exporter.leaf
        def checked(*args): seen.append(args[1]); return leaf(*args)
        with patch.object(exporter, 'leaf', checked):
            result = exporter.export(inner, inner.parents[2]/'evidence', expected, os.getuid())
        self.assertFalse(result['accepting']); self.assertEqual(result['payload_status'], 'HOLD')
        self.assertIn('build-1/artifacts/'+new_log, seen)
        self.assertNotIn('build-1/artifacts/'+old_log, seen); self.assertNotIn('private-key', seen)
        manifest = json.loads((inner.parents[2]/'evidence/inner-public-manifest.json').read_bytes())
        self.assertFalse(manifest['truncation']); self.assertFalse(manifest['private_trees_read'])

    def test_factory_verifies_physical_source_and_refuses_mode_drift_or_extra_paths(self):
        root = self.source()
        self.assertEqual(P.verify_source(root)['tree'], P.FIXED['factory']['source']['tree'])
        leaf = root/'source-map.json'
        leaf.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'mode 0644'):
            P.verify_source(root)
        leaf.chmod(0o644)
        (root/'unlisted').mkdir()
        with self.assertRaisesRegex(ValueError, 'directory namespace'):
            P.verify_source(root)

    def test_actual_source_unissued_admission_refuses_before_secret_or_actor(self):
        root = self.source(); carrier = load(root/P.PREFIX/'native349_carrier.py', 'md4c_unissued_carrier')
        class ForbiddenEnv(dict):
            def pop(self, *args): raise AssertionError('secret access before Root admission')
        self.assertEqual(carrier.EXPECTED['input_lock_sha256'], P.FIXED['all501']['sha256'])
        self.assertEqual(len(carrier.EXPECTED['files']), 182)
        with patch.object(carrier.platform, 'machine', return_value='aarch64'):
            with self.assertRaises(ValueError):
                carrier.fetch(root, self.area/'fetch', environment=ForbiddenEnv(),
                              runner=lambda *_:self.fail('actor before Root admission'))
        self.assertFalse((self.area/'fetch').exists())


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('Use python -I -B unoptimized')
    unittest.main(verbosity=2)
