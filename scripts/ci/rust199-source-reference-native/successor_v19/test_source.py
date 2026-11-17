# SPDX-License-Identifier: MIT
"""Explicit MODEL construction controls plus genuine Source367 inverse proof.

Synthetic keys/signatures/native records confer no signature or native credit.
Only immutable recipe/source checksum selections are replaced for MODEL fixtures;
all metadata, complete native receipt joins and Source closure checks run normally.
"""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import resource
import shutil
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PARENT = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-rust367-source-r1/closed-source-tree')
sys.dont_write_bytecode = True
ATTEMPTS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event == 'os.system':
        ATTEMPTS.append(event)
        raise AssertionError('SOURCE_DATA_NO_ACTOR: ' + event)


sys.addaudithook(fence)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


P = module('v19_source_constructor_controls', HERE / 'prepare.py')


def model_fixture(A):
    """Reuse trusted DATA fixture definitions without its process-global fence."""
    source = HERE.parent / 'project_test_provider_v1/test_admission.py'
    tree = ast.parse(source.read_bytes())
    constants = {'ELF', 'RECIPE', 'SMOKE', 'LICENSE', 'KEY_BODY', 'KEY', 'SIGNATURE', 'FPR'}
    nodes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Controls'
             or isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets)]
    namespace = dict(A=A, D=A.D, HERE=source.parent, copy=copy, hashlib=hashlib, io=io,
                     Path=Path, tarfile=tarfile, tempfile=tempfile, unittest=unittest,
                     patch=patch, SimpleNamespace=SimpleNamespace, ATTEMPTS=[])
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
    fixture = namespace['Controls'](); fixture.setUp()
    for row in fixture.packages:
        native_pairs(fixture, row)
    fixture.p['packages'] = fixture.packages
    fixture.put('project-test/provider-policy.json', A.encode(fixture.p))
    fixture.put('project-test/Root-provider-decision.json', A.encode(fixture.decision()))
    selection = {key: fixture.put(name, (fixture.root / name).read_bytes()) for key, name in (
        ('policy', 'project-test/provider-policy.json'), ('decision', 'project-test/Root-provider-decision.json'))}
    return fixture, selection


def native_pairs(fixture, row):
    """Complete retained MODEL native pair; original package bytes are never run."""
    A, root = fixture.patch.target, fixture.root
    D = A.D
    name, filename = row['name'], row['filename']
    original = (root / 'build-dependencies' / filename).read_bytes()
    prefix = Path(row['license_provenance']['pkgbuild']['path']).parent
    native = dict(builds=[], comparison={})
    for number in (1, 2):
        folder = root / 'native-evidence' / name / ('build-' + str(number))
        (folder / 'artifacts').mkdir(parents=True)
        for relative in row['license_provenance']['recipe_files']:
            leaf = str(Path(relative).relative_to(prefix)); target = folder / 'inputs' / leaf
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes((root / relative).read_bytes())
        lock = (root / 'expected349.lock').read_bytes()
        for relative in ('build.log', 'expected-packages.lock', 'artifacts/packages.lock', 'artifacts/generated.SRCINFO',
                         'artifacts/environment.txt', 'artifacts/config.sha256', 'artifacts/makepkg.conf', 'artifacts/pacman.conf'):
            (folder / relative).write_bytes(b'MODEL_RETAINED_DATA\n')
        (folder / 'expected-packages.lock').write_bytes(lock); (folder / 'artifacts/packages.lock').write_bytes(lock)
        (folder / 'artifacts/environment.txt').write_bytes(b'Linux MODEL aarch64\n')
        (folder / 'artifacts' / filename).write_bytes(original)
        members = {}
        for relative, pin in row['providers'].items():
            members[relative] = (dict(type='0', mode=pin['mode'], size=pin['bytes'], sha256=pin['sha256']) if pin['kind'] == 'file'
                                 else dict(type='2', mode=pin['mode'], link=pin['target']))
        validation = dict(errors=[], artifacts=[dict(artifact=filename, sha256=row['archive']['sha256'], errors=[], members=members,
            metadata={'.PKGINFO': row['metadata'], '.BUILDINFO': dict(format=['2'], pkgname=[name], pkgver=[row['version']],
                pkgarch=['aarch64'], pkgbuild_sha256sum=[row['license_provenance']['pkgbuild']['sha256']])},
            elf={n: dict(machine=183, errors=[]) for n, pin in row['providers'].items() if pin['kind'] == 'file'})])
        (folder / 'validation.json').write_bytes(D.encode(validation))
        record = dict(schema_version=1, status='built-package-static-pass', exit_code=0, mode='native', builder_host_arch='aarch64',
            image='sha256:' + 'a' * 64, image_id='sha256:' + 'a' * 64, network='none', source_date_epoch=1791748800,
            clean_environment_id='MODEL-' + name + '-clean-' + str(number),
            recipe_inputs={str(Path(n).relative_to(prefix)): v['sha256'] for n, v in row['license_provenance']['recipe_files'].items()},
            recipe_metadata=row['metadata'], expected_packages_sha256=D.pin(lock)['sha256'],
            entry_script_sha256='89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24', artifacts={filename: row['archive']['sha256']})
        record['command'] = ['docker', 'run', '--rm', '--name', record['clean_environment_id'], '--pull=never', '--platform', 'linux/arm64',
            '--user', '1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--pids-limit', '512',
            '--memory', '4g', '--memory-swap', '4g', '--cpus', '4', '--network', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g',
            '--env', 'CACHY_ASAHI_CONTAINER=1', '--env', 'SOURCE_DATE_EPOCH=1791748800',
            '--mount', 'type=bind,src=/MODEL/inputs,dst=/inputs,readonly', '--mount', 'type=bind,src=/MODEL/out,dst=/out',
            '--mount', 'type=bind,src=/MODEL/entry.sh,dst=/builder-entry.sh,readonly',
            '--mount', 'type=bind,src=/MODEL/expected.lock,dst=/expected-packages.lock,readonly', '--entrypoint', '/bin/bash', record['image_id'], '/builder-entry.sh']
        record['files'] = {str(path.relative_to(folder)): D.pin(path.read_bytes())['sha256'] for path in folder.rglob('*')
                           if path.is_file() and not path.is_relative_to(folder / 'inputs')}
        (folder / 'provenance.json').write_bytes(D.encode(record))
        ref = lambda path: dict(path=str(path.relative_to(root)), **D.pin(path.read_bytes()))
        native['builds'].append(dict(provenance=ref(folder / 'provenance.json'), validation=ref(folder / 'validation.json')))
    comparison = dict(status='contents-reproduced', errors=[], packages={filename: dict.fromkeys(
        ('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'), True)})
    path = root / 'native-evidence' / name / 'comparison.json'; path.write_bytes(D.encode(comparison))
    native['comparison'] = dict(path=str(path.relative_to(root)), **D.pin(path.read_bytes()))
    row['native'] = native


class Source(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ.get('RUST199_V19_PARENT', PARENT))
        if not path.exists():
            raise AssertionError('genuine Source367 operand is mandatory; set RUST199_V19_PARENT')
        cls.before = P.capture(path)

    def setUp(self):
        self.f, self.selection = model_fixture(P.A)
        self.addCleanup(self.f.doCleanups)

    def leaves(self):
        return P.payload(self.f.root, self.selection, now=1000)

    def profile(self, leaves):
        return dict(schema=19, scope=P.SCOPE, parent=P.PARENT, actual=P.ACTUAL, Root_review=None, accepted=None,
                    unadmitted=True, constructor_files=P.inputs(), provider_inputs=P.fs.descriptors(P.fs.snapshot(self.f.root)),
                    selection=self.selection, **P.identity(P.render(self.before, leaves)))

    def test_MODEL_complete_admission_native_receipts_and_source_inverse(self):
        new = self.leaves(); after = P.render(self.before, new)
        self.assertEqual(P.undo(after), self.before)
        for name, value in self.before.items():
            if name not in P.REPLACED | {'source-map.json'}:
                self.assertEqual(after[name], value, name)
        census = P.fs.decode(after['source-map.json'][0])
        self.assertEqual(census['files'], P.fs.descriptors({n: v for n, v in after.items() if n != 'source-map.json'}))
        marker = P.fs.decode(after[P.MARKER][0])
        self.assertTrue(marker['unadmitted']); self.assertIsNone(marker['Root_grants']); self.assertIsNone(marker['dispatch'])
        self.assertEqual(marker['actual'], P.ACTUAL)

    def test_whole_genuine367_364_361_355_351_344_340_inverse_and_rerender(self):
        current = self.before
        for version, count in ((17, 364), (16, 361), (15, 355), (14, 351), (13, 344), (12, 340)):
            q = module('v19_genuine_inverse_' + str(version), HERE.parent / ('successor_v' + str(version)) / 'prepare.py')
            previous = current; current = q.undo(previous)
            self.assertEqual(len(current), count); self.assertEqual(q.render(current), previous)

    def test_MODEL_constructor_requires_external_profile_and_publishes_closed_data(self):
        leaves = self.leaves()
        with tempfile.TemporaryDirectory(prefix='v19-constructor-MODEL-') as td:
            base = Path(td); parent = base / 'parent'; P.fs.publish(self.before, parent)
            raw = P.encode(self.profile(leaves)); profile = base / 'profile.DATA.json'; profile.write_bytes(raw)
            with self.assertRaises(ValueError):
                P.construct(parent, self.f.root, base / 'REFUSED', profile, '0' * 64, now=1000)
            self.assertFalse((base / 'REFUSED').exists())
            result = P.construct(parent, self.f.root, base / 'MODEL_SOURCE', profile, P.fs.pin(raw)['sha256'], now=1000)
            after = P.fs.snapshot(base / 'MODEL_SOURCE')
            self.assertEqual(P.undo(after), self.before); self.assertEqual(P.identity(after), P.identity(P.render(self.before, leaves)))
            self.assertTrue(result['unadmitted']); self.assertEqual(result['actual'], P.ACTUAL)
            closed = base / 'MODEL_SOURCE'; bridge = module('v19_emitted_bridge_DATA', closed / P.BRIDGE)
            embedded = bridge.interface(closed)
            self.assertEqual(embedded.ROOT, closed); self.assertTrue(embedded.BASE.is_relative_to(closed))
            self.assertEqual(embedded.pin(embedded.D.read(embedded.HERE / 'recipes.DATA.json')), embedded.SPECS_PIN)
            self.assertEqual(bridge.binding(closed, embedded, lambda: None), P.config(self.selection))
            for helper in ('archive.py', 'native.py', 'image.py'):
                loaded = embedded.module(embedded.HERE / helper)
                self.assertTrue(Path(loaded.__file__).is_relative_to(closed))
                if helper == 'image.py':
                    probes, natural = loaded.qualification_predicates(); self.assertEqual(len(probes), 9)
            # The emitted original interface still refuses MODEL recipe/source pins.
            with self.assertRaisesRegex(ValueError, 'recipe|source'):
                bridge.policy(closed, now=1000)
            self.assertEqual(ATTEMPTS, [])
            with self.assertRaises(ValueError):
                P.construct(parent, self.f.root, base / 'MODEL_SOURCE', profile, P.fs.pin(raw)['sha256'], now=1000)

    def test_changed_map_body_mode_archive_extra_namespace_refuse_inverse(self):
        after = P.render(self.before, self.leaves())
        for name in (P.MARKER, 'source-map.json', P.ARCHIVE + 'hosted/bootstrap.py',
                     'hosted/bootstrap.py', 'hosted/project_provider.py', 'project-test/provider-policy.json'):
            changed = dict(after); raw, mode = changed[name]; changed[name] = (raw + b'CHANGED', mode)
            with self.subTest(name=name), self.assertRaises((ValueError, KeyError)):
                P.undo(changed)
        changed = dict(after); raw, mode = changed['hosted/bootstrap.py']; changed['hosted/bootstrap.py'] = (raw, 0o755)
        with self.assertRaises(ValueError): P.undo(changed)
        with self.assertRaises(ValueError): P.undo(dict(after, EXTRA=(b'MODEL', 0o644)))

    def test_missing_native_signature_license_key_and_baseline_refuse_payload(self):
        row = self.f.packages[0]
        names = [row['native']['builds'][0]['provenance']['path'], 'build-dependencies/' + row['filename'] + '.sig',
                 next(iter(row['license_provenance']['license_files'])), self.f.key['path'], 'expected349.lock']
        for name in names:
            path = self.f.root / name; raw = path.read_bytes(); path.unlink()
            try:
                with self.subTest(name=name), self.assertRaises((ValueError, KeyError, FileNotFoundError)):
                    self.leaves()
            finally: path.write_bytes(raw)

    def test_extra_input_namespace_and_changed_selected_pin_refuse(self):
        path = self.f.root / 'EXTRA'; path.write_bytes(b'MODEL')
        with self.assertRaises(ValueError): self.leaves()
        path.unlink()
        for key in ('policy', 'decision'):
            selected = copy.deepcopy(self.selection); selected[key]['sha256'] = '0' * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                P.payload(self.f.root, selected, now=1000)

    def test_expired_unapproved_and_changed_native_tuple_refuse(self):
        with self.assertRaises(ValueError): P.payload(self.f.root, self.selection, now=1100)
        decision = self.f.decision(); decision['approved'] = False
        self.selection['decision'] = self.f.put('project-test/Root-provider-decision.json', P.A.encode(decision))
        with self.assertRaises(ValueError): self.leaves()
        row = self.f.packages[0]; selected = row['native']['builds'][0]
        name = selected['provenance']['path']; record = P.A.decode((self.f.root / name).read_bytes())
        record['mode'] = 'host'
        selected['provenance'] = self.f.put(name, P.A.encode(record))
        self.selection['policy'] = self.f.put('project-test/provider-policy.json', P.A.encode(self.f.p))
        self.selection['decision'] = self.f.put('project-test/Root-provider-decision.json', P.A.encode(self.f.decision()))
        with self.assertRaisesRegex(ValueError, 'native'):
            self.leaves()

    def test_actual_unbound_inputs_cannot_produce_source(self):
        with tempfile.TemporaryDirectory(prefix='v19-unbound-DATA-') as td:
            root = Path(td); (root / 'expected349.lock').write_bytes(self.before['expected349.lock'][0])
            with self.assertRaises((ValueError, FileNotFoundError, KeyError)):
                P.payload(root, dict(policy=None, decision=None), now=1000)

    def test_profile_cannot_issue_authority_change_closure_or_identity(self):
        leaves = self.leaves(); original = self.profile(leaves)
        with tempfile.TemporaryDirectory(prefix='v19-profile-refusal-MODEL-') as td:
            base = Path(td); parent = base / 'parent'; P.fs.publish(self.before, parent)
            mutations = [lambda p: p.update(accepted=True), lambda p: p['actual'].update(run=1),
                         lambda p: p['constructor_files'].clear(), lambda p: p['provider_inputs'].clear(),
                         lambda p: p.update(tree='0' * 40), lambda p: p.update(map_sha256='0' * 64)]
            for index, change in enumerate(mutations):
                value = copy.deepcopy(original); change(value); raw = P.encode(value)
                profile = base / 'profile.DATA.json'; profile.write_bytes(raw)
                with self.subTest(index=index), self.assertRaises(ValueError):
                    P.construct(parent, self.f.root, base / ('REFUSED-' + str(index)), profile, P.fs.pin(raw)['sha256'], now=1000)
                self.assertFalse((base / ('REFUSED-' + str(index))).exists())

    def test_source_file_count_size_mode_and_alias_caps_refuse(self):
        with tempfile.TemporaryDirectory(prefix='v19-cap-refusal-DATA-') as td:
            root = Path(td)
            for index in range(513): (root / ('file-' + str(index))).write_bytes(b'MODEL')
            with self.assertRaisesRegex(ValueError, 'aliases/special|source node cap'): P.fs.snapshot(root)
            for path in root.iterdir(): path.unlink()
            path = root / 'oversized.DATA'
            with path.open('wb') as stream: stream.truncate(P.fs.MAX_FILE + 1)
            with self.assertRaisesRegex(ValueError, 'bounded regular'): P.fs.snapshot(root)
            path.unlink(); path.write_bytes(b'MODEL'); path.chmod(0o666)
            with self.assertRaisesRegex(ValueError, 'mode'): P.fs.snapshot(root)
            path.chmod(0o644); (root / 'alias.DATA').symlink_to(path.name)
            with self.assertRaisesRegex(ValueError, 'aliases/special'): P.fs.snapshot(root)
        self.assertEqual(P.fs.MAX_FILES, 512); self.assertEqual(P.fs.MAX_FILE, 64 * 1024**2)
        self.assertEqual(P.fs.MAX_TOTAL, 128 * 1024**2); self.assertEqual(ATTEMPTS, [])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
    unittest.main(verbosity=2)
