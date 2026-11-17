# SPDX-License-Identifier: MIT
"""Explicit MODEL native receipts; no archive/signature/native authority claim."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ATTEMPTS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in ('os.system', 'fcntl.flock'):
        ATTEMPTS.append(event)
        raise AssertionError('MODEL_NATIVE_EVIDENCE_NO_ACTOR: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('project_native_controls', HERE / 'native.py')
N = importlib.util.module_from_spec(spec); spec.loader.exec_module(N)
D = N.D
PACKAGE = b'MODEL_ARCHIVE_BYTES_ONLY_NOT_A_PACKAGE_OR_NATIVE_RESULT'
RECIPE = b'# MODEL never source or execute\npkgname=cachy-asahi-libgit2-reference\n'
BODY = b'MODEL_PROVIDER_BYTES_NOT_LOADED'


class Fixture:
    def __init__(self, root):
        self.root = root
        name = 'cachy-asahi-libgit2-reference'; filename = name + '-1.9.7-1-aarch64.pkg.tar.xz'
        prefix = 'dependency-provenance/' + name + '/'
        self.row = dict(name=name, version='1:1.9.7-1', filename=filename, archive=D.pin(PACKAGE),
            metadata=dict(pkgname=[name], pkgver=['1:1.9.7-1'], arch=['aarch64'], license=['LicenseRef-libgit2'],
                          depend=['glibc', 'llhttp=9.3.1'], provides=['libgit2=1:1.9.7'], conflict=['libgit2'], replaces=[]),
            providers={'usr/lib/libgit2.so.1.9.7': dict(kind='file', mode=0o755, **D.pin(BODY)),
                       'usr/lib/libgit2.so': dict(kind='symlink', mode=0o777, target='libgit2.so.1.9.7')},
            license_provenance=dict(pkgbuild=dict(path=prefix + 'PKGBUILD', **D.pin(RECIPE)),
                recipe_files={prefix + 'PKGBUILD': D.pin(RECIPE), prefix + 'nested/receipt.DATA': D.pin(b'MODEL_RECIPE_DATA')}))
        inventory = D.inventory((HERE.parent / 'successor_v18/fixtures/parent350.ACTUAL367.lock').read_bytes())
        inventory['cachy-asahi-llhttp-reference'] = '9.3.1-1'
        lock = ''.join(k + ' ' + v + '\n' for k, v in sorted(inventory.items())).encode()
        self.records = []; self.row['native'] = dict(builds=[], comparison={})
        for number in (1, 2):
            folder = root / ('build-' + str(number)); (folder / 'artifacts').mkdir(parents=True)
            (folder / 'inputs/nested').mkdir(parents=True)
            (folder / 'inputs/PKGBUILD').write_bytes(RECIPE)
            (folder / 'inputs/nested/receipt.DATA').write_bytes(b'MODEL_RECIPE_DATA')
            record = dict(schema_version=1, status='built-package-static-pass', exit_code=0, mode='native',
                builder_host_arch='aarch64', image='sha256:' + 'a' * 64, image_id='sha256:' + 'a' * 64,
                network='none', source_date_epoch=1791748800, clean_environment_id='MODEL-clean-native-' + str(number),
                recipe_inputs={'PKGBUILD': D.pin(RECIPE)['sha256'], 'nested/receipt.DATA': D.pin(b'MODEL_RECIPE_DATA')['sha256']},
                recipe_metadata={'pkgname': [name], 'arch': ['aarch64'], 'depends': ['glibc', 'llhttp=9.3.1']},
                expected_packages_sha256=D.pin(lock)['sha256'], entry_script_sha256=sorted(N.ENTRY)[0],
                artifacts={filename: D.pin(PACKAGE)['sha256']})
            record['command'] = ['docker', 'run', '--rm', '--name', record['clean_environment_id'], '--pull=never',
                '--platform', 'linux/arm64', '--user', '1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--read-only', '--pids-limit', '512', '--memory', '4g', '--memory-swap', '4g', '--cpus', '4',
                '--network', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g',
                '--env', 'CACHY_ASAHI_CONTAINER=1', '--env', 'SOURCE_DATE_EPOCH=1791748800',
                '--mount', 'type=bind,src=/MODEL/inputs,dst=/inputs,readonly',
                '--mount', 'type=bind,src=/MODEL/out,dst=/out',
                '--mount', 'type=bind,src=/MODEL/entry.sh,dst=/builder-entry.sh,readonly',
                '--mount', 'type=bind,src=/MODEL/expected.lock,dst=/expected-packages.lock,readonly',
                '--entrypoint', '/bin/bash', record['image_id'], '/builder-entry.sh']
            for relative in N.REQUIRED:
                (folder / relative).write_bytes(b'MODEL_RETAINED_DATA\n')
            (folder / 'expected-packages.lock').write_bytes(lock); (folder / 'artifacts/packages.lock').write_bytes(lock)
            (folder / 'artifacts/environment.txt').write_bytes(b'Linux MODEL aarch64\n')
            (folder / 'artifacts' / filename).write_bytes(PACKAGE)
            members = {'usr/lib/libgit2.so.1.9.7': dict(type='0', mode=0o755, size=len(BODY), sha256=D.pin(BODY)['sha256']),
                       'usr/lib/libgit2.so': dict(type='2', mode=0o777, link='libgit2.so.1.9.7')}
            validation = dict(errors=[], artifacts=[dict(artifact=filename, sha256=D.pin(PACKAGE)['sha256'], errors=[], members=members,
                metadata={'.PKGINFO': self.row['metadata'], '.BUILDINFO': dict(format=['2'], pkgname=[name], pkgver=['1:1.9.7-1'], pkgarch=['aarch64'], pkgbuild_sha256sum=[D.pin(RECIPE)['sha256']])},
                elf={'usr/lib/libgit2.so.1.9.7': dict(machine=183, errors=[], hardware_status='NOT RUN')})])
            (folder / 'validation.json').write_bytes(D.encode(validation))
            self.records.append(record); self.row['native']['builds'].append({}); self.refresh(number - 1)
        flags = dict.fromkeys(('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'), True)
        self.comparison = dict(status='contents-reproduced', errors=[], packages={filename: flags}, hardware_status='NOT RUN')
        self.save_comparison()

    def reference(self, path):
        return dict(path=str(path.relative_to(self.root)), **D.pin(path.read_bytes()))

    def refresh(self, index):
        folder = self.root / ('build-' + str(index + 1)); record = self.records[index]
        record['files'] = {str(path.relative_to(folder)): D.pin(path.read_bytes())['sha256']
            for path in folder.rglob('*') if path.is_file() and path.name != 'provenance.json' and not path.is_relative_to(folder / 'inputs')}
        (folder / 'provenance.json').write_bytes(D.encode(record))
        self.row['native']['builds'][index] = dict(provenance=self.reference(folder / 'provenance.json'), validation=self.reference(folder / 'validation.json'))

    def save_comparison(self):
        path = self.root / 'comparison.json'; path.write_bytes(D.encode(self.comparison))
        self.row['native']['comparison'] = self.reference(path)

    def validate(self):
        return N.validate(self.root, self.row)


class NativeEvidence(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='project-native-evidence-MODEL-'); self.addCleanup(temporary.cleanup)
        self.f = Fixture(Path(temporary.name))

    def test_complete_model_join_preserves_all_native_and_root_holds(self):
        proof = self.f.validate()
        self.assertFalse(proof['native_acceptance']); self.assertIsNone(proof['Root_acceptance'])
        self.assertEqual(proof['archive'], self.f.row['archive'])
        self.assertEqual(proof['inventory'], D.pin((self.f.root / 'build-1/expected-packages.lock').read_bytes()))

    def test_host_emulation_noninteger_exit_and_wrong_image_refuse_after_rehash(self):
        original = copy.deepcopy(self.f.records[0])
        for changes in (dict(mode='emulated'), dict(builder_host_arch='x86_64'), dict(exit_code=False), dict(image_id='sha256:' + 'b' * 64)):
            self.f.records[0] = dict(original, **changes); self.f.refresh(0)
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.f.validate()

    def test_missing_native_pair_same_clean_run_and_partial_evidence_refuse(self):
        original = copy.deepcopy(self.f.row['native'])
        self.f.row['native']['builds'].pop()
        with self.assertRaises(ValueError): self.f.validate()
        self.f.row['native'] = original
        self.f.records[1]['clean_environment_id'] = self.f.records[0]['clean_environment_id']; self.f.refresh(1)
        with self.assertRaises(ValueError): self.f.validate()
        self.f.records[1]['clean_environment_id'] = 'MODEL-clean-native-2'; self.f.refresh(1)
        (self.f.root / 'build-1/artifacts/packages.lock').unlink(); self.f.refresh(0)
        with self.assertRaisesRegex(ValueError, 'complete retained'): self.f.validate()

    def test_inventory_environment_and_archive_substitution_never_qualify(self):
        for relative in ('artifacts/packages.lock', 'artifacts/environment.txt', 'artifacts/' + self.f.row['filename']):
            path = self.f.root / 'build-1' / relative; before = path.read_bytes(); path.write_bytes(b'OTHER_BYTES\n'); self.f.refresh(0)
            with self.subTest(relative=relative), self.assertRaises(ValueError): self.f.validate()
            path.write_bytes(before); self.f.refresh(0)

    def test_complete_recipe_snapshot_cannot_be_silently_subset_or_aliased(self):
        self.f.records[0]['recipe_inputs'].pop('nested/receipt.DATA'); self.f.refresh(0)
        with self.assertRaisesRegex(ValueError, 'complete recipe inputs'): self.f.validate()
        self.f.records[0]['recipe_inputs']['nested/receipt.DATA'] = D.pin(b'MODEL_RECIPE_DATA')['sha256']; self.f.refresh(0)
        path = self.f.root / 'build-1/inputs/nested/receipt.DATA'; path.unlink(); path.symlink_to('../PKGBUILD')
        with self.assertRaisesRegex(ValueError, 'ordinary absolute'): self.f.validate()

    def test_unlisted_recipe_and_additional_package_artifact_refuse(self):
        source = self.f.root / 'build-1/inputs/UNLISTED'; source.write_bytes(b'UNREVIEWED')
        with self.assertRaisesRegex(ValueError, 'unlisted recipe'): self.f.validate()
        source.unlink()
        extra = self.f.root / 'build-1/artifacts/other-1-1-aarch64.pkg.tar.xz'; extra.write_bytes(b'OTHER')
        with self.assertRaisesRegex(ValueError, 'unexpected native package'): self.f.validate()

    def test_nodeps_unknown_entry_and_unbounded_argv_refuse(self):
        original = copy.deepcopy(self.f.records[0])
        for changes in ('nodeps', 'entry', 'memory', 'privileged', 'environment', 'writable-input'):
            self.f.records[0] = copy.deepcopy(original)
            if changes == 'nodeps': self.f.records[0]['command'].insert(2, '--nodeps')
            elif changes == 'entry': self.f.records[0]['entry_script_sha256'] = 'f' * 64
            elif changes == 'memory': self.f.records[0]['command'][self.f.records[0]['command'].index('--memory') + 1] = '8g'
            elif changes == 'privileged': self.f.records[0]['command'].insert(2, '--privileged')
            elif changes == 'environment': self.f.records[0]['command'][2:2] = ['--env', 'LD_PRELOAD=/UNSELECTED']
            else:
                argv = self.f.records[0]['command']; index = next(i for i, v in enumerate(argv) if v.endswith('dst=/inputs,readonly'))
                argv[index] = argv[index].removesuffix(',readonly')
            self.f.refresh(0)
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.f.validate()

    def test_rehashed_static_report_provider_mode_architecture_and_buildinfo_refuse(self):
        path = self.f.root / 'build-1/validation.json'; original = D.decode(path.read_bytes())
        for mutate in (lambda v:v['artifacts'][0]['members']['usr/lib/libgit2.so.1.9.7'].update(mode=0o644),
                       lambda v:v['artifacts'][0]['elf']['usr/lib/libgit2.so.1.9.7'].update(machine=62),
                       lambda v:v['artifacts'][0]['metadata']['.BUILDINFO'].update(pkgbuild_sha256sum=['f' * 64])):
            value = copy.deepcopy(original); mutate(value); path.write_bytes(D.encode(value)); self.f.refresh(0)
            with self.assertRaises(ValueError): self.f.validate()

    def test_strict_comparator_flags_and_whole_selected_receipt_bytes_refuse(self):
        for key in ('bytes_equal', 'buildinfo_equal', 'installed_contents_equal'):
            flags = self.f.comparison['packages'][self.f.row['filename']]; flags[key] = False; self.f.save_comparison()
            with self.assertRaises(ValueError): self.f.validate()
            flags[key] = True
        self.f.save_comparison(); (self.f.root / 'comparison.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'whole original receipt'): self.f.validate()

    def test_cancel_and_actor_fence_are_not_waived(self):
        def cancel(): raise ValueError('MODEL cancellation')
        with self.assertRaisesRegex(ValueError, 'cancellation'): N.validate(self.f.root, self.f.row, cancel)
        self.assertEqual(ATTEMPTS, [])


if __name__ == '__main__': unittest.main(verbosity=2)
