#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline synthetic archive/batch tests; no native build or installation claims."""
import copy
import fcntl
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('build_outputs.py')
loader = importlib.util.spec_from_file_location('build_outputs', SCRIPT)
m = importlib.util.module_from_spec(loader)
loader.loader.exec_module(m)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.spec = dict(schema_version=1, purpose='local-build-output-candidate', synthetic=True,
                         input={}, batches=[], pairs=[dict(package='alpha', first='first', second='second')])
        self.batches = {}
        for index, bid in enumerate(('first', 'second'), 1):
            path = root / bid
            path.mkdir()
            (path / '.lock').touch()
            output = path / 'alpha/attempt-001/build'
            (output / 'inputs').mkdir(parents=True)
            (output / 'artifacts').mkdir()
            recipe = output / 'inputs'
            (recipe / 'payload').write_text('synthetic fixture, never built\n')
            (recipe / 'PKGBUILD').write_text("pkgname=alpha\npkgver=1\npkgrel=1\narch=('aarch64')\nlicense=('MIT')\ndepends=('fixture-base>=1')\nsource=('payload')\nsha256sums=('" + m.digest(recipe / 'payload') + "')\npackage() { :; }\n")
            (recipe / '.SRCINFO').write_text('pkgname = alpha\npkgver = 1\npkgrel = 1\narch = aarch64\nlicense = MIT\ndepends = fixture-base>=1\nsource = payload\nsha256sums = ' + m.digest(recipe / 'payload') + '\n')
            reviewed = m.BUILD.recipe(recipe / 'PKGBUILD')
            metadata = reviewed['metadata']
            inputs = reviewed['input_sha256']
            lock = b'fixture-base 1-1\n'
            for name, raw in {'build.log': b'SYNTHETIC FIXTURE ONLY\n', 'validation.json': b'{"errors": []}\n',
                    'expected-packages.lock': lock, 'artifacts/packages.lock': lock,
                    'artifacts/generated.SRCINFO': ''.join(f'{k} = {v}\n' for k, vs in metadata.items() for v in vs).encode(),
                    'artifacts/environment.txt': b'SYNTHETIC\n', 'artifacts/config.sha256': b'SYNTHETIC\n',
                    'artifacts/makepkg.conf': b'SYNTHETIC\n', 'artifacts/pacman.conf': b'SYNTHETIC\n'}.items():
                (output / name).write_bytes(raw)
            filename = 'alpha-1-1-aarch64.pkg.tar.xz'
            self.archive(output / 'artifacts' / filename, inputs['PKGBUILD'])
            record = dict(schema_version=1, status='built-package-static-pass', exit_code=0,
                mode='native', builder_host_arch='aarch64', image='sha256:' + 'a' * 64,
                image_id='sha256:' + 'a' * 64, network='none', source_date_epoch=0,
                clean_environment_id='cachy-asahi-' + str(index) * 16,
                recipe_inputs=inputs, recipe_metadata=metadata, expected_packages_sha256=m.sha(lock),
                entry_script_sha256='b' * 64, artifacts={filename: m.digest(output / 'artifacts' / filename)})
            record['files'] = {str(p.relative_to(output)): m.digest(p) for p in output.rglob('*') if p.is_file() and not p.is_relative_to(recipe)}
            (output / 'provenance.json').write_bytes(m.encoded(record))
            (output.parent / 'reviewed_inputs.reviewed').write_bytes(m.encoded(inputs))
            (output.parent / 'expected_packages.reviewed').write_bytes(lock)
            task = dict(package='alpha', mode='native', image=record['image'], recipe_inputs=inputs,
                source_date_epoch=0, expected_packages_sha256=m.sha(lock), reviewed_inputs_sha256=m.sha(m.encoded(inputs)))
            admission = dict(schema_version=1, status='ADMISSION_ONLY_NOT_BUILT', input_sha256='',
                planned_packages=['alpha'], tasks=dict(alpha=task), max_attempts=3, global_holds=[],
                implementation={str(m.ROOT / 'scripts/build/container-entry.sh'): record['entry_script_sha256']},
                groups=[dict(id='g1', held=False, packages=['alpha'])])
            state = dict(schema_version=1, status='COMPLETE', kind='PINNED_OCI_BUILD_PY',
                admission_sha256='', packages=dict(alpha=dict(status='SUCCESS', attempts=[dict(status='SUCCESS',
                    exit_code=0, output='alpha/attempt-001/build', artifact_sha256=record['artifacts'][filename], files=m.snapshot(output))])))
            self.batches[bid] = dict(path=path, output=output, record=record, admission=admission, state=state)
            self.spec['batches'].append(dict(id=bid, path=str(path), admission_sha256='', state_sha256=''))
        self.source = dict(schema_version=1, packages=[dict(name='alpha', version='1-1', arch='aarch64', depend=['fixture-base>=1'], provides=[])],
            sources=[dict(id='alpha-src', recipe_sha256=inputs['PKGBUILD'], sources=[dict(url='payload', sha256=inputs['payload'])])],
            build_dependencies=[dict(package='alpha', source_id='alpha-src', makedepend=[], checkdepend=[])])
        self.spec_path = root / 'selection.json'

    @staticmethod
    def archive(path, recipe_hash, change=None, duplicate=False, unsafe=False):
        pkg = dict(pkgname=['alpha'], pkgbase=['alpha'], pkgver=['1-1'], arch=['aarch64'], license=['MIT'], depend=['fixture-base>=1'])
        build = dict(format=['2'], pkgname=['alpha'], pkgver=['1-1'], pkgarch=['aarch64'],
                     pkgbuild_sha256sum=[recipe_hash], installed=['fixture-base-1-1-aarch64'])
        if change:
            target, key, values = change
            (pkg if target == 'pkg' else build)[key] = values
        def metadata(data):
            return ''.join(f'{k} = {v}\n' for k, vs in data.items() for v in vs).encode()
        rows = [('.PKGINFO', metadata(pkg)), ('.BUILDINFO', metadata(build)), ('.MTREE', b'fixture mtree\n'),
                ('usr/share/alpha/payload', b'SYNTHETIC ARCHIVE ONLY\n')]
        if duplicate:
            rows.append(rows[0])
        if unsafe:
            rows.append(('../escape', b'forbidden'))
        with tarfile.open(path, 'w:xz') as archive:
            for name, raw in rows:
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(raw))

    def refresh_record(self, bid):
        b = self.batches[bid]; out = b['output']; record = b['record']
        for name in record['artifacts']:
            record['artifacts'][name] = m.digest(out / 'artifacts' / name)
        record['files'] = {name: m.digest(out / name) for name in record['files']}
        (out / 'provenance.json').write_bytes(m.encoded(record))
        attempt = b['state']['packages']['alpha']['attempts'][-1]
        attempt.update(files=m.snapshot(out), artifact_sha256=next(iter(record['artifacts'].values())))

    def write(self):
        input_path = self.root / 'input.json'
        input_path.write_bytes(m.encoded(self.source))
        self.spec['input'] = dict(path=str(input_path), sha256=m.digest(input_path))
        for row in self.spec['batches']:
            b = self.batches[row['id']]
            b['admission']['input_sha256'] = self.spec['input']['sha256']
            admission = m.encoded(b['admission'])
            row['admission_sha256'] = m.sha(admission)
            b['state']['admission_sha256'] = row['admission_sha256']
            (b['path'] / 'admission.json').write_bytes(admission)
            (b['path'] / '.build-batch-owner').write_text(row['admission_sha256'] + '\n')
            (b['path'] / 'state.json').write_bytes(m.encoded(b['state']))
            row['state_sha256'] = m.digest(b['path'] / 'state.json')
        self.spec_path.write_bytes(m.encoded(self.spec))

    def candidate(self):
        self.write()
        return m.candidate(self.spec_path, m.digest(self.spec_path))


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='build-outputs-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.f = Fixture(self.root)

    def reject(self, message):
        with self.assertRaisesRegex(ValueError, message):
            self.f.candidate()

    def archive_change(self, **kwargs):
        b = self.f.batches['second']
        path = b['output'] / 'artifacts' / next(iter(b['record']['artifacts']))
        self.f.archive(path, b['record']['recipe_inputs']['PKGBUILD'], **kwargs)
        self.f.refresh_record('second')

    def test_complete_pair_deterministic_content_addressed_cli(self):
        first = self.f.candidate()
        self.assertEqual(first, self.f.candidate())
        self.assertEqual(first['status'], 'SYNTHETIC_LOCAL_CANDIDATE')
        self.assertFalse(first['full_overlay_accepted'])
        self.assertFalse(first['authenticated'])
        self.assertTrue(first['packages'][0]['bytes_equal'])
        output = self.root / 'candidates'; output.mkdir()
        path = m.store(first, output)
        self.assertEqual(path, m.store(first, output))
        self.assertEqual(path.stem, m.digest(path))
        with self.assertRaisesRegex(ValueError, 'overlaps retained batch'):
            m.store(first, self.f.batches['first']['path'])
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), 'candidate', '--spec', str(self.f.spec_path),
            '--spec-sha256', m.digest(self.f.spec_path), '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['sha256'], path.stem)

    def test_partial_failed_held_unrun_interrupted_batches_refused(self):
        original = copy.deepcopy(self.f.batches['second']['state'])
        for status in ('FAILED', 'HELD', 'BLOCKED', 'PENDING', 'ACTIVE', 'INTERRUPTED'):
            with self.subTest(status=status):
                state = self.f.batches['second']['state'] = copy.deepcopy(original)
                state['status'] = 'INCOMPLETE'
                state['packages']['alpha']['status'] = status
                self.reject('incomplete batch')
        self.f.batches['second']['state'] = original

    def test_complete_label_cannot_hide_failed_task(self):
        self.f.batches['first']['state']['packages']['alpha']['status'] = 'FAILED'
        self.reject('incomplete batch')

    def test_same_environment_copied_pair_refused(self):
        self.f.batches['second']['record']['clean_environment_id'] = self.f.batches['first']['record']['clean_environment_id']
        self.f.refresh_record('second')
        self.reject('distinct clean environment')

    def test_same_batch_pair_refused(self):
        self.f.spec['pairs'][0]['second'] = 'first'
        self.reject('different selected batches')

    def test_duplicate_pair_refused(self):
        self.f.spec['pairs'].append(copy.deepcopy(self.f.spec['pairs'][0]))
        self.reject('duplicate/unknown pair')

    def test_duplicate_batch_id_and_path_refused(self):
        self.f.spec['batches'].append(copy.deepcopy(self.f.spec['batches'][0]))
        self.reject('duplicate batch ID')
        self.f.spec['batches'].pop()
        self.f.spec['batches'][1]['path'] = self.f.spec['batches'][0]['path']
        # Selected hashes now disagree with the first batch; either check refuses.
        self.reject('selected input checksum mismatch|duplicate batch directory')

    def test_arch_version_runtime_dependency_recipe_and_build_lock_mismatch(self):
        for change in (('pkg', 'arch', ['any']), ('pkg', 'pkgver', ['2-1']),
                       ('pkg', 'depend', ['different-dependency']),
                       ('build', 'pkgbuild_sha256sum', ['0' * 64]),
                       ('build', 'installed', ['fixture-base-2-1-aarch64'])):
            with self.subTest(change=change):
                self.archive_change(change=change)
                self.reject('archive inspection|archive differs|dependency inventory')

    def test_corrupt_archive_even_when_resealed(self):
        b = self.f.batches['second']
        (b['output'] / 'artifacts' / next(iter(b['record']['artifacts']))).write_bytes(b'not a tar archive')
        self.f.refresh_record('second')
        self.reject('archive inspection failed')

    def test_missing_archive(self):
        b = self.f.batches['second']
        (b['output'] / 'artifacts' / next(iter(b['record']['artifacts']))).unlink()
        self.reject('snapshot changed')

    def test_unexpected_archive_even_when_snapshot_resealed(self):
        b = self.f.batches['second']
        shutil.copyfile(b['output'] / 'artifacts' / next(iter(b['record']['artifacts'])), b['output'] / 'artifacts/extra.pkg.tar.xz')
        self.f.refresh_record('second')
        self.reject('unexpected/missing archive')

    def test_duplicate_member_and_escaping_archive(self):
        for kwargs in (dict(duplicate=True), dict(unsafe=True)):
            self.archive_change(**kwargs)
            self.reject('archive inspection failed')

    def test_source_version_arch_dependency_pin_correspondence(self):
        source = copy.deepcopy(self.f.source)
        for section, key, value in (('packages', 'version', '2-1'), ('packages', 'arch', 'any'),
                ('packages', 'depend', ['missing']), ('sources', 'recipe_sha256', 'c' * 64)):
            self.f.source = copy.deepcopy(source)
            self.f.source[section][0][key] = value
            self.reject('source package identity|source dependency|source recipe hash')

    def test_source_descriptor_mismatch(self):
        self.f.source['sources'][0]['sources'][0]['sha256'] = 'c' * 64
        self.reject('source descriptor mismatch')

    def test_byte_difference_even_with_valid_metadata(self):
        b = self.f.batches['second']
        path = b['output'] / 'artifacts' / next(iter(b['record']['artifacts']))
        # Legal xz stream padding changes archive bytes without changing members.
        path.write_bytes(path.read_bytes() + b'\x00' * 4)
        self.f.refresh_record('second')
        self.reject('independent rebuild bytes differ')

    def test_image_lock_epoch_task_mismatch(self):
        task = self.f.batches['second']['admission']['tasks']['alpha']
        for key, value in (('image', 'sha256:' + 'c' * 64), ('source_date_epoch', 1), ('expected_packages_sha256', 'c' * 64)):
            original = task[key]; task[key] = value
            self.reject('task/build identity mismatch')
            task[key] = original

    def test_resume_uses_latest_success_and_retains_failure(self):
        b = self.f.batches['second']
        old = b['output'].parent
        new = old.with_name('attempt-002')
        old.rename(new); b['output'] = new / 'build'
        success = b['state']['packages']['alpha']['attempts'][0]
        success['output'] = 'alpha/attempt-002/build'
        b['state']['packages']['alpha']['attempts'].insert(0, dict(status='FAILED', exit_code=1,
            output='alpha/attempt-001/build', error='synthetic earlier failure'))
        result = self.f.candidate()
        self.assertEqual([r['status'] for r in result['packages'][0]['rebuilds'][1]['attempts']], ['FAILED', 'SUCCESS'])
        success['status'] = 'RUNNING'
        self.reject('unresolved/duplicate successful')

    def test_active_batch_lock_refused(self):
        self.f.write()
        with (self.f.batches['first']['path'] / '.lock').open('rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.reject('still owned')

    def test_symlink_build_input_refused(self):
        out = self.f.batches['second']['output']
        p = out / 'inputs/payload'; p.unlink(); p.symlink_to(self.f.batches['first']['output'] / 'inputs/payload')
        self.reject('symlink evidence')

    def test_fake_builder_kind_refused(self):
        self.f.batches['first']['state']['kind'] = 'HOST_FAKE_PROCESSES_NOT_OCI_NOT_ARM'
        self.reject('production batch evidence')

    def test_omitted_pair_and_uncovered_tasks_refused(self):
        self.f.spec['pairs'] = []
        self.reject('finite rebuild pair')
        self.f.spec['pairs'] = [dict(package='alpha', first='first', second='second')]
        b = self.f.batches['first']
        b['admission']['planned_packages'].append('unrun')
        self.reject('task coverage mismatch')

    def test_pair_coverage_cannot_silently_omit_other_successful_tasks(self):
        b = self.f.batches['first']
        b['admission']['planned_packages'].append('beta')
        b['admission']['tasks']['beta'] = dict(b['admission']['tasks']['alpha'], package='beta')
        b['state']['packages']['beta'] = copy.deepcopy(b['state']['packages']['alpha'])
        b['state']['packages']['beta']['attempts'][0]['output'] = 'beta/attempt-001/build'
        self.reject('pair coverage omits completed tasks')

    def test_changed_admitted_entry_script_refused(self):
        b = self.f.batches['first']
        b['admission']['implementation'][str(m.ROOT / 'scripts/build/container-entry.sh')] = 'c' * 64
        self.reject('admitted container entry identity mismatch')

    def test_selected_hash_duplicate_json_and_no_write_on_refusal(self):
        self.f.write()
        with self.assertRaisesRegex(ValueError, 'selected input checksum'):
            m.candidate(self.f.spec_path, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'JSON object required'):
            m.decode(b'[]')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            m.decode(b'{"schema_version":1,"schema_version":1}')
        self.f.batches['first']['state']['status'] = 'INCOMPLETE'
        self.f.write()
        output = self.root / 'empty'; output.mkdir()
        code = m.main(['candidate', '--spec', str(self.f.spec_path), '--spec-sha256', m.digest(self.f.spec_path), '--output', str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(list(output.iterdir()), [])


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--exercise':
        path = Path(sys.argv[2]).absolute()
        path.mkdir(exist_ok=False)
        fixture = Fixture(path)
        value = fixture.candidate()
        (path / 'candidates').mkdir()
        output = m.store(value, path / 'candidates')
        print(json.dumps(dict(synthetic=True, status=value['status'], candidate=str(output)), sort_keys=True))
    else:
        unittest.main()
