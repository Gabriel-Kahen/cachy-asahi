# The original build validation contract, applied to the explicit v2 helpers.
import io
import contextlib
import os
import json
import struct
import subprocess
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'checks'))
sys.path.insert(0, str(ROOT / 'scripts' / 'build'))
import package_checks as checks
import dependencies
import compare_v2 as compare
import build_v2 as build
import provision


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def test_compare_cli_resolves_selected_helpers_under_isolation(self):
        marker = self.root / 'ambient-imported'
        (self.root / 'build_v2.py').write_text(
            'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise RuntimeError("ambient helper")\n')
        result = subprocess.run([sys.executable, '-I', '-S', '-B', str(ROOT / 'scripts/build/compare_v2.py'), '--help'],
                                cwd=self.root, env=dict(os.environ, PYTHONPATH=str(self.root)),
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'--require-bytes', result.stdout)
        self.assertFalse(marker.exists())

    def recipe(self, extra=''):
        directory = self.root / 'packages' / 'desktop' / 'nested' / 'example'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'payload').write_text('data')
        (directory / 'PKGBUILD').write_text("pkgname=example\npkgver=1\npkgrel=1\narch=('any')\nlicense=('MIT')\nsource=('payload')\nsha256sums=('" + checks.digest(directory / 'payload') + "')\n" + extra)
        return directory / 'PKGBUILD'

    def archive(self, name='example.pkg.tar.gz', payload=b'data', extra=None, arch='any'):
        path = self.root / name
        entries = {'.PKGINFO': f'pkgname = example\npkgver = 1-1\narch = {arch}\nlicense = MIT\n'.encode(),
                   '.BUILDINFO': ('format = 2\npkgname = example\npkgver = 1-1\npkgarch = ' + arch + '\npkgbuild_sha256sum = ' + 'a' * 64 + '\n').encode(), '.MTREE': b'mtree',
                   'usr/share/example/data': payload}
        entries.update(extra or {})
        with tarfile.open(path, 'w') as archive:
            for key, data in entries.items():
                member = tarfile.TarInfo(key)
                member.size = len(data)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))
        return path

    def evidence(self, name, artifact):
        directory = self.root / name
        (directory / 'artifacts').mkdir(parents=True)
        (directory / 'inputs').mkdir()
        dest = directory / 'artifacts' / artifact.name
        dest.write_bytes(artifact.read_bytes())
        (directory / 'inputs' / 'PKGBUILD').write_text('reviewed')
        recipe_hash = checks.digest(directory / 'inputs' / 'PKGBUILD')
        rewritten = dest.with_suffix('.new')
        with tarfile.open(dest) as source, tarfile.open(rewritten, 'w') as target:
            for member in source:
                content = source.extractfile(member).read() if member.isfile() else b''
                if member.name == '.BUILDINFO':
                    content = content.replace(('a' * 64).encode(), recipe_hash.encode())
                if member.name == '.PKGINFO':
                    content += b'pkgbase = example\n'
                member.size = len(content)
                target.addfile(member, io.BytesIO(content) if member.isfile() else None)
        rewritten.replace(dest)
        for file_name in ('build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                     'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                     'artifacts/makepkg.conf', 'artifacts/pacman.conf'):
            (directory / file_name).write_text('synthetic fixture')
        record = {'status': 'built-package-static-pass', 'image': 'digest', 'image_id': 'id',
                  'mode': 'native', 'clean_environment_id': name, 'source_date_epoch': 1, 'recipe_metadata': {'pkgname': ['example'], 'pkgver': ['1'], 'pkgrel': ['1'], 'arch': ['any'], 'license': ['MIT']},
                  'expected_packages_sha256': 'lock', 'entry_script_sha256': 'entry',
                  'recipe_inputs': {'PKGBUILD': checks.digest(directory / 'inputs' / 'PKGBUILD')},
                  'artifacts': {artifact.name: checks.digest(dest)},
                  'files': {str(p.relative_to(directory)): checks.digest(p) for p in directory.rglob('*')
                            if p.is_file() and not p.is_relative_to(directory / 'inputs')}}
        (directory / 'provenance.json').write_text(json.dumps(record))
        return directory

    def test_recursive_discovery(self):
        path = self.recipe()
        self.assertEqual(checks.discover(self.root), [path])
        self.assertFalse(checks.recipe(path)['errors'])

    def test_static_inspection_never_executes_shell(self):
        sentinel = self.root / 'executed'
        path = self.recipe(f'package() {{ touch {sentinel}; }}\n')
        self.assertFalse(checks.recipe(path)['errors'])
        self.assertFalse(sentinel.exists())
        with path.open('a') as stream:
            stream.write(f'pkgver=$(touch {sentinel})\n')
        with self.assertRaisesRegex(ValueError, 'dynamic'):
            checks.recipe(path)
        self.assertFalse(sentinel.exists())

    def test_local_source_escape_and_tampering(self):
        path = self.recipe()
        (path.parent / 'payload').write_text('modified')
        self.assertIn('checksum mismatch', ' '.join(checks.recipe(path)['errors']))
        path.write_text(path.read_text().replace("source=('payload')", "source=('../payload')"))
        self.assertIn('unsafe/missing', ' '.join(checks.recipe(path)['errors']))

    def test_remote_checksums_and_git_pin(self):
        path = self.recipe()
        text = path.read_text().replace("source=('payload')", "source=('https://example.org/latest.tar')")
        path.write_text(text.replace(checks.digest(path.parent / 'payload'), 'SKIP'))
        self.assertIn('missing fixed', ' '.join(checks.recipe(path)['errors']))
        path.write_text(path.read_text().replace('https://example.org/latest.tar', 'git+https://example.org/repo#branch=main'))
        self.assertIn('unpinned Git', ' '.join(checks.recipe(path)['errors']))

    def test_symlink_input_rejected(self):
        path = self.recipe()
        (path.parent / 'link').symlink_to('/etc/passwd')
        self.assertIn('symlink recipe input', ' '.join(checks.recipe(path)['errors']))

    def test_artifact_metadata_and_no_extraction(self):
        path = self.archive()
        self.assertFalse(checks.package(path)['errors'])
        self.assertFalse((self.root / 'usr').exists())

    def test_archive_traversal_and_duplicate(self):
        path = self.archive(extra={'../outside': b'bad'})
        with self.assertRaisesRegex(ValueError, 'unsafe archive'):
            checks.package(path)
        with tarfile.open(path, 'w') as archive:
            for _ in range(2):
                archive.addfile(tarfile.TarInfo('duplicate'))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            checks.package(path)

    def test_archive_hooks_protected_paths_and_ownership(self):
        path = self.archive(extra={'.INSTALL': b'commands', 'boot/kernel': b'kernel'})
        errors = ' '.join(checks.package(path)['errors'])
        self.assertIn('hook requires', errors)
        self.assertIn('protected platform', errors)
        with tarfile.open(path, 'w') as archive:
            member = tarfile.TarInfo('file')
            member.uid = 1000
            member.mode = 0o4755
            archive.addfile(member)
        errors = ' '.join(checks.package(path)['errors'])
        self.assertIn('non-root', errors)
        self.assertIn('setuid', errors)

    def test_escaping_link_special_member_and_size_limit(self):
        path = self.root / 'bad.tar'
        with tarfile.open(path, 'w') as archive:
            member = tarfile.TarInfo('usr/link')
            member.type = tarfile.SYMTYPE
            member.linkname = '../../outside'
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, 'escaping symlink'):
            checks.package(path)
        with tarfile.open(path, 'w') as archive:
            member = tarfile.TarInfo('device')
            member.type = tarfile.CHRTYPE
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, 'special archive'):
            checks.package(path)
        with patch.object(checks, 'MAX_MEMBER', 1):
            with self.assertRaisesRegex(ValueError, 'oversized'):
                checks.package(self.archive())

    def test_elf_arch_and_16k_alignment(self):
        data = bytearray(120)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 16, 2)
        struct.pack_into('<H', data, 18, 183)
        struct.pack_into('<H', data, 52, 64)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<I', data, 64, 1)
        struct.pack_into('<Q', data, 112, 16384)
        self.assertFalse(checks.elf_check(data)['errors'])
        struct.pack_into('<Q', data, 112, 4096)
        self.assertIn('16K', ' '.join(checks.elf_check(data)['errors']))
        struct.pack_into('<H', data, 18, 62)
        self.assertIn('machine', ' '.join(checks.elf_check(data)['errors']))
        self.assertIn('arch=any', ' '.join(checks.package(self.archive(payload=bytes(data)))['errors']))

    def test_conflicting_package_file(self):
        report = checks.package(self.archive())
        self.assertTrue(checks.conflicts([report, report]))

    def test_comparison_and_tampered_evidence(self):
        artifact = self.archive()
        first, second = self.evidence('first', artifact), self.evidence('second', artifact)
        self.assertEqual(compare.compare(first, second)['status'], 'contents-reproduced')
        with self.assertRaisesRegex(ValueError, 'different evidence'):
            compare.compare(first, first)
        (second / 'artifacts' / artifact.name).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'changed evidence'):
            compare.compare(first, second)

    def test_comparison_content_and_provenance_failure(self):
        first = self.evidence('first', self.archive())
        second = self.evidence('second', self.archive(payload=b'different'))
        self.assertEqual(compare.compare(first, second)['status'], 'fail')
        path = second / 'provenance.json'
        record = json.loads(path.read_text())
        record['image'] = 'other'
        path.write_text(json.dumps(record))
        self.assertIn('input mismatch: image', compare.compare(first, second)['errors'])
        record['status'] = 'failed'
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'has not passed'):
            compare.compare(first, second)

    def test_unpinned_images_rejected(self):
        for value in ('arm:latest', 'arm@sha256:123', 'image;command'):
            with self.assertRaises(Exception):
                build.image_pin(value)
        self.assertEqual(build.image_pin('sha256:' + 'a' * 64), 'sha256:' + 'a' * 64)

    def test_missing_dependencies_and_cycle(self):
        report = checks.recipe(self.recipe())
        report['metadata']['depends'] = ['missing']
        self.assertIn('unresolved', ' '.join(dependencies.resolve([report], [])['errors']))
        report['metadata']['depends'] = ['example']
        self.assertIn('cycle', ' '.join(dependencies.resolve([report], [])['errors']))
        self.assertFalse(dependencies.resolve([report], [{'name': 'example', 'version': '1-1', 'arch': 'aarch64'}])['errors'])

    def test_versioned_provides_and_wrong_arch(self):
        report = checks.recipe(self.recipe())
        report['metadata']['depends'] = ['virtual>=2']
        with patch.object(dependencies.subprocess, 'check_output', return_value='0'):
            result = dependencies.resolve([report], [{'name': 'provider', 'version': '2', 'arch': 'any', 'provides': ['virtual=2']}])
        self.assertFalse(result['errors'])
        result = dependencies.resolve([report], [{'name': 'provider', 'version': '2', 'arch': 'any', 'provides': ['virtual']}])
        self.assertTrue(result['errors'])
        with self.assertRaisesRegex(ValueError, 'invalid aarch64'):
            dependencies.resolve([report], [{'name': 'bad', 'version': '1', 'arch': 'x86_64'}])

    def test_generated_metadata_binding_both_directions(self):
        reviewed = checks.recipe(self.recipe())['metadata']
        generated = dict(reviewed)
        generated['pkgbase'] = ['example']
        build.bind_generated(reviewed, generated)
        for key in ('depends', 'depends_aarch64', 'provides', 'conflicts', 'replaces', 'install'):
            changed = dict(generated)
            changed[key] = ['unexpected']
            with self.assertRaisesRegex(ValueError, 'differs'):
                build.bind_generated(reviewed, changed)
        with self.assertRaisesRegex(ValueError, 'split'):
            build.normalize_metadata(dict(reviewed, pkgname=['first', 'second']))

    def test_final_artifact_binds_version_dependencies_and_recipe(self):
        reviewed = checks.recipe(self.recipe())['metadata']
        report = checks.package(self.archive())
        report['metadata']['.PKGINFO']['pkgbase'] = ['example']
        self.assertFalse(build.bind_artifact(reviewed, report, 'a' * 64))
        for field in ('depend', 'provides', 'conflict', 'replaces', 'pkgver'):
            changed = json.loads(json.dumps(report))
            changed['metadata']['.PKGINFO'][field] = ['unexpected']
            self.assertTrue(build.bind_artifact(reviewed, changed, 'a' * 64))
        self.assertIn('PKGBUILD hash', ' '.join(build.bind_artifact(reviewed, report, 'b' * 64)))
        report['members']['.INSTALL'] = {}
        self.assertIn('installation hook', ' '.join(build.bind_artifact(reviewed, report, 'a' * 64)))

    def test_audio_override_and_link_ancestor_are_blocked(self):
        for path in ('usr/share/pipewire/asahi.conf', 'etc/wireplumber/asahi.conf',
                     'etc/modprobe.d/asahi.conf', 'etc/modules-load.d/asahi.conf',
                     'etc/sysctl.d/asahi.conf', 'usr/lib/systemd/system/speakersafetyd.service'):
            self.assertIn('protected platform', ' '.join(checks.package(self.archive(extra={path: b'override'}))['errors']))
        artifact = self.root / 'link.tar'
        with tarfile.open(artifact, 'w') as archive:
            member = tarfile.TarInfo('usr/share/link')
            member.type = tarfile.SYMTYPE
            member.linkname = '/boot'
            archive.addfile(member)
            archive.addfile(tarfile.TarInfo('usr/share/link/kernel'))
        self.assertIn('non-directory ancestor', ' '.join(checks.package(artifact)['errors']))

    def test_executable_without_load_segments_and_relocatable(self):
        data = bytearray(64)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 16, 2)
        struct.pack_into('<H', data, 18, 183)
        struct.pack_into('<H', data, 52, 64)
        self.assertIn('program headers', ' '.join(checks.elf_check(data)['errors']))
        struct.pack_into('<H', data, 16, 1)
        result = checks.elf_check(data)
        self.assertFalse(result['errors'])
        self.assertEqual(result['page_alignment'], 'not-applicable-relocatable')

    def test_full_build_acceptance_rejects_hidden_metadata_and_wrong_version(self):
        path = self.recipe()
        reviewed = checks.recipe(path)
        reviewed_file = self.root / 'reviewed.json'
        reviewed_file.write_text(json.dumps(reviewed['input_sha256']))
        lock = self.root / 'packages.lock'
        lock.write_text('base-devel 1-1\n')
        image = 'sha256:' + 'c' * 64

        def fake_capture(command):
            if command[1:3] == ['image', 'inspect']:
                return json.dumps([{'Architecture': 'arm64', 'Os': 'linux', 'Id': image}])
            return 'aarch64'

        for scenario in ('valid', 'hidden-dependency', 'wrong-version', 'hidden-provide', 'hidden-install', 'symlink-output', 'missing-evidence', 'invalid-archive', 'timeout'):
            output = self.root / ('build-' + scenario)

            def fake_run(command, **kwargs):
                if command[1:3] == ['rm', '-f']:
                    return subprocess.CompletedProcess(command, 0)
                mount = next(value for value in command if value.startswith('type=bind,src=') and ',dst=/out' in value)
                directory = Path(mount.split('src=', 1)[1].split(',dst=', 1)[0])
                directory.joinpath('packages.lock').write_text(lock.read_text())
                for name in ('environment.txt', 'config.sha256', 'makepkg.conf', 'pacman.conf'):
                    directory.joinpath(name).write_text('synthetic test fixture')
                generated = dict(reviewed['metadata'], pkgbase=['example'])
                if scenario == 'hidden-dependency':
                    generated['depends_aarch64'] = ['unexpected']
                if scenario == 'hidden-install':
                    generated['install'] = ['hook.install']
                directory.joinpath('generated.SRCINFO').write_text(''.join(
                    f'{key} = {value}\n' for key, values in generated.items() for value in values))
                version = '999-1' if scenario == 'wrong-version' else '1-1'
                pkginfo = f'pkgname = example\npkgbase = example\npkgver = {version}\narch = any\nlicense = MIT\n'
                if scenario == 'hidden-provide':
                    pkginfo += 'provides = linux-asahi\n'
                buildinfo = f'format = 2\npkgname = example\npkgver = {version}\npkgarch = any\npkgbuild_sha256sum = {reviewed["input_sha256"]["PKGBUILD"]}\n'
                artifact = self.archive(extra={'.PKGINFO': pkginfo.encode(), '.BUILDINFO': buildinfo.encode()})
                directory.joinpath(artifact.name).write_bytes(artifact.read_bytes())
                if scenario == 'invalid-archive':
                    directory.joinpath(artifact.name).write_bytes(b'not a package archive')
                if scenario == 'missing-evidence':
                    directory.joinpath('environment.txt').unlink()
                if scenario == 'timeout':
                    raise subprocess.TimeoutExpired(command, 1)
                if scenario == 'symlink-output':
                    directory.joinpath('host-path').symlink_to(self.root / 'reviewed.json')
                return subprocess.CompletedProcess(command, 0)

            argv = ['build_v2.py', str(path.parent), '--image', image, '--output', str(output),
                    '--mode', 'native', '--source-date-epoch', '1', '--expected-packages', str(lock),
                    '--reviewed-inputs', str(reviewed_file)]
            with patch.object(sys, 'argv', argv), patch.object(build, 'capture', side_effect=fake_capture), \
                 patch.object(build.subprocess, 'run', side_effect=fake_run) as execution, contextlib.redirect_stderr(io.StringIO()):
                result = build.main()
            record = json.loads((output / 'provenance.json').read_text())
            self.assertEqual(result, 0 if scenario == 'valid' else 1, scenario)
            self.assertEqual(record['status'], 'built-package-static-pass' if scenario == 'valid' else 'failed', scenario)
            if scenario == 'timeout':
                cleanup = [call.args[0] for call in execution.call_args_list if call.args[0][1:3] == ['rm', '-f']]
                self.assertEqual(cleanup, [['docker', 'rm', '-f', record['clean_environment_id']]])

    def test_copied_evidence_does_not_count_as_second_execution(self):
        first = self.evidence('first', self.archive())
        second = self.root / 'copied'
        shutil.copytree(first, second)
        self.assertIn('different recorded clean container IDs required', compare.compare(first, second)['errors'])

    def test_provision_context_only_and_missing_signature(self):
        cache = self.root / 'cache'
        cache.mkdir()
        package = cache / 'dependency-1-1-any.pkg.tar.zst'
        signature = cache / (package.name + '.sig')
        package.write_bytes(b'synthetic archive for context-only test')
        signature.write_bytes(b'synthetic signature; not trusted')
        checksums = self.root / 'cache.json'
        checksums.write_text(json.dumps({p.name: checks.digest(p) for p in (package, signature)}))
        output = self.root / 'context'
        argv = ['provision.py', '--base-image', 'registry.example/arm@sha256:' + 'a' * 64,
                '--cache', str(cache), '--checksums', str(checksums), '--output', str(output)]
        with patch.object(sys, 'argv', argv), patch.object(provision, 'capture') as captured, \
             patch.object(provision.subprocess, 'run') as executed, patch('builtins.print'):
            self.assertEqual(provision.main(), 0)
            captured.assert_not_called()
            executed.assert_not_called()
        self.assertEqual(json.loads((output / 'provision.json').read_text())['status'], 'context-only')
        self.assertIn('LocalFileSigLevel = Required', (output / 'offline-pacman.conf').read_text())
        checksums.write_text(json.dumps({package.name: checks.digest(package)}))
        argv[-1] = str(self.root / 'missing-sig-context')
        with patch.object(sys, 'argv', argv), patch('builtins.print'):
            self.assertEqual(provision.main(), 1)
        self.assertFalse((self.root / 'missing-sig-context').exists())

    def test_special_recipe_inputs_and_empty_discovery_fail(self):
        path = self.recipe()
        os.mkfifo(path.parent / 'pipe')
        self.assertIn('special recipe input', ' '.join(checks.recipe(path)['errors']))
        empty = self.root / 'empty'
        empty.mkdir()
        with patch.object(sys, 'argv', ['checks.py', 'recipes', '--root', str(empty)]), patch('builtins.print'):
            self.assertEqual(checks.main(), 1)

    def test_protected_package_relations_rejected(self):
        path = self.recipe("provides=('linux-asahi')\n")
        self.assertIn('protected platform package relation', ' '.join(checks.recipe(path)['errors']))
        artifact = self.archive(extra={'.PKGINFO': b'pkgname = example\npkgver = 1-1\narch = any\nlicense = MIT\nprovides = linux-asahi\n'})
        self.assertIn('protected platform package relation', ' '.join(checks.package(artifact)['errors']))

    def test_native_label_and_image_architecture_fail_before_execution(self):
        path = self.recipe()
        reviewed_file = self.root / 'reviewed.json'
        reviewed_file.write_text(json.dumps(checks.recipe(path)['input_sha256']))
        lock = self.root / 'packages.lock'
        lock.write_text('base-devel 1-1\n')
        image = 'sha256:' + 'c' * 64
        for host_arch, image_arch in (('x86_64', 'arm64'), ('aarch64', 'amd64')):
            out = self.root / (host_arch + '-' + image_arch)
            argv = ['build_v2.py', str(path.parent), '--image', image, '--output', str(out),
                    '--mode', 'native', '--source-date-epoch', '1', '--expected-packages', str(lock),
                    '--reviewed-inputs', str(reviewed_file)]
            def fake_capture(command):
                return json.dumps([{'Architecture': image_arch, 'Os': 'linux', 'Id': image}]) if command[1:3] == ['image', 'inspect'] else host_arch
            with patch.object(sys, 'argv', argv), patch.object(build, 'capture', side_effect=fake_capture), \
                 patch.object(build.subprocess, 'run') as executed, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(build.main(), 1)
                executed.assert_not_called()
            self.assertFalse(out.exists())

    def test_symlinked_metadata_never_reads_external_target(self):
        path = self.recipe()
        external = self.root / 'private.txt'
        external.write_text('secret that must never be parsed as metadata')
        (path.parent / '.SRCINFO').symlink_to(external)
        self.assertIn('symlink recipe input', ' '.join(checks.recipe(path)['errors']))
        (path.parent / '.SRCINFO').unlink()
        path.unlink()
        path.symlink_to(external)
        self.assertIn('symlink recipe input', ' '.join(checks.recipe(path)['errors']))

    def test_aarch64_only_sources_and_dependencies(self):
        path = self.recipe("depends_aarch64=('arm-runtime')\n")
        path.write_text(path.read_text().replace('source=', 'source_aarch64=').replace('sha256sums=', 'sha256sums_aarch64='))
        report = checks.recipe(path)
        self.assertFalse(report['errors'])
        self.assertIn('arm-runtime', ' '.join(dependencies.resolve([report], [])['errors']))
        self.assertFalse(dependencies.resolve([report], [{'name': 'arm-runtime', 'version': '1', 'arch': 'aarch64'}])['errors'])

    def test_aarch64_provider_and_conflict_participate_in_resolution(self):
        report = checks.recipe(self.recipe("provides_aarch64=('arm-virtual')\nconflicts_aarch64=('old-runtime')\n"))
        inventory = [{'name': 'old-runtime', 'version': '1', 'arch': 'aarch64'}]
        self.assertIn('conflicts', ' '.join(dependencies.resolve([report], inventory)['errors']))
        consumer = {'metadata': {'pkgname': ['consumer'], 'pkgver': ['1'], 'pkgrel': ['1'], 'depends_aarch64': ['arm-virtual']}}
        del report['metadata']['conflicts_aarch64']
        self.assertEqual(dependencies.resolve([consumer, report], [])['build_order'], ['example', 'consumer'])

    def test_provision_mixed_original_archive_formats_preserve_signed_bytes(self):
        cache = self.root / 'signed-cache'
        cache.mkdir()
        expected, original = {}, {}
        for suffix in ('.zst', '.xz', '.gz'):
            name = 'dependency-' + suffix[1:] + '-1-1-aarch64.pkg.tar' + suffix
            for filename, data in ((name, ('original signed archive ' + suffix).encode()),
                                   (name + '.sig', ('detached signature ' + suffix).encode())):
                (cache / filename).write_bytes(data)
                original[filename] = data
                expected[filename] = checks.digest(cache / filename)
        checksums = self.root / 'signed-cache.json'
        checksums.write_text(json.dumps(expected))
        output = self.root / 'mixed-context'
        argv = ['provision.py', '--base-image', 'registry.example/arm@sha256:' + 'a' * 64,
                '--cache', str(cache), '--checksums', str(checksums), '--output', str(output)]
        with patch.object(sys, 'argv', argv), patch.object(provision, 'capture') as captured, \
             patch.object(provision.subprocess, 'run') as executed, patch('builtins.print'):
            self.assertEqual(provision.main(), 0)
            captured.assert_not_called()
            executed.assert_not_called()
        dockerfile = (output / 'Dockerfile').read_text()
        for name, data in original.items():
            self.assertEqual((output / 'deps' / name).read_bytes(), data)
            self.assertEqual(checks.digest(output / 'deps' / name), expected[name])
            if not name.endswith('.sig'):
                self.assertIn('/tmp/deps/' + name, dockerfile)
            else:
                self.assertNotIn('/tmp/deps/' + name, dockerfile)
        self.assertNotIn('*.pkg.tar.', dockerfile)
        self.assertEqual(json.loads((output / 'provision.json').read_text())['cache_sha256'], expected)
        xz_name = next(name for name in expected if name.endswith('.pkg.tar.xz'))
        (cache / xz_name).write_bytes(b'changed archive bytes')
        rejected = self.root / 'tampered-xz-context'
        argv[-1] = str(rejected)
        with patch.object(sys, 'argv', argv), patch('builtins.print'):
            self.assertEqual(provision.main(), 1)
        self.assertFalse(rejected.exists())

    def test_provision_rejects_unsupported_or_mismatched_signature_formats(self):
        cache = self.root / 'invalid-cache'
        cache.mkdir()
        checksums = self.root / 'invalid-cache.json'
        cases = [('unsupported.pkg.tar.bz2', 'unsupported.pkg.tar.bz2.sig'),
                 ('archive.pkg.tar.xz', 'archive.pkg.tar.gz.sig'),
                 ('unsafe name.pkg.tar.xz', 'unsafe name.pkg.tar.xz.sig')]
        for index, names in enumerate(cases):
            expected = {}
            for name in names:
                (cache / name).write_bytes(b'unchanged synthetic signed bytes')
                expected[name] = checks.digest(cache / name)
            checksums.write_text(json.dumps(expected))
            output = self.root / ('invalid-context-' + str(index))
            argv = ['provision.py', '--base-image', 'registry.example/arm@sha256:' + 'a' * 64,
                    '--cache', str(cache), '--checksums', str(checksums), '--output', str(output)]
            with patch.object(sys, 'argv', argv), patch('builtins.print'):
                self.assertEqual(provision.main(), 1)
            self.assertFalse(output.exists())

    def srcinfo_comparison(self, reviewed, generated):
        # Execute only the trusted read-only comparison function, never the
        # container entry or any recipe body on the host.
        source = (ROOT / 'scripts/build/container-entry-v2.sh').read_text()
        start = source.index('compare_srcinfo() {')
        end = source.index('\n}', start) + len('\n}')
        self.assertIn('compare_srcinfo .SRCINFO /out/generated.SRCINFO', source)
        first, second = self.root / 'reviewed.SRCINFO', self.root / 'generated.SRCINFO'
        first.write_text(reviewed)
        second.write_text(generated)
        function = source[start:end] + '\ncompare_srcinfo "$1" "$2"\n'
        return subprocess.run(['bash', '-c', function, 'comparison-test', str(first), str(second)],
                              capture_output=True, text=True)

    def test_srcinfo_introductory_comments_and_blank_lines_are_only_normalization(self):
        generated = 'pkgbase = example\n\tdepends = runtime>=1\n\tsource = source.tar\npkgname = example\n'
        reviewed = '# Reviewed metadata; not executable\n\n' + generated.replace('\tpkg', '\n\tpkg') + '  # trailing full-line comment\n\n'
        self.assertEqual(self.srcinfo_comparison(reviewed, generated).returncode, 0)
        for changed in (generated.replace('runtime>=1', 'runtime>=2'),
                        generated + '\tdepends_aarch64 = unexpected\n',
                        generated + '\tinstall = hook.install\n',
                        generated.replace('\tdepends = runtime>=1\n\tsource = source.tar\n',
                                          '\tsource = source.tar\n\tdepends = runtime>=1\n'),
                        generated.replace('source.tar', 'source.tar # inline comment')):
            self.assertNotEqual(self.srcinfo_comparison(reviewed, changed).returncode, 0)

    def test_srcinfo_comparison_missing_input_never_passes(self):
        source = (ROOT / 'scripts/build/container-entry-v2.sh').read_text()
        start = source.index('compare_srcinfo() {')
        end = source.index('\n}', start) + len('\n}')
        result = subprocess.run(['bash', '-c', source[start:end] + '\ncompare_srcinfo "$1" "$2"\n',
                                 'comparison-test', str(self.root / 'missing-a'), str(self.root / 'missing-b')],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
