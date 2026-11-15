# SPDX-License-Identifier: MIT
"""Static metadata and refusal controls only. No archives, publisher code or makepkg."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reference', HERE / 'reference.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def array(text, name):
    match = re.search(r'^' + name + r'=\((.*?)\)', text, re.M | re.S)
    if not match:
        return []
    return shlex.split(match.group(1), comments=True)


class ReferenceTests(unittest.TestCase):
    def test_recipe_metadata_is_local_only_and_matches_srcinfo(self):
        recipe = (HERE / 'PKGBUILD').read_text()
        subprocess.run(['/usr/bin/bash', '-n', str(HERE / 'PKGBUILD')], check=True)
        info = {}
        for line in (HERE / '.SRCINFO').read_text().splitlines():
            if ' = ' in line:
                key, value = line.strip().split(' = ', 1)
                info.setdefault(key, []).append(value)
        self.assertEqual(info['pkgname'], ['cachy-asahi-rust199-source-reference'])
        for field in ['arch', 'license', 'depends', 'makedepends', 'options', 'source', 'noextract', 'sha256sums']:
            self.assertEqual(array(recipe, field), info[field], field)
        self.assertEqual(info['arch'], ['aarch64'])
        for forbidden in ['provides', 'replaces', 'conflicts', 'install', 'groups']:
            self.assertNotIn(forbidden, info)
            self.assertNotRegex(recipe, r'^' + forbidden + '=', forbidden)
        manifest = r.load(HERE / 'inputs.json')
        source = array(recipe, 'source')
        sums = array(recipe, 'sha256sums')
        self.assertEqual(len(source), len(sums))
        self.assertEqual(set(array(recipe, 'noextract')), set(manifest['archives']))
        for name, expected in zip(source, sums):
            self.assertEqual(Path(name).name, name)
            self.assertNotIn('://', name)
            self.assertTrue(r.is_digest(expected))
            actual = manifest['archives'][name]['sha256'] if name in manifest['archives'] else r.digest(HERE / name)
            self.assertEqual(expected, actual, name)

    def test_pins_derive_from_retained_inputs_and_stage0_only(self):
        root = HERE.parents[2]
        c = root / 'scripts/port/arm-rust-toolchain-inputs/source-closure'
        manifest = r.load(HERE / 'inputs.json')
        previous = r.load(c / 'source-inputs.json')
        stage0 = c / 'build-source-plan/sources/stage0.txt'
        fields = dict(line.split('=', 1) for line in stage0.read_text().splitlines() if '=' in line and not line.startswith('#'))
        self.assertEqual(r.digest(stage0), manifest['provenance']['stage0_metadata_sha256'])
        for name, pin in manifest['archives'].items():
            if pin['role'] == 'source':
                self.assertEqual(pin['sha256'], previous['archives'][name]['checksums']['sha256'])
                self.assertEqual(pin['commit'], previous['archives'][name]['expected_upstream_commit'])
            else:
                key = pin['url'].removeprefix(fields['dist_server'] + '/')
                self.assertEqual(pin['sha256'], fields[key])
                self.assertTrue(key.startswith('dist/2026-08-20/'))
        self.assertEqual(len(manifest['holds']['original_binary_recipe_correspondence']), 4)
        self.assertTrue(all(p['status'] == 'UNRESOLVED' for p in manifest['holds']['original_binary_recipe_correspondence'].values()))

    def test_config_keeps_toolset_and_private_native_external_paths(self):
        import tomllib
        config = tomllib.loads((HERE / 'bootstrap.toml').read_text())
        old = r.load(HERE.parents[2] / 'scripts/port/arm-rust-toolchain-inputs/source-closure/build-source-plan/report.json')
        self.assertEqual(config['build']['tools'], old['effective_config_literal_shell_variables_unexpanded']['build']['tools'])
        self.assertEqual(config['build']['host'], [r.TARGET])
        self.assertEqual(config['build']['target'], [r.TARGET])
        self.assertEqual(config['build']['rustc'], '/stage0/bin/rustc')
        self.assertNotIn('rustfmt', config['build'])
        self.assertFalse(config['build']['submodules'])
        self.assertFalse(config['rust']['download-rustc'])
        self.assertTrue(config['rust']['rpath'])
        self.assertFalse(config['llvm']['download-ci-llvm'])
        self.assertFalse(config['gcc']['download-ci-gcc'])
        self.assertTrue(config['build']['vendor'])
        self.assertTrue(config['build']['locked-deps'])
        self.assertEqual(config['install']['prefix'], str(r.PREFIX))
        self.assertTrue(config['install']['sysconfdir'].startswith(str(r.PREFIX) + '/'))
        self.assertEqual(config['target'][r.TARGET]['llvm-config'], '/usr/bin/llvm-config')

    def test_default_cli_refuses_without_execution_or_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            before = list(Path(directory).iterdir())
            env = {'PATH': '/usr/bin:/bin'}
            result = subprocess.run([os.sys.executable, '-I', str(HERE / 'reference.py'), 'prepare', '--work', directory], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('explicit CACHY_ASAHI_RUST199_BUILD=1 required', result.stderr)
            self.assertEqual(before, list(Path(directory).iterdir()))

    def test_example_admission_is_unqualified_and_digest_binding_is_real(self):
        path = HERE / 'admission.example.json'
        with self.assertRaisesRegex(ValueError, 'unqualified'):
            r.admission(path, r.digest(path), HERE / 'inputs.json')
        with self.assertRaisesRegex(ValueError, 'digest'):
            r.admission(path, 'f' * 64, HERE / 'inputs.json')

    def test_native_qualified_fixture_still_refuses_missing_archive_before_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, image = root / 'work', root / 'image'
            work.mkdir()
            for name in ['work', 'stage0', 'proc', 'dev', 'tmp', 'usr/bin']:
                (image / name).mkdir(parents=True, exist_ok=True)
            for name in ['python', 'gcc', 'g++', 'gcc-ar', 'gcc-ranlib', 'llvm-config', 'clang', 'ld.lld', 'cmake', 'ninja', 'make', 'pkg-config', 'perl', 'bash']:
                (image / 'usr/bin' / name).write_text('TEST DATA: never executed')
            proof = root / 'proof.json'
            proof.write_text('{"fixture": true}\n')
            a = r.load(HERE / 'admission.example.json')
            a['status'] = 'QUALIFIED_FOR_PRIVATE_BUILD_ONLY'
            a['environment'].update(root=str(image), tree_sha256=r.tree_digest(image))
            a['stage0'].update(assembled_tree_sha256='a' * 64, compatibility='QUALIFIED_FOR_THIS_SOURCE')
            a['source_audit'].update(status='REVIEWED_FOR_THIS_PRIVATE_BUILD', library_cargo_config_sha256='b' * 64, consumed_git_dependencies_and_paths_reviewed=True, compiler_rt_libunwind_members_and_notices_reviewed=True, retained_source_authentication_rejoined=True)
            a['qualification_evidence'] = {'path': str(proof), 'sha256': r.digest(proof)}
            path = root / 'admission.json'
            path.write_text(json.dumps(a))
            with patch.dict(os.environ, {'CACHY_ASAHI_RUST199_BUILD': '1'}), patch.object(r.platform, 'machine', return_value='aarch64'), patch.object(r.platform, 'system', return_value='Linux'), patch.object(r.os, 'geteuid', return_value=1000), patch.object(r.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'local material missing'):
                    r.preflight(work, path, r.digest(path))
                run.assert_not_called()
                name = next(iter(r.load(HERE / 'inputs.json')['archives']))
                (root / 'tiny-local-source').write_text('TEST DATA only')
                (work / name).symlink_to(root / 'tiny-local-source')
                with self.assertRaisesRegex(ValueError, 'wrong material (size|digest)'):
                    r.preflight(work, path, r.digest(path))
                run.assert_not_called()
                (image / 'usr/bin/gcc').write_text('changed')
                with self.assertRaisesRegex(ValueError, 'inventory changed'):
                    r.preflight(work, path, r.digest(path))
                run.assert_not_called()

    def test_fakeroot_package_guard_preserves_real_nonroot_requirement(self):
        with patch.object(r.os, 'geteuid', return_value=0), patch.object(Path, 'read_text', return_value='Uid:\t1000\t1000\t1000\t1000\n'):
            self.assertTrue(r.nonroot_user(True))
            self.assertFalse(r.nonroot_user(False))
        with patch.object(r.os, 'geteuid', return_value=0), patch.object(Path, 'read_text', return_value='Uid:\t0\t0\t0\t0\n'):
            self.assertFalse(r.nonroot_user(True))

    def test_tree_inventory_binds_bytes_modes_links_and_refuses_specials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'file'
            file.write_text('one')
            initial = r.tree_digest(root)
            file.write_text('two')
            self.assertNotEqual(initial, r.tree_digest(root))
            initial = r.tree_digest(root)
            file.chmod(0o755)
            self.assertNotEqual(initial, r.tree_digest(root))
            (root / 'link').symlink_to('file')
            initial = r.tree_digest(root)
            (root / 'link').unlink()
            (root / 'link').symlink_to('other')
            self.assertNotEqual(initial, r.tree_digest(root))
            os.mkfifo(root / 'fifo')
            with self.assertRaisesRegex(ValueError, 'special file'):
                r.tree_digest(root)

    def test_cargo_sources_must_end_inside_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            rust = Path(directory) / 'rust'
            config = rust / '.cargo/config.toml'
            config.parent.mkdir(parents=True)
            (rust / 'vendor').mkdir()
            config.write_text('[source.crates-io]\nreplace-with="local"\n[source.local]\ndirectory="vendor"\n')
            r.source_config(config, rust)
            config.write_text('[source.crates-io]\nreplace-with="local"\n[source.local]\ndirectory="../../outside"\n')
            with self.assertRaisesRegex(ValueError, 'escapes or is missing'):
                r.source_config(config, rust)
            config.write_text('[source.crates-io]\nreplace-with="crates-io"\n')
            with self.assertRaisesRegex(ValueError, 'cycle'):
                r.source_config(config, rust)

    def test_vendor_verifies_file_bytes_and_complete_file_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / 'test-1.0.0'
            crate.mkdir()
            (crate / 'Cargo.toml').write_text('[package]\nname="test"\nversion="1.0.0"\n')
            checksums = {'files': {'Cargo.toml': r.digest(crate / 'Cargo.toml')}, 'package': 'c' * 64}
            (crate / '.cargo-checksum.json').write_text(json.dumps(checksums))
            self.assertIn(('test', '1.0.0', 'c' * 64), r.check_vendor(root))
            (crate / 'extra').write_text('unrecorded')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                r.check_vendor(root)
            (crate / 'extra').unlink()
            (crate / 'Cargo.toml').write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                r.check_vendor(root)

    def test_network_sandbox_has_readonly_image_and_stage0_private_homes(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'stage0').mkdir()
            command = r.sandbox_command(work, Path('/test/qualified-image'), ['NOT_EXECUTED'])
            self.assertIn('--unshare-all', command)
            self.assertIn('--clearenv', command)
            self.assertIn(['--ro-bind', '/test/qualified-image', '/'], [command[i:i+3] for i in range(len(command)-2)])
            self.assertIn(['--ro-bind', str(work / 'stage0'), '/stage0'], [command[i:i+3] for i in range(len(command)-2)])
            self.assertIn(['--setenv', 'CARGO_NET_OFFLINE', 'true'], [command[i:i+3] for i in range(len(command)-2)])
            self.assertIn(['--ro-bind', str(work / 'stage0'), '/work/stage0'], [command[i:i+3] for i in range(len(command)-2)])
            self.assertIn('/work/home', command)
            self.assertIn('/work/cargo-home', command)
            self.assertNotIn('/run', command)
            self.assertEqual(command[-1], 'NOT_EXECUTED')

    def test_internal_probe_refuses_without_qualified_inventory(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(r.subprocess, 'check_output') as run:
            with self.assertRaisesRegex(ValueError, 'requires qualified'):
                r.probe()
            run.assert_not_called()

    def test_package_refuses_stale_stage_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            work, destination = base / 'src', base / 'pkg/package'
            (work / 'dest').mkdir(parents=True)
            destination.mkdir(parents=True)
            record = {'admission_sha256': 'c' * 64, 'config_sha256': r.digest(HERE / 'bootstrap.toml'), 'staged_tree_sha256': 'd' * 64}
            (work / 'built.json').write_text(json.dumps(record))
            with patch.dict(os.environ, {'CACHY_ASAHI_RUST199_ADMISSION_SHA256': 'c' * 64}):
                with self.assertRaisesRegex(ValueError, 'built stage changed'):
                    r.package(work, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_stage_rejects_global_payload_and_escaping_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / r.PREFIX.relative_to('/')
            names = ['bin/rustc', 'bin/cargo', 'bin/rustdoc', 'bin/rustfmt', 'bin/clippy-driver', 'libexec/rust-analyzer-proc-macro-srv', 'lib/rustlib/src/rust/library/Cargo.toml']
            for name in names:
                p = prefix / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('TEST DATA only')
                p.chmod(0o755)
            r.check_stage(root)
            (root / 'usr').mkdir()
            with self.assertRaisesRegex(ValueError, 'escaped private prefix'):
                r.check_stage(root)
            (root / 'usr').rmdir()
            (prefix / 'bin/bad').symlink_to('/usr/bin/rustc')
            with self.assertRaisesRegex(ValueError, 'symlink escapes'):
                r.check_stage(root)


if __name__ == '__main__':
    unittest.main()
