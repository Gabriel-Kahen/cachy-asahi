#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source controls and optional real pinned-source host plumbing checks.

Set CACHY_ASAHI_ZLIB_SOURCE to enable source/host checks, and
CACHY_ASAHI_ZLIB_PACKAGES for a complete context-freeze check. Host binaries use
host ISA explicitly; this suite cannot award native ARM/install/M2 credit.
"""
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import package_variants as p

ROOT = Path(__file__).resolve().parents[2]
SOURCE = os.environ.get('CACHY_ASAHI_ZLIB_SOURCE')
PACKAGES = os.environ.get('CACHY_ASAHI_ZLIB_PACKAGES')


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def copy_source(self):
        target = self.root / 'root'
        shutil.copytree(ROOT / p.PACKAGE_ROOT, target / p.PACKAGE_ROOT)
        (target / p.HELPER).parent.mkdir(parents=True)
        shutil.copyfile(ROOT / p.HELPER, target / p.HELPER)
        return target

    def makefile(self, variant='baseline'):
        c, ld = p.flags(variant)
        return (f'CC=gcc\nAR=gcc-ar\nRANLIB=gcc-ranlib\nCFLAGS={c} -fPIC -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN\n'
                f'LDFLAGS={ld}\nprefix = {p.prefix(variant)}\n').encode()

    def archive(self, mutate=lambda rows: rows):
        own = p.prefix('baseline').relative_to('/').as_posix()
        payload = {own + '/' + f: b'fixture' for f in ('bin/minigzip', 'bin/probe', 'bin/strict-gzip', 'lib/libz.a',
                   'include/zlib.h', 'include/zconf.h', 'build/Makefile', 'source/zlib-1.3.2.tar.gz',
                   'source/probe.c', 'source/strict-gzip.c', 'source/LICENSE.project', 'source/PKGBUILD')}
        payload.update({'usr/share/licenses/' + p.name('baseline') + '/' + f: b'fixture'
                        for f in ('LICENSE.zlib', 'LICENSE.project')})
        payload.update({f: b'fixture' for f in p.META})
        payload['.PKGINFO'] = b'pkgname = cachy-asahi-zlib-baseline\npkgver = 1.3.2-1\narch = aarch64\ndepend = glibc\n'
        rows = []
        for path, data in payload.items():
            entry = tarfile.TarInfo(path); entry.size = len(data)
            entry.mode = 0o755 if '/bin/' in path else 0o644
            rows.append((entry, data))
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:xz') as archive:
            for entry, data in mutate(rows):
                archive.addfile(entry, io.BytesIO(data))
        return stream.getvalue()

    def test_source_audit_and_shell_syntax(self):
        self.assertEqual(set(p.audit(ROOT)), set(p.VARIANTS))
        for v in p.VARIANTS:
            subprocess.run(['bash', '-n', str(ROOT / p.PACKAGE_ROOT / p.name(v) / 'PKGBUILD')], check=True)

    def test_recipe_pin_tamper_refused(self):
        root = self.copy_source()
        path = root / p.PACKAGE_ROOT / p.name('baseline') / 'probe.c'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'source pins'):
            p.audit(root)

    def test_flag_drift_refused(self):
        root = self.copy_source()
        path = root / p.PACKAGE_ROOT / p.name('lto') / 'PKGBUILD'
        path.write_text(path.read_text().replace('-O2 ', '-O3 '))
        with self.assertRaisesRegex(ValueError, 'flags'):
            p.audit(root)

    def test_only_lto_setting_changes(self):
        base, base_ld = p.flags('baseline'); lto, lto_ld = p.flags('lto')
        self.assertEqual(base.removesuffix(' -fno-lto'), lto.removesuffix(' -flto=2 -Werror=lto-type-mismatch'))
        self.assertEqual(base_ld.removesuffix(' -fno-lto'), lto_ld.removesuffix(' -flto=2'))
        self.assertIn('-march=armv8-a -mtune=generic', base)
        with self.assertRaises(ValueError):
            p.flags('m2')

    def test_actual_configured_flags(self):
        for v in p.VARIANTS:
            self.assertEqual(p.configured_flags(self.makefile(v), v)['AR'], 'gcc-ar')

    def test_extra_arch_or_tool_or_duplicate_configured_assignment_refused(self):
        for old, new in ((b'-fPIC', b'-fPIC -mcpu=native'), (b'AR=gcc-ar', b'AR=ar'),
                         (b'-mtune=generic', b'-mtune=native'), (b'CC=gcc', b'CC=gcc\nCC=gcc')):
            with self.subTest(new=new), self.assertRaises(ValueError):
                p.configured_flags(self.makefile().replace(old, new), 'baseline')

    def test_unscoped_replacement_metadata_refused(self):
        root = self.copy_source()
        path = root / p.PACKAGE_ROOT / p.name('baseline') / 'PKGBUILD'
        path.write_text(path.read_text() + '\nprovides=(zlib)\n')
        with self.assertRaisesRegex(ValueError, 'replacement'):
            p.audit(root)

    def test_recipe_direct_compile_link_uses_local_archive_and_target_seed(self):
        for v in p.VARIANTS:
            work = self.root / v; (work / 'zlib-1.3.2').mkdir(parents=True)
            configure = work / 'zlib-1.3.2/configure'
            configure.write_text('#!/bin/sh\nexit 0\n'); configure.chmod(0o755)
            calls = work / 'calls'; calls.mkdir()
            script = ('source "$1"; srcdir="$2"; record="$3"; count=0; '
                      'make() { :; }; gcc() { printf "%s\\0" "$@" > "$record/$count"; ((count+=1)); }; build')
            subprocess.run(['bash', '-e', '-c', script, 'fixture',
                            str(ROOT / p.PACKAGE_ROOT / p.name(v) / 'PKGBUILD'), str(work), str(calls)], check=True)
            argv = [(calls / str(i)).read_bytes().decode().split('\0')[:-1] for i in range(4)]
            self.assertIn('-frandom-seed=probe.o', argv[0])
            self.assertIn('-frandom-seed=strict-gzip.o', argv[2])
            self.assertIn('-DEXPERIMENT_PREFIX="' + str(p.prefix(v)) + '"', argv[0])
            for invocation in (argv[1], argv[3]):
                self.assertIn('./libz.a', invocation)
                self.assertNotIn('-lz', invocation)
                self.assertIn('-fno-lto' if v == 'baseline' else '-flto=2', invocation)

    def test_bounded_regular_inputs(self):
        path = self.root / 'real'; path.write_bytes(b'a')
        alias = self.root / 'alias'; alias.symlink_to(path)
        with self.assertRaises(ValueError):
            p.read(alias)
        with self.assertRaises(ValueError):
            p.read(path, 0)

    def test_package_allowlist_accepts_complete_regular_payload(self):
        with patch.object(p, 'source_material'):
            rows = p.package_members(self.archive(), 'baseline')
        self.assertEqual(len(rows), 17)

    def test_package_system_file_traversal_link_device_or_duplicate_refused(self):
        for kind in ('system', 'traversal', 'symlink', 'device', 'duplicate'):
            def mutate(rows):
                if kind == 'duplicate':
                    return rows + [rows[0]]
                entry, data = rows[0]
                if kind == 'system': entry.name = 'usr/lib/libz.so.1'
                if kind == 'traversal': entry.name = '../escape'
                if kind == 'symlink': entry.type = tarfile.SYMTYPE; entry.linkname = '/usr/lib/libz.so'
                if kind == 'device': entry.type = tarfile.CHRTYPE
                return rows
            with self.subTest(kind=kind), patch.object(p, 'source_material'), self.assertRaises(ValueError):
                p.package_members(self.archive(mutate), 'baseline')

    def test_missing_payload_or_wrong_owner_or_mode_refused(self):
        for kind in ('missing', 'owner', 'mode'):
            def mutate(rows):
                if kind == 'missing': return rows[1:]
                if kind == 'owner': rows[0][0].uid = 1000
                if kind == 'mode': rows[0][0].mode = 0o4755
                return rows
            with self.subTest(kind=kind), patch.object(p, 'source_material'), self.assertRaises(ValueError):
                p.package_members(self.archive(mutate), 'baseline')

    def test_package_metadata_cannot_replace_system_zlib(self):
        def mutate(rows):
            for entry, data in rows:
                if entry.name == '.PKGINFO':
                    data += b'provides = zlib\n'; entry.size = len(data)
                yield entry, data
        with patch.object(p, 'source_material'), self.assertRaises(ValueError):
            p.package_members(self.archive(mutate), 'baseline')

    def test_non_native_job_refuses_before_mutation(self):
        with patch.object(p.platform, 'machine', return_value='x86_64'), self.assertRaisesRegex(ValueError, 'native ARM'):
            p.native_job(self.root / 'missing', 'a' * 64, self.root / 'out')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_command_failure_and_timeout_are_retained(self):
        runner = p.Commands(self.root, seconds=10)
        with self.assertRaises(ValueError):
            runner.run('failure', ['python3', '-B', '-c', 'raise SystemExit(7)'])
        with self.assertRaises(subprocess.TimeoutExpired):
            runner.run('timeout', ['python3', '-B', '-c', 'import time; time.sleep(5)'], timeout=0.05)
        rows = json.loads((self.root / 'commands.json').read_text())
        self.assertEqual([r['status'] for r in rows], ['FAIL', 'FAIL'])
        self.assertEqual(rows[0]['exit'], 7)
        self.assertIsNone(runner.active)

    def test_command_combined_output_cap_includes_appended_stdout(self):
        runner = p.Commands(self.root)
        for extra in (0, 1):
            argv = [sys.executable, '-B', '-c',
                    'import sys; sys.stderr.buffer.write(b"x" * (16 * 1024**2 - 1));'
                    f'sys.stdout.buffer.write(b"x" * {1 + extra})']
            if extra:
                with self.assertRaisesRegex(ValueError, 'output bound'):
                    runner.run('build-over', argv)
            else:
                self.assertEqual(runner.run('build-limit', argv), b'x')
        self.assertEqual([row['status'] for row in runner.rows], ['PASS', 'FAIL'])
        self.assertEqual((self.root / runner.rows[0]['log']).stat().st_size, 16 * 1024**2)
        self.assertLessEqual((self.root / runner.rows[1]['log']).stat().st_size, 16 * 1024**2)

    def test_command_excess_stdout_or_stderr_fails_before_retaining_it(self):
        with patch.object(p, 'STDOUT_LIMIT', 32), patch.object(p, 'LOG_LIMIT', 64):
            runner = p.Commands(self.root)
            for stream, size in (('stdout', 33), ('stderr', 65)):
                with self.subTest(stream=stream), self.assertRaisesRegex(ValueError, 'output bound'):
                    runner.run(stream, [sys.executable, '-B', '-c',
                                       f'import sys; sys.{stream}.buffer.write(b"x" * {size})'])
        for row in runner.rows:
            self.assertEqual(row['status'], 'FAIL')
            self.assertLessEqual((self.root / row['log']).stat().st_size, 64)

    def test_command_cancel_during_pass_receipt_rewrites_failure(self):
        runner = p.Commands(self.root)
        original_save = p.save

        def save_then_cancel(path, rows):
            original_save(path, rows)
            if rows[0]['status'] == 'PASS':
                runner.cancel()

        with patch.object(p, 'save', side_effect=save_then_cancel), self.assertRaises(KeyboardInterrupt):
            runner.run('cancelled', [sys.executable, '-B', '-c', 'pass'])
        row, = json.loads((self.root / 'commands.json').read_bytes())
        self.assertEqual((row['status'], row['cancelled']), ('FAIL', True))
        self.assertIsNone(runner.active)

    def test_native_job_cancel_during_final_pass_save_returns_failure(self):
        context, output, work = [self.root / name for name in ('inputs', 'out', 'work')]
        context.mkdir()
        output.mkdir()
        names = p.VARIANTS
        variants = {p.name(v): v for v in names}
        prefixes = {v: self.root / v for v in names}
        inventory = {}
        payload = {}
        paths = {'/inputs': context, '/out': output}
        for name in ('/.dockerenv', '/usr/lib/libz.so.1', '/usr/lib/libc.so.6', '/usr/bin/pacman', '/etc/pacman.conf'):
            paths[name] = self.root / Path(name).name
            paths[name].write_bytes(b'fixture')
        paths['/builder-disabled-hooks'] = self.root / 'hooks'
        paths['/builder-disabled-hooks'].mkdir()
        (context / 'packages.lock').write_bytes(b'')
        for variant in names:
            recipe = context / p.PACKAGE_ROOT / p.name(variant)
            recipe.mkdir(parents=True)
            for name in (*p.FILES, 'zlib-1.3.2.tar.gz'):
                (recipe / name).write_bytes(b'pkgrel=1\n')
            own = prefixes[variant].relative_to('/').as_posix()
            payload[variant] = {own + '/source/' + name: b'pkgrel=1\n' for name in p.FILES}
            payload[variant][own + '/source/zlib-1.3.2.tar.gz'] = b'fixture'
            payload[variant][own + '/build/Makefile'] = b'fixture'
            payload[variant]['usr/share/licenses/' + p.name(variant) + '/LICENSE.zlib'] = b'notice'

        def members(raw, variant):
            result = dict(payload[variant])
            key = prefixes[variant].relative_to('/').as_posix() + '/source/PKGBUILD'
            if raw == b'pkgrel=2\n':
                result[key] = raw
            return result

        def fixture_run(label, argv, **kwargs):
            if label.startswith('build-'):
                variant = label.split('-')[1]
                recipe = (work / 'PKGBUILD').read_bytes()
                release = 2 if recipe == b'pkgrel=2\n' else 1
                (work / f'{p.name(variant)}-1.3.2-{release}-aarch64.pkg.tar.xz').write_bytes(recipe)
                src = work / 'src/zlib-1.3.2'
                src.mkdir(parents=True)
                for name in ('Makefile', 'configure.log'):
                    (src / name).touch()
            if label.startswith('elf-'):
                return b'AArch64 libc.so\n LOAD 0x0 0x0 R 0x4000\n'
            if label.startswith('sections-lto-'):
                return b'.gnu.lto_'
            if label.startswith('pacman-'):
                if '-R' in argv:
                    for name in argv[argv.index('-R') + 1:]:
                        inventory.pop(name)
                        prefixes[variants[name]].rmdir()
                else:
                    for archive in map(Path, argv[argv.index('-U') + 1:]):
                        name = p.name(archive.name.split('-')[0])
                        inventory[name] = '1.3.2-' + archive.name.split('-')[1][1:]
                        prefixes[variants[name]].mkdir(exist_ok=True)
            return b''

        original_read, original_save = p.read, p.save

        def fixture_read(path, *args):
            for name, version in inventory.items():
                variant = variants[name]
                installed = members(b'pkgrel=2\n' if version.endswith('-2') else b'', variant)
                if str(path)[1:] in installed:
                    return installed[str(path)[1:]]
            return original_read(path, *args)

        def save_then_cancel(path, data):
            original_save(path, data)
            if data['status'] == 'PASS':
                signal.raise_signal(signal.SIGTERM)

        runner = p.Commands(output)
        runner.run = Mock(side_effect=fixture_run)
        handlers = [signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)]
        with patch.object(p, 'Path', side_effect=lambda value, *parts: paths.get(str(value), Path(value, *parts))), \
             patch.object(p, 'WORK', work), patch.object(p, 'prefix', side_effect=prefixes.__getitem__), \
             patch.object(p.platform, 'machine', return_value='aarch64'), patch.object(p.os, 'getuid', return_value=0), \
             patch.object(p.os, 'geteuid', return_value=0), patch.object(p.os, 'chown'), \
             patch.dict(p.os.environ, {'CACHY_ASAHI_DISPOSABLE_ZLIB': '1'}), \
             patch.object(p.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)), \
             patch.object(p, 'verify_context', return_value={'base_commit': 'b' * 40}), \
             patch.object(p, 'Commands', return_value=runner), patch.object(p, 'inventory', side_effect=lambda *_: dict(inventory)), \
             patch.object(p, 'read', side_effect=fixture_read), patch.object(p, 'package_members', side_effect=members), \
             patch.object(p, 'source_material', return_value={'LICENSE': b'notice'}), patch.object(p, 'configured_flags', return_value={}), \
             patch.object(p, 'workload', return_value={}), patch.object(p, 'save', side_effect=save_then_cancel), \
             patch.object(p.subprocess, 'Popen', side_effect=AssertionError('actors forbidden')):
            status = p.native_job(context, 'a' * 64, output)

        result = json.loads((output / 'result.json').read_bytes())
        self.assertEqual(len(result['phases']), 8, result.get('error'))
        self.assertEqual((status, result['status'], result['installed_behavior'], result.get('cancelled')),
                         (1, 'FAIL', 'FAIL', True))
        self.assertEqual([signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)], handlers)

    def test_command_expected_rejection_and_preexisting_cancel(self):
        runner = p.Commands(self.root)
        runner.run('reject', ['python3', '-B', '-c', 'raise SystemExit(2)'], expected=2)
        with self.assertRaises(KeyboardInterrupt): runner.cancel()
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            runner.run('late', ['true'])
        self.assertEqual(len(runner.rows), 1)

    @unittest.skipUnless(SOURCE and PACKAGES, 'retained source and 341-package lock are optional external fixtures')
    def test_real_context_and_tamper_refusal(self):
        root = self.copy_source()
        output = self.root / 'context'
        p.prepare(root, Path(SOURCE), Path(PACKAGES), output, '1' * 40)
        pin = p.sha(p.read(output / 'context.json'))
        self.assertEqual(p.verify_context(output, pin)['native_build'], 'NOT RUN')
        (output / p.PACKAGE_ROOT / p.name('lto') / 'probe.c').write_text('tampered')
        with self.assertRaisesRegex(ValueError, 'drift'):
            p.verify_context(output, pin)

    @unittest.skipUnless(SOURCE, 'retained pinned source is an optional external fixture')
    def test_real_source_and_wrong_pin_refusal(self):
        data = p.read(SOURCE)
        self.assertIn(b'zlib', p.source_material(data)['README'])
        with self.assertRaisesRegex(ValueError, 'pin'):
            p.source_material(data[:-1])


@unittest.skipUnless(SOURCE and all(shutil.which(t) for t in ('gcc', 'make', 'gcc-ar', 'gcc-ranlib')),
                     'optional real pinned-source host fixture requires source and build tools')
class HostPlumbing(unittest.TestCase):
    def test_actual_host_pinned_library_tools_workload_and_wrong_prefix(self):
        # Explicit HOST fixture: strip only ARM ISA flags, build private upstream twice;
        # no makepkg, ALPM installation, target architecture or performance evidence.
        data = p.read(SOURCE); p.source_material(data)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); roots = {}
            out = root / 'logs'; out.mkdir(); runner = p.Commands(out, seconds=120)
            for v in p.VARIANTS:
                work = root / v; work.mkdir()
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                    archive.extractall(work, filter='data')
                src = work / 'zlib-1.3.2'
                cflags, ldflags = p.flags(v)
                cflags = cflags.replace(' -march=armv8-a -mtune=generic', '')
                env = {**os.environ, 'CC': 'gcc', 'AR': 'gcc-ar', 'RANLIB': 'gcc-ranlib', 'CFLAGS': cflags,
                       'LDFLAGS': ldflags, 'QEMU_RUN': '', 'SOURCE_DATE_EPOCH': p.EPOCH}
                runner.run('build-' + v + '-configure', ['./configure', '--static', '--prefix=' + str(p.prefix(v))], cwd=src, env=env)
                runner.run('build-' + v + '-make', ['make', '-j2', 'static'], cwd=src, env=env)
                binpath = work / 'bin'; binpath.mkdir(); roots[v] = work
                shutil.copyfile(src / 'minigzip', binpath / 'minigzip'); (binpath / 'minigzip').chmod(0o755)
                for tool in ('probe', 'strict-gzip'):
                    flags = cflags.replace('$@', tool + '.o').split()
                    runner.run('build-' + v + '-' + tool + '-compile', ['gcc', *flags, '-I' + str(src),
                        '-DEXPERIMENT_VARIANT="' + v + '"', '-DEXPERIMENT_PREFIX="' + str(p.prefix(v)) + '"',
                        '-c', str(ROOT / p.PACKAGE_ROOT / p.name(v) / (tool + '.c')), '-o', str(work / (tool + '.o'))])
                    runner.run('build-' + v + '-' + tool + '-link', ['gcc', str(work / (tool + '.o')),
                               str(src / 'libz.a'), '-o', str(binpath / tool), *ldflags.split()])
                runner.run(v + '-wrong-installed-prefix', [str(binpath / 'probe'), '--installed-check'], expected=2)
                # Exercise the real recipe's package() against this host-only build tree.
                recipe = ROOT / p.PACKAGE_ROOT / p.name(v)
                for tool in ('probe', 'strict-gzip'):
                    shutil.copyfile(binpath / tool, src / tool)
                (work / 'zlib-1.3.2.tar.gz').write_bytes(data)
                for f in p.FILES[1:]:
                    shutil.copyfile(recipe / f, work / f)
                staging = work / 'stage'; staging.mkdir()
                runner.run('build-' + v + '-stage-package', ['bash', '-e', '-c',
                    'source "$1"; srcdir="$2"; pkgdir="$3"; startdir="$4"; package',
                    'fixture', str(recipe / 'PKGBUILD'), str(work), str(staging), str(recipe)])
                files = [f for f in staging.rglob('*') if f.is_file()]
                self.assertEqual(len(files), 14)
                own = staging / p.prefix(v).relative_to('/')
                license_dir = staging / 'usr/share/licenses' / p.name(v)
                self.assertTrue(all(f.is_relative_to(own) or f.is_relative_to(license_dir) for f in files))
                self.assertEqual((own / 'source/zlib-1.3.2.tar.gz').read_bytes(), data)
                self.assertEqual((own / 'bin/probe').read_bytes(), (binpath / 'probe').read_bytes())
                self.assertEqual((license_dir / 'LICENSE.zlib').read_bytes(), p.source_material(data)['LICENSE'])
            report = p.workload(runner, p.VARIANTS, 'host', roots=roots, installed=False)
            self.assertEqual((report['encodes'], report['cross_decodes'], report['strict_rejections']), (42, 84, 6))


if __name__ == '__main__':
    unittest.main()
