# SPDX-License-Identifier: MIT
"""Small static/refusal controls. Never execute a compiler or archive extractor."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch, Mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm_reference', HERE/'reference.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def small_elf(path, machine=183, alignment=16384, *, kind=3, filesz=120, memsz=120, vaddr=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', header, 16, kind, machine, 1)
    struct.pack_into('<H', header, 52, 64)
    row = b''
    if kind != 1:
        struct.pack_into('<Q', header, 32, 64)
        struct.pack_into('<HH', header, 54, 56, 1)
        row = struct.pack('<IIQQQQQQ', 1, 5, 0, vaddr, 0, filesz, memsz, alignment)
    path.write_bytes(header+row)
    path.chmod(0o755)


def stage(root):
    prefix = root/r.PREFIX.relative_to('/')
    for name in ('llvm-config','clang','clang++','ld.lld','llvm-ar','llvm-ranlib'):
        small_elf(prefix/'bin'/name)
    for name in ('libLLVM.so.23.1', 'libunwind.so.1'):
        small_elf(prefix/'lib'/name)
    for name in ('lib/libunwind.a','lib/clang/23/lib/linux/libclang_rt.builtins-aarch64.a','lib/clang/23/lib/linux/libclang_rt.profile-aarch64.a'):
        p = prefix/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b'!<arch>\n')
    config = prefix/'lib/cmake/llvm/LLVMConfig.cmake'
    config.parent.mkdir(parents=True)
    config.write_text('# synthetic fixture, never loaded')
    return prefix


class ReferenceTests(unittest.TestCase):
    def test_exact_pins_and_preserved_holds(self):
        pins = r.load(HERE/'inputs.json')
        self.assertEqual(pins['archive']['bytes'], 179168672)
        self.assertEqual(pins['archive']['sha256'], 'ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6')
        self.assertEqual(pins['archive']['commit'], '6dfe1677ab8dffbc6ec13d53a1e0215d75147689')
        self.assertEqual(pins['holds']['original_binary_recipe_correspondence'], 'ALL_FOUR_UNRESOLVED')
        for name, digest in pins['files'].items():
            self.assertEqual(r.digest(HERE/name), digest, name)
        for name, digest in pins['evidence'].items():
            self.assertEqual(r.digest(r.ROOT/name), digest, name)
        for name in pins['helpers']:
            r.helper(name, pins)
        auth = r.load(r.ROOT/pins['authentication_report'])['source_signatures']['llvm']
        self.assertEqual(auth['signature_mathematics'], 'PASS')
        self.assertEqual(auth['archive']['sha256'], pins['archive']['sha256'])

    def test_recipe_local_sources_and_checksums(self):
        text = (HERE/'PKGBUILD').read_text()
        names = re.findall("'([^']+)'", re.search(r'^source=\((.*?)\)', text, re.S|re.M)[1])
        hashes = re.findall("'([^']+)'", re.search(r'^sha256sums=\((.*?)\)', text, re.S|re.M)[1])
        self.assertEqual(len(names), len(hashes))
        self.assertEqual(hashes[0], r.load(HERE/'inputs.json')['archive']['sha256'])
        for name, digest in zip(names[1:], hashes[1:]):
            self.assertEqual(r.digest(HERE/name), digest)
        self.assertNotIn('://', ''.join(names))
        self.assertNotRegex(text, r'(?m)^(provides|conflicts|replaces|install)=')
        self.assertIn("arch=('aarch64')", text)
        self.assertIn('noextract=', text)
        self.assertIn('check() { _reference check;', text)

    def test_unqualified_and_wrong_digest_refuse(self):
        p = HERE/'admission.example.json'
        with self.assertRaisesRegex(ValueError, 'unqualified'):
            r.admission(p, r.digest(p), r.load(HERE/'inputs.json'))
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            r.admission(p, 'f'*64, {})

    def test_qualification_evidence_and_inputs_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root/'evidence.json'
            evidence.write_text('{}')
            a = r.load(HERE/'admission.example.json')
            a.update(status='QUALIFIED_FOR_PRIVATE_BUILD_ONLY', page_size=16384)
            a['environment']['tree_sha256'] = 'b'*64
            a['source'].update(tree_sha256='c'*64, authentication_rejoined=True, consumed_paths_and_notices_reviewed=True, no_downloads_reviewed=True)
            a['resources']['dedicated_cgroup'] = True
            a['qualification_evidence'] = {'path':str(evidence), 'sha256':r.digest(evidence)}
            path = root/'admission.json'
            def write(): path.write_text(json.dumps(a))
            write()
            r.admission(path, r.digest(path), r.load(HERE/'inputs.json'))
            evidence.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'evidence'):
                r.admission(path, r.digest(path), r.load(HERE/'inputs.json'))
            a['inputs_sha256'] = 'a'*64
            write()
            with self.assertRaisesRegex(ValueError, 'candidate inputs'):
                r.admission(path, r.digest(path), r.load(HERE/'inputs.json'))

    def test_default_refusal_starts_no_commands(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(r.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'BUILD=1'):
                r.preflight(Path('/unused'), Path('/unused'), '')
            launch.assert_not_called()

    def test_tree_content_modes_links_and_special_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'file').write_text('one')
            first = r.tree_digest(root)
            (root/'file').write_text('two')
            self.assertNotEqual(first, r.tree_digest(root))
            before = r.tree_digest(root)
            (root/'file').chmod(0o755)
            self.assertNotEqual(before, r.tree_digest(root))
            (root/'link').symlink_to('/never-follow')
            r.tree_digest(root)
            os.mkfifo(root/'fifo')
            with self.assertRaisesRegex(ValueError, 'special file'):
                r.tree_digest(root)

    def test_missing_header_crt_library_and_changed_image_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)
            for name in ('work','source','proc','dev','tmp',str(r.PREFIX.relative_to('/'))):
                (image/name).mkdir(parents=True, exist_ok=True)
            p = image/'usr/include/stdio.h'
            p.parent.mkdir(parents=True)
            p.write_text('synthetic header')
            pins = {'environment_tools':[], 'environment_development':['gcc'], 'development_roles':['c_header']}
            a = {'environment':{'packages':{'gcc':'QUALIFIED-TEST-ONLY'}, 'development_files':{'c_header':{'path':'usr/include/stdio.h','sha256':r.digest(p)}}, 'tree_sha256':r.tree_digest(image)}}
            r.check_environment(image, a, pins)
            (image/'unexpected').write_text('fixture change')
            with self.assertRaisesRegex(ValueError, 'qualified image changed'):
                r.check_environment(image, a, pins)
            (image/'unexpected').unlink()
            p.unlink()
            with self.assertRaisesRegex(ValueError, 'development input'):
                r.check_environment(image, a, pins)
            a['environment']['development_files'] = {}
            with self.assertRaisesRegex(ValueError, 'roles incomplete'):
                r.check_environment(image, a, pins)

    def test_sandbox_readonly_dual_source_and_private_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'reference-build.sh').write_text('fixture')
            argv = r.sandbox(root, Path('/qualified-image'), ['NOT_EXECUTED'], source=True, private=True)
            self.assertIn('--unshare-all', argv)
            self.assertIn('--clearenv', argv)
            self.assertIn('--die-with-parent', argv)
            self.assertNotIn('--share-net', argv)
            self.assertIn(str(r.PREFIX), argv)
            self.assertIn('/work/'+r.SOURCE, argv)
            self.assertEqual(argv[argv.index('--ro-bind')+1:argv.index('--ro-bind')+3], ['/qualified-image','/'])
            self.assertEqual(argv[-2:], ['--','NOT_EXECUTED'])

    def test_cmake_native_private_runtime_and_geometry_contract(self):
        text = (HERE/'build.sh').read_text()
        for needle in ('-DLLVM_TARGETS_TO_BUILD=AArch64', '-DLLVM_BUILD_LLVM_DYLIB=ON', '-DLLVM_LINK_LLVM_DYLIB=ON', '-DLLVM_ENABLE_RTTI=ON', '-DLLVM_ENABLE_RUNTIMES=\'compiler-rt;libunwind\'', '-DCOMPILER_RT_BUILD_PROFILE=ON', '-DCOMPILER_RT_BUILD_SANITIZERS=OFF', '-DLIBUNWIND_INSTALL_LIBRARY_DIR=lib', '-DLLVM_LIBDIR_SUFFIX=', 'max-page-size=16384', '$ORIGIN/../lib;$ORIGIN', 'DESTDIR=/work/dest', 'CMAKE_C_COMPILER="$prefix/bin/clang"'):
            self.assertIn(needle, text)
        for forbidden in ('-march=native', '-mcpu=', 'x86-64', 'ldconfig', 'pacman -S', 'curl ', 'wget '):
            self.assertNotIn(forbidden, text)

    def test_elf_arch_and_16k_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'elf'
            small_elf(path)
            self.assertTrue(r.elf(path))
            small_elf(path, machine=62)
            with self.assertRaisesRegex(ValueError, 'non-AArch64'):
                r.elf(path)
            small_elf(path, alignment=4096)
            with self.assertRaisesRegex(ValueError, '16K'):
                r.elf(path)

    def test_dynamic_private_llvm_rpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp)/'prefix'
            binary = prefix/'bin/tool'
            binary.parent.mkdir(parents=True)
            def write(rpath):
                strings = b'\0libLLVM.so.23.1\0'+rpath.encode()+b'\0'
                header = bytearray(64)
                header[:6] = b'\x7fELF\x02\x01'
                struct.pack_into('<HH', header, 16, 3, 183)
                struct.pack_into('<Q', header, 32, 64)
                struct.pack_into('<HH', header, 54, 56, 2)
                data = [(5,256),(10,len(strings)),(1,1),(29,17),(0,0)]
                body = b''.join(struct.pack('<qQ', *row) for row in data)
                # libLLVM string starts at 1 and has 16 bytes including NUL.
                strings = b'\0libLLVM.so.23.1\0'+rpath.encode()+b'\0'
                data[3] = (29,len(b'\0libLLVM.so.23.1\0'))
                body = b''.join(struct.pack('<qQ', *row) for row in data)
                total = 256+len(strings)
                load = struct.pack('<IIQQQQQQ', 1,5,0,0,0,total,total,16384)
                dyn = struct.pack('<IIQQQQQQ', 2,4,176,176,176,80,80,8)
                binary.write_bytes(header+load+dyn+body+strings)
            write('$ORIGIN/../lib')
            self.assertTrue(r.elf(binary, prefix))
            write('/usr/lib')
            with self.assertRaisesRegex(ValueError, 'RPATH escapes'):
                r.elf(binary, prefix)
            write('$ORIGIN')
            with self.assertRaisesRegex(ValueError, 'lacks private library RPATH'):
                r.elf(binary, prefix)

    def test_existing_cgroup_and_capacity_are_checked_without_writes(self):
        group = '/sys/fs/cgroup/test-llvm23'
        a = {'resources':{'cgroup':group}}
        values = {'/proc/self/cgroup':'0::/test-llvm23\n', '/proc/meminfo':'MemAvailable: 12582912 kB\n',
                  group+'/memory.max':str(8*r.GIB), group+'/memory.swap.max':'0',
                  group+'/cpu.max':'200000 100000', group+'/pids.max':'512'}
        capacity = Mock()
        def read(path, *args, **kwargs): return values[str(path)]
        with patch.object(Path, 'read_text', read), patch.object(r, 'helper', return_value=capacity):
            r.resource_check(Path('/not-created'), a, {})
            capacity.check.assert_called_once()
            values[group+'/memory.max'] = 'max'
            with self.assertRaisesRegex(ValueError, 'memory.max'):
                r.resource_check(Path('/not-created'), a, {})
            values[group+'/memory.max'] = str(8*r.GIB)
            values['/proc/meminfo'] = 'MemAvailable: 1024 kB\n'
            with self.assertRaisesRegex(ValueError, 'reserve unavailable'):
                r.resource_check(Path('/not-created'), a, {})

    def test_stage_missing_runtime_escape_and_wrong_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prefix = stage(root)
            r.check_stage(root)
            link = prefix/'lib/link.so'
            link.symlink_to('/usr/lib/global.so')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                r.check_stage(root)
            link.unlink()
            binary = prefix/'bin/clang'
            binary.write_text('not a native executable')
            with self.assertRaisesRegex(ValueError, 'native executable'):
                r.check_stage(root)
            small_elf(binary)
            (prefix/'lib/libunwind.a').unlink()
            with self.assertRaisesRegex(ValueError, 'component missing'):
                r.check_stage(root)

    def test_stage_elf_roles_allow_tool_and_library_aliases_and_relocatable_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prefix = stage(root)
            clang = prefix/'bin/clang'
            clangxx = prefix/'bin/clang++'
            library = prefix/'lib/libLLVM.so.23.1'
            clangxx.unlink()
            clangxx.symlink_to(clang.name)
            (prefix/'lib/libLLVM.so').symlink_to(library.name)
            small_elf(prefix/'lib/startup.o', kind=1)
            small_elf(library, alignment=32768, memsz=4096)
            small_elf(clang, kind=2)
            r.check_stage(root)
            small_elf(clang, kind=3)
            r.check_stage(root)
            small_elf(clang, kind=1)
            with self.assertRaisesRegex(ValueError, 'native executable'):
                r.check_stage(root)
            small_elf(clang)
            for kind in (1, 2):
                with self.subTest(library_type=kind):
                    small_elf(library, kind=kind)
                    with self.assertRaisesRegex(ValueError, 'native shared library'):
                        r.check_stage(root)

    def test_stage_rejects_bad_load_bounds_and_alignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            library = stage(root)/'lib/libLLVM.so.23.1'
            for fields, error in (
                (dict(filesz=121, memsz=121, alignment=16512), 'segment bounds'),
                (dict(filesz=121, memsz=121), 'segment bounds'),
                (dict(memsz=119), 'file/memory size'),
                (dict(alignment=16512), '16K PT_LOAD'),
                (dict(alignment=32768, vaddr=16384), '16K PT_LOAD'),
            ):
                with self.subTest(fields=fields):
                    small_elf(library, **fields)
                    with self.assertRaisesRegex(ValueError, error):
                        r.check_stage(root)

    def test_prepare_accepts_makepkg_source_links_without_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work, source = root/'work', root/'fixture'
            work.mkdir();source.mkdir()
            for component in ('llvm','clang','lld','compiler-rt','libunwind','runtimes','cmake'):
                p = source/component
                p.mkdir()
                (p/'CMakeLists.txt').write_text('# fixture')
                (p/'LICENSE.TXT').write_text('fixture notice')
            material = root/'archive'
            material.write_bytes(b'fixture archive, not a tar file')
            (work/'archive').symlink_to(material)
            (work/'build.sh').symlink_to(HERE/'build.sh')
            pins = {'archive':{'filename':'archive','sha256':r.digest(material)}, 'notices':{'llvm':r.digest(source/'llvm/LICENSE.TXT')}}
            a = {'source':{'tree_sha256':r.tree_digest(source)}}
            with patch.object(r, 'run', side_effect=lambda *args, **kw: shutil.copytree(source, work/r.SOURCE)), patch.dict(os.environ, {r.ENV+'ADMISSION_SHA256':'a'*64}):
                r.prepare(work, pins, a, Path('/image'))
            self.assertTrue((work/'build.sh').is_symlink())
            self.assertFalse((work/'reference-build.sh').is_symlink())
            self.assertEqual(r.digest(work/'reference-build.sh'), r.digest(HERE/'build.sh'))

    def test_owned_retirement_is_required_before_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            owned = Mock()
            owned.run.side_effect = lambda *args, **kw: kw['lifecycle'].update(retirement='UNKNOWN', group_absent=False)
            with patch.object(r, 'resource_check'), patch.object(r, 'helper', return_value=owned):
                with self.assertRaisesRegex(ValueError, 'retirement unverified'):
                    r.run(work, {}, {}, Path('/image'), ['NOT_EXECUTED'], 'fake')
            self.assertEqual(json.loads((work/'logs/fake.json').read_bytes())['retirement'], 'UNKNOWN')

    def test_checked_stage_cannot_be_replaced_before_packaging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root/'work';work.mkdir()
            dest = root/'pkg';dest.mkdir()
            (work/'dest').mkdir()
            (work/'checked.json').write_text(json.dumps({'admission_sha256':'a'*64,'build_sha256':'b'*64,'staged_tree_sha256':'c'*64}))
            with patch.object(r, 'binding', return_value={'admission_sha256':'a'*64,'build_sha256':'b'*64}):
                with self.assertRaisesRegex(ValueError, 'checked stage binding'):
                    r.package(work, dest, {})
            self.assertEqual(list(dest.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
