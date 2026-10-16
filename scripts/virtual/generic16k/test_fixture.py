#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable refusal/format/supervisor controls; no guest execution."""
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixture16k', HERE/'fixture.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fixture-controls-', dir=HERE)
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)

    def archive(self, entries):
        path = self.root/'rootfs.tar'
        with tarfile.open(path, 'w') as t:
            for name, kind, value in entries:
                m = tarfile.TarInfo(name); m.type = kind
                if kind == tarfile.REGTYPE:
                    m.size = len(value); t.addfile(m, io.BytesIO(value))
                else:
                    if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): m.linkname = value
                    t.addfile(m)
        a = f.Archive(path); self.addCleanup(a.tar.close); return a

    def test_link_resolution_does_not_extract_or_follow_host(self):
        a = self.archive([('usr', tarfile.DIRTYPE, ''), ('usr/lib', tarfile.DIRTYPE, ''),
                          ('lib', tarfile.SYMTYPE, 'usr/lib'), ('usr/lib/value', tarfile.REGTYPE, b'guest'),
                          ('usr/lib/alias', tarfile.SYMTYPE, '/lib/value')])
        self.assertEqual(a.read('lib/alias')[:2], ('usr/lib/value', b'guest'))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['rootfs.tar'])

    def test_link_escape_loop_and_special_refused(self):
        for entries, name in [([('x', tarfile.SYMTYPE, '../outside')], 'x'),
                              ([('x', tarfile.SYMTYPE, '/x')], 'x'),
                              ([('x', tarfile.CHRTYPE, '')], 'x')]:
            with self.subTest(entries=entries):
                a = self.archive(entries)
                with self.assertRaises(ValueError): a.read(name)
        with self.assertRaises(ValueError): f.clean('../outside')

    def test_duplicate_and_file_size_budget_refused(self):
        with self.assertRaises(ValueError): self.archive([('x', tarfile.REGTYPE, b'a'), ('x', tarfile.REGTYPE, b'b')])
        a = self.archive([('x', tarfile.REGTYPE, b'a')]); a.nodes['x'].size = f.LIMIT+1
        with self.assertRaises(ValueError): a.read('x')

    def test_newc_console_and_null_nodes(self):
        data = f.cpio({'init': (stat.S_IFREG|0o755, b'hello')}); offset = 0; nodes = {}
        while True:
            self.assertEqual(data[offset:offset+6], b'070701')
            fields = [int(data[offset+6+i*8:offset+14+i*8], 16) for i in range(13)]
            start = offset+110; name = data[start:start+fields[11]-1].decode()
            payload = (start+fields[11]+3)//4*4
            nodes[name] = (fields, data[payload:payload+fields[6]])
            offset = (payload+fields[6]+3)//4*4
            if name == 'TRAILER!!!': break
        self.assertEqual(nodes['dev/console'][0][9:11], [5, 1])
        self.assertEqual(nodes['dev/null'][0][9:11], [1, 3])
        self.assertEqual(nodes['init'][1], b'hello')

    def test_actual_static_smoke_compiles_aarch64_16k(self):
        if not shutil.which('clang') or not shutil.which('ld.lld'): self.skipTest('clang/lld absent')
        out = self.root/'smoke'
        code, _ = f.supervise(['clang', '--target=aarch64-linux-gnu', '-nostdlib', '-static', '-fuse-ld=lld',
                        '-O2', '-fno-stack-protector', '-fno-builtin', '-Wl,-z,max-page-size=16384',
                        '-Wl,-e,_start', str(HERE/'smoke.c'), '-o', str(out)], self.root/'compile.log', timeout=30)
        self.assertEqual(code, 0, (self.root/'compile.log').read_text())
        interp, needed, loads = f.elf(out.read_bytes())
        self.assertIsNone(interp); self.assertFalse(needed); self.assertTrue(loads)
        self.assertTrue(all(align >= 16384 and (va-off)%16384 == 0 for va, off, _, align in loads))
        with self.assertRaises(ValueError): f.elf(b'not an ELF')

    def test_result_requires_identity_page_order_unique_and_natural_exit(self):
        nonce = 'a'*32; release = '7.0-fixture'
        good = (f'UNAME16K aarch64 {release}\r\nGETCONF16K 16384\r\n'
                f'SMOKE16K: mmap,mprotect,file-offset PASS\r\nFIXTURE16K PASS {nonce}\r\n').encode()
        f.validate_output(good, 0, nonce, release)
        for output, code in [(good, -9), (good.replace(b'16384', b'4096'), 0),
                             (good.replace(nonce.encode(), b'b'*32), 0), (good+good, 0),
                             (b'FIXTURE16K FAIL\n'+good, 0), (b'\n'.join(reversed(good.splitlines())), 0)]:
            with self.subTest(output=output, code=code), self.assertRaises(ValueError):
                f.validate_output(output, code, nonce, release)

    def test_supervisor_natural_exit_timeout_and_output_cap(self):
        code, output = f.supervise([sys.executable, '-c', 'print("bounded")'], self.root/'ok.log', 2, 1024)
        self.assertEqual((code, output), (0, b'bounded\n'))
        with self.assertRaises(TimeoutError):
            f.supervise([sys.executable, '-c', 'import time;time.sleep(20)'], self.root/'timeout.log', .1, 1024)
        with self.assertRaises(ValueError):
            f.supervise([sys.executable, '-c', 'print("x"*8192)'], self.root/'overflow.log', 2, 1024)
        self.assertLessEqual((self.root/'overflow.log').stat().st_size, 1024)

    def test_guest_script_quotes_identity_and_only_boots_owned_commands(self):
        script = f.init_script('a'*32, '7.0-fixture')
        self.assertIn(b'/usr/bin/getconf PAGESIZE', script); self.assertIn(b'exec /smoke poweroff', script)
        with self.assertRaises(ValueError): f.init_script('a'*32, 'release;whoami')


if __name__ == '__main__': unittest.main()
