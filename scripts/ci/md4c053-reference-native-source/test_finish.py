#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Synthetic archive/ELF controls only; never a native acceptance fixture."""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import tarfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('md4c_model_finisher', HERE / 'finish_pair.py')
F = importlib.util.module_from_spec(spec); spec.loader.exec_module(F)
LICENSE_TEXT = '\n# The MIT License (MIT)\n\nCopyright © 2016-2024 Martin Mitáš\n\nPermission is hereby granted, free of charge, to any person obtaining a\ncopy of this software and associated documentation files (the “Software”),\nto deal in the Software without restriction, including without limitation\nthe rights to use, copy, modify, merge, publish, distribute, sublicense,\nand/or sell copies of the Software, and to permit persons to whom the\nSoftware is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included\nin all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS\nOR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL\nTHE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\nFROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS\nIN THE SOFTWARE.\n'
IMAGE = 'sha256:' + '1' * 64


def model_elf(name, needed=None, soname='DEFAULT', rpath=False):
    expected, libraries = F.ELFS[name]
    if needed is None: needed = sorted(libraries)
    if soname == 'DEFAULT': soname = expected
    strings = bytearray(b'\0'); tags = []
    def string(value):
        index = len(strings); strings.extend(value.encode() + b'\0'); return index
    for value in needed: tags.append((1, string(value)))
    if soname: tags.append((14, string(soname)))
    if rpath: tags.append((29, string('/MODEL/foreign')))
    tags.extend(((5, 0x300), (10, len(strings)), (0, 0)))
    raw = bytearray(1024); count = 2 if expected else 3
    raw[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + b'\0' * 9,
                          3, 183, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    segments = [(1, 5, 0, 0, 0, len(raw), len(raw), 16384),
                (2, 6, 0x180, 0x180, 0, 16 * len(tags), 16 * len(tags), 8)]
    if not expected:
        loader = b'/lib/ld-linux-aarch64.so.1\0'; raw[0x280:0x280 + len(loader)] = loader
        segments.append((3, 4, 0x280, 0x280, 0, len(loader), len(loader), 1))
    for index, row in enumerate(segments): struct.pack_into('<IIQQQQQQ', raw, 64 + 56 * index, *row)
    for index, row in enumerate(tags): struct.pack_into('<qQ', raw, 0x180 + 16 * index, *row)
    raw[0x300:0x300 + len(strings)] = strings
    return bytes(raw)


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='md4c-finisher-MODEL-')
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.patch = patch.object(F, 'HERE', self.root); self.patch.start(); self.addCleanup(self.patch.stop)
        self.reviewed = {'PKGBUILD': 'a' * 64}; self.lock = b'MODEL expected349 immutable inventory\n'
        (self.root / 'reviewed-inputs.json').write_text(json.dumps(self.reviewed))
        (self.root / 'recipe-pin.json').write_text(json.dumps(dict(license=F.LICENSE)))
        (self.root / 'expected349.lock').write_bytes(self.lock)
        self.bodies = {name: b'MODEL payload\n' for name in F.FILES}
        self.bodies[F.LICENSE['path']] = LICENSE_TEXT.encode()
        self.bodies['.PKGINFO'] = b'pkgname = md4c\npkgver = 0.5.3-1\narch = aarch64\ndepend = glibc\n'
        self.bodies['.BUILDINFO'] = b'format = 2\npkgname = md4c\npkgver = 0.5.3-1\npkgarch = aarch64\n'
        self.bodies['.MTREE'] = gzip.compress(b'#mtree\nMODEL\n', mtime=0)
        self.bodies['usr/share/man/man1/md2html.1.gz'] = gzip.compress(b'MODEL manual\n', mtime=0)
        for name in F.ELFS: self.bodies[name] = model_elf(name)
        self.comparison = self.root / 'comparison.json'
        self.comparison_value = dict(status='contents-reproduced', errors=[], packages={F.PACKAGE:
            dict(installed_contents_equal=True, pkginfo_equal=True, buildinfo_equal=True, bytes_equal=True)})
        self.comparison.write_text(json.dumps(self.comparison_value))
        self.first = self.root / 'first'; self.second = self.root / 'second'
        self.build(self.first, 'MODEL-clean-1'); self.build(self.second, 'MODEL-clean-2')

    def build(self, root, identity, bodies=None, extra=None, links=None):
        bodies = self.bodies if bodies is None else bodies; out = root / 'artifacts'; out.mkdir(parents=True, exist_ok=True)
        archive = out / F.PACKAGE
        with tarfile.open(archive, 'w:xz') as tf:
            for name, body in {**bodies, **(extra or {})}.items():
                member = tarfile.TarInfo(name); member.size = len(body); member.mode = 0o755 if name in F.ELFS else 0o644
                tf.addfile(member, io.BytesIO(body))
            for name, target in (F.LINKS if links is None else links).items():
                member = tarfile.TarInfo(name); member.type = tarfile.SYMTYPE; member.linkname = target; member.mode = 0o777; tf.addfile(member)
        (out / 'environment.txt').write_text('MODEL uname aarch64 identity\n')
        (out / 'md4c-0.5.3-1-aarch64-check.log').write_bytes(b'\n'.join(F.MARKERS) + b'\n')
        provenance = dict(status='built-package-static-pass', exit_code=0, mode='native', image_id=IMAGE,
                          recipe_inputs=self.reviewed, expected_packages_sha256=F.pin(self.lock)['sha256'],
                          builder_host_arch='aarch64', clean_environment_id=identity,
                          artifacts={F.PACKAGE: F.pin(archive.read_bytes())['sha256']})
        report = dict(artifact=F.PACKAGE, errors=[], sha256=provenance['artifacts'][F.PACKAGE],
                      elf={name: dict(errors=[]) for name in F.ELFS},
                      members={name: F.pin(body) for name, body in bodies.items()})
        (root / 'provenance.json').write_text(json.dumps(provenance))
        (root / 'validation.json').write_text(json.dumps(dict(errors=[], artifacts=[report])))

    def finish(self): return F.finish(self.first, self.second, self.comparison, IMAGE)

    def test_synthetic_pair_exercises_complete_finisher_without_issuing_acceptance(self):
        result = self.finish()
        self.assertEqual(result['status'], 'MD4C053_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED')
        self.assertIsNone(result['Root_acceptance']); self.assertEqual(result['official_binary_recovery'], 'HOLD')
        self.assertEqual(result['native16K'], 'NOT RUN'); self.assertTrue(all(
            row[name]['ELF']['structural16K'] for row in result['observations'] for name in F.ELFS))

    def test_rehashed_wrong_version_dependency_or_license_refuses(self):
        for key, body in [('.PKGINFO', self.bodies['.PKGINFO'].replace(b'0.5.3-1', b'0.6.0-2')),
                          ('.PKGINFO', self.bodies['.PKGINFO'] + b'depend = foreign\n'),
                          (F.LICENSE['path'], b'MODEL license drift')]:
            with self.subTest(key=key, body=body):
                changed = dict(self.bodies, **{key: body}); self.build(self.first, 'MODEL-clean-1', changed)
                with self.assertRaises(ValueError): self.finish()
        self.build(self.first, 'MODEL-clean-1')

    def test_elf_arch_soname_needed_rpath_and_cli_loader_refuse(self):
        library = 'usr/lib/libmd4c.so.0.5.3'
        wrong_arch = bytearray(model_elf(library)); struct.pack_into('<H', wrong_arch, 18, 62)
        cases = [(library, bytes(wrong_arch)), (library, model_elf(library, soname='libmd4c.so.1')),
                 (library, model_elf(library, needed=['libc.so.6', 'libforeign.so'])),
                 (library, model_elf(library, rpath=True)),
                 ('usr/bin/md2html', model_elf('usr/bin/md2html').replace(b'ld-linux-aarch64', b'ld-linux-x86____'))]
        for name, body in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError): F.elf(body, name)

    def test_rehashed_extra_hook_and_wrong_symlink_are_not_provider_packages(self):
        self.build(self.first, 'MODEL-clean-1', extra={'.INSTALL': b'MODEL unexpected script'})
        with self.assertRaises(ValueError): self.finish()
        links = dict(F.LINKS); links['usr/lib/libmd4c.so.0'] = 'libmd4c.so.1'
        self.build(self.first, 'MODEL-clean-1', links=links)
        with self.assertRaises(ValueError): self.finish()

    def test_missing_checks_same_clean_container_or_false_byte_comparison_refuse(self):
        log = self.first / 'artifacts/md4c-0.5.3-1-aarch64-check.log'
        for marker in F.MARKERS:
            log.write_bytes(b'\n'.join(m for m in F.MARKERS if m != marker))
            with self.assertRaises(ValueError): self.finish()
        self.build(self.first, 'MODEL-clean-2')
        with self.assertRaises(ValueError): self.finish()
        self.build(self.first, 'MODEL-clean-1')
        value = copy.deepcopy(self.comparison_value); value['packages'][F.PACKAGE]['bytes_equal'] = False
        self.comparison.write_text(json.dumps(value))
        with self.assertRaises(ValueError): self.finish()

    def test_stale_current_archive_digest_and_missing_cli_validation_refuse(self):
        p = self.first / 'provenance.json'; value = json.loads(p.read_text()); value['artifacts'][F.PACKAGE] = '0' * 64
        p.write_text(json.dumps(value))
        with self.assertRaises(ValueError): self.finish()
        self.build(self.first, 'MODEL-clean-1')
        p = self.first / 'validation.json'; value = json.loads(p.read_text()); value['artifacts'][0]['elf'].pop('usr/bin/md2html')
        p.write_text(json.dumps(value))
        with self.assertRaises(ValueError): self.finish()


if __name__ == '__main__': unittest.main(verbosity=2)
