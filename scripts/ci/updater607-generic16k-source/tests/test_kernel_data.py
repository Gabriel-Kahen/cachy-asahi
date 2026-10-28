"""Source controls only: the exact accepted Image/config are not acquired here."""
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'templates/kernel_data.py.in'
loader = importlib.machinery.SourceFileLoader('updater_kernel_data', str(PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
kernel = importlib.util.module_from_spec(spec)
loader.exec_module(kernel)


class KernelDataControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kernel-data-source-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'data'
        self.root.mkdir()
        self.descriptor = kernel.expected_descriptor()

    def inputs(self):
        (self.root / 'kernel-input.json').write_bytes(kernel.encoded(self.descriptor))
        (self.root / 'Image').write_bytes(b'not the accepted kernel')
        (self.root / 'config').write_bytes(b'not the accepted config')

    def test_full_descriptor_matches_exact_accepted_source_profile(self):
        fallback = Path(__file__).resolve().parents[2] / 'latest607-alpm-list-abi-trial-root-20261026/source'
        source = Path(os.environ.get('FRESH16K_SOURCE', str(fallback))) / 'implementation/page-mode-profile.json'
        value = json.loads(source.read_bytes())['kernel']
        expected = dict(purpose='FRESH607_GENERIC16K_BUILD_ONLY_KERNEL_INPUT', source=value['source'],
                        ref=value['ref'], run=value['run'], artifact=value['artifact'], Image=value['Image'],
                        config=value['config'], header=value['members']['Image.header'],
                        build_decision=value['kernel_decision'], page_size=16384,
                        kernel='7.1.13-generic16k-managed-gui', modules='DISABLED',
                        boot='NOT_RUN', fresh607='NOT_RUN', hardware='NOT_RUN')
        self.assertEqual(kernel.profile(expected), expected)
        expected['Image']['bytes'] = 1
        self.assertEqual(kernel.expected_descriptor()['Image']['bytes'], 9019400)

    def test_foreign_partial_extra_typed_or_boot_claim_descriptor_refused(self):
        changes = [('source', '0' * 40), ('page_size', True), ('page_size', 16384.0),
                   ('kernel', '7.2.10-1-aarch64-ARCH'), ('boot', 'PASS'), ('extra', None)]
        for key, value in changes:
            changed = copy.deepcopy(self.descriptor)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                kernel.profile(changed)
        del self.descriptor['header']
        with self.assertRaises(ValueError):
            kernel.profile(self.descriptor)

    def test_current_runtime_facts_are_closed_typed_and_do_not_change_data_authority(self):
        facts = dict(sysname='Linux', architecture='aarch64', page_size=16384, kernel=kernel.RELEASE)
        self.assertEqual(kernel.actual(facts, self.descriptor), facts)
        self.assertEqual(self.descriptor['boot'], 'NOT_RUN')
        for key, value in [('page_size', 4096), ('page_size', True), ('page_size', 16384.0),
                           ('sysname', 'Darwin'), ('architecture', 'x86_64'),
                           ('kernel', 'foreign'), ('boot', 'PASS')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                kernel.actual(dict(facts, **{key: value}), self.descriptor)
        del facts['kernel']
        with self.assertRaises(ValueError):
            kernel.actual(facts, self.descriptor)

    def test_missing_extra_directory_and_root_symlink_refused(self):
        with self.assertRaises(ValueError):
            kernel.verify(self.root, self.descriptor)
        self.inputs()
        (self.root / 'extra').mkdir()
        with self.assertRaises(ValueError):
            kernel.verify(self.root, self.descriptor)
        (self.root / 'extra').rmdir()
        link = self.root.parent / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            kernel.verify(link, self.descriptor)

    def test_malformed_duplicate_nonfinite_and_noncanonical_descriptor_refused(self):
        self.inputs()
        metadata = self.root / 'kernel-input.json'
        variants = (b'{', b'{"x":1,"x":2}', b'{"x":NaN}',
                    kernel.encoded(self.descriptor).replace(b'"page_size": 16384', b'"page_size": 16384.0'),
                    json.dumps(self.descriptor, separators=(',', ':')).encode())
        for raw in variants:
            metadata.write_bytes(raw)
            with self.subTest(raw=raw[:40]), self.assertRaises((ValueError, UnicodeError)):
                kernel.verify(self.root, self.descriptor)

    def test_leaf_symlink_hardlink_directory_and_fifo_refused(self):
        self.inputs()
        metadata = self.root / 'kernel-input.json'
        outside = self.root.parent / 'outside'
        outside.write_bytes(kernel.encoded(self.descriptor))
        for kind in ('symlink', 'hardlink', 'directory', 'fifo'):
            metadata.unlink()
            if kind == 'symlink': metadata.symlink_to(outside)
            elif kind == 'hardlink': os.link(outside, metadata)
            elif kind == 'directory': metadata.mkdir()
            else: os.mkfifo(metadata)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                kernel.verify(self.root, self.descriptor)
            if kind == 'directory': metadata.rmdir()
            else: metadata.unlink()
            metadata.write_bytes(kernel.encoded(self.descriptor))

    def test_oversize_descriptor_and_fabricated_image_refused(self):
        self.inputs()
        with self.assertRaises(ValueError):
            kernel.verify(self.root, self.descriptor)
        metadata = self.root / 'kernel-input.json'
        metadata.write_bytes(kernel.encoded(self.descriptor) + b' ')
        with self.assertRaises(ValueError):
            kernel.verify(self.root, self.descriptor)

    def test_stable_nofollow_read_refuses_same_size_late_mutation(self):
        leaf = self.root / 'fixture'
        leaf.write_bytes(b'abcd')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        original = os.read
        changed = False
        def mutate(file, size):
            nonlocal changed
            value = original(file, size)
            if not changed:
                changed = True
                leaf.write_bytes(b'wxyz')
            return value
        with patch.object(kernel.os, 'read', side_effect=mutate), self.assertRaises(ValueError):
            kernel.read_at(fd, 'fixture', 4)

    def test_named_builtin_configuration_and_duplicate_or_missing_refusal(self):
        rows = [key + '=y' for key in kernel.BUILTINS]
        rows += ['# CONFIG_MODULES is not set', '# CONFIG_ARM64_4K_PAGES is not set',
                 '# CONFIG_ARM64_64K_PAGES is not set', 'CONFIG_LOCALVERSION="-generic16k-managed-gui"']
        raw = ('\n'.join(rows) + '\n').encode()
        self.assertIsNone(kernel.configuration(raw))
        for bad in (raw + b'CONFIG_USER_NS=y\n', raw.replace(b'CONFIG_USER_NS=y\n', b''),
                    raw.replace(b'# CONFIG_MODULES is not set', b'CONFIG_MODULES=y')):
            with self.assertRaises(ValueError):
                kernel.configuration(bad)


if __name__ == '__main__':
    unittest.main()
