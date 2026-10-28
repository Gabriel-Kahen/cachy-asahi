"""Inert observed-map controls for ldconfig's source-defined scan-link rules."""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'manifests/packages.toml').is_file())
sys.path.insert(0, str(ROOT / 'scripts/update'))
spec = importlib.util.spec_from_file_location('scan_link_checkpoint', HERE / 'aux_checkpoint.py')
aux = importlib.util.module_from_spec(spec); spec.loader.exec_module(aux)
sys.path.pop(0)


class Reader:
    def __init__(self, nodes):
        self.nodes = nodes
        self.limits = aux.roots.Limits(deadline=time.monotonic() + 10, max_nodes=100)
        self.reads = []

    def resolve(self, name):
        return aux.root_path.resolve(self.nodes, name, limits=self.limits)

    def literal(self, name):
        self.reads.append(name)
        return dict(node=copy.deepcopy(self.nodes[name]), identity=(1, len(name), 0, 0, 0, 1, 0, 0, 0))


class ScanLinks(unittest.TestCase):
    def setUp(self):
        directory = dict(type='directory', mode=0o755, uid=0, gid=0)
        self.nodes = {n:dict(directory) for n in ('usr', 'usr/lib', 'usr/share', 'usr/share/terminfo',
            'usr/lib/glibc-hwcaps', 'usr/lib/glibc-hwcaps/fixture')}
        self.nodes['usr/share/not-a-library'] = dict(type='file', mode=0o644, uid=0, gid=0, bytes=1, sha256='a'*64)
        self.state = dict(scan={}, aliases={})
        self.scan = {'usr/lib', 'usr/lib/glibc-hwcaps/fixture'}
        self.hwcaps = {'usr/lib/glibc-hwcaps/fixture'}
        self.closure = set()

    def link(self, name, target):
        row = dict(type='symlink', mode=0o777, uid=0, gid=0, target=target)
        self.nodes[name] = row
        self.state['scan'][name] = dict(node=row, identity=(1, len(name)))

    def check(self):
        reader = Reader(self.nodes)
        aux.scan_link_closure(reader, self.state, self.scan, self.closure, self.hwcaps)
        return reader

    def test_normal_non_dso_directory_link_is_retained_with_its_target(self):
        self.link('usr/lib/terminfo', '../share/terminfo')
        reader = self.check()
        self.assertIn('usr/share/terminfo', self.closure)
        self.assertEqual(self.state['aliases']['usr/share/terminfo']['node'], self.nodes['usr/share/terminfo'])
        self.assertIn('usr/share/terminfo', reader.reads)
        self.assertEqual(self.state['scan']['usr/lib/terminfo']['node']['target'], '../share/terminfo')

    def test_normal_non_dso_file_target_is_retained_and_drift_compares_unequal(self):
        self.link('usr/lib/nonlibrary', '../share/not-a-library')
        self.check(); before = copy.deepcopy(self.state)
        self.nodes['usr/share/not-a-library']['sha256'] = 'b'*64
        self.check()
        self.assertNotEqual(before['aliases'], self.state['aliases'])

    def test_dso_candidates_cannot_use_unselected_external_directory_targets(self):
        for basename in ('libfixture.so', 'ld-fixture.so', 'ld.so.fixture', 'ld64.so.fixture'):
            with self.subTest(basename=basename):
                self.state['scan'].clear()
                self.link('usr/lib/' + basename, '../share/not-a-library')
                with self.assertRaisesRegex(ValueError, 'library-link-closure'): self.check()

    def test_hwcaps_non_dso_symlink_keeps_library_closure_requirement(self):
        self.link('usr/lib/glibc-hwcaps/fixture/nonlibrary', '../../../share/not-a-library')
        with self.assertRaisesRegex(ValueError, 'library-link-closure'): self.check()

    def test_ignored_name_still_refuses_missing_or_escaping_targets(self):
        for target in ('../share/missing', '../../../escape'):
            with self.subTest(target=target):
                self.link('usr/lib/nonlibrary', target)
                with self.assertRaises(ValueError): self.check()

    def test_selected_in_scan_dso_endpoint_keeps_existing_admission(self):
        self.nodes['usr/lib/libfixture.so.1'] = dict(type='file', mode=0o755, uid=0, gid=0, bytes=1, sha256='c'*64)
        self.state['scan']['usr/lib/libfixture.so.1'] = dict(node=self.nodes['usr/lib/libfixture.so.1'])
        self.link('usr/lib/libfixture.so', 'libfixture.so.1')
        self.check(); self.assertIn('usr/lib/libfixture.so.1', self.closure)


@unittest.skipUnless(os.geteuid() == 0, 'mapped root required for held UID0 checkpoint fixture')
class CheckpointIntegration(unittest.TestCase):
    def setUp(self):
        import test_auxiliary as fixtures
        self.fixtures = fixtures
        fixtures.Closure.setUp(self)

    # Reuse only the existing inert metadata fixture; its helper never executes.
    def limits(self):
        from test_auxiliary import Closure
        return Closure.limits(self)

    def mkdir(self, *args, **kwargs):
        return self.fixtures.Closure.mkdir(self, *args, **kwargs)

    def write(self, *args, **kwargs):
        return self.fixtures.Closure.write(self, *args, **kwargs)

    def keys(self): return self.fixtures.Closure.keys(self)

    def test_full_checkpoint_retains_non_dso_target_and_refuses_its_drift(self):
        checkpoint = self.fixtures.aux
        target = self.mkdir('usr/share/terminfo')
        (self.root / 'usr/lib/terminfo').symlink_to('../share/terminfo')
        observe = lambda: checkpoint.roots.observe(self.root, limits=self.limits(), hardlinks='generic-development-internal')
        before = checkpoint.checkpoint(self.root, observe(), self.limits())
        self.assertEqual(before['aliases']['usr/share/terminfo']['node']['type'], 'directory')
        target.chmod(0o700)
        after = checkpoint.checkpoint(self.root, observe(), self.limits())
        with self.assertRaisesRegex(ValueError, 'aliases-changed'):
            checkpoint.compare(before, after, self.comparator)


if __name__ == '__main__': unittest.main()
