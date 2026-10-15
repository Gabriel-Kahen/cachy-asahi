"""Synthetic observed-map tests; no filesystem fixture or product execution."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('candidate_root_path', Path(__file__).with_name('root_path.py'))
resolver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolver)


class Limits:
    def __init__(self, max_nodes=10000, max_depth=128, fail_after=None):
        self.max_nodes, self.max_depth = max_nodes, max_depth
        self.fail_after, self.calls = fail_after, 0

    def tick(self):
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise TimeoutError('synthetic original deadline')


def directory():
    return {'type': 'directory'}


def file():
    return {'type': 'file'}


def link(target):
    return {'type': 'symlink', 'target': target}


class RootPathTests(unittest.TestCase):
    def resolve(self, nodes, path, **limits):
        return resolver.resolve(nodes, path, limits=Limits(**limits))

    def refused(self, nodes, path, **limits):
        with self.assertRaises(ValueError):
            self.resolve(nodes, path, **limits)

    def test_root_and_direct_path_trace(self):
        self.assertEqual(self.resolve({}, ''), ('', ('',)))
        self.assertEqual(self.resolve({}, '/'), ('', ('',)))
        self.assertEqual(self.resolve({'d': directory(), 'd/f': file()}, 'd/f'),
                         ('d/f', ('', 'd', 'd/f')))

    def test_query_is_canonical_root_relative(self):
        for path in ('/d', '//', '.', '..', './d', 'd/../f', 'd//f', 'd/', 'd/./f', 'd\x00f', None, 1):
            with self.subTest(path=path):
                self.refused({'d': directory(), 'f': file()}, path)

    def test_absolute_target_resets_to_observed_root(self):
        nodes = {'d': directory(), 'd/a': link('/target'), 'target': file()}
        self.assertEqual(self.resolve(nodes, 'd/a'),
                         ('target', ('', 'd', 'd/a', '', 'target')))
        self.assertEqual(nodes['d/a']['target'], '/target')

    def test_relative_target_uses_link_parent(self):
        nodes = {'d': directory(), 'd/a': link('f'), 'd/f': file()}
        self.assertEqual(self.resolve(nodes, 'd/a'), ('d/f', ('', 'd', 'd/a', 'd/f')))

    def test_suffix_follows_expanded_target(self):
        nodes = {'a': link('/d'), 'd': directory(), 'd/f': file()}
        self.assertEqual(self.resolve(nodes, 'a/f'), ('d/f', ('', 'a', '', 'd', 'd/f')))

    def test_component_resolution_precedes_dotdot(self):
        nodes = {'p': directory(), 'p/a': link('b/../f'), 'p/b': link('/x/y'),
                 'x': directory(), 'x/y': directory(), 'x/f': file(), 'p/f': file()}
        endpoint, trace = self.resolve(nodes, 'p/a')
        self.assertEqual(endpoint, 'x/f')
        self.assertEqual(trace, ('', 'p', 'p/a', 'p/b', '', 'x', 'x/y', 'x', 'x/f'))

    def test_dot_and_repeated_separators_preserve_trace_and_literal(self):
        nodes = {'a': link('//d///./f'), 'd': directory(), 'd/f': file()}
        endpoint, trace = self.resolve(nodes, 'a')
        self.assertEqual(endpoint, 'd/f')
        self.assertGreater(trace.count('d'), 1)
        self.assertEqual(nodes['a']['target'], '//d///./f')

    def test_missing_and_file_components_cannot_be_erased(self):
        for target in ('missing/../f', 'f/../f', 'f/./', 'f/', 'f//'):
            with self.subTest(target=target):
                self.refused({'a': link(target), 'f': file()}, 'a')
        self.refused({'d/f': file()}, 'd/f')
        self.refused({'a': link('missing')}, 'a')

    def test_directory_trailing_slash_and_parent_root(self):
        nodes = {'a': link('d/'), 'd': directory(), 'd/up': link('..')}
        self.assertEqual(self.resolve(nodes, 'a')[0], 'd')
        self.assertEqual(self.resolve(nodes, 'd/up'), ('', ('', 'd', 'd/up', '')))
        self.assertEqual(self.resolve({'a': link('/')}, 'a'), ('', ('', 'a', '')))

    def test_above_root_is_refused(self):
        for target in ('..', '../f', '/..', '/d/../../f'):
            with self.subTest(target=target):
                self.refused({'a': link(target), 'd': directory(), 'f': file()}, 'a')

    def test_cycles_refuse_but_finite_revisit_succeeds(self):
        for nodes in ({'a': link('a')}, {'a': link('/a')},
                      {'a': link('b'), 'b': link('a')}):
            self.refused(nodes, 'a')
        endpoint, trace = self.resolve({'a': link('.'), 'f': file()}, 'a/a/f')
        self.assertEqual(endpoint, 'f')
        self.assertEqual(trace.count('a'), 2)
        self.assertEqual(self.resolve({'up': link('.')}, 'up')[0], '')

    def test_exact_symlink_expansion_bound(self):
        nodes = {f'l{i}': link(f'l{i + 1}') for i in range(40)}
        nodes['l40'] = file()
        self.assertEqual(self.resolve(nodes, 'l0')[0], 'l40')
        nodes['l40'] = link('f'); nodes['f'] = file()
        self.refused(nodes, 'l0')

    def test_target_byte_bound_and_surrogateescape(self):
        self.assertEqual(self.resolve({'a': link('./' * 2047 + 'f'), 'f': file()}, 'a')[0], 'f')
        self.assertEqual(self.resolve({'a': link('./' * 2047 + 'd/'), 'd': directory()}, 'a')[0], 'd')
        self.refused({'a': link('./' * 2048 + 'f'), 'f': file()}, 'a')
        name = os.fsdecode(b'raw\xff')
        target = '/' + name
        nodes = {'a': link(target), name: file()}
        self.assertEqual(self.resolve(nodes, 'a')[0], name)
        self.assertEqual(os.fsencode(nodes['a']['target']), b'/raw\xff')
        for target in ('', '\x00', '\ud800', None, True):
            with self.subTest(target=repr(target)):
                self.refused({'a': link(target)}, 'a')

    def test_consumed_dot_components_exhaust_total_work(self):
        nodes = {'a': link('./' * 1400 + 'b'), 'b': link('./' * 1400 + 'c'),
                 'c': link('./' * 1400 + 'f'), 'f': file()}
        self.refused(nodes, 'a')

    def test_node_depth_and_original_deadline_bounds(self):
        self.refused({'f': file()}, 'f', max_nodes=0)
        self.refused({'f': file(), 'g': file()}, 'f', max_nodes=1)
        self.refused({'d': directory(), 'd/e': directory(), 'd/e/f': file()}, 'd/e/f', max_depth=1)
        limits = Limits(fail_after=1)
        with self.assertRaisesRegex(TimeoutError, 'original deadline'):
            resolver.resolve({'d': directory(), 'd/f': file()}, 'd/f', limits=limits)
        self.assertGreater(limits.calls, 1)

    def test_only_visited_rows_are_validated(self):
        self.assertEqual(self.resolve({'f': file(), 'unused': object()}, 'f')[0], 'f')
        for row in (None, [], {'type': 'fifo'}, {'type': True}, {'type': 'symlink'}):
            with self.subTest(row=row):
                self.refused({'f': row}, 'f')
        calls = []
        class ForeignTag:
            def __eq__(self, other):
                calls.append(other)
                raise AssertionError('foreign type-tag equality')
        class StringTag(str):
            def __eq__(self, other):
                calls.append(other)
                raise AssertionError('subclass type-tag equality')
        for tag in (ForeignTag(), StringTag('file')):
            self.refused({'f': {'type': tag}}, 'f')
        self.assertEqual(calls, [])
        for nodes in ([], None):
            self.refused(nodes, '')

    def test_no_host_io_or_resolve_and_no_input_mutation(self):
        nodes = {'a': link('/d/f'), 'd': directory(), 'd/f': file()}
        before = repr(nodes)
        with patch('builtins.open', side_effect=AssertionError('host file read')), \
             patch.object(os, 'open', side_effect=AssertionError('host fd open')), \
             patch.object(os, 'stat', side_effect=AssertionError('host stat')), \
             patch.object(os, 'readlink', side_effect=AssertionError('host link read')), \
             patch.object(Path, 'resolve', side_effect=AssertionError('host resolve')):
            self.assertEqual(self.resolve(nodes, 'a')[0], 'd/f')
        self.assertEqual(repr(nodes), before)


if __name__ == '__main__':
    unittest.main()
