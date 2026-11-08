"""Declared dependency planning regressions; no package installation."""
import copy
import itertools
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import dependencies as deps


def report(name, *, depends=(), provides=(), version='1', **fields):
    return {'metadata': dict(pkgname=[name], pkgver=[version], pkgrel=['1'],
                             depends=list(depends), provides=list(provides), **fields)}


class ProviderIdentityTests(unittest.TestCase):
    def test_repository_named_overlay_is_a_prerequisite(self):
        reports = [report('aaa', depends=['repository']), report('repository')]
        before = copy.deepcopy(reports)
        result = deps.resolve(reports, [])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['build_order'], ['repository', 'aaa'])
        self.assertEqual(reports, before)

    def test_repository_named_overlay_cycle_is_reported(self):
        result = deps.resolve([report('aaa', depends=['repository']),
                               report('repository', depends=['aaa'])], [])
        self.assertTrue(any('cycle' in error for error in result['errors']))
        self.assertEqual(result['build_order'], [])

    def test_repository_named_virtual_provider_is_a_prerequisite(self):
        result = deps.resolve([report('aaa', depends=['virtual']),
                               report('repository', provides=['virtual'])], [])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['build_order'], ['repository', 'aaa'])

    def test_external_provider_removes_only_the_dependency_edge(self):
        reports = [report('aaa', depends=['repository']), report('repository')]
        for inventory in ([dict(name='repository', version='1', arch='any')],
                          [dict(name='external', version='1', arch='any',
                                provides=['repository'])]):
            with self.subTest(inventory=inventory):
                result = deps.resolve(reports, inventory)
                self.assertEqual(result['errors'], [])
                self.assertEqual(result['build_order'], ['aaa', 'repository'])

    def test_external_repository_name_requires_no_overlay_node(self):
        result = deps.resolve([report('aaa', depends=['repository'])],
                              [dict(name='repository', version='1', arch='any')])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['build_order'], ['aaa'])


class DuplicateOverlayTests(unittest.TestCase):
    def test_distinct_recipes_cannot_supply_one_shared_build_node(self):
        reports = [report('same', version='1', provides=['virtual-a']),
                   report('same', version='2', provides=['virtual-b']),
                   report('consumer', depends=['virtual-a', 'virtual-b'])]
        with self.assertRaisesRegex(ValueError, 'duplicate overlay'):
            deps.resolve(reports, [])

    def test_identical_reports_are_still_duplicate_build_nodes(self):
        first = report('same')
        with self.assertRaisesRegex(ValueError, 'duplicate overlay'):
            deps.resolve([first, copy.deepcopy(first)], [])

    def test_repeated_name_inside_one_report_is_rejected(self):
        duplicate = report('same')
        duplicate['metadata']['pkgname'] = ['same', 'same']
        with self.assertRaisesRegex(ValueError, 'duplicate overlay'):
            deps.resolve([duplicate], [])

    def test_external_name_overlap_and_shared_virtual_names_remain_valid(self):
        cases = [([report('same')], [dict(name='same', version='1', arch='any')]),
                 ([report('b', provides=['virtual']), report('c', provides=['virtual']),
                   report('consumer', depends=['virtual'])], [])]
        for reports, inventory in cases:
            with self.subTest(reports=reports):
                result = deps.resolve(reports, inventory)
                self.assertEqual(result['errors'], [])
                self.assertEqual(set(result['build_order']),
                                 {row['metadata']['pkgname'][0] for row in reports})


class AlternativeProviderTests(unittest.TestCase):
    def test_small_graphs_match_an_independent_permutation_oracle(self):
        def check(requirements, external):
            count = len(requirements)
            reports = [report('p' + str(i)) for i in range(count)]
            external_names = []
            for consumer, groups in enumerate(requirements):
                for index, providers in enumerate(groups):
                    virtual = f'v{consumer}-{index}'
                    reports[consumer]['metadata']['depends'].append(virtual)
                    for provider in providers:
                        reports[provider]['metadata']['provides'].append(virtual)
                    if (consumer, index) in external:
                        external_names.append(virtual)

            def valid(order):
                built = set()
                for consumer in order:
                    for index, providers in enumerate(requirements[consumer]):
                        if (consumer, index) not in external and not providers.intersection(built):
                            return False
                    built.add(consumer)
                return True

            possible = any(valid(order) for order in itertools.permutations(range(count)))
            inventory = ([dict(name='external', version='1', arch='any', provides=external_names)]
                         if external_names else [])
            result = deps.resolve(reports, inventory)
            self.assertEqual(not result['errors'], possible, (requirements, external, result))
            if possible:
                self.assertEqual(sorted(result['build_order']), ['p' + str(i) for i in range(count)])
                self.assertTrue(valid([int(name[1:]) for name in result['build_order']]))

        for masks in itertools.product(range(8), repeat=3):
            requirements = [[{i for i in range(3) if mask & (1 << i)}] if mask else []
                            for mask in masks]
            check(requirements, set())
        rng = random.Random(7281)
        for _ in range(1000):
            requirements = []
            for _node in range(4):
                groups = []
                for _requirement in range(rng.randrange(3)):
                    mask = rng.randrange(1, 16)
                    groups.append({i for i in range(4) if mask & (1 << i)})
                requirements.append(groups)
            external = {(i, j) for i, groups in enumerate(requirements)
                        for j in range(len(groups)) if rng.randrange(5) == 0}
            check(requirements, external)

    def test_alternatives_work_in_every_report_order_and_dependency_field(self):
        for field in ('depends', 'makedepends', 'checkdepends',
                      'depends_aarch64', 'makedepends_aarch64', 'checkdepends_aarch64'):
            consumer = report('a')
            consumer['metadata'][field] = ['virtual']
            candidates = [consumer, report('b', depends=['a'], provides=['virtual']),
                          report('c', provides=['virtual'])]
            for reports in itertools.permutations(candidates):
                with self.subTest(field=field, order=[r['metadata']['pkgname'] for r in reports]):
                    result = deps.resolve(reports, [])
                    self.assertEqual(result['errors'], [])
                    self.assertEqual(result['build_order'], ['c', 'a', 'b'])

    def test_genuine_cycle_remains_when_no_provider_can_bootstrap(self):
        result = deps.resolve([report('a', depends=['virtual']),
                               report('b', depends=['a'], provides=['virtual'])], [])
        self.assertTrue(any('cycle' in error for error in result['errors']))
        self.assertEqual(result['build_order'], [])

    def test_separate_dependencies_still_require_all_prerequisites(self):
        result = deps.resolve([report('a', depends=['x', 'y']),
                               report('b', depends=['a'], provides=['y']),
                               report('c', provides=['x'])], [])
        self.assertTrue(any('cycle' in error for error in result['errors']))
        self.assertEqual(result['build_order'], ['c'])

    def test_external_provider_can_bootstrap_the_cycle(self):
        result = deps.resolve([report('a', depends=['virtual']),
                               report('b', depends=['a'], provides=['virtual'])],
                              [dict(name='external', version='1', arch='any',
                                    provides=['virtual'])])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['build_order'], ['a', 'b'])

    def test_version_constraints_filter_alternative_providers(self):
        def compare_version(command, **kwargs):
            self.assertEqual(command[0], 'vercmp')
            self.assertEqual(command[2], '2')
            return '0' if command[1] == '2' else '-1'

        for independent_version in ('1', '2'):
            reports = [report('a', depends=['virtual>=2']),
                       report('b', depends=['a'], provides=['virtual=2']),
                       report('c', provides=['virtual=' + independent_version])]
            with self.subTest(version=independent_version), \
                    patch.object(deps.subprocess, 'check_output', side_effect=compare_version):
                result = deps.resolve(reports, [])
            if independent_version == '1':
                self.assertTrue(any('cycle' in error for error in result['errors']))
                self.assertEqual(result['build_order'], ['c'])
            else:
                self.assertEqual(result['errors'], [])
                self.assertEqual(result['build_order'], ['c', 'a', 'b'])

    def test_unused_alternatives_still_build_in_sorted_ready_batches(self):
        result = deps.resolve([report('a', depends=['virtual']),
                               report('d', provides=['virtual']),
                               report('b', depends=['a'], provides=['virtual']),
                               report('c', provides=['virtual'])], [])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['build_order'], ['c', 'd', 'a', 'b'])

    def test_unrelated_unresolved_dependency_is_not_lost(self):
        result = deps.resolve([report('a', depends=['virtual']),
                               report('b', depends=['a'], provides=['virtual']),
                               report('c', provides=['virtual']),
                               report('unrelated', depends=['missing'])], [])
        self.assertTrue(any('unresolved depends missing' in error for error in result['errors']))


if __name__ == '__main__':
    unittest.main()
