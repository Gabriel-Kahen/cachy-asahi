"""Cross-package ancestor collisions without extracting package contents."""
import copy
import itertools
from pathlib import Path
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import package_checks as checks


def report(label, path, kind):
    return dict(artifact=label, members={path: dict(type=kind)})


class PackageAncestorTests(unittest.TestCase):
    def test_non_directory_ancestors_conflict_in_both_report_orders(self):
        for parent_type, child_type in itertools.product(('0', '1', '2'), ('0', '5')):
            parent = report('parent.pkg.tar', 'usr/share/node', parent_type)
            child = report('child.pkg.tar', 'usr/share/node/child', child_type)
            for reports in ([parent, child], [child, parent]):
                with self.subTest(parent_type=parent_type, child_type=child_type, reports=reports):
                    before = copy.deepcopy(reports)
                    findings = checks.conflicts(reports)
                    self.assertEqual(len(findings), 1)
                    for text in ('usr/share/node', 'parent.pkg.tar', 'child.pkg.tar'):
                        self.assertIn(text, findings[0])
                    self.assertEqual(reports, before)

    def test_equal_artifact_labels_do_not_merge_distinct_reports(self):
        findings = checks.conflicts([report('same.pkg.tar', 'usr/node', '0'),
                                     report('same.pkg.tar', 'usr/node/leaf', '0')])
        self.assertEqual(len(findings), 1)

    def test_directory_sharing_and_textual_prefixes_are_allowed(self):
        cases = [([report('a', 'usr/node', '5'), report('b', 'usr/node/child', '0')]),
                 ([report('a', 'usr/node', '0'), report('b', 'usr/nodes/child', '0')])]
        for reports in cases:
            with self.subTest(reports=reports):
                self.assertEqual(checks.conflicts(reports), [])

    def test_archive_metadata_is_excluded_from_ancestor_ownership(self):
        for path in checks.PACKAGE_METADATA:
            with self.subTest(path=path):
                self.assertEqual(checks.conflicts([report('a', path, '0'),
                                                   report('b', path + '/child', '0')]), [])

    def test_single_archive_ancestor_validation_remains_with_package_reader(self):
        single = dict(artifact='a', members={'usr/node': dict(type='0'),
                                           'usr/node/child': dict(type='0')})
        self.assertEqual(checks.conflicts([single]), [])

    def test_small_path_space_matches_pairwise_oracle(self):
        paths = ('a', 'a/b', 'a/b/c', 'ab', 'x/y')
        for left, right, left_type, right_type in itertools.product(paths, paths, ('0', '5'), ('0', '5')):
            same_path = left == right and (left_type != '5' or right_type != '5')
            left_blocks = right.startswith(left + '/') and left_type != '5'
            right_blocks = left.startswith(right + '/') and right_type != '5'
            with self.subTest(left=left, right=right, left_type=left_type, right_type=right_type):
                findings = checks.conflicts([report('a', left, left_type), report('b', right, right_type)])
                self.assertEqual(bool(findings), same_path or left_blocks or right_blocks)

    def test_large_unrelated_path_sets_do_not_create_conflicts(self):
        reports = [dict(artifact='a', members={f'usr/a/file{i}': dict(type='0') for i in range(4000)}),
                   dict(artifact='b', members={f'usr/b/file{i}': dict(type='0') for i in range(4000)})]
        self.assertEqual(checks.conflicts(reports), [])

    def test_multimember_reports_match_an_independent_pairwise_oracle(self):
        rng = random.Random(8102)
        paths = ['a', 'a/b', 'a/b/c', 'ab', 'ab/c', 'x', 'x/y', '.PKGINFO', '.PKGINFO/child']
        kinds = ['0', '1', '2', '5', '\x00', '7']
        for case in range(3000):
            reports = [dict(artifact=rng.choice(['same', 'a', 'b']),
                            members={path: dict(type=rng.choice(kinds))
                                     for path in rng.sample(paths, rng.randrange(1, 6))})
                       for _ in range(rng.randrange(2, 5))]
            expected = False
            for left_report, right_report in itertools.combinations(reports, 2):
                for left, left_member in left_report['members'].items():
                    for right, right_member in right_report['members'].items():
                        if left in checks.PACKAGE_METADATA or right in checks.PACKAGE_METADATA:
                            continue
                        same = left == right and (left_member['type'] != '5' or right_member['type'] != '5')
                        left_blocks = left in map(str, Path(right).parents) and left_member['type'] != '5'
                        right_blocks = right in map(str, Path(left).parents) and right_member['type'] != '5'
                        expected |= same or left_blocks or right_blocks
            self.assertEqual(bool(checks.conflicts(reports)), expected, (case, reports))


if __name__ == '__main__':
    unittest.main()
