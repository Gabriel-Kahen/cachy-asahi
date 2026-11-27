# SPDX-License-Identifier: MIT
"""Source-only controls for both sealed releases. No build or install actors."""

import ast
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare as P

REPO = Path(__file__).resolve().parents[3]
CONTRACT = r"""
import hashlib
import json
from pathlib import Path
import sys

root, version, other, other_map = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), sys.argv[4]
sys.path.insert(0, str(root / 'native'))
import common
import build_tools_alpm_v2 as actor
import build_tools_probe_v2 as probe
import build_tools_projection_v2 as projection
import build_tools_reader_v2 as reader
import build_tools_tools_v2 as tools

def refuse(call, expected):
    try:
        call()
    except ValueError as error:
        assert expected in str(error), (str(error), expected)
    else:
        raise AssertionError('unexpected acceptance: ' + expected)

def pin(raw):
    return hashlib.sha256(raw).hexdigest()

manifest = root / 'native/source-map.json'
map_sha = pin(manifest.read_bytes())
source = common.verify_source(root, map_sha)
assert len(source['files']) == 199 and source == reader.build_tools_local_binding(map_sha)
assert reader.PRODUCERS == projection.PRODUCERS
assert all(pin((root / name).read_bytes()) == expected for name, expected in reader.PRODUCERS.items())
refuse(lambda: common.verify_source(root, other_map), 'whole source map differs')
refuse(lambda: reader.build_tools_local_binding(other_map), 'Root-bound local SourceMap')

policy, baseline = tools.source_policy(root)
assert policy == reader.build_tools_contract()
assert len(baseline.splitlines()) == 349
assert common.input_contract(root)[2] == baseline
recipe = policy['recipe']
assert tools.VERSION == probe.VERSION == recipe['version'] == version
assert recipe['expected_test_names'] == list(tools.TEST_NAMES)
members = tools.recipe_members(root, policy)
assert set(members) == {'recipe/' + name for name in tools.SOURCE_FILES}
assert len(tools.SOURCE_FILES) == (15 if version == '0.1.1-2' else 16)
assert len(recipe['payload_files']) == tools.PAYLOAD_COUNT == (11 if version == '0.1.1-2' else 12)
assert policy['invocation']['inventory_counts'] == [349, 350, 349]
assert policy['invocation']['signature_policy'] == 'Required/Required'
assert policy['resources']['consumer']['memory_bytes'] == 4 * 1024**3
assert len(tools.fixture_members(members['recipe/check-inputs.tar.gz'], policy)) == 14
dockerfile = actor.dockerfile('USER alarm\nWORKDIR /tmp\n', map_sha)
launcher, = [json.loads(line.removeprefix('RUN ')) for line in dockerfile.splitlines() if line.startswith('RUN [')]
assert launcher[:5] == ['/usr/bin/bash', '--noprofile', '--norc', '-p', '-c']
assert 'test "$BASHPID" -eq 1' in launcher[-1]

opposite = json.loads((other / 'native/build-tools-contract-v2.json').read_bytes())
def model_log(names):
    lines = ['==> Starting check()...']
    lines.extend(f'{name} (__main__.PackageTests.{name}) ... ok' for name in names)
    lines.extend((f'Ran {len(names)} tests in 1.01s', 'OK'))
    return ('\n'.join(lines) + '\n').encode()

checks = model_log(recipe['expected_test_names'])
assert actor.check_result(checks) == reader.build_tools_check_result(checks)
for check in (actor.check_result, reader.build_tools_check_result):
    refuse(lambda: check(model_log(opposite['recipe']['expected_test_names'])), 'package checks')
    refuse(lambda: check(checks + b'FAILED (failures=1)\n'), 'without skip')
requests = probe.requests('/usr/bin/cachy-asahi-build-tools', '/fixtures', '/work', policy)
assert tuple(row[0] for row in requests) == probe.STEPS
assert len(requests) == policy['probe']['observations_per_location']
assert len({args[0] for _, args, _ in requests}) == policy['probe']['commands']
assert policy['probe']['commands'] == (5 if version == '0.1.1-2' else 6)
assert policy['probe']['observations_per_location'] == (6 if version == '0.1.1-2' else 9)

producer = root / 'native/build_tools_probe_v2.py'
old = producer.read_bytes()
foreign = (other / producer.relative_to(root)).read_bytes()
producer.write_bytes(foreign)
try:
    refuse(lambda: common.verify_source(root, map_sha), 'source bytes/mode differ')
    expected = ('bounded local Source leaf' if len(foreign) > len(old) else 'every local Source200 body/mode held')
    refuse(lambda: reader.build_tools_local_binding(map_sha), expected)
    producer.write_bytes(b'#' + old[1:] if not old.startswith(b'#') else b' ' + old[1:])
    refuse(lambda: reader.build_tools_local_binding(map_sha), 'every local Source200 body/mode held')
finally:
    producer.write_bytes(old)

print(version, 'sealed source contract independently checked')
"""


class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = cls.enterClassContext(tempfile.TemporaryDirectory(prefix="build-tools-arm4k-data-"))
        cls.root = Path(cls.storage)
        cls.parent = P.parent_files(REPO)
        cls.sources = {release: P.render(REPO, release, cls.parent) for release in P.RELEASES}
        for release, files in cls.sources.items():
            P.write_source(cls.root / release, files)

    def test_exact_closed_deltas_and_read_only_input_identity(self):
        parent, _ = self.parent
        for version, source in self.sources.items():
            with self.subTest(version=version):
                self.assertEqual(set(source), set(parent))
                self.assertEqual({name for name in source if source[name] != parent[name]}, P.CHANGED)
                self.assertEqual(source[P.WORKFLOWS[0]], source[P.WORKFLOWS[1]])
                workflow = source[P.WORKFLOWS[0]][0]
                self.assertIn(b"options: [build-tools-alpm-v2]", workflow)
                self.assertIn(b'test "$(getconf PAGESIZE)" = 4096', workflow)
                self.assertLess(workflow.index(b'test "$(getconf PAGESIZE)" = 4096'),
                                workflow.index(b"Seed the six exact retained inputs"))
                self.assertEqual(source, P.render(REPO, version, self.parent))
                contract = json.loads(source[P.CONTRACT][0])
                self.assertTrue(all(value is None for value in contract["actual"].values()))
                self.assertEqual(contract["package_origin"]["commit"], P.PACKAGE_COMMIT)
                self.assertEqual(contract["bundle"]["sha256"], P.RELEASES[version]["bundle_sha256"])

    def test_actors_and_matching_readers_bind_own_release_only(self):
        for version, source in self.sources.items():
            other, = self.sources.keys() - {version}
            other_map = P.pin(self.sources[other][P.MAP][0])["sha256"]
            with self.subTest(version=version):
                result = subprocess.run([sys.executable, "-I", "-B", "-c", CONTRACT, str(self.root / version),
                                         version, str(self.root / other), other_map],
                                        capture_output=True, text=True, timeout=25)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_actor_and_reader_exact_image_and_cleanup_seams(self):
        for version, source in self.sources.items():
            with self.subTest(version=version):
                actor = ast.parse(source[P.ACTOR][0])
                check = next(node for node in actor.body if isinstance(node, ast.FunctionDef) and node.name == "inside")
                implementation = ast.unparse(check)
                self.assertLess(implementation.index("page_bytes'] == 4096"), implementation.index("T.source_policy(source)"))
                self.assertIn("SigLevel='Required', LocalFileSigLevel='Required'", implementation)
                reader = source[P.READER][0]
                self.assertIn(b"native['page_bytes'] == 4096", reader)
                self.assertIn(b"runner['page_size'] == 4096", reader)
                self.assertIn(b"PASS_EXACT_OWNED_RESOURCES_RETIRED", reader)

    def test_unissued_outputs_are_no_clobber(self):
        version = "0.1.1-2"
        source = self.sources[version]
        with self.assertRaises(FileExistsError):
            P.write_source(self.root / version, source)
        self.assertEqual((self.root / version / P.MAP).read_bytes(), source[P.MAP][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
