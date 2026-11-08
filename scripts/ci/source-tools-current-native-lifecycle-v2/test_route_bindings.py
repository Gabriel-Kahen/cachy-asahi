#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the concrete published-input joins; no Source constructor or reader."""
import hashlib
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
MAP = 'native/source-map.json'
SEAMS = {MAP, 'native/common.py', 'native/owner.py', 'native/invocation.json',
    '.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def undo_owner(raw):
    """Remove exactly the explicit v2 dispatch branches, recovering frozen419."""
    replacements = (
        ("operation in ('source184','source-tools-alpm-v1','source-tools-alpm-v2')", "operation in ('source184','source-tools-alpm-v1')"),
        ("choices=('source184','source-tools-alpm-v1','source-tools-alpm-v2')", "choices=('source184','source-tools-alpm-v1')"),
        ("if operation in ('source-tools-alpm-v1','source-tools-alpm-v2'):report['operation']=operation", "if operation=='source-tools-alpm-v1':report['operation']=operation"),
        ("        elif operation=='source-tools-alpm-v2':\n            from source_tools_alpm_v2 import prepare,dockerfile as release_dockerfile\n            prepare(root,context,args.map_sha256);dockerfile=release_dockerfile(dockerfile,args.map_sha256)\n", ''),
        ("('/source/native/source_tools_guest_v2.py' if operation=='source-tools-alpm-v2' else '/source/native/source_tools_guest_v1.py' if operation=='source-tools-alpm-v1' else '/source/native/guest.py')", "('/source/native/source_tools_guest_v1.py' if operation=='source-tools-alpm-v1' else '/source/native/guest.py')"),
        ("if operation in ('source-tools-alpm-v1','source-tools-alpm-v2') else 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY'", "if operation=='source-tools-alpm-v1' else 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY'"),
        ("        if operation in ('source-tools-alpm-v1','source-tools-alpm-v2'):\n            try:\n                result_path=output/('journey/'+operation+'/result.json')", "        if operation=='source-tools-alpm-v1':\n            try:\n                result_path=output/'journey/source-tools-alpm-v1/result.json'"),
        ("            elif operation=='source-tools-alpm-v2':\n                from source_tools_projection_v2 import project\n", ''),
    )
    text = raw.decode()
    for after, before in replacements:
        if text.count(after) != 1:
            raise ValueError('one explicit owner route seam required')
        text = text.replace(after, before, 1)
    return text.encode()


class ConcreteRouteBindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = json.loads((HERE / 'profile.json').read_bytes())
        cls.manifest = json.loads((HERE / 'overlay' / MAP).read_bytes())

    def test_all_eighteen_overlay_and_211_map_rows_match_pinned_bodies(self):
        files = {path.relative_to(HERE/'overlay').as_posix(): path.read_bytes()
                 for path in (HERE/'overlay').rglob('*') if path.is_file()}
        self.assertEqual(set(files), set(self.profile['overlay']))
        self.assertEqual(len(files), 18)
        self.assertEqual(len(self.manifest['files']), 211)
        self.assertEqual(self.manifest['source_tools_operation'], 'source-tools-alpm-v2')
        self.assertEqual(self.manifest['actual'], dict(source=None, ref=None, run=None))
        for name, raw in files.items():
            self.assertEqual(self.profile['overlay'][name], dict(bytes=len(raw), sha256=sha(raw), mode=0o644))
            if name != MAP:
                self.assertEqual(self.manifest['files'][name], self.profile['overlay'][name])
        self.assertEqual(sha(files[MAP]), self.profile['source_map_sha256'])

    def test_all_194_unlisted_parent_rows_and_v1_identities_remain_exact(self):
        held = {name: row for name, row in self.profile['parent_files'].items() if name not in SEAMS}
        self.assertEqual(len(held), 194)
        self.assertTrue(all(self.manifest['files'][name] == row for name, row in held.items()))
        self.assertEqual(self.manifest['source_tools_v1_frozen_base']['source'],
                         '419d27f1d519dc91789a322385eb603bd1ca1f09')

    def test_owner_inverse_is_byte_exact_not_a_resource_policy_rewrite(self):
        raw = (HERE/'overlay/native/owner.py').read_bytes()
        old = undo_owner(raw)
        self.assertEqual(sha(old), self.profile['parent_files']['native/owner.py']['sha256'])
        self.assertEqual(len(old), self.profile['parent_files']['native/owner.py']['bytes'])

    def test_common_namespace_seam_and_both_workflow_inverses_are_exact(self):
        current = (HERE/'overlay/native/common.py').read_bytes()
        before = b"rows = manifest['files']; need(MAP not in rows and len(rows) <= 200, 'finite nonrecursive source map')"
        after = b"rows = manifest['files']; need(MAP not in rows and (len(rows) == 211 if manifest.get('source_tools_operation') == 'source-tools-alpm-v2' else len(rows) <= 200), 'finite nonrecursive source map')"
        self.assertEqual(current.count(after), 1)
        old = current.replace(after, before, 1)
        self.assertEqual(sha(old), self.profile['parent_files']['native/common.py']['sha256'])
        for name in ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml'):
            raw = (HERE/'overlay'/name).read_bytes()
            restored = raw.replace(b'options: [source184, source-tools-alpm-v1, source-tools-alpm-v2]',
                                   b'options: [source184, source-tools-alpm-v1]', 1)
            restored = restored.replace(sha(current).encode(), sha(old).encode(), 1)
            self.assertEqual(sha(restored), self.profile['parent_files'][name]['sha256'])

    def test_nine_producers_current_contract_and_reader_paths_join(self):
        pinfile = json.loads((HERE/'overlay/native/source-tools-producers-v2.json').read_bytes())
        self.assertEqual(len(pinfile['files']), 9)
        for name, row in pinfile['files'].items():
            self.assertEqual(row, self.manifest['files'][name])
        contract = json.loads((HERE/'overlay/native/source-tools-contract-v2.json').read_bytes())
        self.assertEqual(contract['recipe']['version'], '0.2.0-1')
        self.assertEqual(len(contract['recipe']['source_files']), 16)
        self.assertEqual(len(contract['recipe']['payload_files']), 18)
        self.assertEqual(contract['recipe']['expected_test_count'], 28)
        self.assertTrue(all(value is None for value in contract['actual'].values()))
        invocation = json.loads((HERE/'overlay/native/invocation.json').read_bytes())
        route = invocation['operations']['source-tools-alpm-v2']
        self.assertEqual(route['matching_reader'], 'native/source_tools_reader_v2.py')
        self.assertEqual(route['actual'], dict(source=None, ref=None, run=None))
        self.assertEqual(route['argv_extra'], ['--operation', 'source-tools-alpm-v2'])

    def test_genuine_parent_raw_commit_and_current_recipe_bundle_pin(self):
        raw = (HERE/'parent-commit.txt').read_bytes()
        self.assertEqual(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                         self.profile['genuine_parent'])
        self.assertEqual(raw.splitlines()[0], b'tree '+self.profile['parent_tree'].encode())
        contract = json.loads((HERE/'overlay/native/source-tools-contract-v2.json').read_bytes())
        bundle = (HERE/'overlay/native/source-tools-sources-v2.tar').read_bytes()
        self.assertEqual(dict(bytes=len(bundle), sha256=sha(bundle)),
                         {key: contract['bundle'][key] for key in ('bytes', 'sha256')})
        self.assertEqual(contract['bundle']['members'], 16)
        self.assertLessEqual(contract['bundle']['max_bytes'], 1024**2)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ConcreteRouteBindings))
    print(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        evidence='CONCRETE_SOURCE_PROFILE_BINDINGS_NOT_CONSTRUCTOR_OR_NATIVE',
        Source_constructor=0, actual_reader=0, native='NOT_RUN'), sort_keys=True))
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped))
