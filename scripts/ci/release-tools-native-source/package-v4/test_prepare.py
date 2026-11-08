"""NEW metadata/AST/archive controls only; never constructs or executes Source."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
EVENTS = []
PROFILE_SHA = None


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn',
                         'os.fork', 'os.posix_spawn')) or event in ('os.system', 'os.kill', 'os.killpg'):
        EVENTS.append(event)
        raise AssertionError('package-v4 DATA checks forbid actors')


sys.addaudithook(fence)
spec = importlib.util.spec_from_file_location('release_package_v4_prepare', HERE / 'prepare.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def portable_dump(value):
    """The parent pins use Python3.14's omitted empty AST fields, also on3.12."""
    if isinstance(value, ast.AST):
        fields = []
        for key, item in ast.iter_fields(value):
            if item == [] or (item is None and not (
                    key == 'value' and isinstance(value, (ast.Constant, ast.MatchSingleton)))):
                continue
            fields.append(key + '=' + portable_dump(item))
        return type(value).__name__ + '(' + ', '.join(fields) + ')'
    if isinstance(value, list):
        return '[' + ', '.join(portable_dump(item) for item in value) + ']'
    return repr(value)


def assignments(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = ast.literal_eval(node.value)
            except (TypeError, ValueError):
                pass
    return result


def bundled():
    """Read archive bodies in memory; no extraction or recipe execution."""
    raw = P.read(HERE / 'payload/native/release-sources-v1.tar', 1024**2)
    contract = json.loads(P.read(HERE / 'payload/native/release-contract-v1.json'))
    if contract['schema'] != 1:
        raise ValueError('release contract schema1 required')
    wanted = {recipe['prefix'] + '/' + name: row
              for recipe in contract['recipes'].values() for name, row in recipe['source_files'].items()}
    bodies = {}
    rebuilt = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive, tarfile.open(
            fileobj=rebuilt, mode='w', format=tarfile.USTAR_FORMAT) as output:
        members = archive.getmembers()
        if len(members) != 51 or [m.name for m in members] != sorted(wanted):
            raise ValueError('exact sorted source51 bundle required')
        for member in members:
            if not member.isfile() or member.pax_headers or member.name not in wanted:
                raise ValueError('regular finite source member required')
            row = wanted[member.name]
            if (member.mode, member.uid, member.gid, member.mtime, member.uname, member.gname) != (
                    row['mode'], 0, 0, 0, '', ''):
                raise ValueError('canonical source member metadata')
            with archive.extractfile(member) as stream:
                body = stream.read(row['bytes'] + 1)
            if P.pin(body) != {key: row[key] for key in ('bytes', 'sha256')}:
                raise ValueError('exact source member body')
            bodies[member.name] = body
            item = tarfile.TarInfo(member.name)
            item.size, item.mode = len(body), row['mode']
            output.addfile(item, io.BytesIO(body))
    if rebuilt.getvalue() != raw:
        raise ValueError('exact canonical USTAR bytes required')
    return contract, bodies, raw


class PrepareData(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(P, 'construct', side_effect=AssertionError('constructor forbidden in DATA tests'))
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.rows = json.loads(P.read(HERE / 'parent-files.json'))
        self.manifest = json.loads(P.read(HERE / 'parent-source-map.json'))
        self.payload = {path: P.read(HERE / 'payload' / path) for path in P.PAYLOAD}

    def test_pure_plan_exact201_seven_delta_194held_and_inverse(self):
        planned = P.pureplan(PROFILE_SHA)
        expected = P.compose(self.rows, self.manifest, self.payload)
        self.assertEqual(planned, expected)
        self.assertEqual(len(planned['rows']), 201)
        self.assertEqual(set(planned['changed']), P.PAYLOAD | {P.MAP})
        self.assertEqual(planned['held'], 194)
        inverse = dict(planned['rows'])
        for path in planned['changed']:
            inverse[path] = self.rows[path]
        self.assertEqual(inverse, self.rows)
        self.assertEqual(P.tree(inverse), P.PARENT_TREE)
        self.assertEqual(json.loads(planned['source_map_bytes'])['actual'], P.ACTUAL)

    def test_wrong_external_profile_pin_refused(self):
        with self.assertRaisesRegex(ValueError, 'externally reviewed'):
            P.pureplan('0' * 64)

    def test_parent_raw_rows_and_map_body_pins_join(self):
        profile = json.loads(P.read(HERE / 'profile.json'))
        for key, leaf in (('parent_files', 'parent-files.json'), ('parent_raw', 'parent.raw-commit'),
                          ('parent_source_map', 'parent-source-map.json'),
                          ('parent_function_pins', 'parent-function-pins.json')):
            self.assertEqual(P.pin(P.read(HERE / leaf)), profile[key])
        self.assertEqual(P.oid('commit', P.read(HERE / 'parent.raw-commit')), P.PARENT)
        self.assertEqual(P.tree(self.rows), P.PARENT_TREE)
        self.assertEqual(P.pin(P.encode(self.manifest)), {
            key: self.rows[P.MAP][key] for key in ('bytes', 'sha256')})

    def test_compose_refuses_parent_metadata_or_namespace_drift_without_mutation(self):
        original = copy.deepcopy(self.rows)
        for path, changed in ((next(iter(self.rows)), dict(bytes=1, sha256='0' * 64,
                                                        mode='100644', oid='0' * 40)),
                              ('unlisted', dict(bytes=0, sha256='0' * 64,
                                                mode='100644', oid='0' * 40))):
            rows = copy.deepcopy(self.rows)
            rows[path] = changed
            with self.assertRaises(ValueError):
                P.compose(rows, self.manifest, self.payload)
        manifest = copy.deepcopy(self.manifest)
        manifest['actual']['source'] = '0' * 40
        with self.assertRaises(ValueError):
            P.compose(self.rows, manifest, self.payload)
        self.assertEqual(self.rows, original)

    def test_compose_requires_exact_six_changed_regular_payloads(self):
        short = dict(self.payload)
        short.pop(next(iter(short)))
        with self.assertRaisesRegex(ValueError, 'six payload'):
            P.compose(self.rows, self.manifest, short)
        bad = dict(self.payload)
        bad['native/extra.py'] = b'extra'
        with self.assertRaises(ValueError):
            P.compose(self.rows, self.manifest, bad)

    def test_regular_data_reader_refuses_alias_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'data'
            target.write_bytes(b'bounded data')
            alias = root / 'alias'
            alias.symlink_to(target)
            with self.assertRaises(ValueError):
                P.read(alias)
            alias.unlink()
            os.link(target, alias)
            with self.assertRaises(ValueError):
                P.read(target)

    def test_output_metadata_refuses_existing_alias_and_overlapping_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'metadata-parent'
            parent.mkdir()
            output = root / 'fresh'
            self.assertEqual(P.output_target(parent, output), output)
            self.assertFalse(output.exists())
            for target in (parent, parent / 'nested', root):
                with self.subTest(target=str(target)), self.assertRaises(ValueError):
                    P.output_target(parent, target)
            alias = root / 'alias'
            alias.symlink_to(parent, target_is_directory=True)
            with self.assertRaises(ValueError):
                P.output_target(parent, alias / 'fresh')
            self.assertFalse(output.exists())

    def test_source51_bundle_identity_and_unchanged_one_MiB_cap(self):
        contract, bodies, raw = bundled()
        self.assertEqual(P.pin(raw), dict(bytes=942080,
            sha256='8acd9d4203c5c84acad374b5aba66251abe1dc237c1d38a07322c282a51403e2'))
        self.assertEqual(contract['bundle']['max_bytes'], 1024**2)
        self.assertEqual(contract['bundle']['members'], len(bodies))
        self.assertLessEqual(len(raw), contract['bundle']['max_bytes'])
        self.assertEqual({k: contract['bundle'][k] for k in ('bytes', 'sha256')}, P.pin(raw))

    def test_recipe18_33_payload12_23_check13_19_and_v2_protocol_prefix(self):
        contract, bodies, _ = bundled()
        self.assertEqual(set(contract['recipes']), {'0.1.0-1', '0.4.0-1'})
        for version, prefix, sources, payloads, checks in (
                ('0.1.0-1', 'v1', 18, 12, 13), ('0.4.0-1', 'v2', 33, 23, 19)):
            row = contract['recipes'][version]
            self.assertEqual((row['prefix'], len(row['source_files']), len(row['payload_files']),
                              row['expected_test_count']), (prefix, sources, payloads, checks))
            self.assertEqual(bodies[prefix + '/LICENSE'], bodies['v1/LICENSE'])
            self.assertEqual(P.pin(bodies[prefix + '/LICENSE']), {
                key: row['MIT_license'][key] for key in ('bytes', 'sha256')})
        self.assertEqual(contract['recipes']['0.4.0-1']['product_merge'],
                         '0dc457ae4a785bfa273890d84114d52f0cf87c17')
        self.assertEqual(contract['recipes']['0.4.0-1']['product_merge_tree'],
                         'c40548c13d014c15716d04a6dfca5fefcd5a779d')
        self.assertEqual(contract['recipes']['0.4.0-1']['source_commit'],
                         'c393c38043bd34f2380ceab55434a59c2d3183d1')

    def test_target_PKGBUILD31_local_source_pins_join_without_execution(self):
        contract, bodies, _ = bundled()
        text = bodies['v2/PKGBUILD'].decode()
        source = shlex.split(re.search(r'^source=\((.*?)\)$', text, re.M | re.S)[1])
        hashes = shlex.split(re.search(r'^sha256sums=\((.*?)\)$', text, re.M | re.S)[1])
        self.assertEqual(len(source), 31)
        self.assertEqual(len(hashes), 31)
        self.assertEqual(set(source), set(contract['recipes']['0.4.0-1']['source_files']) - {'.SRCINFO', 'PKGBUILD'})
        for name, digest in zip(source, hashes):
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
            self.assertEqual(hashlib.sha256(bodies['v2/' + name]).hexdigest(), digest)
        self.assertIn('pkgver=0.4.0\n', text)
        self.assertIn('license=(MIT)', text)
        self.assertIn('check()', text)
        self.assertIn('test_package.py', text)

    def test_target17_provenance_MIT_and23_payload_rows_join(self):
        contract, bodies, _ = bundled()
        recipe = contract['recipes']['0.4.0-1']
        provenance = json.loads(bodies['v2/source-provenance.json'])
        self.assertEqual(provenance['schema_version'], 1)
        self.assertEqual(provenance['files'], recipe['runtime_closure'])
        self.assertEqual(len(provenance['files']), 17)
        self.assertEqual(provenance['license_file_sha256'], P.pin(bodies['v2/LICENSE'])['sha256'])
        payload = json.loads(bodies['v2/payload-map.json'])['files']
        self.assertEqual(set(payload), set(recipe['payload_files']))
        self.assertEqual(len(payload), 23)
        for path, row in recipe['payload_files'].items():
            self.assertEqual(payload[path], dict(mode=row['mode'], source=row['source']))
            self.assertEqual(P.pin(bodies['v2/' + row['source']]), {
                key: row[key] for key in ('bytes', 'sha256')})
        for name, row in provenance['files'].items():
            self.assertEqual(row['license'], 'MIT')
            self.assertRegex(row['origin_commit'], r'^[0-9a-f]{40}$')
            self.assertEqual(P.pin(bodies['v2/' + name]), {
                key: row[key] for key in ('bytes', 'sha256')})
            self.assertEqual(recipe['payload_files'][row['installed_path']]['source'], name)

    def test_transport7_dependencies_and_launcher9_literal_pins_join(self):
        contract, bodies, _ = bundled()
        recipe = contract['recipes']['0.4.0-1']
        deps = json.loads(bodies['v2/endpoint__dependencies.json'])['files']
        self.assertEqual(len(deps), 7)
        for path, wanted in deps.items():
            found = [name for name, row in recipe['runtime_closure'].items() if row['origin_path'] == path]
            self.assertEqual(len(found), 1)
            self.assertEqual(P.pin(bodies['v2/' + found[0]]), wanted)
        launcher = assignments(bodies['v2/cachy-asahi-release-tools'])
        self.assertEqual(launcher['VERSION'], '0.4.0')
        self.assertEqual(len(launcher['TRANSPORT_FILES']), 9)
        for path, (size, digest) in launcher['TRANSPORT_FILES'].items():
            installed = 'usr/lib/cachy-asahi/release-tools-v4/' + path
            source = recipe['payload_files'][installed]['source']
            self.assertEqual(P.pin(bodies['v2/' + source]), dict(bytes=size, sha256=digest))
        self.assertEqual(len(launcher['LEGACY']), 5)

    def test_frozen_base349_signature_retirement_resource_contract_fields(self):
        contract, _, _ = bundled()
        self.assertEqual(contract['expected349'], dict(bytes=6800, count=349,
            sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'))
        self.assertEqual(contract['genuine_parent'], '111f14d2b21b220d86912d5ead978848c7ef1cb0')
        retirement_path = 'scripts/virtual/owned_process_retirement_v2.py'
        retirement_row = self.rows[retirement_path]
        self.assertEqual(contract['retirement_profile'], dict(
            bytes=retirement_row['bytes'], caller='BUNDLED_FIXED_RETIREMENT_COMMANDS',
            group_census='RESERVED_LEADER_ONLY', name=self.manifest['release_retirement_profile'],
            path=retirement_path, sha256=retirement_row['sha256']))
        self.assertEqual(contract['operation'], 'release-alpm-upgrade-v1')
        self.assertEqual(contract['dependencies']['libarchive'], '3.8.9-1')
        self.assertEqual(len(contract['dependencies']), 7)
        self.assertEqual(contract['invocation']['signature_policy'], 'Required/Required')
        self.assertEqual(contract['invocation']['inventory_counts'], [349, 350, 350, 350, 349])
        self.assertEqual(contract['invocation']['payload_counts'], [12, 23, 12, 0])
        self.assertIn('all8 commands', contract['invocation']['lifecycle'])
        self.assertTrue(contract['dispatch_prerequisite']['all1154_data_required'])
        self.assertEqual(contract['makepkg_config']['checks'], 'REQUIRED_ENABLED')
        for key in ('ALPM', 'GPG', 'native'):
            self.assertEqual(contract[key], 'NOT_RUN')
        self.assertTrue(all(value is None for value in contract['actual'].values()))

    def test_parent_function_predicates_held_with_exact_whitelist(self):
        pins = json.loads(P.read(HERE / 'parent-function-pins.json'))
        changes = {
            'native/release_tools_v1.py': {'source_policy', 'recipe_members', 'business'},
            'native/release_alpm_v1.py': {'inside'},
            'native/release_reader_v1.py': {'release_contract', 'retained_release_alpm'},
            'native/release_projection_v1.py': set(),
        }
        added = {
            'native/release_tools_v1.py': {'endpoint_tar', 'stable_endpoint', 'endpoint_business'},
            'native/release_alpm_v1.py': set(),
            'native/release_reader_v1.py': {'retained_business_features'},
            'native/release_projection_v1.py': set(),
        }
        for path, before in pins.items():
            nodes = [node for node in ast.parse(self.payload[path]).body if isinstance(node, ast.FunctionDef)]
            after = {node.name: hashlib.sha256(portable_dump(node).encode()).hexdigest() for node in nodes}
            self.assertEqual(len(after), len(nodes), path)
            self.assertTrue(set(before) <= set(after), path)
            self.assertEqual(set(after) - set(before), added[path], path)
            self.assertEqual({name for name in before if before[name] != after[name]}, changes[path], path)

    def test_portable_AST_dump_matches_reviewed_314_format(self):
        if sys.version_info >= (3, 14):
            for path in ('native/release_tools_v1.py', 'native/release_alpm_v1.py',
                         'native/release_reader_v1.py', 'native/release_projection_v1.py'):
                for node in ast.parse(self.payload[path]).body:
                    if isinstance(node, ast.FunctionDef):
                        self.assertEqual(portable_dump(node), ast.dump(node, include_attributes=False))
        else:
            self.assertEqual(portable_dump(ast.parse('def x():\n pass\n').body[0]),
                             "FunctionDef(name='x', args=arguments(), body=[Pass()])")

    def test_import_and_DATA_workflow_never_call_constructor_or_checkout_Source(self):
        tree = ast.parse(P.read(HERE / 'prepare.py'))
        top_calls = [node for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)]
        self.assertEqual(top_calls, [])
        own = ast.parse(P.read(HERE / 'test_prepare.py'))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and node.func.attr == 'construct' for node in ast.walk(own)))
        workflow = P.read(HERE.parents[3] / '.github/workflows/release-tools-v4-native-source.yml').decode()
        self.assertIn("python: ['3.12', '3.14']", workflow)
        self.assertIn('test_prepare.py', workflow)
        self.assertIn('test_reader_data.py', workflow)
        for forbidden in ('--parent-source', '--execute-root-constructor', 'workflow_dispatch:',
                          'sudo ', 'makepkg ', 'ref: 686958', '.ci-inputs/', 'run: python prepare.py'):
            self.assertNotIn(forbidden, workflow)
        self.assertEqual(EVENTS, [])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile-sha256', required=True)
    args = parser.parse_args()
    PROFILE_SHA = args.profile_sha256
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PrepareData))
    if EVENTS or result.testsRun != 16 or result.skipped or not result.wasSuccessful():
        raise SystemExit(1)
