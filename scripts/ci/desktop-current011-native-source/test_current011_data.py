#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prospective DATA/AST controls; no Source constructor or native/reader entry."""
import ast
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SUPPORT = HERE if (HERE / 'payload').is_dir() else HERE.parent / 'candidate/scripts/ci/desktop-current011-native-source'
CONTRACT = SUPPORT / 'payload/native/desktop-contract-v1.json'
if not CONTRACT.is_file():
    CONTRACT = HERE.parent.parent / 'reader/candidate/native/desktop-contract-v1.json'
ACTIVE = False


def deny_actors(event, args):
    if ACTIVE and (event.startswith(('subprocess.', 'socket.')) or event in
                   {'os.system', 'os.posix_spawn', 'os.fork', 'os.exec'}):
        raise AssertionError('DATA controls deny actor: ' + event)


sys.addaudithook(deny_actors)


@contextmanager
def data_only():
    global ACTIVE
    old = ACTIVE
    ACTIVE = True
    try:
        yield
    finally:
        ACTIVE = old



def canonical_ast(node):
    # Optional empty AST fields differ across supported Python parser versions.
    if isinstance(node, ast.AST):
        return (type(node).__name__, [(name, canonical_ast(value)) for name, value in ast.iter_fields(node)
                                     if value is not None and value != []])
    if isinstance(node, list):
        return [canonical_ast(value) for value in node]
    return (type(node).__name__, repr(node))


def ast_pin(node):
    return hashlib.sha256(json.dumps(canonical_ast(node), separators=(',', ':')).encode()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load('_current011_constructor_data', HERE / 'prepare.py')
T = load('_current011_tools_data', SUPPORT / 'payload/native/desktop_tools_v1.py')
sys.modules['prepare'] = P
U = load('_current011_publisher_data', HERE / 'publish.py')


class DataControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='current011-DATA-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def inputs(self):
        root = self.root / 'input-DATA'
        shutil.copytree(SUPPORT / 'fixtures', root)
        for name in ('native/desktop-contract-v1.json', 'native/desktop-sources-v1.tar'):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(CONTRACT if name == 'native/desktop-contract-v1.json' else SUPPORT / 'payload' / name, target)
        return root

    def functions(self, relative, names, scope):
        tree = ast.parse((SUPPORT / 'payload' / relative).read_bytes())
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in nodes}, set(names))
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<prospective-DATA>', 'exec'), scope)
        return scope

    def factory_data(self):
        head, base, tree = '1' * 40, '2' * 40, '3' * 40
        raw = ('tree ' + tree + '\nparent ' + base + '\nparent ' + head + '\n\nSynthetic DATA only\n').encode()
        merged = P.oid(b'commit', raw).hex()
        files = {name: (name.encode(), 0o644) for name in ('prepare.py', 'publish.py', 'profile.json', 'test_current011_data.py')}
        rows = P.body_rows(files)
        expected = dict(checks=dict(total=3, success=2, skipped=1, failure=0, cancelled=0, pending=0),
                        workflows=dict(total=1, success=1, skipped=0, failure=0, cancelled=0, pending=0), workflow_ids=[123])
        ci = dict(schema=1, role='ROOT_FACTORY_CI_TERMINAL', head=head, attempt=1, reruns=0,
                  status='EXACT_HEAD_COMPLETE_CI_GREEN', checks=expected['checks'], workflows=expected['workflows'],
                  runs=[dict(workflow_id=123, head=head, attempt=1, status='completed', conclusion='success', run_id=456)])
        raw_pin = dict(path='factory-merge.raw', **P.pin(raw))
        proof = dict(schema=1, role='ROOT_FACTORY_MERGE_PROOF', head=head, merge=merged, tree=tree,
                     parents=[base, head], raw_commit=raw_pin)
        authority = dict(schema=1, role='ROOT_CURRENT011_SOURCE_PUBLICATION', ref=U.REF, parent=P.PARENT,
            product_merge=U.PRODUCT_MERGE, package_source_commit='446f657723c2e4443f8a3fe8ccbe592ebbaf282b',
            profile_sha256=rows['profile.json']['sha256'], maintained_namespace=rows,
            factory=dict(head=head, merge=merged, raw_commit=raw_pin, expected_CI=expected,
                         CI_receipt=dict(path='CI.json', **P.pin(P.encoded(ci))),
                         Root_merge_proof=dict(path='merge.json', **P.pin(P.encoded(proof)))))
        return authority, ci, proof, raw, files

    def test_publisher_requires_whole_pinned_genuine_receipts_before_git(self):
        authority, ci, proof, raw, files = self.factory_data()
        with data_only():
            U.publication_authority(authority, authority['profile_sha256'])
        for key in ('CI_receipt', 'Root_merge_proof', 'raw_commit', 'expected_CI'):
            bad = copy.deepcopy(authority); bad['factory'][key] = None
            with data_only(), self.assertRaises(ValueError):
                U.publication_authority(bad, bad['profile_sha256'])
        with data_only(), self.assertRaises(FileNotFoundError):
            U.factory_evidence(authority, self.root)
        for name, body in [('CI.json', P.encoded(ci)), ('merge.json', P.encoded(proof)), ('factory-merge.raw', raw)]:
            (self.root / name).write_bytes(body); (self.root / name).chmod(0o644)
        with data_only():
            self.assertEqual(U.factory_evidence(authority, self.root)['raw'], raw)
        (self.root / 'CI.json').write_bytes(P.encoded(dict(ci, head='4' * 40)))
        with data_only(), self.assertRaisesRegex(ValueError, 'externally pinned'):
            U.factory_evidence(authority, self.root)

    def test_publisher_rejects_wrong_ci_counts_attempts_heads_and_workflows(self):
        authority, ci, proof, raw, files = self.factory_data()
        variants = [dict(ci, head='4' * 40), dict(ci, attempt=2), dict(ci, reruns=1), dict(ci, attempt=True),
                    dict(ci, runs=[]), dict(ci, status='SELF_DECLARED_GREEN')]
        for field, replacement in [('failure', 1), ('total', 99), ('success', True)]:
            bad = copy.deepcopy(ci); bad['checks'][field] = replacement; variants.append(bad)
        for field, replacement in [('workflow_id', 999), ('attempt', 2), ('head', '4' * 40), ('conclusion', 'failure')]:
            bad = copy.deepcopy(ci); bad['runs'][0][field] = replacement; variants.append(bad)
        for bad in variants:
            with data_only(), self.assertRaises(ValueError):
                U.evidence_data(authority, bad, proof, raw)

    def test_publisher_rejects_wrong_raw_merge_parents_tree_and_proof(self):
        authority, ci, proof, raw, files = self.factory_data()
        with data_only():
            U.evidence_data(authority, ci, proof, raw)
        for bad in (dict(proof, parents=[authority['factory']['head']]),
                    dict(proof, parents=list(reversed(proof['parents']))), dict(proof, tree='4' * 40),
                    dict(proof, merge='4' * 40)):
            with data_only(), self.assertRaises(ValueError):
                U.evidence_data(authority, ci, bad, raw)
        with data_only(), self.assertRaises(ValueError):
            U.evidence_data(authority, ci, proof, raw + b'changed')

    def test_publisher_fake_git_joins_merge_main_namespace_and_ancestry(self):
        authority, ci, proof, raw, files = self.factory_data()
        evidence = U.evidence_data(authority, ci, proof, raw)
        main, remote = '5' * 40, 'synthetic-only'
        listing = b''.join(('100644 blob ' + row['blob'] + '\t' + U.PREFIX + name).encode() + b'\0'
                           for name, row in authority['maintained_namespace'].items())
        bodies = {P.row(body, mode)['blob']: body for body, mode in files.values()}
        def fake(mode):
            def git(*args, **kwargs):
                command = args[0]
                if command == 'rev-parse':
                    out = (('6' * 40 if mode == 'tracking' and args[1] == 'refs/remotes/origin/main' else main) + '\n').encode()
                elif command == 'ls-remote': out = (('6' * 40 if mode == 'remote' else main) + '\trefs/heads/main\n').encode()
                elif command == 'status': out = b' M synthetic' if mode == 'dirty' else b''
                elif command == 'merge-base':
                    return SimpleNamespace(returncode=int(mode == 'nonancestor' or (mode == 'product_nonancestor' and args[2] == U.PRODUCT_MERGE)), stdout=b'')
                elif command == 'ls-tree': out = listing + (b'100644 blob ' + b'7' * 40 + b'\t' + U.PREFIX.encode() + b'extra\0' if mode == 'namespace' or (mode == 'current_namespace' and args[3] == main) else b'')
                elif command == 'cat-file': out = raw + (b'drift' if mode == 'raw' else b'') if args[1] == 'commit' else bodies[args[2]]
                else: raise AssertionError('unexpected synthetic Git request ' + repr(args))
                return SimpleNamespace(returncode=0, stdout=out)
            return git
        with data_only(), patch.object(P, 'snapshot', return_value=files):
            U.factory_gate(authority, evidence, fake('good'), remote, main)
            for mode in ('tracking', 'remote', 'dirty', 'nonancestor', 'product_nonancestor', 'namespace', 'current_namespace', 'raw'):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    U.factory_gate(authority, evidence, fake(mode), remote, main)
        altered = dict(files); altered['profile.json'] = (b'drifted', 0o644)
        with data_only(), patch.object(P, 'snapshot', return_value=altered), self.assertRaisesRegex(ValueError, 'HERE/profile'):
            U.factory_gate(authority, evidence, fake('good'), remote, main)

    def test_publisher_receipt_output_cannot_mutate_verified_inputs(self):
        stage, repo = self.root / 'stage', self.root / 'repository'
        for output in (stage / 'source/receipts', stage, stage.parent, P.HERE / 'receipts',
                       repo / U.PREFIX / 'receipts', repo / '.git/receipts'):
            with data_only(), self.assertRaises(ValueError):
                U.disjoint_receipts(stage, repo, output)
        with data_only():
            U.disjoint_receipts(stage, repo, repo / 'artifacts/private/receipts')

    def test_original_predicate_function_asts_remain_exact(self):
        expected = json.loads((SUPPORT / 'fixtures/legacy-asts.json').read_bytes())
        for path, rows in expected.items():
            methods = {node.name: ast_pin(node)
                       for node in ast.parse((SUPPORT / 'payload' / path).read_bytes()).body if isinstance(node, ast.FunctionDef)}
            for name, digest in rows.items():
                with self.subTest(path=path, method=name):
                    self.assertEqual(methods[name], digest)

    def test_only_fixed_current_namespace_and_old_constants_held(self):
        current = T.current011_namespace()
        self.assertEqual((T.VERSION, T.UPDATE_VERSION), ('0.1.0-1', '0.1.0-2'))
        self.assertEqual((current.VERSION, current.UPDATE_VERSION), ('0.1.1-1', '0.1.1-2'))
        self.assertEqual(current.SOURCE_ARCHIVE_SHA256, '11a59ada0d99f1202694ed98adb7891594b27a7048e39a99d5590e425fc31986')
        self.assertEqual(current.package_selection(), dict(schema=1, selection='desktop-current011',
            version='0.1.1-1', update_version='0.1.1-2', expected_test_count=91,
            source_archive_sha256=current.SOURCE_ARCHIVE_SHA256))

    def test_current_policy_and_exact_bundle_are_data_only(self):
        root = self.inputs()
        with data_only():
            policy, lock = T.current011_source_policy(root)
            members = T.current011_recipe_members(root, policy)
            generation = T.current011_update_generation(policy, members)
        self.assertEqual(len(lock.splitlines()), 349)
        self.assertEqual(len(members), 5)
        self.assertEqual(set(members), {'recipe/PKGBUILD', 'recipe/export_source.py', 'recipe/test_export_source.py',
            'recipe/cachy-asahi-desktop-tools-0.1.1.tar.gz', 'update/PKGBUILD'})
        self.assertEqual(generation['version_from'], '0.1.1-1')
        self.assertEqual(generation['version_to'], '0.1.1-2')
        self.assertEqual(generation['changed_sources'], ['PKGBUILD'])
        self.assertTrue(generation['unchanged_payload'])
        self.assertEqual(members['update/PKGBUILD'], T.update_recipe_bytes(members['recipe/PKGBUILD']))
        self.assertEqual(policy['recipe']['payload_files'], policy['update_recipe'].get('payload_files', policy['recipe']['payload_files']))

    def test_current_contract_does_not_make_legacy_route_current(self):
        with data_only(), self.assertRaisesRegex(ValueError, 'frozen recipe'):
            T.source_policy(self.inputs())

    def test_current_policy_refuses_old_versions_counts_and_unbound_product(self):
        root = self.inputs()
        path = root / 'native/desktop-contract-v1.json'
        initial = json.loads(path.read_bytes())
        variants = []
        for field, value in [('expected_test_count', 81), ('expected_test_count', True),
                             ('archive', 'cachy-asahi-desktop-tools-0.1.0-1-any.pkg.tar.zst')]:
            altered = copy.deepcopy(initial); altered['recipe'][field] = value; variants.append(altered)
        altered = copy.deepcopy(initial); altered['product']['accepted_main'] = None; variants.append(altered)
        altered = copy.deepcopy(initial); altered['current011']['version'] = '0.1.0-1'; variants.append(altered)
        for value in variants:
            path.write_bytes(T.encoded(value))
            with self.subTest(value=value['recipe']['expected_test_count']), data_only(), self.assertRaises(ValueError):
                T.current011_source_policy(root)

    def test_current_owner_flag_requires_exact_operation_and_owned_v2(self):
        scope = self.functions('native/owner.py', ['current011_selection'], {'need': P.need})
        good = dict(desktop_current011=True, operation='desktop-alpm-v1', desktop_owned_retirement_v2=True)
        self.assertEqual(scope['current011_selection'](SimpleNamespace(**good)), 'desktop-current011')
        for update in [dict(desktop_current011=False), dict(desktop_current011='true'),
                       dict(operation='source184'), dict(desktop_owned_retirement_v2=False)]:
            with self.subTest(update=update), self.assertRaises(ValueError):
                scope['current011_selection'](SimpleNamespace(**(good | update)))

    def test_current_dockerfile_requires_opt_in_and_keeps_pid1_layout(self):
        scope = self.functions('native/desktop_alpm_v1.py', ['dockerfile', 'current011_dockerfile'],
                               {'need': P.need, 'json': json, 're': re})
        scope['_LEGACY_DOCKERFILE'] = scope['dockerfile']
        base = 'FROM SYNTHETIC\nUSER alarm\nWORKDIR /tmp\n'
        with self.assertRaises(ValueError): scope['current011_dockerfile'](base, 'a' * 64)
        current = scope['current011_dockerfile'](base, 'a' * 64, owned_retirement_v2=True)
        self.assertIn('--owned-retirement-v2 --current011 --map-sha256 ', current)
        self.assertIn('/usr/bin/bash', current)
        self.assertIn('test \\\"$$\\\" -eq 1', current)
        self.assertIn('wait \\\"$desktop_owner\\\"', current)
        self.assertEqual(current.replace('--current011 ', ''), scope['dockerfile'](base, 'a' * 64, owned_retirement_v2=True))

    def test_wrong_inside_flag_refuses_before_any_actor_or_source_read(self):
        scope = self.functions('native/desktop_alpm_v1.py', ['current011_inside'], {'need': P.need})
        with data_only(), self.assertRaisesRegex(ValueError, 'explicit owned-retirement'):
            scope['current011_inside'](self.root / 'missing', 'a' * 64, owned_retirement_v2=False)

    def test_constructor_wrong_selection_refuses_before_io(self):
        for selection, owned in [('desktop-owned-retirement-v2', True), ('desktop-current011', False),
                                 ('desktop-current011', 'true')]:
            with self.subTest(selection=selection, owned=owned), data_only(), patch.object(P, 'snapshot', side_effect=AssertionError('NO_SOURCE_ENTRY')):
                with self.assertRaisesRegex(ValueError, 'explicit current package'):
                    P.materialize(self.root / 'missing', self.root / 'output', selection=selection,
                                  owned_retirement_v2=owned, profile_sha256='a' * 64)
        self.assertFalse((self.root / 'output').exists())

    def test_profile_closed_current_reader_and_prospective_actuals(self):
        names = sorted(P.ALLOWED_CHANGES - {'native/reader.py'})
        names += ['synthetic/leaf' + str(i) for i in range(200 - len(names))]
        before = {name: P.row(b'before', 0o644) for name in names}
        before['native/source-map.json']['sha256'] = P.PARENT_MAP_SHA256
        after = copy.deepcopy(before)
        changed = P.ALLOWED_CHANGES - {'native/reader.py'}
        for name in changed:
            after[name] = P.row(b'after', 0o644)
        current = json.loads(CONTRACT.read_bytes())
        reader = dict(selection=P.READER_SELECTION, path='native/desktop_reader_v1.py',
            runtime_selection='desktop-owned-retirement-v2', payload_contract='native/desktop-contract-v1.json',
            payload_files=6, package_version='0.1.1-1', update_version='0.1.1-2', expected_test_count=91,
            package_source_commit=current['product']['package_source_commit'],
            source_archive_sha256=T.CURRENT011_SOURCE_ARCHIVE_SHA256,
            private_layout='desktop-alpm-v1-public-data-v1', process_layout='bash-pid1-direct-python-child-v1',
            scope='FINITE_NATURAL_RETIREMENT_OPTIONAL_QUALIFIED_ZERO_CHILD')
        value = dict(schema=1, kind='desktop-current011-source-proposal-v1', selection=P.SELECTION,
            actual=dict(P.NULL_ACTUAL), matching_reader_actual=dict(P.NULL_READER), Source_generated=False,
            package_input=dict(accepted_main='2561dcebee3ba70b924c9c4b42e4316b2994d832',source_commit='446f657723c2e4443f8a3fe8ccbe592ebbaf282b'),
            parent=dict(commit=P.PARENT, tree=P.PARENT_TREE, map_sha256=P.PARENT_MAP_SHA256,
                raw_commit=dict(path='parent-commit.raw', bytes=335, sha256=P.PARENT_RAW_SHA256)),
            before200=before, after200=after, payload={name:'payload/' + name for name in changed},
            output=dict(tree='a' * 40, map_sha256=after['native/source-map.json']['sha256']), reader_contract=reader)
        with data_only():
            self.assertIs(P.validate_profile(value), value)
        variants = []
        for key, replacement in [('package_source_commit', 'a' * 40), ('expected_test_count', True),
                                 ('scope', 'ANY_VERSION'), ('extra', 'waiver')]:
            altered = copy.deepcopy(value); altered['reader_contract'][key] = replacement; variants.append(altered)
        altered = copy.deepcopy(value); altered['actual']['source'] = 'a' * 40; variants.append(altered)
        for replacement in (None, {}, dict(accepted_main=None, source_commit='446f657723c2e4443f8a3fe8ccbe592ebbaf282b'),
                            dict(value['package_input'], unknown='waiver'), dict(value['package_input'], accepted_main=True)):
            altered = copy.deepcopy(value); altered['package_input'] = replacement; variants.append(altered)
        for altered in variants:
            with data_only(), self.assertRaises(ValueError):
                P.validate_profile(altered)

    def test_integrated_profile_binds_closed_payload_and_map(self):
        raw = (HERE / 'profile.json').read_bytes()
        with data_only():
            value = P.profile(P.pin(raw)['sha256'])
            payload = P.snapshot(HERE / 'payload', value['payload'])
            self.assertEqual(P.body_rows(payload), {n: value['after200'][n] for n in value['payload']})
            mapped = P.document(payload['native/source-map.json'][0])
            self.assertEqual(mapped['files'], {n: r for n, r in P.simple_rows(value['after200']).items()
                                               if n != 'native/source-map.json'})
            self.assertEqual(mapped['desktop_current011_reader'], value['reader_contract'])
            self.assertEqual(mapped['actual'], dict(source=None, ref=None, run=None))
            self.assertEqual(P.raw_parent(value), (HERE / 'parent-commit.raw').read_bytes())

    def test_constructor_caps_and_unknown_leaf_before_read(self):
        self.assertEqual((P.MAX_FILES, P.MAX_FILE, P.MAX_TOTAL), (200, 64 * 1024**2, 96 * 1024**2))
        root = self.root / 'tiny-DATA'; root.mkdir(); (root / 'ok').write_bytes(b'ok')
        os.mkfifo(root / 'unknown')
        with data_only(), self.assertRaisesRegex(ValueError, 'unlisted Source leaf'):
            P.snapshot(root, {'ok': {}})

    def test_explicit_workflow_input_and_invocation_only(self):
        raw = (SUPPORT / 'payload/.github/workflows/native-arm-build.yml').read_text()
        self.assertEqual(raw, (SUPPORT / 'payload/.github/workflows/native-arm-developer-workflows.yml').read_text())
        self.assertIn('default: source184', raw)
        self.assertIn('desktop_current011:\n', raw)
        self.assertIn('[[ "$NATIVE_OPERATION" == desktop-alpm-v1 && "$NATIVE_OWNED_RETIREMENT_V2" == true ]]', raw)
        invocation = json.loads((SUPPORT / 'payload/native/invocation.json').read_bytes())
        current = invocation['operations']['desktop-current011-owned-v2']
        self.assertEqual(current['argv_extra'], ['--operation', 'desktop-alpm-v1', '--desktop-owned-retirement-v2', '--desktop-current011'])
        self.assertTrue(all(v is None for v in current['actual'].values()))
        self.assertEqual(invocation['operations']['default'], 'source184')

    def test_package_marker_env_logs_and_test_count91_are_literal(self):
        tree = ast.parse((SUPPORT / 'payload/native/desktop_alpm_v1.py').read_bytes())
        methods = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        for name in ('current011_build_pair', 'current011_build_update'):
            values = [n.value for n in ast.walk(methods[name]) if isinstance(n, ast.Constant)]
            self.assertIn(91, values)
            self.assertNotIn(81, values)
        tools = ast.parse((SUPPORT / 'payload/native/desktop_tools_v1.py').read_bytes())
        business = next(n for n in tools.body if isinstance(n, ast.FunctionDef) and n.name == 'current011_business')
        literals = {n.value for n in ast.walk(business) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        self.assertTrue({'env_unset_capture', 'env_unset_audit', 'env_unset_path_refusal', 'env_unset_absolute_capture',
                         'env_unset_restored_capture', 'env_unset_malformed_refusal'} <= literals)
        self.assertIn('env --unset=PATH /usr/bin/tool-link %F', literals)
        self.assertIn('env --unset=PATH PATH=/usr/bin tool-link %F', literals)

    def test_source_entries_and_publisher_have_explicit_root_gates(self):
        constructor = (HERE / 'prepare.py').read_text()
        publisher = (HERE / 'publish.py').read_text()
        self.assertIn("'--root-source-authorized'", constructor)
        self.assertIn("'--root-source-publish-authorized'", publisher)
        self.assertIn("'--no-force'", publisher)
        self.assertIn("selected['GIT_INDEX_FILE']", publisher)
        self.assertIn("'COMMIT-ONCE.intent.json'", publisher)
        self.assertIn("'PUSH-ONCE.intent.json'", publisher)
        self.assertIn('rename(source_fd, b\'stage\', output_fd, os.fsencode(output.name), 1)', constructor)

    def test_unbound_factory_authority_refuses_before_actor_or_source_entry(self):
        tree = ast.parse((HERE / 'publish.py').read_bytes())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'publication_authority')
        scope = dict(P=P, re=re, REF='refs/heads/codex/native-desktop-current011-owned-v2-v1')
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), '<authority-DATA>', 'exec'), scope)
        pending = dict(schema=1, role='ROOT_CURRENT011_SOURCE_PUBLICATION', ref=None, parent=P.PARENT,
            product_merge='2561dcebee3ba70b924c9c4b42e4316b2994d832',
            package_source_commit='446f657723c2e4443f8a3fe8ccbe592ebbaf282b', profile_sha256='a' * 64,
            factory=dict(head=None, merge=None, CI_receipt_sha256=None), maintained_namespace=None)
        for update in ({}, dict(ref=scope['REF'])):
            with data_only(), patch.object(P, 'snapshot', side_effect=AssertionError('NO_SOURCE_ENTRY')):
                with self.assertRaises(ValueError):
                    scope['publication_authority'](pending | update, 'a' * 64)


if __name__ == '__main__':
    unittest.main(verbosity=2)
