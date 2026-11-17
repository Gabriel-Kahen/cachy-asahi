# SPDX-License-Identifier: MIT
"""Fenced public DATA/AST controls; no Root issuance, native role or HTTP.

The optional Source196 operands are public unissued Source/profile DATA. All
delegations below are synthetic MODEL inputs to an assumed external admission
boundary, never authentic Root requests. Success means DATA acceptance only.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
FAMILY = 'scripts/ci/first-login-enrollment-native-source'
LAUNCHER = FAMILY+'/payload/native/hosted_current_v3.py'
CONTEXT = FAMILY+'/payload/native/delegated_context_v4.py'
DOMAIN = FAMILY+'/payload/native/material_domain_current_v3.py'
WORKFLOW = '.github/workflows/native-arm-current-onboarding-delegated-v3.yml'
REGISTRY = FAMILY+'/successor_v6_source/program.json'
FIXED = {
    LAUNCHER: dict(bytes=66263, sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97'),
    DOMAIN: dict(bytes=42462, sha256='ead51cfa3bcf4b74fbccc8c469926c71fbb72edefcf9525b297e1737fde3ab8f'),
    WORKFLOW: dict(bytes=8949, sha256='4aaa31fae8b6665d502372467d3da5ceef0bb30553d2dfb1ac9f38a41fc90165'),
}
SOURCE196 = dict(files=196, bytes=45726789, tree='e85302474308dbf579b79bd6d501f5ad86b66bbb',
                 source_map=dict(bytes=38809, sha256='a8f5ab1c1ceee9f3450634e14dd172d7421d6fe49d8e17ce680cb4cfe43da86a'))
SOURCE_ROOT = PROFILE = None
NOW = 1800000000


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn')) or event in (
            'os.system', 'os.fork', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit'):
        raise AssertionError('public DATA controls cannot enter a role: '+event)


sys.dont_write_bytecode = True
sys.addaudithook(fence)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


L = load('MODEL_v6_trusted_launcher', REPO/LAUNCHER)
C = load('MODEL_v6_actual_context', REPO/CONTEXT)


def workflow_blocks(raw):
    blocks = []
    for part in raw.decode().split("python3 -I -B - <<'PY'\n")[1:]:
        lines = []
        for line in part.splitlines():
            if line.strip() == 'PY':
                break
            if not line.startswith(' '*10):
                raise ValueError('reviewed workflow Python indentation')
            lines.append(line[10:])
        blocks.append(ast.parse('\n'.join(lines)))
    if len(blocks) != 2:
        raise ValueError('exact two workflow DATA/argv blocks')
    return blocks


def data_prefix():
    """Run the actual launcher statements through Source/hosted DATA admission.

    Stop before native identity, executable probes, staging or control creation.
    No predicate or call from the selected prefix is replaced or weakened.
    """
    tree = ast.parse((REPO/LAUNCHER).read_bytes())
    function = copy.deepcopy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'preflight'))
    ends = [i for i, n in enumerate(function.body) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
            and any(isinstance(a, ast.Constant) and a.value == 'actual hosted Source/ref/workflow/stage selectors before GET or privilege'
                    for a in n.value.args)]
    if len(ends) != 1:
        raise ValueError('one exact preactor Source/hosted DATA boundary')
    function.name = 'preflight_public_data'
    function.body = function.body[:ends[0]+1]+[ast.parse('return H, d, root').body[0]]
    scope = dict(L.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), '<actual-launcher-DATA-prefix>', 'exec'), scope)
    return scope['preflight_public_data'], scope


def model_delegation(root, programs, materials, policy):
    """Explicit synthetic selectors; they never identify the unissued Source."""
    limits = policy['context']
    return dict(schema=4, kind=C.DELEGATION, issuer='Root', approved=True,
                scope='CURRENT_PRIVATE_STAGE_ONLY', stage='backend', nonce='a'*64,
                binding=dict(source='b'*40, ref='refs/heads/codex/MODEL-unissued-source196', run=None, job=None,
                             attempt=1, source_lock=L.pin((root/'source-map.json').read_bytes())),
                issued_epoch=NOW-1, expires_epoch=NOW+7200,
                programs=programs, materials=materials,
                policy=dict(member=policy['_member'], **L.pin((root/policy['_member']).read_bytes())),
                capability=dict(operation=C.OPERATION, stage='backend', allow_provisional_context=True,
                                allow_provisional_image_checks=True, allow_pair_adoption=False,
                                **policy['stage_capabilities']['backend']),
                context_limits=limits, image_ids=dict(backend=None, ui=None, lifecycle=None),
                hosted=dict(repository='example/MODEL', workflow_ref='example/MODEL/'+WORKFLOW+'@refs/heads/codex/MODEL-unissued-source196',
                            workflow_sha='b'*40, job_key='current', job_name='MODEL current',
                            runner_environment='github-hosted', runner_os='Linux', runner_arch='ARM64'), **C.FINAL)


def call_inputs(root, main, d):
    raw = L.encoded(d)
    r = dict(launcher=d['programs']['hosted_launcher'], delegation_json=raw.decode(), delegation_pin=L.pin(raw),
             control_name='cachy-current-hosted-'+d['nonce'])
    h, b = d['hosted'], d['binding']
    env = dict(GITHUB_WORKSPACE=str(root), RUNNER_TEMP=str(main.parent), GITHUB_SHA=b['source'], GITHUB_REF=b['ref'],
               GITHUB_RUN_ATTEMPT='1', GITHUB_REPOSITORY=h['repository'], GITHUB_JOB=h['job_key'],
               GITHUB_WORKFLOW_REF=h['workflow_ref'], GITHUB_WORKFLOW_SHA=h['workflow_sha'],
               RUNNER_ARCH='ARM64', RUNNER_OS='Linux', RUNNER_ENVIRONMENT='github-hosted', GITHUB_ACTIONS='true')
    return r, root, main, main.parent/r['control_name'], env, NOW


def git_tree(root, rows):
    def object_id(kind, body):
        return hashlib.sha1(kind+b' '+str(len(body)).encode()+b'\0'+body).digest()
    tree = {}
    for name, row in rows.items():
        parent = tree
        for part in Path(name).parts[:-1]:
            parent = parent.setdefault(part, {})
        parent[Path(name).name] = (row['mode'], object_id(b'blob', (root/name).read_bytes()))
    def encode(node):
        parts = []
        for name, value in sorted(node.items(), key=lambda item: (item[0]+('/' if isinstance(item[1], dict) else '')).encode()):
            mode, oid = (0o40000, encode(value)) if isinstance(value, dict) else value
            git_mode = b'40000' if mode == 0o40000 else b'100755' if mode == 0o755 else b'100644'
            parts.append(git_mode+b' '+name.encode()+b'\0'+oid)
        return object_id(b'tree', b''.join(parts))
    return encode(tree).hex()


class Controls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='MODEL-v6-trusted-cascade-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root, self.main = self.base/'MODEL-source', self.base/'MODEL-main'
        self.root.mkdir(); self.main.mkdir()
        path = self.main/LAUNCHER; path.parent.mkdir(parents=True); path.write_bytes((REPO/LAUNCHER).read_bytes())
        ceilings = dict(max_command_seconds=600, total_seconds=3600, builder_cpus=4,
                        builder_memory_bytes=2*1024**3, builder_pids=512, command_rows=400)
        self.policy = dict(context=dict(metadata_query_seconds=30, metadata_max_bytes=1024**2,
                                       max_context_age_seconds=300, max_delegation_seconds=7560),
                           stage_capabilities={s: ceilings for s in ('backend', 'ui', 'lifecycle')})
        self.files = {CONTEXT: (REPO/CONTEXT).read_bytes(), LAUNCHER: (REPO/LAUNCHER).read_bytes(),
                      'MODEL/owner.py': b'# MODEL inert owner\n', 'MODEL/image.py': b'# MODEL inert image\n',
                      'MODEL/executor.py': b'# MODEL inert executor\n', 'MODEL/material.DATA': b'MODEL public DATA\n',
                      'MODEL/policy.json': L.encoded(self.policy),
                      REGISTRY: L.encoded(dict(schema=6, kind='DELEGATED_CURRENT_CAPTURE_PROGRAM_REGISTRY_V6', actual=dict(source=None, ref=None, run=None)))}
        self.seal()
        def row(name): return dict(member=name, **L.pin(self.files[name]))
        programs = dict(context=row(CONTEXT), hosted_launcher=row(LAUNCHER), owner=row('MODEL/owner.py'),
                        image=row('MODEL/image.py'), image_executor=row('MODEL/executor.py'))
        self.d = model_delegation(self.root, programs, dict(model=row('MODEL/material.DATA')),
                                  dict(self.policy, _member='MODEL/policy.json'))

    def seal(self):
        for name, raw in self.files.items():
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); path.chmod(0o644)
        raw = L.encoded(dict(schema=1, kind='CURRENT_ONBOARDING_CLOSED_SOURCE_V3', operation=C.OPERATION,
                             actual=dict(source=None, ref=None, run=None, job=None),
                             files={n: dict(L.pin(b), mode=0o644) for n, b in self.files.items()}))
        for name in ('source-map.json', 'source.lock.json'):
            path = self.root/name; path.write_bytes(raw); path.chmod(0o644)

    def test_fixed_runtime_bodies_and_workflow_remain_exact(self):
        for name, pin in FIXED.items():
            with self.subTest(member=name): self.assertEqual(L.pin((REPO/name).read_bytes()), pin)

    def test_workflow_separates_source_and_main_then_invokes_exact_main_direct_argv(self):
        text = (REPO/WORKFLOW).read_text()
        self.assertIn('ref: ${{ steps.bound.outputs.source }}', text)
        self.assertIn('ref: ${{ steps.bound.outputs.main }}', text)
        self.assertIn('path: .current-trusted-main-transfer', text)
        self.assertNotIn('push:', text); self.assertNotIn('pull_request:', text)
        bind, invoke = workflow_blocks(text.encode())
        self.assertIn("os.environ['GITHUB_SHA'] == source", ast.unparse(bind))
        transfer = self.root/'.current-trusted-main-transfer'; transfer.mkdir()
        main = self.base/'MODEL-transferred-main'
        env = dict(GITHUB_WORKSPACE=str(self.root), TRUSTED_MAIN_PATH=str(main), ROOT_REQUEST_PATH='/MODEL/external-root-request',
                   ROOT_REQUEST_SHA256='d'*64, CONTROL_PATH='/MODEL/control')
        with patch.dict(os.environ, env), patch.object(L.subprocess, 'run', return_value=SimpleNamespace(returncode=23)) as run:
            with self.assertRaises(SystemExit) as exited:
                exec(compile(invoke, '<actual-workflow-direct-argv>', 'exec'), {})
        self.assertEqual(exited.exception.code, 23)
        self.assertTrue(main.is_dir()); self.assertFalse(transfer.exists())
        run.assert_called_once_with(['/usr/bin/python3', '-I', '-B', str(main/LAUNCHER), 'launch',
                                     '--request', env['ROOT_REQUEST_PATH'], '--request-sha256', 'd'*64,
                                     '--source-root', str(self.root), '--main-root', str(main), '--control-root', '/MODEL/control'],
                                    stdin=L.subprocess.DEVNULL, timeout=7800)
        # Equal workflow body pins do not register a future Main workflow or
        # turn the synthetic b*40 selector into an actual Source/Main commit.
        self.assertNotIn('git', run.call_args.args[0])

    def test_real_context_v4_accepts_whole_schema6_mapped_data_before_any_role(self):
        prefix, _ = data_prefix()
        H, d, root = prefix(*call_inputs(self.root, self.main, self.d))
        self.assertEqual(d, self.d); self.assertEqual(root, self.root)
        self.assertEqual(H.CONTEXT, C.CONTEXT)
        self.assertEqual(L.decode((root/REGISTRY).read_bytes())['schema'], 6)
        self.assertFalse((self.base/('cachy-current-hosted-'+'a'*64)).exists())

    def test_actual_full_preflight_source_join_refuses_environment_before_native_or_actor(self):
        args = list(call_inputs(self.root, self.main, self.d)); args[4]['GITHUB_SHA'] = '0'*40
        imports = []
        original = L.program
        def actual_program(root, row, name):
            imports.append(name)
            return original(root, row, name)
        with patch.object(L, 'program', side_effect=actual_program), self.assertRaisesRegex(ValueError, 'actual hosted Source/ref/workflow'):
            L.preflight(*args)
        self.assertEqual(imports, ['current_hosted_delegated_context'])
        self.assertFalse(args[3].exists())

    def test_outer_request_stays_schema3_while_delegation_is_v4_and_registry_is_v6(self):
        request = call_inputs(self.root, self.main, self.d)[0]
        request.update(schema=3, kind='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3', issuer='Root', approved=True,
                       trusted_main_commit='c'*40, staged_root='/MODEL/no-material-domain-entered',
                       staged_inputs=dict(path='/MODEL/no-material-read', bytes=1, sha256='d'*64),
                       authorization=dict(jobs_metadata=True, privileged_controller=True, launcher_limits=L.LIMITS))
        path = self.base/'MODEL-synthetic-request.json'; raw = L.encoded(request); path.write_bytes(raw)
        self.assertEqual(L.request(path, L.pin(raw)['sha256']), request)
        self.assertEqual(L.decode(request['delegation_json'])['schema'], 4)
        self.assertEqual(L.decode(self.files[REGISTRY])['schema'], 6)
        with self.assertRaisesRegex(ValueError, 'external whole Root launch request pin'): L.request(path, '0'*64)
        for key, value in (('schema', 6), ('approved', False), ('trusted_main_commit', None), ('authorization', {})):
            changed = dict(request, **{key: value}); raw = L.encoded(changed); path.write_bytes(raw)
            with self.subTest(key=key), self.assertRaises(ValueError): L.request(path, L.pin(raw)['sha256'])

    def test_root_whole_pins_authority_and_selector_mismatches_hold_in_data_prefix(self):
        prefix, _ = data_prefix()
        for mode in ('launcher-pin', 'delegation-pin', 'map-pin', 'descriptor-pin', 'unapproved', 'acceptance', 'null-source', 'null-ref',
                     'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ATTEMPT', 'RUNNER_ARCH'):
            d = copy.deepcopy(self.d)
            if mode == 'launcher-pin': d['programs']['hosted_launcher']['sha256'] = '0'*64
            elif mode == 'map-pin': d['binding']['source_lock']['sha256'] = '0'*64
            elif mode == 'descriptor-pin': d['materials']['model']['sha256'] = '0'*64
            elif mode == 'unapproved': d['approved'] = False
            elif mode == 'acceptance': d['hardware_acceptance'] = True
            elif mode == 'null-source': d['binding']['source'] = None
            elif mode == 'null-ref': d['binding']['ref'] = None
            args = list(call_inputs(self.root, self.main, d))
            if mode == 'delegation-pin': args[0]['delegation_pin']['sha256'] = '0'*64
            elif mode in args[4]: args[4][mode] = 'MODEL-WRONG'
            with self.subTest(mode=mode), self.assertRaises(ValueError): prefix(*args)
            self.assertFalse(args[3].exists())

    def test_source_namespace_body_mode_map_alias_and_registry_drift_refuse(self):
        prefix, _ = data_prefix()
        for mode in ('extra', 'body', 'mode', 'alias', 'registry'):
            path = self.root/('MODEL/extra.DATA' if mode == 'extra' else REGISTRY if mode == 'registry' else
                              'source.lock.json' if mode == 'alias' else 'MODEL/material.DATA')
            previous = path.read_bytes() if path.exists() else None
            if mode == 'mode': path.chmod(0o755)
            else: path.write_bytes(b'MODEL drift\n')
            try:
                with self.subTest(mode=mode), self.assertRaises(ValueError): prefix(*call_inputs(self.root, self.main, self.d))
            finally:
                if previous is None: path.unlink()
                else: path.write_bytes(previous); path.chmod(0o644)

    def test_source196_public_whole_closure_and_external_profile_if_supplied(self):
        if SOURCE_ROOT is None:
            self.skipTest('public Source196/profile operands not supplied; portable MODEL controls still run')
        profile_raw = PROFILE.read_bytes(); profile = L.decode(profile_raw)
        root = SOURCE_ROOT
        registry = L.decode((root/profile['program']['path']).read_bytes())
        self.assertEqual(profile['schema'], 6); self.assertEqual(registry['schema'], 6)
        self.assertEqual(profile['capture_commit'], '441832e1d687255434c9001d603d400e4932f26a')
        for key in ('files', 'bytes', 'source_map'):
            self.assertEqual(profile[key], SOURCE196[key])
        self.assertEqual(profile['prospective_tree'], SOURCE196['tree'])
        self.assertEqual(L.pin((root/'source-map.json').read_bytes()), SOURCE196['source_map'])
        self.assertEqual(profile['program']['path'], REGISTRY)
        self.assertEqual({k: profile['program'][k] for k in ('bytes', 'sha256')}, L.pin((root/REGISTRY).read_bytes()))
        self.assertTrue(all(v is None for v in profile['actual'].values()))
        self.assertTrue(all(v is None for v in registry['actual'].values()))
        self.assertEqual(profile['delegation_programs'], registry['delegation_programs'])
        for name, expected in FIXED.items():
            self.assertEqual(L.pin((root/name).read_bytes()), expected)
        # The frozen Source workflow body is distinct provenance from whatever
        # workflow Root may later register on Main, even when bodies are equal.
        self.assertEqual(registry['roles']['workflow'], dict(member=WORKFLOW, **FIXED[WORKFLOW]))
        self.assertIsNone(profile['actual']['source']); self.assertIsNone(profile['actual']['ref']); self.assertIsNone(profile['actual']['run'])
        policy_member = registry['roles']['policy']['member']
        policy = dict(L.decode((root/policy_member).read_bytes()), _member=policy_member)
        d = model_delegation(root, profile['delegation_programs'], dict(profile['materials'], **profile['staging_materials']), policy)
        prefix, _ = data_prefix()
        H, checked, actual_root = prefix(*call_inputs(root, self.main, d))
        self.assertEqual(checked, d); self.assertEqual(actual_root, root)
        _, rows = H.source(checked, root)
        self.assertEqual(len(rows)+2, SOURCE196['files'])
        self.assertEqual(sum(v['bytes'] for v in rows.values())+2*SOURCE196['source_map']['bytes'], SOURCE196['bytes'])
        tree_rows = dict(rows, **{name: dict(SOURCE196['source_map'], mode=0o644) for name in ('source-map.json', 'source.lock.json')})
        self.assertEqual(git_tree(root, tree_rows), SOURCE196['tree'])
        self.assertEqual(PROFILE.read_bytes(), profile_raw)
        self.assertTrue(all(v is None for v in L.decode(PROFILE.read_bytes())['actual'].values()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--profile', type=Path)
    args, unittest_args = parser.parse_known_args()
    if bool(args.source_root) != bool(args.profile):
        parser.error('--source-root and --profile are required together')
    if args.source_root:
        SOURCE_ROOT, PROFILE = args.source_root.resolve(), args.profile.resolve()
        if PROFILE.is_relative_to(SOURCE_ROOT):
            parser.error('external public profile must remain outside the closed Source')
    unittest.main(argv=[sys.argv[0], *unittest_args], verbosity=2)
