#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced Source-readonly proposal controls; ordinary DATA files only."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parent
RETAINED = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114')
PARENT = Path(os.environ.get('LLHTTP_V5_PARENT', str(RETAINED/'llhttp-filesystem-observation-DATA-20261117-r4')))
PUBLIC = RETAINED/'Root-llhttp85-native-result-r1/public-files/llhttp-reference-owned-public-ek_30fy4'
PREFIX = 'scripts/ci/llhttp-reference-native-source/owner/'
GUARD = "    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')"
MAP = '9a4b43eedecd09e5e1edc68677620ccd17a38a1bed8218fdb429b65b04715645'
NONCE = '0123456789abcdef0123456789abcdef'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn',
        'fcntl.flock', 'os.pidfd_open', 'resource.setrlimit',
    ):
        raise RuntimeError('fenced DATA actor forbidden: '+event)


sys.addaudithook(fence)
P = module(HERE/'prepare.py', 'llhttp_v5_prepare_control')
Q = module(HERE/'source_readonly.py', 'llhttp_v5_readonly_control')
D = module((PARENT/PREFIX/'data.py') if PARENT.exists() else HERE.parent/'owner/data.py',
           'llhttp_v5_existing_declarations')


class Controls(unittest.TestCase):
    def setUp(self):
        self.area = tempfile.TemporaryDirectory(prefix='llhttp-v5-MODEL-DATA-', dir='/home/gabe')
        self.addCleanup(self.area.cleanup)
        self.base = Path(self.area.name)
        self.root, self.out = self.base/'MODEL_SOURCE', self.base/'MODEL_OWNED'
        self.root.mkdir(); self.out.mkdir()

    def argv(self, kind='owner'):
        limits = dict(memory_bytes=2147483648, AS_bytes=2147483648, cpus=1, pids=256)
        command = ['/usr/bin/python3', str(self.root/'MODEL_payload.py'), '--MODEL-DATA']
        args = D.service_args(NONCE, kind, limits, command, self.out/'volume'/(kind+'.log'), 1000, 1000)
        args.insert(3, '--description=cachy-llhttp-reference-owned-'+NONCE+'-'+kind)
        return args

    def retained(self):
        if not PARENT.exists():
            self.skipTest('genuine retained public Source85 DATA required')
        return P.parent_bodies(PARENT)[0]

    def test_actual92_identifies_source_failure_without_tmp_waiver(self):
        if not PUBLIC.exists():
            self.skipTest('genuine retained actual92 public DATA required')
        lines = (PUBLIC/'owner.log').read_text().splitlines()
        self.assertEqual(len(lines), 2)
        mount = json.loads(lines[0].removeprefix('MOUNT_CLASS: '))
        failure = json.loads(lines[1].removeprefix('HOLD_PAYLOAD: '))
        for label in ('root', 'tmp', 'var_tmp'):
            row = mount['paths'][label]
            self.assertIs(row['cover']['mount_readonly'], True)
            self.assertIs(row['statvfs_readonly'], True)
            self.assertIs(row['writable'], False)
        source, work = (mount['paths'][k] for k in ('source', 'work'))
        self.assertEqual(source['cover']['mount_class'], 'other')
        self.assertIs(source['cover']['mount_readonly'], False)
        self.assertIs(source['statvfs_readonly'], False)
        self.assertIs(source['writable'], True)
        self.assertIs(work['writable'], True)
        self.assertIs(mount['confinement_acceptance'], False)
        message = b'actual owner writable filesystem restricted to quota work domain'
        self.assertEqual(failure, dict(exception='ValueError', kind='LLHTTP_PAYLOAD_PHASE_HASH_ONLY_V3',
            message_bytes=64, message_prefix_bytes=64, message_prefix_sha256=hashlib.sha256(message).hexdigest(),
            phase='readonly-filesystem', truncated=False))
        report = json.loads((PUBLIC/'owner-report.json').read_bytes())
        self.assertEqual((report['status'], report['native_pair'], report['source_map_sha256']), ('HOLD', 'NOT RUN', MAP))
        self.assertIsNone(report['Root_acceptance'])
        self.assertEqual(report['cleanup']['errors'], [])
        self.assertIs(report['cleanup']['owned_storage_absent'], True)
        owner = report['cleanup']['services']['owner']
        self.assertEqual(owner['retirement'], 'STOPPED_EMPTY_FAILED_OWNER')
        self.assertIs(owner['payload_success'], False)
        self.assertIs(owner['unit_reset'], False)
        self.assertEqual(owner['payload_exit'], 2)
        args = json.loads((PUBLIC/'command-012.json').read_bytes())['argv']
        self.assertIn('--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup', args)
        self.assertFalse(any(a.startswith('--property=BindReadOnlyPaths=') for a in args))

    def test_both_service_binds_are_exact_copy_with_unchanged_write_properties(self):
        for kind in ('owner', 'daemon'):
            with self.subTest(kind=kind):
                before = self.argv(kind); saved = before[:]
                after = Q.project_service(before, self.root, self.out, NONCE, kind)
                position = before.index('--')
                self.assertIsNot(after, before)
                self.assertEqual(before, saved)
                self.assertEqual(after, before[:position]+['--property=BindReadOnlyPaths='+str(self.root)]+before[position:])
                for prefix in ('--property=ReadWritePaths=', '--property=ReadOnlyPaths=', '--property=ProtectSystem='):
                    self.assertEqual([a for a in after if a.startswith(prefix)], [a for a in before if a.startswith(prefix)])
                self.assertEqual(after[after.index('--')+1:], before[position+1:])

    def test_alias_overlap_noncanonical_and_unknown_service_refuse(self):
        alias = self.base/'MODEL_ALIAS'; alias.symlink_to(self.root, target_is_directory=True)
        file = self.base/'MODEL_FILE'; file.write_text('DATA')
        cases = [(alias, self.out), (self.root, alias), (self.root, self.root),
                 (self.root, self.root/'nested'), (self.out/'nested', self.out),
                 (Path('relative'), self.out), (self.root, Path('relative')),
                 (str(self.root)+'/../MODEL_SOURCE', self.out),
                 (self.root, str(self.out)+'//nested'), (str(self.root)+'//', self.out),
                 (str(self.root)+'/.', self.out), (self.root, str(self.out)+'/'),
                 (file, self.out), (self.root, file)]
        for root, out in cases:
            with self.subTest(root=str(root), out=str(out)), self.assertRaises(ValueError):
                Q.project_service(self.argv(), root, out, NONCE, 'owner')
        for kind in ('other', '', 'OWNER'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                Q.project_service(self.argv(), self.root, self.out, NONCE, kind)
        with self.assertRaises(ValueError):
            Q.project_service(self.argv(), self.root, self.out, 'invalid', 'owner')

    def test_conflicting_duplicate_or_unknown_properties_refuse(self):
        for kind in ('owner', 'daemon'):
            args = self.argv(kind)
            props = [a for a in args if a.startswith(('--property=ProtectSystem=', '--property=ReadOnlyPaths=', '--property=ReadWritePaths='))]
            bad = [args+["--"], args[:args.index('--')],
                   ['--property=ReadWritePaths='+str(self.root) if a.startswith('--property=ReadWritePaths=') else a for a in args],
                   ['--property=ProtectSystem=false' if a.startswith('--property=ProtectSystem=') else a for a in args],
                   ['--property=ReadOnlyPaths=/tmp /var/tmp' if a.startswith('--property=ReadOnlyPaths=') else a for a in args]]
            extras = props+['--property=BindPaths='+str(self.root),
                '--property=BindReadOnlyPaths='+str(self.base/'WRONG_ROOT'),
                '--property=ReadWritePaths='+str(self.out/'volume')+' '+str(self.root)]
            for extra in extras:
                bad.append(args[:args.index('--')]+[extra]+args[args.index('--'):])
            for value in bad:
                with self.subTest(kind=kind, argv=value), self.assertRaises(ValueError):
                    Q.project_service(value, self.root, self.out, NONCE, kind)

    def test_complete85_inverse_and_source93_canonical_metadata(self):
        old = self.retained()
        self.assertEqual((len(old), sum(map(len, old.values()))), (85, 1120826))
        self.assertEqual(hashlib.sha256(old['source-map.json']).hexdigest(), MAP)
        code, seams = P.projections(old)
        for name, raw in code.items():
            text = raw.decode()
            for seam in reversed(seams[name]):
                self.assertEqual(text.count(seam['after']), 1)
                text = text.replace(seam['after'], seam['before'])
            self.assertEqual(text.encode(), old[name])
        output = self.base/'Source93'
        result = P.construct(PARENT, output)
        bodies = {str(n.relative_to(output)): n.read_bytes() for n in output.rglob('*') if n.is_file()}
        self.assertEqual(P.inverse(bodies), old)
        self.assertEqual((len(bodies), result['files']), (93, 93))
        self.assertLess(len(bodies), 96)
        self.assertLess(sum(map(len, bodies.values())), 2*1024**2)
        self.assertTrue(all(v is None for v in result['actual'].values()))
        self.assertEqual(result['native_pair'], 'NOT RUN')
        self.assertEqual(result['Root_closure_review'], 'PENDING')
        policy_before = json.loads(old[PREFIX+'policy.json'])
        policy_after = json.loads(bodies[PREFIX+'policy.json'])
        self.assertEqual({k: policy_after[k] for k in policy_before}, policy_before)
        added = set(policy_after)-set(policy_before)
        self.assertEqual(len(added), 1)
        self.assertEqual(policy_after[added.pop()], Q.DECLARATION)
        self.assertEqual(bodies[PREFIX+'data.py'], old[PREFIX+'data.py'])
        for name, raw in old.items():
            if name not in (*P.CHANGED, 'source-map.json'):
                self.assertEqual(bodies[name], raw, name)
        for name in ('source-map.json', PREFIX+'owner-program.json'):
            value = json.loads(bodies[name])
            self.assertEqual(bodies[name], (json.dumps(value, indent=2, sort_keys=True)+'\n').encode())
            for file, pin in value['files'].items():
                self.assertEqual(pin, dict(bytes=len(bodies[file]), sha256=hashlib.sha256(bodies[file]).hexdigest(), mode=0o644))

    def test_canonical_inverse_refuses_guard_program_policy_map_and_ancestry_tampering(self):
        self.retained()
        output = self.base/'Source93'
        P.construct(PARENT, output)
        bodies = {str(n.relative_to(output)): n.read_bytes() for n in output.rglob('*') if n.is_file()}
        ancestry = next(n for n in bodies if n.startswith('previous-v4/') and n.endswith('source-map.json'))
        names = [PREFIX+'payload.py', PREFIX+'hosted_owner.py', PREFIX+'data.py',
                 PREFIX+'policy.json', PREFIX+'owner-program.json', PREFIX+'source_readonly.py',
                 ancestry, 'source-map.json']
        for name in names:
            with self.subTest(tamper=name), self.assertRaises(ValueError):
                P.inverse(dict(bodies, **{name: bodies[name]+b'\n# FOREIGN DATA\n'}))

    def test_controller_only_import_and_presubmission_projection_ast_change(self):
        old = self.retained()
        code, _ = P.projections(old)
        before = ast.parse(old[PREFIX+'hosted_owner.py'])
        after = ast.parse(code[PREFIX+'hosted_owner.py'])
        cls = next(n for n in after.body if isinstance(n, ast.ClassDef) and n.name == 'Controller')
        start = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'start')
        index, assignment = next((i, n) for i, n in enumerate(start.body)
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Attribute) and ast.unparse(n.value.func) == 'Q.project_service')
        self.assertEqual(ast.unparse(assignment), 'argv = Q.project_service(argv, self.root, self.out, self.nonce, kind)')
        self.assertIn('argv.insert', ast.unparse(start.body[index-1]))
        self.assertEqual(ast.unparse(start.body[index+1]), "self.units[kind] = dict(submitted=True, cgroup=None)")
        self.assertEqual(ast.unparse(start.body[index+2]), 'self.run(argv)')
        start.body.pop(index)
        # The importlib loader's three assignments are the only module-level addition.
        after.body = [n for n in after.body if not (
            isinstance(n, ast.Assign) and (
                any(isinstance(t, ast.Name) and t.id == 'Q' for t in n.targets)
                or (isinstance(n.value, ast.Call) and 'source_readonly' in ast.unparse(n.value))))
            and not (isinstance(n, ast.Expr) and 'exec_module(Q)' in ast.unparse(n))]
        self.assertEqual(ast.dump(after, include_attributes=False), ast.dump(before, include_attributes=False))
        for name in ('payload.py', 'data.py', 'failed_retirement.py', 'go_cli_va.py', 'host_tools.py'):
            self.assertNotIn(PREFIX+name, code)
        self.assertEqual(old[PREFIX+'payload.py'].decode().count(GUARD), 1)
        self.assertIn('32 < len(rows) < 96', old[PREFIX+'data.py'].decode())

    def test_unchanged_guard_refuses_each_writable_path(self):
        def need(ok, message):
            if not ok:
                raise ValueError(message)
        root = Path('/MODEL/SOURCE')
        code = compile(ast.parse(GUARD.strip()), '<unchanged-guard-DATA>', 'exec')
        for writable in (None, '/tmp', '/var/tmp', root):
            observed = []
            def access(path, mode):
                observed.append((path, mode))
                return path == writable
            scope = dict(D=types.SimpleNamespace(need=need), root=root,
                         os=types.SimpleNamespace(access=access, W_OK=os.W_OK))
            with self.subTest(writable=str(writable)):
                if writable is None:
                    exec(code, scope)
                    self.assertEqual([p for p, _ in observed], ['/tmp', '/var/tmp', root])
                else:
                    with self.assertRaisesRegex(ValueError, '^actual owner writable filesystem restricted to quota work domain$'):
                        exec(code, scope)
                self.assertTrue(all(mode == os.W_OK for _, mode in observed))


if __name__ == '__main__':
    unittest.main(verbosity=2)
