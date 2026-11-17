#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Filesystem observation DATA controls; no native or system actors."""
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
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
RETAINED = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114')
PARENT = Path(os.environ.get('LLHTTP_V4_PARENT', str(RETAINED/'Root-llhttp76-source-r1/closed-source-tree')))
PUBLIC = RETAINED/'Root-llhttp76-native-result-r1/public-files/llhttp-reference-owned-public-nb1_x126'
GUARD = "    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')"


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
P = module(HERE/'prepare.py', 'llhttp_v4_prepare_control')
M = module(HERE/'mount_accounting.py', 'llhttp_v4_mount_control')
SOURCE = Path('/MODEL/PRIVATE_SOURCE_TOKEN')
WORK = Path('/MODEL/PRIVATE_OWNED_TOKEN/work')


def mount(point, *, ident=1, readonly=True, super_readonly=False, fstype='ext4'):
    point = point.replace('\\', '\\134').replace(' ', '\\040').replace('\t', '\\011')
    return (f'{ident} 0 1:2 / {point} '+('ro' if readonly else 'rw')+
            ' - '+fstype+' /PRIVATE_DEVICE_TOKEN '+('ro' if super_readonly else 'rw')+'\n').encode()


def fixture(extra=b''):
    return b''.join((mount('/'), mount('/tmp', ident=2), mount('/var/tmp', ident=3),
                     mount(str(SOURCE), ident=4), mount(str(WORK), ident=5, readonly=False), extra))


def observe(raw=None, *, access=None, statvfs=None):
    return M.observe(SOURCE, WORK, mountinfo=fixture() if raw is None else raw,
                     access=access or (lambda path, mode: Path(path) == WORK),
                     statvfs=statvfs or (lambda path: types.SimpleNamespace(
                         f_flag=0 if Path(path) == WORK else os.ST_RDONLY)))


class Controls(unittest.TestCase):
    def test_bounded_parser_and_longest_component_covering_prefix(self):
        raw = fixture(mount('/tmp-extra', ident=6, readonly=False)+
                      mount('/MODEL/space dir', ident=7))
        parsed = M.parse(raw)
        self.assertEqual(len(parsed), 7)
        self.assertIn('/MODEL/space dir', [r['mountpoint'] for r in parsed])
        row = observe(raw)
        self.assertEqual(row['mountinfo']['status'], 'OK')
        self.assertEqual(row['mountinfo']['rows'], 7)
        self.assertEqual(set(row['paths']), {'root', 'tmp', 'var_tmp', 'source', 'work'})
        for label in ('root', 'tmp', 'var_tmp', 'source'):
            self.assertEqual(row['paths'][label]['cover']['status'], 'OK')
            self.assertIs(row['paths'][label]['cover']['mount_readonly'], True)
        self.assertIs(row['paths']['work']['cover']['mount_readonly'], False)
        self.assertIs(row['paths']['tmp']['cover']['super_readonly'], False)
        partial = fixture().replace(mount(str(SOURCE), ident=4), b'')
        partial += mount('/MODEL/PRIVATE_SOURCE', ident=6, readonly=False)
        self.assertIs(observe(partial)['paths']['source']['cover']['mount_readonly'], True)
        self.assertIs(row['confinement_acceptance'], False)

    def test_stacked_covering_mounts_remain_ambiguous(self):
        raw = fixture(mount('/tmp', ident=6, readonly=False))
        for value in (raw, b'\n'.join(reversed(raw.rstrip(b'\n').split(b'\n')))+b'\n'):
            cover = observe(value)['paths']['tmp']['cover']
            self.assertEqual(cover['status'], 'AMBIGUOUS')
            self.assertIsNone(cover['mount_readonly'])
            self.assertIsNone(cover['super_readonly'])
        self.assertIs(observe(raw)['confinement_acceptance'], False)

    def test_malformed_truncated_and_over_budget_inputs_never_guess(self):
        cases = [b'', fixture()[:-1], b'not mountinfo\n',
                 mount('/bad\\777'),
                 mount('/alias//directory'), mount('/alias/../directory'),
                 mount('/tmp').replace(b' ro - ', b' ro,rw - '),
                 mount('/tmp')+mount('/var/tmp'),
                 b''.join(mount('/many/'+str(n), ident=n+1) for n in range(M.MAX_ROWS+1)),
                 b'x'*(M.MAX_BYTES+1),
                 b'x'*(M.MAX_LINE+1)+b'\n']
        # A literal unknown kernel escape is distinct from an escaped backslash.
        cases[3] = b'1 0 1:2 / /bad\\777 ro - ext4 /private rw\n'
        self.assertEqual((M.MAX_BYTES, M.MAX_ROWS, M.MAX_LINE), (1048576, 1024, 16384))
        for raw in cases:
            with self.subTest(bytes=len(raw)):
                with self.assertRaises(ValueError):
                    M.parse(raw)
                row = observe(raw)
                self.assertEqual(row['mountinfo']['status'], 'UNKNOWN')
                self.assertTrue(all(p['cover']['status'] == 'UNKNOWN' for p in row['paths'].values()))
                self.assertIsNone(row['rw_mount_classes']['counts'])
                self.assertIsNone(row['rw_mount_classes']['other_rw_points_sha256'])
                self.assertIs(row['confinement_acceptance'], False)

    def test_fixed_path_access_statvfs_and_permission_unknowns(self):
        accesses, stats = [], []
        def access(path, mode):
            accesses.append((str(path), mode))
            if Path(path) == Path('/var/tmp'):
                raise PermissionError('/PRIVATE_EXCEPTION_TOKEN')
            return Path(path) in (SOURCE, WORK)
        def statvfs(path):
            stats.append(str(path))
            if Path(path) == SOURCE:
                raise PermissionError('/PRIVATE_EXCEPTION_TOKEN')
            return types.SimpleNamespace(f_flag=0 if Path(path) == WORK else os.ST_RDONLY)
        row = observe(access=access, statvfs=statvfs)
        expected = {'/', '/tmp', '/var/tmp', str(SOURCE), str(WORK)}
        self.assertEqual({p for p, _ in accesses}, expected)
        self.assertEqual(set(stats), expected)
        self.assertEqual(len(accesses), 5)
        self.assertEqual(len(stats), 5)
        self.assertTrue(all(mode == os.W_OK for _, mode in accesses))
        self.assertIsNone(row['paths']['var_tmp']['writable'])
        self.assertIsNone(row['paths']['source']['statvfs_readonly'])
        self.assertIs(row['paths']['source']['writable'], True)
        self.assertIs(row['paths']['work']['statvfs_readonly'], False)
        self.assertIs(row['confinement_acceptance'], False)

    def test_bounded_hash_only_privacy_and_diagnostic_nonacceptance(self):
        private = '/PRIVATE_UNRELATED_MOUNT_TOKEN'
        raw = fixture(mount(private, ident=6, readonly=False, fstype='PRIVATE_FSTYPE_TOKEN'))
        row = observe(raw)
        summary = row['rw_mount_classes']
        self.assertIn('other_rw_points_sha256', summary)
        self.assertRegex(summary['other_rw_points_sha256'], '^[0-9a-f]{64}$')
        line = M.record(row)
        self.assertTrue(line.startswith('MOUNT_CLASS: '))
        self.assertLessEqual(len(line.encode()), 4096)
        self.assertEqual(json.loads(line.removeprefix('MOUNT_CLASS: ')), row)
        for secret in (private, str(SOURCE), str(WORK), 'PRIVATE_DEVICE_TOKEN', 'PRIVATE_FSTYPE_TOKEN'):
            self.assertNotIn(secret, line)
        self.assertIs(row['confinement_acceptance'], False)
        with patch.object(M, 'parse', side_effect=PermissionError('/PRIVATE_EXCEPTION_TOKEN')):
            unknown = observe()
        self.assertEqual(unknown['mountinfo']['status'], 'UNKNOWN')
        self.assertNotIn('PRIVATE_EXCEPTION_TOKEN', M.record(unknown))
        self.assertIs(unknown['confinement_acceptance'], False)
        for altered in (dict(row, confinement_acceptance=True), dict(row, private_path=private)):
            with self.assertRaises(ValueError):
                M.record(altered)

    def test_complete76_inverse_and_preserved_service_scope(self):
        if not PARENT.exists():
            self.skipTest('genuine retained public Source76 DATA required')
        original, prior = P.parent_bodies(PARENT)
        projected, seams = P.projections(original)
        self.assertEqual(len(original), 76)
        self.assertEqual(hashlib.sha256(original['source-map.json']).hexdigest(),
                         '8e6290fb7c916ba52d094d2a324b7ba77e8813c910a6e454a8f78f0aeda92d57')
        for name, raw in projected.items():
            text = raw.decode()
            for seam in reversed(seams[name]):
                self.assertEqual(text.count(seam['after']), 1)
                text = text.replace(seam['after'], seam['before'])
            self.assertEqual(text.encode(), original[name])
        owner = P.PREFIX+'hosted_owner.py'
        self.assertEqual(projected.get(owner, original[owner]), original[owner])
        payload = P.PREFIX+'payload.py'
        self.assertEqual(original[payload].decode().count(GUARD), 1)
        self.assertEqual(projected[payload].decode().count(GUARD), 1)
        with tempfile.TemporaryDirectory(prefix='llhttp-v4-Source-DATA-', dir='/home/gabe') as name:
            output = Path(name)/'Source'
            result = P.construct(PARENT, output)
            bodies = {str(n.relative_to(output)): n.read_bytes()
                      for n in output.rglob('*') if n.is_file()}
            self.assertEqual(P.inverse(bodies), original)
            self.assertEqual(result['files'], 85)
            self.assertLess(result['files'], 96)
            self.assertTrue(all(v is None for v in result['actual'].values()))
            self.assertEqual(result['native_pair'], 'NOT RUN')
            self.assertEqual(bodies[owner], original[owner])
            before = json.loads(original[P.PREFIX+'policy.json'])
            after = json.loads(bodies[P.PREFIX+'policy.json'])
            self.assertEqual({k: after[k] for k in before}, before)
            self.assertEqual(len(set(after)-set(before)), 1)
            self.assertEqual(prior['actual'], result['actual'])
            data = P.PREFIX+'data.py'
            self.assertEqual(bodies[data].decode().replace('32 < len(rows) < 96', '32 < len(rows) < 80'),
                             original[data].decode())
            changed = {payload: bodies[payload].replace(GUARD.encode(), b'    pass'),
                       owner: bodies[owner]+b'\n# foreign controller\n',
                       data: bodies[data].replace(b'ProtectSystem=strict', b'ProtectSystem=false'),
                       P.PREFIX+P.HELPER: bodies[P.PREFIX+P.HELPER]+b'\n# foreign\n',
                       'previous-v3/source-map.json': bodies['previous-v3/source-map.json']+b' ',
                       P.PREFIX+'policy.json': bodies[P.PREFIX+'policy.json']+b' ',
                       P.PREFIX+'owner-program.json': bodies[P.PREFIX+'owner-program.json']+b' ',
                       'source-map.json': bodies['source-map.json']+b' '}
            for name, raw in changed.items():
                self.assertNotEqual(raw, bodies[name])
                tampered = dict(bodies, **{name: raw})
                with self.subTest(tamper=name), self.assertRaises(ValueError):
                    P.inverse(tampered)

    def test_original_aggregate_guard_still_refuses_each_writable_path(self):
        def need(ok, message):
            if not ok:
                raise ValueError(message)
        body = ast.parse(GUARD.strip())
        code = compile(body, '<unchanged-aggregate-guard-DATA>', 'exec')
        root = Path('/MODEL/PRIVATE_SOURCE')
        for writable in (None, '/tmp', '/var/tmp', root):
            accesses = []
            def access(path, mode):
                accesses.append((path, mode))
                return path == writable
            scope = dict(D=types.SimpleNamespace(need=need), root=root,
                         os=types.SimpleNamespace(access=access, W_OK=os.W_OK))
            with self.subTest(writable=str(writable)):
                if writable is None:
                    exec(code, scope)
                    self.assertEqual([p for p, _ in accesses], ['/tmp', '/var/tmp', root])
                else:
                    with self.assertRaisesRegex(ValueError, '^actual owner writable filesystem restricted to quota work domain$'):
                        exec(code, scope)
                self.assertTrue(all(mode == os.W_OK for _, mode in accesses))

    def test_actual87_failure_and_verified_cleanup_remain_distinct(self):
        if not (PUBLIC.exists() and PARENT.exists()):
            self.skipTest('genuine retained actual87 public DATA required')
        report = json.loads((PUBLIC/'owner-report.json').read_bytes())
        line = (PUBLIC/'owner.log').read_text()
        diagnostic = json.loads(line.removeprefix('HOLD_PAYLOAD: '))
        self.assertEqual(diagnostic, dict(exception='ValueError',
            kind='LLHTTP_PAYLOAD_PHASE_HASH_ONLY_V3', message_bytes=64,
            message_prefix_bytes=64,
            message_prefix_sha256='fb486df27f93098ca0869bbefefdfc5eebd0260b10abfcc4fb1b8c1dfb3286bb',
            phase='readonly-filesystem', truncated=False))
        message = b'actual owner writable filesystem restricted to quota work domain'
        self.assertEqual(len(message), 64)
        self.assertEqual(hashlib.sha256(message).hexdigest(), diagnostic['message_prefix_sha256'])
        self.assertEqual(report['status'], 'HOLD')
        self.assertEqual(report['native_pair'], 'NOT RUN')
        self.assertEqual(report['source_map_sha256'],
                         '8e6290fb7c916ba52d094d2a324b7ba77e8813c910a6e454a8f78f0aeda92d57')
        self.assertEqual(report['failure']['message'], 'ordinary payload natural success required')
        self.assertEqual(report['cleanup']['errors'], [])
        self.assertIs(report['cleanup']['owned_storage_absent'], True)
        retired = report['cleanup']['services']['owner']
        self.assertEqual(retired['retirement'], 'STOPPED_EMPTY_FAILED_OWNER')
        self.assertIs(retired['payload_success'], False)
        self.assertEqual(retired['payload_exit'], 2)
        self.assertIs(retired['unit_reset'], False)
        argv = json.loads((PUBLIC/'command-012.json').read_bytes())['argv']
        self.assertIn('--property=ProtectSystem=strict', argv)
        self.assertIn('--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup', argv)
        self.assertEqual([a for a in argv if a.startswith('--property=ReadWritePaths=')],
            ['--property=ReadWritePaths=/home/runner/work/_temp/llhttp-reference-owned-v2/volume/work'])
        self.assertIn('/home/runner/work/cachy-asahi/cachy-asahi/'+P.PREFIX+'payload.py', argv)
        D = module(PARENT/P.PREFIX/'data.py', 'llhttp_v4_actual87_declarations')
        observation = json.loads((PUBLIC/'actual-domains.json').read_bytes())
        owner = observation['owner']
        admission = {k: observation[k] for k in ('source', 'ref', 'nonce')}
        policy = json.loads((PARENT/P.PREFIX/'policy.json').read_bytes())
        D.observation(observation, admission, observation['source_map_sha256'], policy,
                      owner['pid'], owner['starttime'], owner['cgroup'])
        names = {n.name for n in PUBLIC.iterdir()}
        self.assertFalse(any('mountinfo' in n or 'statvfs' in n for n in names))


if __name__ == '__main__':
    unittest.main(verbosity=2)
