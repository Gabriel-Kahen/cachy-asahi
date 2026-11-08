"""Failure-only input metadata and preparation-phase controls; no native actor."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest

P = Path(__file__).resolve().parents[1] / 'overlay/native'
MARKER = 'SECURITY_RECOVERY_INPUT_REFUSED '
FIELDS = {'schema', 'role', 'kind', 'uid', 'gid', 'nlink', 'size', 'mode', 'maximum', 'bounded'}


def parsed(name):
    return ast.parse((P / name).read_bytes())


class InputDiagnostic(unittest.TestCase):
    def fixture(self, *, role='candidate-archive', maximum=16, output_failure=False, changed=False, **changes):
        data = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1,
                    st_size=3, st_dev=91, st_ino=92, st_mtime_ns=93, st_ctime_ns=94)
        data.update(changes); before = SimpleNamespace(**data)
        calls = {'open': [], 'fstat': [], 'read': [], 'close': [], 'resolve': 0, 'lstat': 0}
        class FakePath:
            def resolve(self): calls['resolve'] += 1; return self
            def lstat(self): calls['lstat'] += 1; return before
        path = FakePath()
        def open_fd(value, flags): calls['open'].append((value, flags)); return 17
        def fstat_fd(fd):
            calls['fstat'].append(fd)
            return SimpleNamespace(**dict(data, st_ino=900)) if changed and len(calls['fstat']) > 1 else before
        def read_fd(fd, size):
            calls['read'].append((fd, size)); return b'abc' if len(calls['read']) == 1 else b''
        fake_os = SimpleNamespace(open=open_fd, fstat=fstat_fd, read=read_fd, close=calls['close'].append,
            **{k: getattr(os, k) for k in ('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK')})
        namespace = dict(Path=lambda value: value, os=fake_os, stat=stat, json=json)
        if output_failure:
            def refused_print(*args, **kwargs): raise OSError('injected output failure')
            namespace['print'] = refused_print
        tree = parsed('security_recovery_native.py')
        body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('need', '_ordinary')]
        exec(compile(ast.Module(body=body, type_ignores=[]), '<isolated-input-check>', 'exec'), namespace)
        stream = io.StringIO(); error = None; result = None
        with contextlib.redirect_stdout(stream):
            try: result = namespace['_ordinary'](path, maximum, role)
            except BaseException as failure: error = failure
        self.assertEqual(calls['close'], [17])
        self.assertEqual(calls['open'], [(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)])
        self.assertEqual(calls['resolve'], 1)
        return result, error, stream.getvalue(), calls, before

    def refused(self, **kwargs):
        result, error, text, calls, before = self.fixture(**kwargs)
        self.assertIsNone(result); self.assertIs(type(error), ValueError)
        self.assertEqual(str(error), 'ordinary bounded root-owned native input')
        self.assertEqual(calls['fstat'], [17]); self.assertEqual(calls['read'], [])
        self.assertEqual(calls['lstat'], 0)
        self.assertEqual(len(text.splitlines()), 1); self.assertTrue(text.startswith(MARKER))
        self.assertLessEqual(len(text), len(MARKER) + 1025)
        value = json.loads(text[len(MARKER):]); self.assertEqual(set(value), FIELDS)
        return value, before

    def test_refusal_reports_same_descriptor_uid_gid_link_size_and_mode(self):
        for change in ({'st_uid': 1000}, {'st_gid': 1001}, {'st_nlink': 2}, {'st_size': 0}, {'st_size': 17}):
            with self.subTest(change=change):
                value, before = self.refused(**change)
                self.assertEqual(value, dict(schema=1, role='candidate-archive', kind='regular',
                    uid=before.st_uid, gid=before.st_gid, nlink=before.st_nlink, size=before.st_size,
                    mode=before.st_mode, maximum=16, bounded=0 < before.st_size <= 16))

    def test_nonregular_types_are_closed_finite_scalars(self):
        for mode, kind in ((stat.S_IFDIR, 'directory'), (stat.S_IFLNK, 'symlink'),
                           (stat.S_IFIFO, 'fifo'), (stat.S_IFSOCK, 'socket'),
                           (stat.S_IFCHR, 'character'), (stat.S_IFBLK, 'block'), (0, 'other')):
            with self.subTest(kind=kind):
                value, _ = self.refused(st_mode=mode | 0o600)
                self.assertEqual(value['kind'], kind)

    def test_success_is_silent_and_retains_original_read_and_stability_checks(self):
        result, error, text, calls, _ = self.fixture()
        self.assertEqual(result, b'abc'); self.assertIsNone(error); self.assertEqual(text, '')
        self.assertEqual(calls['fstat'], [17, 17]); self.assertEqual(calls['lstat'], 1)
        self.assertEqual(calls['read'], [(17, 4), (17, 1)])

    def test_stability_failure_remains_silent_and_closes_descriptor(self):
        _, error, text, calls, _ = self.fixture(changed=True)
        self.assertEqual(str(error), 'native input stable across descriptor/path read')
        self.assertEqual(text, ''); self.assertEqual(calls['fstat'], [17, 17])

    def test_output_failure_cannot_replace_original_refusal(self):
        _, error, text, calls, _ = self.fixture(st_uid=1000, output_failure=True)
        self.assertIs(type(error), ValueError)
        self.assertEqual(str(error), 'ordinary bounded root-owned native input')
        self.assertEqual(text, ''); self.assertEqual(calls['fstat'], [17]); self.assertEqual(calls['read'], [])

    def test_uncontrolled_roles_and_out_of_range_numbers_cannot_leak(self):
        secret = '/private/path/SECRET-CONTENT\nSECOND-MARKER'
        value, _ = self.refused(role=secret, st_uid=2**100, st_gid=-1, st_nlink=2**100, st_size=2**100)
        self.assertEqual(value['role'], 'other')
        self.assertTrue(all(value[k] is None for k in ('uid', 'gid', 'nlink', 'size')))
        self.assertNotIn(secret, json.dumps(value))
        self.assertTrue(set(value).isdisjoint({'path', 'content', 'ino', 'dev', 'timestamp'}))

    def test_prepare_call_sites_assign_exact_input_roles(self):
        tree = parsed('security_recovery_native.py')
        constructor = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '__init__')
        loops = [n for n in constructor.body if isinstance(n, ast.For) and ast.unparse(n.target) == '(role, source)']
        self.assertEqual(len(loops), 1)
        self.assertEqual([ast.literal_eval(row.elts[0]) for row in loops[0].iter.elts],
                         ['candidate-archive', 'candidate-signature', 'prior-archive', 'prior-signature'])
        input_calls = [n for n in ast.walk(constructor) if isinstance(n, ast.Call)
                       and isinstance(n.func, ast.Name) and n.func.id == '_ordinary']
        literal_roles = {n.args[2].value for n in input_calls if len(n.args) == 3 and isinstance(n.args[2], ast.Constant)}
        self.assertEqual(literal_roles, {'scope', 'test-public-armor', 'staged-prior-archive', 'staged-prior-signature'})
        self.assertTrue(all(len(n.args) == 3 for n in input_calls))
        staged = next(n for n in ast.walk(constructor) if isinstance(n, ast.comprehension)
                      and ast.unparse(n.target) == '(role, p)')
        self.assertEqual([ast.literal_eval(row.elts[0]) for row in staged.iter.elts],
                         ['staged-candidate-archive', 'staged-candidate-signature', 'staged-config', 'staged-test-public'])
        trust = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_copy_public_trust')
        calls = [n for n in ast.walk(trust) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == '_ordinary']
        self.assertEqual([n.args[2].value for n in calls], ['public-trust'])
        ordinary = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_ordinary')
        declared = next(n.value for n in ast.walk(ordinary) if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == 'roles' for t in n.targets))
        self.assertEqual(set(ast.literal_eval(declared)), {'other', 'scope', 'public-trust', 'test-public-armor',
            'candidate-archive', 'candidate-signature', 'prior-archive', 'prior-signature',
            'staged-candidate-archive', 'staged-candidate-signature', 'staged-config', 'staged-test-public',
            'staged-prior-archive', 'staged-prior-signature'})

    def test_original_refusal_expression_and_error_are_unchanged(self):
        function = next(n for n in parsed('security_recovery_native.py').body
                        if isinstance(n, ast.FunctionDef) and n.name == '_ordinary')
        call = next(n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == 'need' and len(n.args) == 2
                    and isinstance(n.args[1], ast.Constant) and n.args[1].value == 'ordinary bounded root-owned native input')
        expected = ast.parse('stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 0 and 0 < before.st_size <= maximum', mode='eval')
        self.assertEqual(ast.dump(call.args[0]), ast.dump(expected.body))

    def test_prepare_phase_retained_on_failure_and_cleared_before_later_commands(self):
        inside = next(n for n in parsed('security_native_v1.py').body if isinstance(n, ast.FunctionDef) and n.name == 'inside')
        body = next(n.body for n in inside.body if isinstance(n, ast.Try))
        index = next(i for i,n in enumerate(body) if isinstance(n, ast.Assign)
                     and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id == 'prepare_recovery')
        block = body[index-1:index+2]
        self.assertEqual(ast.unparse(block[0]), "recovery_phase = 'PREPARE_RECOVERY'")
        self.assertEqual(ast.unparse(block[2]), 'recovery_phase = None')
        phase = next(n for n in ast.walk(inside) if isinstance(n, ast.keyword) and n.arg == 'phase').value
        expression = compile(ast.Expression(body=phase), '<isolated-failure-phase>', 'eval')
        ns = dict(sys=SimpleNamespace(modules={'fixture': object()}), __name__='fixture', c=SimpleNamespace(records=[{'step':'verify-test-signature'}]))
        ns.update({k: object() for k in ('archive','prior','paths','prior_paths','fingerprint','public','trust','map_hash')})
        code = compile(ast.Module(body=block, type_ignores=[]), '<isolated-prepare-boundary>', 'exec')
        def fail(*args): raise ValueError('fixture prepare failure')
        ns['prepare_recovery'] = fail
        with self.assertRaises(ValueError): exec(code, ns)
        self.assertEqual(eval(expression, ns), 'PREPARE_RECOVERY')
        ns['prepare_recovery'] = lambda *args: 'context'; exec(code, ns)
        self.assertEqual(ns['recovery_context'], 'context')
        self.assertEqual(eval(expression, ns), 'verify-test-signature')
        ns['c'].records.append({'step':'prior-required-install'})
        self.assertEqual(eval(expression, ns), 'prior-required-install')
        ns['c'].records.clear(); self.assertEqual(eval(expression, ns), 'admission')


if __name__ == '__main__': unittest.main(verbosity=2)
