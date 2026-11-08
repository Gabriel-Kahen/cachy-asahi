#!/usr/bin/env python3
"""Execute the two build functions with in-memory paths and actor-denied logs."""
import ast
from contextlib import contextmanager
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'payload/native/desktop_alpm_v1.py'
# Public summary shape from retained host check(): stderr lines95-98,
# duration3.385s; stdout line8 supplies the makepkg check marker. Synthetic
# concatenation of those captured streams, not a native/original command log.
GOOD = b'==> Starting check()...\n----------------------------------------------------------------------\nRan 91 tests in 3.385s\n\nOK\n'
BAD = {
    'old81': GOOD.replace(b'Ran 91 ', b'Ran 81 '),
    'wrong191': GOOD.replace(b'Ran 91 ', b'Ran 191 '),
    'truncated': GOOD[:-2],
    'wrongOK': GOOD.replace(b'\nOK\n', b'\nOKAY\n'),
    'failed': GOOD.replace(b'\nOK\n', b'\nFAILED (failures=1)\n'),
    'literal_slashes': GOOD.replace(b'\nOK\n', b'\\nOK\\n'),
    'missing_check': GOOD.replace(b'Starting check()', b'Starting build()'),
}
ACTIVE = False
ATTEMPTS = []


def audit(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('os.', 'subprocess.', 'socket.', 'ctypes.', 'signal.', 'fcntl.'))):
        ATTEMPTS.append(event)
        raise AssertionError('in-memory build-log control forbids actor/IO: ' + event)


sys.addaudithook(audit)


@contextmanager
def data_only():
    global ACTIVE
    ACTIVE = True
    try:
        yield
    finally:
        ACTIVE = False


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class MemoryPath:
    """Only the file operations these functions need; no OS-backed paths."""
    def __init__(self, fs, name):
        self.fs, self.key = fs, PurePosixPath(name)

    def __truediv__(self, name):
        return MemoryPath(self.fs, self.key / name)

    def __str__(self):
        return str(self.key)

    @property
    def name(self):
        return self.key.name

    def iterdir(self):
        return [MemoryPath(self.fs, n) for n in self.fs if n.parent == self.key]

    def stat(self):
        inode, body = self.fs[self.key]
        return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=0o40755 if body is None else 0o100644)

    def is_dir(self):
        return self.key in self.fs and self.fs[self.key][1] is None

    def is_file(self):
        return self.key in self.fs and self.fs[self.key][1] is not None

    def is_symlink(self):
        return False

    def rename(self, target):
        need(target.key not in self.fs, 'in-memory destination must be absent')
        moved = {n: value for n, value in self.fs.items() if n == self.key or self.key in n.parents}
        for n in moved:
            del self.fs[n]
        for n, value in moved.items():
            self.fs[target.key / n.relative_to(self.key)] = value


def fixture():
    fs, calls, ownership = {}, [], []
    source, recipes, prefix = [MemoryPath(fs, n) for n in ('/source', '/recipes', '/prefix')]
    files = {'PKGBUILD': b'inert recipe', 'source.tar.gz': b'inert source'}
    rows = {n: dict(**pin(raw), mode=0o644) for n, raw in files.items()}
    for index, label in enumerate(('a', 'b', 'update'), 1):
        directory = recipes / label
        fs[directory.key] = (index, None)
        for name, body in files.items():
            fs[(directory / name).key] = (index + 10, body)
    recipe = dict(source_files=rows, archive='desktop-0.1.1-1-any.pkg.tar.zst')
    update = dict(source_files=rows, archive='desktop-0.1.1-2-any.pkg.tar.zst')
    policy = dict(recipe=recipe, makepkg_config=dict(path='makepkg.conf'),
                  build_pair=dict(source_date_epoch='1', packager='TEST'))
    tools = SimpleNamespace(VERSION='0.1.1-1', UPDATE_VERSION='0.1.1-2', UPDATE_FIXTURE='TEST',
        update_policy=lambda value: update, pin=lambda path: pin(fs[path.key][1]))
    fake_os = SimpleNamespace(path=SimpleNamespace(lexists=lambda path: path.key in fs),
                              chown=lambda path, uid, gid: ownership.append((str(path), uid, gid)))
    scope = dict(T=tools, PREFIX=prefix, os=fake_os, stat=stat, re=re, need=need)
    nodes = [n for n in ast.parse(SOURCE.read_bytes()).body if isinstance(n, ast.FunctionDef)
             and n.name in ('current011_build_pair', 'current011_build_update')]
    need(len(nodes) == 2, 'two actual current build functions required')
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<actual-current-build-functions>', 'exec'), scope)
    def run(label, argv, *, cwd):
        calls.append((label, argv, str(cwd)))
        need('--nocheck' not in argv and '/usr/bin/makepkg' in argv
             and argv[-2:] == ['--config', '/source/makepkg.conf'], 'actual makepkg argv must retain check')
        archive = update['archive'] if label == 'build-update' else recipe['archive']
        fs[(cwd / archive).key] = (99, b'inert archive')
        return GOOD
    return scope, fs, calls, source, recipes, policy, SimpleNamespace(pw_uid=1000, pw_gid=1000), run


class BuildLogControls(unittest.TestCase):
    def exercise(self, target, bad=None):
        scope, fs, calls, source, recipes, policy, alarm, good_run = fixture()
        report = dict(builds={}, stages=[])
        update = target == 'update'
        if update:
            report['builds'] = {n: dict(build_directory=dict(identity=dict(device=1, inode=i)))
                                for n, i in [('a', 1), ('b', 2)]}
        function = scope['current011_build_update' if update else 'current011_build_pair']
        def run(label, argv, *, cwd):
            good = good_run(label, argv, cwd=cwd)
            return bad if bad is not None and label == 'build-' + target else good
        with data_only():
            if bad is None:
                result = function(run, source, recipes, policy, alarm, report)
            else:
                with self.assertRaisesRegex(ValueError, 'actual complete91-test'):
                    function(run, source, recipes, policy, alarm, report)
                result = None
        self.assertFalse((scope['PREFIX'] / 'build-current').key in fs)
        self.assertTrue((recipes / target).is_dir())
        self.assertEqual(ATTEMPTS, [])
        if bad is not None:
            self.assertEqual(report['builds'][target]['check_tests'], 0)
            self.assertNotIn('archive', report['builds'][target])
            self.assertNotIn('build-' + target, report['stages'])
        else:
            labels = ['update'] if update else ['a', 'b']
            for label in labels:
                self.assertEqual(report['builds'][label]['check_tests'], 91)
                self.assertTrue(report['builds'][label]['check_invoked'])
            self.assertEqual([x[0] for x in calls], ['build-' + label for label in labels])
            self.assertIsNotNone(result)

    def test_pair_accepts_actual91_summary_shape(self):
        self.exercise('a')

    def test_update_accepts_actual91_summary_shape(self):
        self.exercise('update')

    def test_both_pair_labels_refuse_old_truncated_and_wrong_ok(self):
        for label in ('a', 'b'):
            for name, log in BAD.items():
                with self.subTest(label=label, log=name):
                    self.exercise(label, log)

    def test_update_refuses_old_truncated_and_wrong_ok(self):
        for name, log in BAD.items():
            with self.subTest(log=name):
                self.exercise('update', log)


if __name__ == '__main__':
    unittest.main(verbosity=2)
