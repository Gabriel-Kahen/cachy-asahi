#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Closed public Source95 fixture and corrected minimal206 source DATA controls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / 'scripts/ci/llhttp-minimal-builder-command512'
BASE_SOURCE = ROOT / 'scripts/ci/llhttp-minimal-builder-source'
INTAKE = ROOT / 'scripts/port/minimal-native-builder-inputs'
FIXTURE = HERE / 'fixtures/Source95'
PARENT_MAP = dict(bytes=20200, sha256='ab743415f602ba8c5f81a063fc7cc5d25587be0d535601396f2ee617fb4149ce')
PARENT_TREE = 'b73f92b1ed4e6f6ab8c4210fdaa19617b1a5721f'
INTAKE_LOCK = dict(bytes=2377, sha256='4730b8f6df4ad17140ec3dddcedbafd78b7012538361ae866757635269ac6bd3')
BASE_LOCK = dict(bytes=1301, sha256='cc2b66fe03676cd00826655fdcbfa43fe89769162b82ddf1507afe6765f5bfa3')
PROJECTION = HERE / 'fixtures/Source96-original-projection.DATA.json'
PROJECTION_PIN = dict(bytes=197700, sha256='313c0a4b205b84c8fe8b8c1ddf7d98750c6e3da86d31b7bc915be55c18814862')
AUTHORED_REVISION = '1f0a2a18600b5aea4c837974f91e3ba2451f18a9'
AUTHORED_LOCK = dict(bytes=934, sha256='14d885eae88fbbb373ff7e666aabac39b6d0ab8aa044183578597731e251e1a3')
AUTHOR_CONTROLS = 14
ATTEMPTS = []
PINNED = {}
AUTHOR_MODULE = None


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def checked(path, expected):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical ordinary DATA leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == expected.get('mode', 0o644)
             and before.st_size == expected['bytes'] <= 2 * 1024**2, 'ordinary exact single-link bounded DATA leaf')
        raw = stream.read(expected['bytes'] + 1)
        identity = lambda s: tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        need(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()) and pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')}, 'stable whole DATA pin')
    return raw


def census(root, cap):
    need(root.is_absolute() and root == root.resolve() and not root.is_symlink(), 'canonical DATA directory')
    leaves = set(); directories = set()
    for count, path in enumerate(root.rglob('*'), 1):
        need(count <= 512 and len(path.relative_to(root).parts) <= 32, 'finite DATA namespace')
        need(not path.is_symlink(), 'no DATA aliases')
        if path.is_dir():
            directories.add(path.relative_to(root).as_posix())
            continue
        need(path.is_file(), 'ordinary DATA leaves only')
        leaves.add(path.relative_to(root).as_posix())
        need(len(leaves) <= cap, 'finite closed DATA leaf count')
    expected_dirs = {str(parent) for name in leaves for parent in Path(name).parents if str(parent) != '.'}
    need(directories == expected_dirs, 'no unlisted empty DATA directories')
    return leaves


def git_tree(bodies):
    def oid(kind, body):
        return hashlib.sha1(kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body).digest()
    def walk(prefix):
        rows = []
        for name in {n[len(prefix):].split('/')[0] for n in bodies if n.startswith(prefix)}:
            path = prefix + name; leaf = path in bodies
            rows.append(((name if leaf else name + '/').encode(), (b'100644' if leaf else b'40000') + b' ' + name.encode() + b'\0' + (oid('blob', bodies[path]) if leaf else walk(path + '/'))))
        return oid('tree', b''.join(row for _, row in sorted(rows)))
    return walk('').hex()


def verify_fixture(root=FIXTURE):
    raw = checked(root / 'source-map.json', PARENT_MAP)
    d = json.loads(raw)
    need(len(d['files']) == 94 and census(root, 95) == set(d['files']) | {'source-map.json'} and all(v is None for v in d['actual'].values()), 'closed unselected original Source95')
    bodies = {'source-map.json': raw}
    for name, row in d['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'literal source fixture member')
        bodies[name] = checked(root / name, row)
    need(sum(map(len, bodies.values())) == 1318237 and git_tree(bodies) == PARENT_TREE, 'whole exact95 body/mode/tree export')
    return bodies


def verify_family(root, lock_pin):
    lock = json.loads(checked(root / 'source.lock.json', lock_pin))
    need(census(root, 32) == set(lock['files']) | {'source.lock.json'}, 'closed original source family')
    for name, row in lock['files'].items():
        checked(root / name, row)
        PINNED[str(root / name)] = row


def verify_projection(path=PROJECTION):
    marker = json.loads(checked(path, PROJECTION_PIN))
    need(marker['parent_map'] == PARENT_MAP and marker['parent_tree'] == PARENT_TREE and marker['parent_files'] == 95
         and marker['parent_bytes'] == 1318237 and len(marker['changed']) == 30 and marker['scope'] == 'BUILD_ONLY'
         and marker['actual'] is None and marker['Root_selection'] is None and marker['native'] is None, 'whole public original Source96 projection only')
    return marker


def verify_provenance():
    proof = json.loads((HERE / 'Source95.DATA.json').read_bytes())
    parent = json.loads((BASE_SOURCE / 'provenance.DATA.json').read_bytes())['parent_source95']
    need((proof['files'], proof['bytes'], proof['tree'], proof['source_map']) ==
         (parent['files'], parent['bytes'], parent['tree'], parent['map']) == (95, 1318237, PARENT_TREE, PARENT_MAP), 'original authored Source95 fixture provenance')
    need(proof['public_CID_recorded_by_source_author'] == parent['public_CID'] == 'c23c2874c82a3e83b76be09fe98ee6e134c8ff81'
         and proof['original_constructor_revision'] == '32336d4d9ff3ccf3ace423c1fa9de05c301ddd5b'
         and all(v is None for v in proof['actual_selectors'].values()) and proof['Root_selection'] is None
         and proof['native'] is None and proof['M2'] is None, 'source-only provenance attribution; no current publication/authority claim')


def module(path, name):
    raw = checked(path, PINNED[str(path)]) if str(path) in PINNED else path.read_bytes()
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in (
            'os.system', 'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit'):
        ATTEMPTS.append(event)
        raise AssertionError('MINIMAL_NATIVE_SOURCE_DATA_NO_ACTOR: ' + event)


def run():
    global AUTHOR_MODULE
    need(AUTHORED_REVISION is not None and AUTHORED_LOCK is not None and type(AUTHOR_CONTROLS) is int,
         'HOLD: corrected authored512 command/receipt source UNISSUED; old6651 is not executed')
    for kind, value in ((resource.RLIMIT_AS, 1024**3), (resource.RLIMIT_CPU, 180), (resource.RLIMIT_FSIZE, 16 * 1024**2), (resource.RLIMIT_NOFILE, 128)):
        resource.setrlimit(kind, (value, value))
    sys.addaudithook(fence)
    verify_fixture(); verify_family(INTAKE, INTAKE_LOCK); verify_family(BASE_SOURCE, BASE_LOCK); verify_family(SOURCE, AUTHORED_LOCK)
    verify_provenance(); marker = verify_projection()
    # Reproduce the predecessor with the historical ledger and exact projected
    # operands. The maintained intake pin also covers the current graph profile.
    corrected = module(SOURCE / 'prepare.py', 'minimal_native_source_corrected_replay')
    with tempfile.TemporaryDirectory(prefix='minimal512-source-data-') as name:
        intermediate = Path(name) / 'Source96-original-DATA'
        corrected.original_call(corrected.P.construct, FIXTURE, INTAKE, BASE_SOURCE / 'fixtures/material-check.DATA.json',
                                BASE_SOURCE / 'fixtures/acquisition-with-catalogs.DATA.json', intermediate, marker=marker, historical=True)
        need(pin((intermediate / corrected.MARKER).read_bytes()) == PROJECTION_PIN, 'exact original Source96 projection replay')
        saved = sys.argv
        # Final option/count/pins are set only after the corrected author commits.
        sys.argv = [str(SOURCE / 'test_data.py'), '--parent', str(intermediate)]
        try:
            author = module(SOURCE / 'test_data.py', 'minimal_native_source_corrected_author_controls')
            AUTHOR_MODULE = author
        finally:
            sys.argv = saved
        focused = module(HERE / 'test_fixture.py', 'minimal_native_source_fixture_controls'); focused.CI = sys.modules[__name__]
        suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(author), unittest.defaultTestLoader.loadTestsFromModule(focused)])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.wasSuccessful() and result.testsRun == AUTHOR_CONTROLS + 2 and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and not ATTEMPTS
    print(json.dumps(dict(status='PASS_CORRECTED_MINIMAL_NATIVE_SOURCE_DATA_ONLY' if passed else 'FAIL',
                         author_revision=AUTHORED_REVISION, tests=result.testsRun, authored_controls=AUTHOR_CONTROLS, fixture_controls=2,
                         skips=len(result.skipped), actor_attempts=len(ATTEMPTS), package_or_rootfs_archive_bodies_read=False,
                         signature_authentication=None, Root_selection=None, native=None, M2=None, old349_admission=None), sort_keys=True))
    return passed


if __name__ == '__main__':
    need(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, 'unoptimized Python -I -B required')
    raise SystemExit(0 if run() else 1)
