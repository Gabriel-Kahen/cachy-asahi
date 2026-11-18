#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-free controls for the Perl serial, journal and retention successor."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
BASE, CASE = 'b' * 32, 'a' * 32
PASSWORD = 'MODEL_ONLY_NOT_A_SECRET'
LOGIN = dict(UID='1000', USERNAME='builder', PID1='systemd', ARCH='aarch64',
             PAGESIZE='16384', XDG_SESSION_ID='c1', Id='c1', Name='builder',
             User='1000', Active='yes', State='active', Class='user', Remote='no',
             Type='tty', Service='login', Leader='142', LOGIND='active', DBUS='active')
DIAGNOSTIC = b'PERL5423_POST_METADATA_DIAGNOSTIC_V1 STAGE='
JOURNAL = 'var/log/journal'
MOUNT = 'systemd.mount-extra=tmpfs:/var/log/journal:tmpfs:rw,nosuid,nodev,noexec,mode=2755,size=64M'


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {
        'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit',
    }:
        raise AssertionError('actor-free Perl source control: ' + event)


def module(root, name):
    spec = importlib.util.spec_from_file_location('journal_controls_' + name, root / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def file_pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def leaves(root):
    return {p.relative_to(root).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
            for p in root.rglob('*') if p.is_file()}


def login_frame(fields=LOGIN, insert=b''):
    rows = [f'{key}={value}'.encode() for key, value in fields.items()]
    if insert:
        rows.insert(6, insert)
    return b'\r\n'.join((b'TCG_LOGIN_BEGIN ' + BASE.encode(), *rows,
                         b'TCG_LOGIN_END ' + BASE.encode(), b''))


def phase(kind, fields):
    return (f'PERL5423_{kind}_BEGIN {CASE}\r\n' +
            ''.join(f'{key}={value}\r\n' for key, value in fields.items()) +
            f'PERL5423_{kind}_END {CASE}\r\n').encode()


class FragmentedStream:
    def __init__(self, data):
        self.chunks = iter(data[i:i + 7] for i in range(0, len(data), 7))
        self.sent = []

    def settimeout(self, seconds):
        if not 0 < seconds <= .5:
            raise AssertionError('bounded serial wait')

    def recv(self, size):
        return next(self.chunks, b'')

    def sendall(self, raw):
        self.sent.append(raw)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.constructor = module(HERE, 'constructor')
        temporary = tempfile.TemporaryDirectory(prefix='perl-journal-source-controls-')
        cls.addClassCleanup(temporary.cleanup)
        work = Path(temporary.name)
        cls.predecessor = cls.constructor.tracked_predecessor(work / 'tracked')
        # The inherited fixture imports ctypes, whose initializer opens the Python process.
        importlib.import_module('ctypes')
        sys.addaudithook(fence)
        cls.source = work / 'source'
        cls.pin = cls.constructor.construct(cls.predecessor, cls.source)
        cls.protocol = module(cls.source, 'protocol')
        cls.actor = module(cls.source, 'actor')
        cls.contracts = module(cls.source, 'contracts')
        cls.reference = cls.contracts.helper('reference_controller.py')

    def test_source_scope_preserves_the_exact_source339_dependencies(self):
        original = leaves(self.predecessor)
        successor = leaves(self.source)
        self.assertEqual(set(successor), set(original))
        changed = {name for name in original if successor[name] != original[name]}
        self.assertEqual(changed, {'actor.py', 'protocol.py', 'retention.py', 'test_controls.py',
                                   'source.lock.json'})
        self.assertEqual({n: mode for n, (_, mode) in successor.items()},
                         {n: mode for n, (_, mode) in original.items()})
        old_lock = original['source.lock.json'][0]
        old_pin = dict(bytes=60210, sha256='7beb4deb63cbd03b34738b41463380b388e67c2a8015b81f7124866e80b17b13')
        self.assertEqual(file_pin(old_lock), old_pin)
        self.assertEqual(module(self.predecessor, 'adapter').source(old_pin['sha256']), old_pin)
        new_lock = successor['source.lock.json'][0]
        self.assertEqual(self.pin, file_pin(new_lock))
        lock = json.loads(new_lock)
        self.assertEqual(lock['actual'], json.loads(old_lock)['actual'])
        self.assertEqual(module(self.source, 'adapter').source(self.pin['sha256']), self.pin)
        with self.assertRaises((FileExistsError, ValueError)):
            self.constructor.construct(self.predecessor, self.source)
        self.assertEqual(leaves(self.source), successor)
        self.assertEqual(leaves(self.predecessor), original)

    def test_initialized_and_legacy_retention_contracts(self):
        modern = self.source / 'retention.py'
        self.assertEqual(file_pin(modern.read_bytes()),
                         dict(bytes=7052, sha256='d7fd778f7b046e93f406413db7d6439127ba17b2b752b174317b9ef84ed24b7c'))
        for root in (self.source, self.source / '_legacy'):
            with self.subTest(runtime=root.name):
                model = module(root, 'test_controls').Controls('test_closed_retained_export_roundtrip_and_refusals')
                model.debug()

    def test_tampered_predecessor_refuses_before_output(self):
        with tempfile.TemporaryDirectory(prefix='perl-journal-mismatched-source-') as name:
            work = Path(name)
            predecessor = work / 'predecessor'
            shutil.copytree(self.predecessor, predecessor)
            image = predecessor / 'image.py'
            image.write_bytes(image.read_bytes() + b'\n# MODEL source tamper\n')
            output = work / 'source'
            with self.assertRaises(ValueError):
                self.constructor.construct(predecessor, output)
            self.assertFalse(output.exists())

    def test_login_projection_retains_only_exact_session_fields(self):
        # Reproduce the shared-TTY layout using modeled IDs and public diagnostic labels.
        wire = (b'login: Password: ARM16K_SHELL_READY ' + BASE.encode() + b'\r\n' +
                login_frame(insert=b'\r\n' + DIAGNOSTIC + b'METADATA_RETURNED\r\n\r\n' +
                                   DIAGNOSTIC + b'SNAPSHOT_META_DONE') + b'outside frame\r\n')
        projected = []

        def parse(data, nonce):
            projected.append(data)
            return self.reference.parse_frame(data, nonce)

        self.assertEqual(self.protocol._login_frame(wire, BASE, parse), LOGIN)
        self.assertEqual(projected, [login_frame().replace(b'\r\n', b'\n')])
        online = dict(LOGIN, Active='no', State='online')
        self.assertEqual(self.protocol._login_frame(login_frame(online), BASE,
                                                   self.reference.parse_frame), online)

    def test_unrecognized_unpaired_and_extra_login_rows_refuse(self):
        variants = {
            'arbitrary line': login_frame(insert=b'unrecognized tty output'),
            'unknown diagnostic': login_frame(insert=b'\r\n' + DIAGNOSTIC + b'UNKNOWN'),
            'unpaired diagnostic': login_frame(insert=DIAGNOSTIC + b'COPY_DONE'),
            'surplus blank': login_frame(insert=b'\r\n\r\n' + DIAGNOSTIC + b'COPY_DONE'),
            'excess diagnostics': login_frame(insert=b'\r\n'.join(
                [b'\r\n' + DIAGNOSTIC + b'COPY_DONE'] * 17)),
            'extra scalar': login_frame(dict(LOGIN, EXTRA_MODEL_FIELD='extra')),
            'duplicate scalar': login_frame(insert=b'Active=yes'),
            'missing Active': login_frame({key: value for key, value in LOGIN.items() if key != 'Active'}),
            'invalid Active': login_frame(dict(LOGIN, Active='unknown')),
            'unmatched session IDs': login_frame(dict(LOGIN, XDG_SESSION_ID='different')),
            'duplicate frame': login_frame() + login_frame(),
            'incomplete end line': login_frame()[:-2],
        }
        for reason, wire in variants.items():
            with self.subTest(reason=reason), self.assertRaises((ValueError, AssertionError)):
                self.protocol._login_frame(wire, BASE, self.reference.parse_frame)

    def test_fragmented_login_proof_and_early_hold_stop_before_restoration(self):
        prefix = (b'login: Password: ARM16K_SHELL_READY ' + BASE.encode() + b'\r\n' +
                  login_frame(insert=b'\r\n' + DIAGNOSTIC + b'USERS_XATTR_MATCHED'))
        hold = phase('PROBE', dict(STATUS='HOLD', FAILED_PHASE='probe_checks', EXIT_STATUS='1'))
        stream = FragmentedStream(prefix + hold)
        serial = self.reference.Serial(stream, time.monotonic() + 5)
        with self.assertRaises(self.protocol.GuestHold) as error:
            self.protocol.journey(serial, PASSWORD, BASE, CASE, self.reference.parse_frame)
        self.assertEqual(error.exception.failure,
                         dict(status='HOLD', waiting='INSTALLED', frame='PROBE', phase='probe_checks'))
        self.assertEqual(stream.sent[:3], [b'builder\n', PASSWORD.encode() + b'\n',
                                          b'unset HISTFILE; /usr/local/libexec/arm16k-login-proof\n'])
        self.assertEqual(len(stream.sent), 4)
        self.assertTrue(stream.sent[-1].endswith(b'/probe.sh ' + CASE.encode() + b'\n'))
        restored = dict(self.protocol.RESTORED, DB_POLICY='EXACT',
                        **dict.fromkeys(self.protocol.HASHES, 'c' * 64),
                        **dict.fromkeys(self.protocol.EPOCHS, '1794779396'))
        stream = FragmentedStream(prefix + phase('INSTALLED', self.protocol.INSTALLED) +
                                  phase('PROBE', self.protocol.PROBE) + phase('RESTORED', restored) + b'login: ')
        result = self.protocol.journey(self.reference.Serial(stream, time.monotonic() + 5), PASSWORD,
                                       BASE, CASE, self.reference.parse_frame)
        self.assertEqual(result['session'], LOGIN)
        self.assertEqual(result['restored'], restored)
        self.assertTrue(result['normal_PAM_logout_observed'])
        self.assertEqual(stream.sent[-2:], [stream.sent[3].rstrip(b'\n') + b' restored\n', b'exit\n'])

    def test_qemu_vector_adds_only_the_fixed_journal_tmpfs(self):
        predecessor = module(self.predecessor, 'actor')
        metadata = dict(baseline_nonce=BASE, nonce=CASE, preboot_etc_descriptor=dict(sha256='d' * 64),
                        root_ssh_descriptor=dict(sha256='e' * 64))
        resources = dict(cpus=2, guest_memory_bytes=128 * 1024**2)
        old = predecessor.qemu_argv(metadata, resources, 1794779396)
        new = self.actor.qemu_argv(metadata, resources, 1794779396)
        append = old.index('-append') + 1
        self.assertEqual(new[append].split().count(MOUNT), 1)
        self.assertEqual(new[:append] + [new[append].replace(MOUNT + ' ', '', 1)] + new[append + 1:], old)

    def test_journal_only_mountpoint_atime_may_vary_without_mutating_scans(self):
        directory = dict(type='directory', inode=41, links=3, mode=0o2755, uid=0, gid=0,
                         mtime=100, mtime_ns=11, atime=101, atime_ns=12, ctime=102, ctime_ns=13, xattrs={})
        child = dict(directory, type='file', inode=42, links=1, mode=0o600, sha256='d' * 64)
        child_directory = JOURNAL + '/model-machine'
        child_path = child_directory + '/model.journal'
        before = dict(nodes={JOURNAL: directory, child_directory: dict(directory, inode=43, links=2), child_path: child})
        after = copy.deepcopy(before)
        after['nodes'][JOURNAL].update(atime=102, atime_ns=13)
        expected_before, expected_after = copy.deepcopy((before, after))
        self.actor.preserve_persistent_journal(self.contracts, before, before)
        self.actor.preserve_persistent_journal(self.contracts, before, after)
        self.assertEqual((before, after), (expected_before, expected_after))

        for path, field, value in (
            (JOURNAL, 'mtime', 103), (JOURNAL, 'mtime_ns', 14), (JOURNAL, 'inode', 45),
            (JOURNAL, 'xattrs', {'user.model': 'eA=='}), (JOURNAL, 'type', 'symlink'),
            (JOURNAL, 'mode', 0o755), (JOURNAL, 'links', 4), (JOURNAL, 'uid', 1000),
            (JOURNAL, 'ctime', 103), (JOURNAL, 'ctime_ns', 14), (JOURNAL, 'gid', 1000),
            (child_directory, 'atime', 103),
            (child_path, 'atime', 103), (child_path, 'atime_ns', 14), (child_path, 'sha256', 'e' * 64),
        ):
            changed = copy.deepcopy(after)
            changed['nodes'][path][field] = value
            with self.subTest(path=path, field=field), self.assertRaisesRegex(ValueError, 'persistent journal tree'):
                self.actor.preserve_persistent_journal(self.contracts, before, changed)
        for nodes in ({}, {JOURNAL: directory}, dict(after['nodes'], **{JOURNAL + '/new.journal': child})):
            with self.assertRaisesRegex(ValueError, 'persistent journal tree'):
                self.actor.preserve_persistent_journal(self.contracts, before, dict(nodes=nodes))


if __name__ == '__main__':
    unittest.main(verbosity=2)
