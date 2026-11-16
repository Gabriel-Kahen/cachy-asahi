#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Actual HOST timestamp/FD controls on owned scratch; no guest or ALPM run.

Only the exact two new root.sh helpers run, projected from /etc into scratch.
UID/GID assertions use the invoking test owner, never sudo or real Root state.
Whole predecessor inverse pins all preexisting transaction/preservation bytes.
"""
import errno
import base64
import copy
import importlib.util
import hashlib
import os
from pathlib import Path
import resource
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE/'guest/root.sh').read_text()
START = '# The normal ldconfig hook can create/remove ld.so.cache and change /etc mtime.\n'
END = 'cache_snapshot() (\n'
HELPERS = SOURCE[SOURCE.index(START):SOURCE.index(END)]
ROOT55_SHA256 = '9be11484131188df57b7f23fec3fe9e75b4fe9066833f752fed7353b7b513aa0'
MTIME = 1794708503123456789
ATIME = 1794708403987654321


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (128*1024**2, 128*1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def fence(event, args):
    if event == 'subprocess.Popen':
        if args[0] != '/usr/bin/bash' or args[1][:3] != ['/usr/bin/bash', '--noprofile', '--norc']:
            raise AssertionError('only fixed HOST Bash helper fixture allowed')
    elif event.startswith(('socket.', 'ctypes.', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.')) or event == 'os.system':
        raise AssertionError('HOST timestamp test actor fence: '+event)


sys.addaudithook(fence)


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='perl-etc-mtime-HOST-')
        self.top = Path(self.tmp.name)
        self.etc = self.top/'etc'
        self.data = self.top/'case'
        self.cache = self.data/'cache'
        self.etc.mkdir(mode=0o755)
        self.cache.mkdir(mode=0o700, parents=True)
        self.reference = self.cache/'etc-mtime.reference'
        self.config = self.etc/'config'
        self.config.write_bytes(b'HOST owned configuration\n')
        self.config.chmod(0o644)
        self.original = None

    def close(self):
        self.tmp.cleanup()

    def stamp(self):
        os.utime(self.etc, ns=(ATIME, MTIME))
        self.original = self.etc.stat()

    def run(self, body, *, before=''):
        uid, gid = os.getuid(), os.getgid()
        # Finite inverse: the production literal and assertions stay exact.
        edits = [('/etc', '"$MODEL_ETC"'), (' == 0:0:755', f' == {uid}:{gid}:755'),
                 (' == 0:0:700', f' == {uid}:{gid}:700'), (' == 0:0:1:600:0', f' == {uid}:{gid}:1:600:0')]
        text = HELPERS
        for old, new in edits:
            if old not in text or new in text:
                raise AssertionError('fixed HOST projection seam')
            text = re.sub(r'/etc(?![A-Za-z0-9._/-])', lambda _: new, text) if old == '/etc' else text.replace(old, new)
        inverse = text
        for old, new in reversed(edits):
            inverse = inverse.replace(new, old)
        if inverse != HELPERS:
            raise AssertionError('whole HOST projection inverse')
        script = 'set -Eeuo pipefail\numask 077\nD=$1\n'+text+before+'\n'+body
        result = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', script, 'HOST-helper', str(self.data)],
                 cwd=self.top, env=dict(PATH='/usr/bin:/bin', HOME=str(self.top), LC_ALL='C', TZ='UTC', MODEL_ETC=str(self.etc)),
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6, preexec_fn=limits)
        if max(len(result.stdout), len(result.stderr)) > 65536:
            raise AssertionError('bounded HOST helper output')
        return result


class Controls(unittest.TestCase):
    def fixture(self):
        value = Fixture()
        self.addCleanup(value.close)
        return value

    def test_exact_nanoseconds_restored_for_original_cache_presence_or_absence(self):
        for present in (False, True):
            with self.subTest(present=present):
                f = self.fixture()
                cache = f.etc/'ld.so.cache'
                if present:
                    cache.write_bytes(b'original HOST cache\n')
                    cache.chmod(0o644)
                f.stamp()
                body = '''cache_etc_timestamp_capture
[[ -f $D/cache/etc-mtime.reference && $(stat -c '%a:%h:%s' -- "$D/cache/etc-mtime.reference") == 600:1:0 ]]
[[ $(stat -Lc '%d:%i' -- "/proc/self/fd/$etc_directory_fd") == $(stat -c '%d:%i' -- "$MODEL_ETC") ]]
printf 'normal hook cache replacement\\n' > "$MODEL_ETC/new-cache"
rm -f -- "$MODEL_ETC/ld.so.cache"
'''
                if present:
                    body += 'printf "original HOST cache\\n" > "$MODEL_ETC/ld.so.cache"\nchmod 644 -- "$MODEL_ETC/ld.so.cache"\n'
                body += '''rm -- "$MODEL_ETC/new-cache"
[[ $(stat -c '%y' -- "$MODEL_ETC") != "$etc_directory_mtime" ]]
cache_etc_timestamp_restore
[[ ! -e /proc/self/fd/$etc_directory_fd && ! -L /proc/self/fd/$etc_directory_fd ]]
[[ ! -e $D/cache/etc-mtime.reference && ! -L $D/cache/etc-mtime.reference ]]
'''
                result = f.run(body)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                info = f.etc.stat()
                self.assertEqual(info.st_mtime_ns, MTIME)
                self.assertEqual(info.st_atime_ns, ATIME)
                self.assertEqual((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink),
                                 (f.original.st_dev, f.original.st_ino, f.original.st_mode, f.original.st_uid, f.original.st_gid, f.original.st_nlink))
                self.assertEqual(f.config.read_bytes(), b'HOST owned configuration\n')
                self.assertEqual(cache.exists(), present)
                self.assertFalse(f.reference.exists())

    def test_directory_replacement_alias_mode_and_link_count_changes_refuse_before_touch(self):
        cases = ['mv -- "$MODEL_ETC" old-etc;mkdir -m755 -- "$MODEL_ETC"',
                 'mv -- "$MODEL_ETC" old-etc;ln -s -- old-etc "$MODEL_ETC"',
                 'chmod 700 -- "$MODEL_ETC"', 'mkdir -- "$MODEL_ETC/new-directory"',
                 '''stat() { local value;value=$(/usr/bin/stat "$@");if [[ ${@: -1} == "$MODEL_ETC" && $2 == '%d:%i:%f:%u:%g:%h' ]];then printf '%sOTHER_UID_GID\\n' "$value";else printf '%s\\n' "$value";fi; }''']
        for mutation in cases:
            with self.subTest(mutation=mutation):
                f = self.fixture()
                f.stamp()
                result = f.run('cache_etc_timestamp_capture\n'+mutation+'\ntouch() { printf BAD_TOUCH;return 0; }\ncache_etc_timestamp_restore\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'BAD_TOUCH', result.stdout)
                self.assertTrue(f.reference.exists())

    def test_replaced_directory_after_precheck_never_gets_its_timestamp_changed(self):
        f = self.fixture()
        f.stamp()
        result = f.run('''cache_etc_timestamp_capture
touch() {
 mv -- "$MODEL_ETC" old-etc
 mkdir -m755 -- "$MODEL_ETC"
 /usr/bin/touch "$@"
}
cache_etc_timestamp_restore
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((f.top/'old-etc').stat().st_mtime_ns, MTIME)
        self.assertNotEqual(f.etc.stat().st_mtime_ns, MTIME)
        self.assertTrue(f.reference.exists())

    def test_capture_refuses_occupied_alias_and_special_references_without_clobber(self):
        for kind in ('regular', 'symlink', 'dangling', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                f = self.fixture()
                outside = f.top/'outside'
                outside.write_bytes(b'UNOWNED MODEL sentinel')
                if kind == 'regular': f.reference.write_bytes(b'existing')
                elif kind == 'symlink': f.reference.symlink_to(outside)
                elif kind == 'dangling': f.reference.symlink_to(f.top/'absent')
                elif kind == 'hardlink': os.link(outside, f.reference)
                else: os.mkfifo(f.reference)
                f.stamp()
                before = f.reference.lstat()
                result = f.run('cache_etc_timestamp_capture\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((f.reference.lstat().st_ino, f.reference.lstat().st_mode), (before.st_ino, before.st_mode))
                self.assertEqual(outside.read_bytes(), b'UNOWNED MODEL sentinel')
                self.assertEqual(f.etc.stat().st_mtime_ns, MTIME)

    def test_refuses_reference_tampering_alias_mode_data_and_cache_parent_changes(self):
        cases = ['printf X > "$D/cache/etc-mtime.reference"',
                 'chmod 644 -- "$D/cache/etc-mtime.reference"',
                 'rm -- "$D/cache/etc-mtime.reference";ln -s -- "$MODEL_ETC/config" "$D/cache/etc-mtime.reference"',
                 'ln -- "$D/cache/etc-mtime.reference" "$D/cache/alias"',
                 'rm -- "$D/cache/etc-mtime.reference";: > "$D/cache/etc-mtime.reference"',
                 'chmod 755 -- "$D/cache"',
                 'mv -- "$D/cache" "$D/original-cache";ln -s -- original-cache "$D/cache"']
        for mutation in cases:
            with self.subTest(mutation=mutation):
                f = self.fixture()
                f.stamp()
                result = f.run('cache_etc_timestamp_capture\n'+mutation+'\ntouch() { printf BAD_TOUCH;return 0; }\ncache_etc_timestamp_restore\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'BAD_TOUCH', result.stdout)

    def test_capture_rejects_noncanonical_or_wrong_mode_directories(self):
        for mutation in ('chmod 700 -- "$MODEL_ETC"', 'chmod 755 -- "$D/cache"',
                         'mv -- "$MODEL_ETC" old-etc;ln -s -- old-etc "$MODEL_ETC"'):
            f = self.fixture()
            f.stamp()
            result = f.run('cache_etc_timestamp_capture\n', before=mutation)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(f.reference.exists())

    def test_only_mtime_changes_and_existing_xattrs_and_configuration_are_preserved(self):
        f = self.fixture()
        try:
            os.setxattr(f.etc, 'user.HOST_timestamp_test', b'directory attribute')
            os.setxattr(f.config, 'user.HOST_timestamp_test', b'configuration attribute')
        except OSError as error:
            if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):self.skipTest('HOST scratch filesystem has no user xattrs')
            raise
        f.stamp()
        config_before = f.config.stat()
        result = f.run('''cache_etc_timestamp_capture
printf CACHE > "$MODEL_ETC/ld.so.cache"
rm -- "$MODEL_ETC/ld.so.cache"
cache_etc_timestamp_restore
''')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(f.etc.stat().st_mtime_ns, MTIME)
        self.assertEqual(f.etc.stat().st_atime_ns, ATIME)
        self.assertEqual(os.getxattr(f.etc, 'user.HOST_timestamp_test'), b'directory attribute')
        self.assertEqual(os.getxattr(f.config, 'user.HOST_timestamp_test'), b'configuration attribute')
        self.assertEqual(f.config.stat(), config_before)

    def test_touch_or_cleanup_error_propagates_and_no_success_is_invented(self):
        for before in ('touch() { return 23; }\n', 'rm() { return 24; }\n'):
            f = self.fixture()
            f.stamp()
            body = 'cache_etc_timestamp_capture\n'+before+'cache_etc_timestamp_restore\nprintf BAD_SUCCESS\n'
            result = f.run(body)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'BAD_SUCCESS', result.stdout)
            self.assertTrue(f.reference.exists())
        f = self.fixture()
        f.stamp()
        result = f.run('cache_etc_timestamp_capture\nprintf BAD_SUCCESS\n', before='touch() { return 23; }\n')
        self.assertEqual(result.returncode, 23)
        self.assertNotIn(b'BAD_SUCCESS', result.stdout)

    def test_independent_preservation_still_refuses_model_etc_timestamp_drift(self):
        spec = importlib.util.spec_from_file_location('HOST_timestamp_image_MODEL', HERE/'image.py')
        image = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(image)
        log = b'MODEL original transaction log\n'
        row = dict(type='directory', mode=0o755, uid=0, gid=0, mtime=1794708503, mtime_ns=0)
        before = dict(nodes={'etc': row, 'var/log/pacman.log': dict(type='file', mode=0o644, uid=0, gid=0,
                           mtime=1, mtime_ns=0, sha256=hashlib.sha256(log).hexdigest())},
                      records={'var/lib/pacman/local/MODEL-1/desc': '%NAME%\nMODEL\n\n%VERSION%\n1\n',
                               'var/lib/pacman/local/MODEL-1/files': '%FILES%\netc/\n'},
                      log_data_b64=base64.b64encode(log).decode())
        runtime = dict(candidate_namespace={}, baseline_namespace={}, dependency_transaction={}, restoration_allowances=dict(
                       install_date_path=None, database_timestamp_paths=['/var/lib/pacman/local'],
                       cache_directory_timestamps=['/var/cache', '/var/cache/ldconfig'], normal_pacman_log='/var/log/pacman.log',
                       pacman_log_before=dict(bytes=len(log), sha256=hashlib.sha256(log).hexdigest())))
        after = copy.deepcopy(before)
        after['nodes']['etc'].update(mtime=1794823231, mtime_ns=184000000)
        with self.assertRaisesRegex(ValueError, 'unrelated baseline timestamp drift: etc'):
            image.preserve(before, after, {'MODEL': '1'}, runtime)
        after['nodes']['etc'] = copy.deepcopy(row)
        self.assertEqual(image.preserve(before, after, {'MODEL': '1'}, runtime)['normal_timestamp_differences'], [])

    def test_full_source55_inverse_and_order_keep_every_prior_preservation_gate(self):
        self.assertEqual(SOURCE.count(HELPERS), 1)
        restored = SOURCE.replace(HELPERS, '', 1)
        for line in ('cache_etc_timestamp_capture\n', 'cache_etc_timestamp_restore\n'):
            self.assertEqual(restored.count(line), 1)
            restored = restored.replace(line, '', 1)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), ROOT55_SHA256)
        capture = SOURCE.index('\ncache_etc_timestamp_capture\n')
        restore = SOURCE.index('\ncache_etc_timestamp_restore\n')
        self.assertLess(SOURCE.index('cache_snapshot > "$S/before.cache"'), capture)
        self.assertLess(capture, SOURCE.index('checkpoint_phase dependency_install'))
        self.assertLess(SOURCE.index('same_bytes "$S/before.cache" "$S/after.cache"'), restore)
        self.assertLess(restore, SOURCE.index('payload_snapshot after'))
        self.assertLess(restore, SOURCE.index('sync -f "$D"', restore))
        self.assertNotIn('touch -a', HELPERS)
        self.assertNotIn('|| :', HELPERS)
        self.assertNotIn('mtime.reference', (HERE/'retention.py').read_text())
        self.assertNotIn("allowed_dirs.add('etc')", (HERE/'image.py').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
