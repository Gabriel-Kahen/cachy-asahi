"""Dormant fixed-operation ports. No constructor or method runs on import.

The future Root caller must separately freeze this Source, runtime, private paths,
whole-invocation deadline and process cleanup. A supplied plan hash is a binding
operand, not intrinsic proof of Root authorization. Cache/key-home retention and
native/transitive-library trust remain external operational responsibilities.
"""
import os
from pathlib import Path
import stat
import subprocess

from common import Bound, loads, need, pin, read_file, sha
from helper_policy import load_helpers, validate_gpg


class RealOperations:
    def __init__(self, bound, bundle, cache, public_key_directory, new_gpg_home, operational_plan_sha256):
        need(type(bound) is Bound, 'BOUND_TYPE')
        self.plan_sha256 = pin(operational_plan_sha256)
        self.bound = bound
        self.rows = {row['name']:row for row in bound.rows()}
        self.cache = Path(cache).absolute()
        self.keydir = Path(public_key_directory).absolute()
        self.home = Path(new_gpg_home).absolute()
        need(len({self.cache,self.keydir,self.home}) == 3 and self.home.parent == self.cache.parent and
             self.home not in self.cache.parents and self.cache not in self.home.parents,
             'PRIVATE_PATH_SEPARATION')
        self.helpers = load_helpers({'scripts/port/authenticate.py':bundle['legacy_authenticate'],
                                     'scripts/ci/native_arm.py':bundle['legacy_native'],
                                     'scripts/port/preview.py':bundle['legacy_preview']})
        self.keys = loads(bundle['builder'])['keyring_files']
        self.prepared = False

    def directory(self, path):
        need(not path.is_symlink(), 'PRIVATE_DIRECTORY_SYMLINK')
        for parent in path.parents:
            need(not parent.is_symlink(), 'PRIVATE_ANCESTOR_SYMLINK')
        info = path.stat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY_OWNER_MODE')

    def command(self, arguments):
        # No shell, key retrieval, agent autostart, user config or inherited stdin.
        allowed = [['--import',str(self.keydir/'archlinuxarm.gpg')]] + [
            ['--status-fd','1','--verify',str(self.cache/(row['filename']+'.sig')),str(self.cache/row['filename'])]
            for row in self.rows.values()]
        need(type(arguments) is list and arguments in allowed, 'FIXED_GPG_COMMAND_SHAPE')
        return subprocess.run(['/usr/bin/gpg','--batch','--no-options','--no-tty',
            '--homedir',str(self.home),'--no-auto-key-retrieve','--no-autostart'] + arguments,
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60,
            close_fds=True, env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C',
                                 'HOME':str(self.home),'GNUPGHOME':str(self.home)})

    def prepare(self):
        need(not self.prepared, 'PREPARE_ONCE')
        self.directory(self.cache)
        self.directory(self.home.parent)
        need(not self.home.exists() and not self.home.is_symlink(), 'GPG_HOME_MUST_BE_NEW')
        for item in self.keys:
            raw = read_file(self.keydir / item['filename'], 65536)
            need(len(raw) == item['size'] and sha(raw) == item['sha256'], 'PUBLIC_KEY_RAW_PIN')
        self.home.mkdir(mode=0o700)
        self.directory(self.home)
        result = self.command(['--import',str(self.keydir/'archlinuxarm.gpg')])
        need(type(result.returncode) is int and result.returncode == 0, 'PUBLIC_KEY_IMPORT_FAILED')
        self.prepared = True

    def selected(self, row):
        need(self.prepared and row == self.rows.get(row.get('name')), 'EXACT_SELECTED_ROW_REQUIRED')
        self.directory(self.cache)
        self.directory(self.home)

    def artifact(self, row, signature=False):
        name = row['filename'] + ('.sig' if signature else '')
        size = row['signature_size'] if signature else row['size']
        expected = row['signature_sha256'] if signature else row['sha256']
        path = self.cache / name
        raw = read_file(path, size)
        need(len(raw) == size and sha(raw) == expected, 'ACQUIRED_RAW_PIN')
        return path, {'sha256':expected,'bytes':size}

    def acquire(self, row):
        self.selected(row)
        for signature in (False,True):
            path = self.cache/(row['filename']+('.sig' if signature else ''))
            if path.exists() or path.is_symlink():
                self.artifact(row,signature)
        self.helpers['fetch'](row, self.cache)
        self.helpers['fetch'](self.helpers['signature_item'](row), self.cache)
        return {'archive':self.artifact(row)[1], 'signature':self.artifact(row,True)[1]}

    def verify(self, row):
        self.selected(row)
        payload = self.artifact(row)[0]
        signature = self.artifact(row,True)[0]
        result = self.command(['--status-fd','1','--verify',str(signature),str(payload)])
        record = {'exit':result.returncode, 'status':result.stdout,
                  'diagnostic':result.stderr.replace(str(self.cache),'<private-cache>').replace(str(self.home),'<public-only-home>')}
        validate_gpg(record)
        self.artifact(row); self.artifact(row,True)
        return record

    def observe(self, row):
        self.selected(row)
        result = self.helpers['observe'](self.artifact(row)[0], row)
        self.artifact(row)
        return result

    def finish(self):
        # No global cleanup claim or unreviewed recursive deletion. The future
        # operational owner must dispose of its private paths/processes explicitly.
        return None
