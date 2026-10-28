#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Session-borrowed Zsh consumer; no loader, original producer or grant issuer."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
from contextlib import contextmanager

ADDON = 'scripts/ci/development/zsh_addon.py'
SELF = 'scripts/ci/development/zsh_session.py'
HANDOFF = 'scripts/ci/development/repository_handoff.py'
CONTRACT = 'manifests/reviewed/zsh-native-addon.json'
ORIGINALS = ('native_arm', 'integration_export', 'lifecycle_inventory',
             'repository_projection', 'desktop_projection', 'commit_image',
             'sign_fixture', 'integration', 'package_checks')
ALIASES = ('repository_projection.inventory', 'desktop_projection.policy')


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


class Budget:
    def __init__(self, job_deadline):
        need(type(job_deadline) in (int, float) and math.isfinite(job_deadline), 'deadline-invalid')
        self.clock = time.monotonic
        self.io_uncertain = []
        self.start = self.clock()
        self.end = min(job_deadline, self.start + 1200)
        self.work_end = min(self.end - 120, self.start + 1080)
        self.remaining(1)

    def remaining(self, cap, cleanup=False):
        need(type(cap) in (int, float) and math.isfinite(cap) and 0 < cap <= 1200,
             'operation-cap-invalid')
        left = (self.end if cleanup else self.work_end) - self.clock()
        need(left > 0, 'deadline-expired')
        return min(left, cap)


def dispose_fd(descriptor, owned, deadline):
    first = None
    if owned is None:
        deadline.io_uncertain.append('descriptor-identity-unavailable')
        return Refusal('descriptor-identity-unavailable')
    for _ in range(3):
        try:
            row = os.fstat(descriptor)
            need((row.st_dev,row.st_ino,stat.S_IFMT(row.st_mode),row.st_rdev)==owned,
                 'descriptor-foreign')
            os.close(descriptor)
            return first
        except BaseException as error:
            if isinstance(error,OSError) and error.errno==9:
                return first
            first = first or error
            if type(error) is Refusal:
                break
    deadline.io_uncertain.append('descriptor-disposal-unproved')
    return first


@contextmanager
def owned_file(path, flags, deadline, cleanup=False):
    descriptor = owned = None
    allocating = False
    try:
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
        try:
            deadline.remaining(1,cleanup)
            need(not deadline.io_uncertain,'descriptor-disposal-unproved')
            allocating=True
            descriptor=os.open(path,flags|os.O_CLOEXEC,0o600)
            row=os.fstat(descriptor)
            owned=(row.st_dev,row.st_ino,stat.S_IFMT(row.st_mode),row.st_rdev)
        finally:
            cause=sys.exc_info()[1]
            try:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
            except BaseException:
                if cause is None:raise
        deadline.remaining(1,cleanup)
        yield descriptor
    finally:
        cause=sys.exc_info()[1]
        error=None
        if descriptor is not None:
            error=dispose_fd(descriptor,owned,deadline)
        elif allocating:
            deadline.io_uncertain.append('descriptor-allocation-unproved')
        if cause is None:
            if error is not None:raise error
            deadline.remaining(1,cleanup)


def borrow_context(session, controller, root, deadline):
    """Require the captured Session class, graph and real suspended original view."""
    root = Path(root).absolute()
    module = sys.modules.get(type(session).__module__)
    need(type(module) is types.ModuleType and module.__name__ == 'development_repository_handoff'
         and module.__file__ == str(root / HANDOFF) and type(session) is module.Session
         and type(session.sources) is module.Sources, 'actual-session-required')
    sources = session.sources
    sources.class_state(session, HANDOFF, module)
    sources.class_state(sources, HANDOFF, module)
    need(sources.root == root and session.controller is controller, 'session-controller-refused')
    sources.guard(deadline, session.cancelled)
    graph = session.source_graph
    zsh = graph.get('zsh')
    need(type(zsh) is dict and set(zsh) == {'zsh_addon', 'zsh_session'}, 'zsh-graph-required')
    own = sys.modules.get(__name__)
    addon = zsh['zsh_addon']
    need(zsh['zsh_session'] is own and type(own) is types.ModuleType and
         own.__file__ == str(root / SELF) and own.run_zsh is run_zsh and
         type(addon) is types.ModuleType and addon.__file__ == str(root / ADDON), 'zsh-namespace-refused')
    context = session.original_context(deadline=deadline, controller=controller)
    need(type(context) is dict and set(context) == {'root','receipt','sha256','original','aliases'} and
         type(context['receipt']) is bytes and 0 < len(context['receipt']) <= 8 * 1024**2 and
         sha(context['receipt']) == context['sha256'] and
         type(context['original']) is dict and set(context['original']) == set(ORIGINALS) and
         type(context['aliases']) is dict and set(context['aliases']) == set(ALIASES), 'original-context-refused')
    need(context['root'] == session.view_root and all(context['original'][name] is graph['original'][name]
         for name in ORIGINALS) and all(context['aliases'][name] is graph['original_aliases'][name]
         for name in ALIASES), 'original-namespace-refused')
    return context


def same_context(before, after):
    need(all(after[key] == before[key] for key in ('root','receipt','sha256')) and
         all(after['original'][key] is value for key,value in before['original'].items()) and
         all(after['aliases'][key] is value for key,value in before['aliases'].items()), 'original-context-drift')


def read_session(addon, path, deadline, limit=8 * 1024**2, cleanup=False):
    deadline.remaining(1, cleanup)
    path = Path(path).absolute()
    need('..' not in path.parts and all(stat.S_ISDIR(item.lstat().st_mode) for item in path.parents),
         'input-parent-refused')
    before = path.lstat()
    shape = lambda row:(row.st_dev,row.st_ino,row.st_mode,row.st_nlink,row.st_uid,row.st_gid,
                       row.st_size,row.st_mtime_ns,row.st_ctime_ns)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0 <= before.st_size <= limit,
         'input-not-bounded-regular')
    with owned_file(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,deadline,cleanup) as fd:
        need(shape(os.fstat(fd))==shape(before),'input-raced')
        chunks=[];size=0
        while True:
            deadline.remaining(1,cleanup)
            chunk=os.read(fd,min(65536,limit+1-size))
            if not chunk:break
            size+=len(chunk);need(size <= limit,'input-byte-bound');chunks.append(chunk)
        need(shape(os.fstat(fd))==shape(path.lstat())==shape(before) and size==before.st_size,'input-raced')
        raw=b''.join(chunks)
    deadline.remaining(1, cleanup)
    return raw


def tree_session(addon, root, max_files=256, max_bytes=64*1024**2, *, deadline, cleanup=False):
    root=Path(root);result={};total=0
    for path,row in addon.nodes(root,deadline,cleanup):
        if stat.S_ISDIR(row.st_mode):continue
        raw=read_session(addon,path,deadline,cleanup=cleanup)
        total+=len(raw)
        need(len(result)<max_files and total <= max_bytes,'tree-bound-exceeded')
        result[path.relative_to(root).as_posix()]={'sha256':sha(raw),'bytes':len(raw),'mode':stat.S_IMODE(row.st_mode)}
        deadline.remaining(1,cleanup)
    return result


def receipt_destination_session(addon, path, parent, key, deadline, cleanup=False):
    row=path.parent.lstat()
    need((row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid)==key,'receipt-parent-raced')
    owned=addon._RECEIPT_FILES.get(str(path))
    need(owned is None or owned['parent']==key,'receipt-parent-foreign')
    try:row=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:return None
    need(owned is not None and addon.receipt_identity(row)==owned['identity'] and
         stat.S_ISREG(row.st_mode) and row.st_nlink==1 and
         sha(read_session(addon,path,deadline,cleanup=cleanup))==owned['sha256'],'receipt-destination-foreign')
    return row


def receipt_remove_session(addon, path, deadline):
    path=Path(path).absolute();parent=None;first=None
    try:
        with addon.defer_cancel():
            deadline.remaining(1,True)
            parent,key=addon.receipt_parent(path)
            for _ in range(3):
                try:
                    if receipt_destination_session(addon,path,parent,key,deadline,True) is None:
                        addon._RECEIPT_FILES.pop(str(path),None)
                        break
                    deadline.remaining(1,True)
                    os.unlink(path.name,dir_fd=parent)
                except BaseException as error:
                    first=first or error
                    if type(error) in (Refusal,addon.Refusal):break
            if receipt_destination_session(addon,path,parent,key,deadline,True) is None:
                addon._RECEIPT_FILES.pop(str(path),None)
            else:first=first or Refusal('receipt-invalidation-unproved')
    except BaseException as error:
        first=first or error
    finally:
        if parent is not None:
            error=addon.receipt_close(parent)
            first=first or error
    if first is not None:
        deadline.io_uncertain.append('receipt-invalidation-unproved')
    return first


def save_session(addon, path, value, deadline, cleanup=False):
    """Exclusive owned temporaries; faults remain failures after bounded retries."""
    deadline.remaining(1, cleanup)
    path = Path(path).absolute()
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    addon.need(len(data) <= addon.MAX_FILE and (not addon._RECEIPT_FDS) and (not addon._RECEIPT_UNCERTAIN), 'receipt-write-refused')
    addon.need(str(path) in addon._RECEIPT_FILES or len(addon._RECEIPT_FILES) < 256, 'receipt-registry-bound')
    first, parent = (None, None)
    try:
        with addon.defer_cancel():
            parent, key = addon.receipt_parent(path)
            receipt_destination_session(addon,path,parent,key,deadline,cleanup)
            for _ in range(3):
                deadline.remaining(1, cleanup)
                fd, temporary, expected, ready, committed = (None, None, None, False, False)
                try:
                    temporary = path.name + '.partial-' + os.urandom(8).hex()
                    deadline.remaining(1, cleanup)
                    fd = addon.receipt_open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, dir_fd=parent)
                    expected = addon._RECEIPT_FDS[fd]
                    position = 0
                    while position < len(data):
                        deadline.remaining(1, cleanup)
                        written = os.write(fd, data[position:])
                        addon.need(written > 0, 'receipt-write-short')
                        position += written
                    os.fchmod(fd, 384)
                    deadline.remaining(1, cleanup)
                    os.fsync(fd)
                    deadline.remaining(1, cleanup)
                    ready = True
                    receipt_destination_session(addon,path,parent,key,deadline,cleanup)
                    staged = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                    addon.need((staged.st_dev, staged.st_ino, stat.S_IFMT(staged.st_mode), staged.st_rdev) == expected and addon.receipt_identity(staged) == addon.receipt_identity(os.fstat(fd)) and (staged.st_nlink == 1), 'receipt-temporary-foreign')
                    deadline.remaining(1, cleanup)
                    os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                    committed = True
                    addon._RECEIPT_FILES[str(path)] = {'parent': key, 'identity': addon.receipt_identity(os.fstat(fd)), 'sha256': addon.sha(data)}
                    addon.need(addon.sha(read_session(addon, path, deadline, cleanup=cleanup)) == addon.sha(data), 'receipt-commit-raced')
                    os.fsync(parent)
                    deadline.remaining(1, cleanup)
                except BaseException as error:
                    first = addon.first_failure(first, error)
                finally:
                    if fd is not None and expected is not None:
                        try:
                            row = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                            if ready and (row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode), row.st_rdev) == expected:
                                addon.need(addon.sha(read_session(addon, path, deadline, cleanup=cleanup)) == addon.sha(data), 'receipt-commit-raced')
                                committed = True
                                addon._RECEIPT_FILES[str(path)] = {'parent': key, 'identity': addon.receipt_identity(row), 'sha256': addon.sha(data)}
                        except FileNotFoundError:
                            pass
                        except BaseException as error:
                            first = addon.first_failure(first, error)
                        for slot in range(3):
                            try:
                                row = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                                addon.need((row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode), row.st_rdev) == expected and row.st_nlink == 1 and (row.st_uid == os.getuid()) and (row.st_gid == os.getgid()), 'receipt-temporary-foreign')
                                os.unlink(temporary, dir_fd=parent)
                            except FileNotFoundError:
                                break
                            except BaseException as error:
                                first = addon.first_failure(first, error)
                                if type(error) is addon.Refusal or slot == 2:
                                    addon._RECEIPT_UNCERTAIN[key, temporary] = error
                                    break
                        error = addon.receipt_close(fd)
                        if error is not None:
                            first = addon.first_failure(first, error)
                    if fd is None and temporary is not None and (not isinstance(first, Exception)):
                        addon._RECEIPT_UNCERTAIN[key, temporary] = first
                if committed or addon._RECEIPT_UNCERTAIN or len(addon._RECEIPT_FDS) > 1 or (not isinstance(first, Exception)):
                    break
    except BaseException as error:
        first = addon.first_failure(first, error)
    finally:
        if parent is not None:
            error = addon.receipt_close(parent)
            if error is not None:
                first = addon.first_failure(first, error)
    if first is not None:
        try:
            if not (type(value) is dict and value.get('status') == 'FAIL' and (str(path) in addon._RECEIPT_FILES) and (addon.sha(read_session(addon, path, deadline, cleanup=cleanup)) == addon.sha(data))):
                removal = receipt_remove_session(addon,path,deadline)
                if removal is not None:
                    first = addon.first_failure(first, removal)
        except BaseException as error:
            first = addon.first_failure(first, error)
        raise first
    deadline.remaining(1, cleanup)


def write_bytes(path, raw, deadline, executable=False):
    """Exclusive bounded child bytes with same-endpoint partial-write checks."""
    need(type(raw) is bytes and 0 < len(raw) <= 8 * 1024**2, 'bootstrap-bound')
    deadline.remaining(1)
    path = Path(path)
    with owned_file(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,deadline) as descriptor:
        offset = 0
        while offset < len(raw):
            deadline.remaining(1)
            count = os.write(descriptor, raw[offset:])
            need(count > 0, 'bootstrap-short-write')
            offset += count
        os.fchmod(descriptor, 0o755 if executable else 0o600)
        deadline.remaining(1)
        os.fsync(descriptor)
        deadline.remaining(1)


def write_bootstrap_session(path, session, context, script, deadline):
    """Embed captured build/compare/checker bytes; never load the old authority."""
    session.sources.guard(deadline.work_end, session.cancelled)
    selected = {'build':'scripts/build/build.py', 'compare':'scripts/build/compare.py',
                'package_checks':'scripts/checks/package_checks.py'}
    modules = {name:{'path':str(context['root']/relative), 'data':session.sources.raw[relative]}
               for name,relative in selected.items()}
    name = Path(script).stem
    need(name in ('build','compare') and str(script) == modules[name]['path'], 'bootstrap-script-refused')
    content = ('import sys,importlib.abc,importlib.util,pathlib\n'
        f'M={modules!r}\nROOTS={[str(session.sources.root),str(context["root"])]!r}\n'
        'class L(importlib.abc.Loader):\n'
        ' def __init__(self,r): self.r=r\n'
        ' def create_module(self,s): return None\n'
        ' def exec_module(self,m):\n'
        '  p=self.r["path"];m.__file__=p;m.__cached__=None;exec(compile(self.r["data"],p,"exec"),m.__dict__)\n'
        'class F(importlib.abc.MetaPathFinder):\n'
        ' def find_spec(self,n,path=None,target=None):\n'
        '  if n in M: return importlib.util.spec_from_loader(n,L(M[n]),origin=M[n]["path"])\n'
        '  if "." not in n:\n'
        '   for e in sys.path:\n'
        '    b=pathlib.Path(e).absolute()\n'
        '    if any(b.is_relative_to(r) for r in ROOTS):\n'
        '     assert not (b/(n+".py")).exists() and not (b/n).exists()\n'
        '  return None\n'
        'sys.meta_path.insert(0,F())\n'
        f'r=M[{name!r}];p=r["path"];sys.argv[0]=p\n'
        'exec(compile(r["data"],p,"exec"),{"__name__":"__main__","__file__":p})\n').encode()
    write_bytes(path, content, deadline)
    session.sources.guard(deadline.work_end, session.cancelled)


def validate_attempt_session(addon, session, context, attempt, package, prerequisite, owned, deadline):
    deadline.remaining(1)
    session.sources.guard(deadline.work_end, session.cancelled)
    files = json.loads(context['receipt'])['files']
    rows = {name:{key:row[key] for key in ('sha256','mode')} for name,row in files.items()}
    need(rows == session.sources.original_rows, 'original-row-drift')
    record = addon.decode(read_session(addon, attempt / 'provenance.json', deadline))
    addon.need(record.get('status') == 'built-package-static-pass' and record.get('exit_code') == 0 and (record.get('mode') == 'native') and (record.get('network') == 'none') and (record.get('image') == record.get('image_id') == prerequisite['image_id']) and (record.get('recipe_inputs') == package['build_helper_reviewed_inputs']) and (record.get('source_date_epoch') == prerequisite['epoch']) and (record.get('expected_packages_sha256') == prerequisite['packages_sha256']) and (record.get('entry_script_sha256') == rows['scripts/build/container-entry.sh']['sha256']) and (record.get('clean_environment_id') == owned['name']) and (owned['status'] == 'EXITED') and (owned.get('observed') is True) and (owned['exit_code'] == 0), 'attempt-binding-refused')
    validation = addon.decode(read_session(addon, attempt / 'validation.json', deadline))
    addon.need(validation.get('errors') == [] and len(validation.get('artifacts', [])) == 1, 'attempt-validation-refused')
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock', 'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256', 'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    addon.need(isinstance(record.get('files'), dict) and required <= record['files'].keys(), 'attempt-files-missing')
    for name, checksum in record['files'].items():
        addon.need(addon.HEX.fullmatch(checksum) and addon.sha(read_session(addon, attempt / addon.relative(name), deadline)) == checksum, 'attempt-file-drift')
    for name in ('expected-packages.lock', 'artifacts/packages.lock'):
        addon.need(addon.sha(read_session(addon, attempt / name, deadline)) == prerequisite['packages_sha256'], 'attempt-inventory-drift')
    snapshot = tree_session(addon, attempt / 'inputs', 12, 54910, deadline=deadline)
    addon.need(snapshot == package['source_files'], 'attempt-input-snapshot-drift')
    artifacts = record['artifacts']
    addon.need(len(artifacts) == 1, 'artifact-count-refused')
    archive_name, checksum = next(iter(artifacts.items()))
    name = archive_name
    addon.need(re.fullmatch(addon.PACKAGE + '-0\\.7\\.1-1-any\\.pkg\\.tar\\.(xz|zst|gz)', name), 'artifact-name-refused')
    archive = attempt / 'artifacts' / name
    addon.need(addon.sha(read_session(addon, archive, deadline)) == checksum, 'artifact-hash-drift')
    inspected = validation['artifacts'][0]
    addon.need(inspected.get('artifact') == archive_name and inspected.get('sha256') == checksum and (inspected.get('status') == 'artifact-static-pass'), 'artifact-report-binding-refused')
    addon.need(inspected['errors'] == [] and (not inspected['elf']), 'artifact-inspection-refused')
    metadata = inspected['metadata']['.PKGINFO']
    for field, values in {'pkgname': [addon.PACKAGE], 'pkgver': ['0.7.1-1'], 'arch': ['any'], 'license': ['MIT'], 'depend': ['zsh>=4.3.11'], 'optdepend': package['optdepends']}.items():
        addon.need(metadata.get(field) == values, 'artifact-metadata-refused')
    addon.need(inspected['metadata']['.BUILDINFO'].get('pkgbuild_sha256sum') == [package['build_helper_reviewed_inputs']['PKGBUILD']], 'artifact-pkgbuild-refused')
    members, payload = (inspected['members'], package['expected_payloads'])
    files = {k for k, v in members.items() if v['type'] == '0'}
    addon.need(files == set(payload) | addon.META, 'artifact-member-set-refused')
    dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents}
    for name, row in members.items():
        addon.need(row['uid'] == row['gid'] == 0 and row['type'] in ('0', '5'), 'artifact-node-refused')
        if row['type'] == '5':
            addon.need(name in dirs and row['mode'] == 493, 'artifact-directory-refused')
        else:
            addon.need(row['mode'] == 420, 'artifact-mode-refused')
            if name in payload:
                addon.need(row['sha256'] == payload[name]['sha256'] and row['size'] == payload[name]['bytes'], 'artifact-payload-refused')
    deadline.remaining(1)
    session.sources.guard(deadline.work_end, session.cancelled)
    return {'name': archive_name, 'sha256': checksum, 'bytes': archive.stat().st_size, 'clean_environment_id': owned['name'], 'cid': owned['cid']}




class SessionDocker:
    def __init__(self, addon, config, deadline):
        self.addon, self.config, self.deadline = addon, config, deadline
        self.env = dict(config['actor_env'])

    def tools(self, cleanup=False):
        addon=self.addon;c=self.config;deadline=self.deadline
        deadline.remaining(1,cleanup)
        need(sha(read_session(addon,c['docker'],deadline,64*1024**2,cleanup))==c['docker_sha256'] and
             addon.identity(c['docker'])==c['docker_identity'] and addon.identity(c['socket'])==c['socket_identity'] and
             stat.S_ISSOCK(Path(c['socket']).lstat().st_mode),'docker-binding-drift')
        need(not any(Path(c['docker_config']).iterdir()),'docker-config-drift')
        need(str(Path(sys.executable).resolve())==c['python'] and addon.identity(c['python'])==c['python_identity'] and
             sha(read_session(addon,c['python'],deadline,64*1024**2,cleanup))==c['python_sha256'], 'python-binding-drift')
        need(c['docker_identity']['uid']==c['python_identity']['uid']==0 and
             not (c['docker_identity']['mode']|c['python_identity']['mode'])&0o022,'trusted-host-tool-mode-required')
        deadline.remaining(1,cleanup)

    def execute(self, argv, cap=30, cleanup=False):
        self.tools(cleanup)
        if 'daemon_binding' in self.config:
            self.binding(cleanup)
        cause = None
        try:
            return supervised_session(self.addon,
                [self.config['docker'],'--host',self.config['endpoint'],'--config',self.config['docker_config'],*argv],
                self.env,self.deadline,cap,cleanup=cleanup,new_group=not self.config.get('inside_helper',False),
                quota_root=None if cleanup else self.config['quota_root'])
        except BaseException as error:
            cause = error
            raise
        finally:
            first = None
            for callback in (self.tools, self.binding if 'daemon_binding' in self.config else None):
                if callback is not None:
                    try:
                        callback(cleanup)
                    except BaseException as error:
                        first = first or error
            if cause is None and first is not None:
                raise first

    def call(self, argv, cap=30, cleanup=False):
        code, raw = self.execute(argv, cap, cleanup)
        need(code == 0, 'docker-command-failed')
        return raw

    def binding(self, cleanup=False):
        self.tools(cleanup)
        code, raw = supervised_session(self.addon,
            [self.config['docker'],'--host',self.config['endpoint'],'--config',self.config['docker_config'],
             'info','--format','{{json .}}'],self.env,self.deadline,30,cleanup=cleanup,
             new_group=not self.config.get('inside_helper',False))
        self.tools(cleanup)
        need(code == 0, 'daemon-query-failed')
        info = self.addon.decode(raw)
        need({key:info.get(key) for key in self.config['daemon_binding']} ==
             self.config['daemon_binding'], 'daemon-binding-drift')

    def inspect(self, cid, cleanup=False):
        return self.addon.Docker.inspect(self, cid, cleanup)

    def absence(self, name, cid=None, cleanup=False):
        return self.addon.Docker.absence(self, name, cid, cleanup)


def supervised_session(addon, argv, env, deadline, cap, log=None, cleanup=False, new_group=True, quota_root=None):
    """Signal-safe spawn, finite output, and witnessed process-group disposal."""
    cutoff = deadline.clock() + deadline.remaining(cap, cleanup)
    addon.need(all(isinstance(v, str) and '\x00' not in v for v in argv), 'argv-invalid')
    process, stream, completed = None, None, False
    data = bytearray()
    next_quota = 0
    try:
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        try:
            argv, env = list(argv), dict(env)
            deadline.remaining(1, cleanup)
            addon.need(deadline.clock() < cutoff, 'process-timeout')
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=env, start_new_session=new_group, close_fds=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous))
        finally:
            # A pending handler can raise here only after process is retained.
            cause=sys.exc_info()[1]
            try:signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            except BaseException:
                if cause is None:raise
        if log is not None:
            stream = Path(log).open('xb')
        with selectors.DefaultSelector() as events:
            events.register(process.stdout, selectors.EVENT_READ)
            while events.get_map() or process.poll() is None:
                addon.need(deadline.clock() < cutoff, 'process-timeout')
                if quota_root is not None and deadline.clock() >= next_quota:
                    addon.quota(quota_root, deadline)
                    addon.need(deadline.clock() < cutoff, 'process-timeout')
                    next_quota = deadline.clock() + 0.5
                for key, _ in events.select(min(0.1, max(0, cutoff - deadline.clock()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        events.unregister(key.fileobj)
                    else:
                        addon.need(len(data) + len(block) <= 4 * 1024**2, 'process-output-bound')
                        data.extend(block)
                        if stream:
                            stream.write(block)
            code = process.wait(timeout=deadline.remaining(1, cleanup))
            completed = True
            deadline.remaining(1, cleanup)
            return code, bytes(data)
    finally:
        first, disposal_started, proof = sys.exc_info()[1], False, 'UNKNOWN' if process is not None else 'NOTRUN'
        try:
            with addon.defer_cancel():
                disposal_started = True
                first, proof = addon.dispose_process(process, deadline, new_group, completed, first)
        except BaseException as error:
            first = addon.first_failure(first, error)
        finally:
            mask = None
            try:
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
            except BaseException as error:
                first = addon.first_failure(first, error)
            try:
                if not disposal_started:
                    # Context entry failed before any signal was sent; one fallback only.
                    disposal_started = True
                    try:
                        first, proof = addon.dispose_process(process, deadline, new_group, completed, first)
                    except BaseException as error:
                        first = addon.first_failure(first, error)
                for owned_stream in (process.stdout if process is not None else None, stream):
                    if owned_stream is not None:
                        try:
                            owned_stream.close()
                        except BaseException as error:
                            first = addon.first_failure(first, error)
                            if getattr(owned_stream, 'closed', False) is not True:
                                proof = 'UNKNOWN'
            finally:
                if mask is not None:
                    try:
                        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                    except BaseException as error:
                        first = addon.first_failure(first, error)
        if proof == 'UNKNOWN' and not addon._PROCESS_DISPOSAL_UNCERTAIN:
            addon._PROCESS_DISPOSAL_UNCERTAIN.append(True)
        if first is not None:
            try:
                first.process_cleanup_status = proof
            except BaseException:
                if not addon._PROCESS_DISPOSAL_UNCERTAIN:
                    addon._PROCESS_DISPOSAL_UNCERTAIN.append(True)
            raise first
        if first is None:
            deadline.remaining(1, cleanup)


def gate_session(addon, config, argv):
    """Only two helper queries and one exact create/inspect/start transformation."""
    config = {**config, 'inside_helper': True}
    # CLI descendants stay in the builder's owned group. The outer supervisor
    # proves disposal of that group; this gate never forks an orphan session.
    deadline = Budget(config['stage_end'])
    deadline.end, deadline.work_end = config['stage_end'], config['work_end']
    deadline.work_end = min(deadline.work_end, config['gate_end'])
    docker = SessionDocker(addon, config, deadline)
    if argv == ['image', 'inspect', config['image']]:
        docker.binding()
        return 0, docker.call(argv)
    if argv == ['info', '--format', '{{.Architecture}}']:
        docker.binding()
        return 0, docker.call(argv)
    run = addon.exact_run(config, argv)
    docker.binding()
    owned = Path(config['owned'])
    addon.need(not owned.exists() and not Path(config['cidfile']).exists(), 'attempt-already-used')
    intent = {'status': 'INTENT', **run, 'image': config['image'], 'endpoint': config['endpoint'],
              'daemon_id': config['daemon_id'], 'cid': None, 'observed': False}
    save_session(addon, owned, intent, deadline)
    docker.absence(run['name'])
    reply = docker.call(run['create']).decode().strip()
    cid = read_session(addon, config['cidfile'], deadline, 128).decode().strip()
    addon.need(addon.HEX.fullmatch(cid) and reply == cid, 'create-cid-unproved')
    intent.update(cid=cid, status='CREATED')
    save_session(addon, owned, intent, deadline)
    docker.binding()
    info = docker.inspect(cid)
    addon.validate_container(config, info, run['name'], cid)
    addon.need(info['State']['Status'] == 'created' and all(info['State'].get(k) is False for k in
         ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled')), 'container-started-before-inspection')
    intent.update(status='OBSERVED_BEFORE_START', observed=True, configuration_sha256=sha(json.dumps(info, sort_keys=True).encode()))
    save_session(addon, owned, intent, deadline)
    # start --attach's client code is not the container exit code; inspect State.
    code, output = docker.execute(['start', '--attach', cid], deadline.remaining(270))
    intent['attach_exit_code'] = code
    save_session(addon, owned, intent, deadline)
    docker.binding()
    info = docker.inspect(cid)
    addon.validate_container(config, info, run['name'], cid)
    addon.need(info['State']['Status'] == 'exited' and all(info['State'].get(k) is False for k in
         ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled')) and
         type(info['State']['ExitCode']) is int and 0 <= info['State']['ExitCode'] <= 255 and
         not info['State'].get('Error') and not info['State'].get('OOMKilled'), 'container-terminal-state-unproved')
    intent.update(status='EXITED', exit_code=info['State']['ExitCode'])
    save_session(addon, owned, intent, deadline)
    addon.need(code == 0, 'docker-attach-failed')
    return info['State']['ExitCode'], output

def cleanup_attempt_session(addon, config, deadline):
    docker = SessionDocker(addon, config, deadline)
    owned = Path(config['owned'])
    addon.need(not owned.is_symlink() and not Path(config['cidfile']).is_symlink(), 'cleanup-evidence-node-refused')
    if not owned.exists():
        addon.need(not Path(config['cidfile']).exists(), 'cleanup-intent-missing-with-cid')
        return {'status': 'PASS', 'container_submitted': False}
    intent = addon.decode(read_session(addon, owned, deadline, cleanup=True))
    run = addon.exact_run(config, intent['original'])
    addon.need(intent['create'] == run['create'] and intent['image'] == config['image'] and
         intent['endpoint'] == config['endpoint'] and intent['daemon_id'] == config['daemon_id'], 'cleanup-intent-drift')
    docker.binding(True)
    cid = intent.get('cid')
    if cid is None:
        # A interrupted create may leave only cidfile; it is never alone a grant.
        if Path(config['cidfile']).exists():
            cid = read_session(addon, config['cidfile'], deadline, 128, True).decode().strip()
        else:
            docker.absence(run['name'], cleanup=True)
            return {'status': 'PASS', 'submitted_intent': True, 'observed_absent': True}
    addon.need(addon.HEX.fullmatch(cid), 'cleanup-cid-invalid')
    info = docker.inspect(cid, True)
    addon.validate_container(config, info, run['name'], cid)
    docker.call(['container', 'rm', '--force', cid], 60, True)
    docker.binding(True)
    docker.absence(run['name'], cid, True)
    return {'status': 'PASS', 'cid': cid, 'name': run['name'], 'observed_absent': True}


def restore_receipts(addon, output, deadline):
    """Restore only healthy selected receipt registries after witnessed retention."""
    need(not addon._RECEIPT_FDS and not addon._RECEIPT_UNCERTAIN and
         not addon._PROCESS_DISPOSAL_UNCERTAIN, 'receipt-cleanup-uncertain')
    for name, row in tuple(addon._RECEIPT_FILES.items()):
        deadline.remaining(1, True)
        path = Path(name)
        need(path.is_relative_to(output) and addon.receipt_identity(path.lstat()) == row['identity']
             and sha(read_session(addon, path, deadline, cleanup=True)) == row['sha256'],
             'receipt-restoration-refused')
    # Files remain retained. Only their temporary helper custody records retire;
    # subsequent aggregation reads them through the coordinator's bounded capture.
    addon._RECEIPT_FILES.clear()


def finalize_stage_session(addon, session, controller, root, context, output, result, configs, deadline):
    cleanups = []
    first = None
    retired = ()
    try:
        with addon.defer_cancel() as cancelled:
            for index, config in enumerate(configs):
                try:
                    deadline.remaining(1, True)
                    if index < len(result['attempts']) and result['attempts'][index].get('cleanup',{}).get('status') == 'PASS':
                        docker = SessionDocker(addon, config, deadline)
                        docker.binding(True)
                        row = result['attempts'][index]['archive']
                        docker.absence(row['clean_environment_id'], row['cid'], True)
                        cleanups.append(result['attempts'][index]['cleanup'])
                    else:
                        cleanups.append(cleanup_attempt_session(addon, config, deadline))
                except BaseException as error:
                    first = first or error
                    cleanups.append({'status':'UNKNOWN','error_code':'owned-cleanup-unproved'})
            result['cleanup'] = {'status':'PASS' if all(row['status']=='PASS' for row in cleanups)
                and result.get('process_cleanup') != 'UNKNOWN' and not deadline.io_uncertain and
                not addon._RECEIPT_FDS and not addon._RECEIPT_UNCERTAIN and
                not addon._PROCESS_DISPOSAL_UNCERTAIN else 'UNKNOWN', 'attempts':cleanups}
            if first is not None or result['cleanup']['status'] != 'PASS' or cancelled:
                result['status'] = 'FAIL'
                result.setdefault('first_failure','addon-finalization-refused')
            same_context(context, borrow_context(session, controller, root, deadline.end))
            tree_session(addon, output, deadline=deadline, cleanup=True)
            for name in ('public','adapter-status'):
                (output/name).mkdir(mode=0o700)
            result['public'] = [str(output/'adapter-status'), str(output/'public')]
            record = {key:value for key,value in result.items() if key!='public'}
            for path, value in ((output/'adapter-status/result.json',record),
                                (output/'public/receipt.json',record),(output/'result.json',result)):
                save_session(addon, path, value, deadline, True)
            tree_session(addon,output/'public',32,2*1024**2,deadline=deadline,cleanup=True)
            tree_session(addon,output/'adapter-status',32,2*1024**2,deadline=deadline,cleanup=True)
            retired = tuple(addon._RECEIPT_FILES.items())
            restore_receipts(addon, output, deadline)
        # Restored handlers/mask, helper state and original custody precede PASS.
        deadline.remaining(1, True)
        same_context(context, borrow_context(session, controller, root, deadline.end))
    except BaseException as error:
        first = first or error
        result['status'], result['public'] = 'FAIL', []
        if deadline.io_uncertain or addon._RECEIPT_FDS or addon._RECEIPT_UNCERTAIN or addon._PROCESS_DISPOSAL_UNCERTAIN:
            result['cleanup']['status']='UNKNOWN'
        result.setdefault('first_failure','addon-finalization-refused')
        # A post-restoration refusal must still invalidate matching owned PASS
        # selectors; retain local custody rather than adopt any foreign file.
        for name, row in retired:
            try:
                path = Path(name)
                if name not in addon._RECEIPT_FILES and addon.receipt_identity(path.lstat()) == row['identity']:
                    addon._RECEIPT_FILES[name] = row
            except BaseException:
                pass
        for name in ('adapter-status/result.json','public/receipt.json','result.json'):
            try:
                receipt_remove_session(addon,output/name,deadline)
            except BaseException:
                pass
        if deadline.io_uncertain or addon._RECEIPT_FDS or addon._RECEIPT_UNCERTAIN or addon._PROCESS_DISPOSAL_UNCERTAIN:
            result['cleanup']['status']='UNKNOWN'
    if isinstance(first,(KeyboardInterrupt,SystemExit)):
        raise first
    return result


def prerequisite_session(addon, session, controller, deadline):
    out = Path(controller.native_out)
    result, bootstrap, inputs = (addon.decode(read_session(addon,out/name,deadline))
        for name in ('result.json','bootstrap.json','inputs.lock.json'))
    need(inputs==addon.decode(session.sources.raw['scripts/ci/inputs.lock.json']),
         'original-inputs-drift')
    need(result.get('native_build')=='PASS' and addon.IMAGE.fullmatch(controller.image or '') and
         read_session(addon,out/'image-id',deadline).decode().strip()==controller.image,
         'native-original-builds-required')
    lock = read_session(addon,out/'packages.lock',deadline)
    packages = {row['name'][0]:row['version'][0] for row in inputs['rootfs_packages']}
    packages.update({row['name']:row['version'] for row in inputs['packages']})
    need(len(packages)==341 and lock.decode()==''.join(f'{name} {version}\n' for name,version in sorted(packages.items())),
         'exact-authenticated-341-base-required')
    need(bootstrap.get('status')=='image-provisioned' and bootstrap.get('image_id')==controller.image and
         bootstrap.get('packages_lock_sha256')==sha(lock) and
         bootstrap.get('inputs_sha256')==sha(read_session(addon,out/'inputs.lock.json',deadline))==
         result.get('reviewed_inputs_sha256'), 'actual-bootstrap-binding-required')
    return {'image_id':controller.image,'packages_lock':str((out/'packages.lock').absolute()),
            'packages_sha256':sha(lock),'epoch':inputs['source_date_epoch'],'package_count':341}


def actor_config(addon, session, controller, output, prerequisite, actor_contract_raw, deadline):
    need(type(actor_contract_raw) is bytes and 0 < len(actor_contract_raw) <= 16*1024, 'runtime-contract-refused')
    runtime = addon.decode(actor_contract_raw)
    need(set(runtime)=={'cli_sha256','endpoint_identity','env'} and
         sha(encoded(runtime))==session.sources.grant['actor_contract_sha256'], 'runtime-contract-refused')
    env = runtime['env']
    need(type(env) is dict and set(env)=={'PATH','HOME','DOCKER_CONFIG','DOCKER_HOST','DOCKER_BUILDKIT','LC_ALL','TMPDIR'} and
         env['PATH']=='/usr/bin:/bin' and env['DOCKER_HOST']=='unix:///run/docker.sock' and
         env['DOCKER_BUILDKIT']=='0' and env['LC_ALL']=='C', 'runtime-environment-refused')
    for key in ('HOME','DOCKER_CONFIG','TMPDIR'):
        path = Path(env[key]);row=path.lstat()
        need(path.is_absolute() and '..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents)
             and stat.S_ISDIR(row.st_mode) and row.st_uid==os.getuid() and stat.S_IMODE(row.st_mode)==0o700
             and not any(path.iterdir()), 'runtime-private-state-refused')
    cli, sock = Path('/usr/bin/docker'), Path('/run/docker.sock')
    info = sock.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and
         [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink]==runtime['endpoint_identity'] and
         sha(read_session(addon,cli,deadline,64*1024**2))==runtime['cli_sha256'], 'runtime-tools-refused')
    runner = addon.decode(read_session(addon,Path(controller.native_out)/'runner.json',deadline))
    need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64') and os.getuid()>0 and
         runner['uid']==os.getuid() and runner['gid']==os.getgid() and
         runner['commit']==controller.commit==session.sources.grant['source_commit']==os.environ.get('GITHUB_SHA') and
         runner['run_id']==session.sources.grant['run_id']==os.environ.get('GITHUB_RUN_ID') and
         session.sources.grant['run_attempt']==os.environ.get('GITHUB_RUN_ATTEMPT') and
         runner['python']==sys.version and runner['docker_server_arch'] in ('aarch64','arm64') and
         runner['docker_endpoint'] in ('unix:///run/docker.sock','unix:///var/run/docker.sock'), 'same-job-native-runner-required')
    python = Path(sys.executable).resolve()
    return {'docker':str(cli),'docker_sha256':runtime['cli_sha256'],'docker_identity':addon.identity(cli),
        'socket':str(sock),'socket_identity':addon.identity(sock),'endpoint':env['DOCKER_HOST'],
        'docker_config':env['DOCKER_CONFIG'],'home':env['HOME'],'actor_env':env,
        'python':str(python),'python_identity':addon.identity(python),
        'python_sha256':sha(read_session(addon,python,deadline,64*1024**2)),
        'quota_root':str(output),'image':prerequisite['image_id'],'uid':os.getuid(),'gid':os.getgid(),
        'epoch':prerequisite['epoch'],'stage_end':deadline.end,'work_end':deadline.work_end}


def run_zsh(controller, root, output, cache=None, *, session, actor_contract_raw):
    """A provisional consumer result; the sole original Session owns acceptance."""
    deadline = Budget(session.job_deadline)
    context = borrow_context(session,controller,root,deadline.work_end)
    addon = session.source_graph['zsh']['zsh_addon']
    need(not addon._RECEIPT_FILES and not addon._RECEIPT_FDS and not addon._RECEIPT_UNCERTAIN and
         not addon._PROCESS_DISPOSAL_UNCERTAIN, 'helper-state-not-restored')
    output = Path(output).absolute();root=Path(root).absolute()
    need('..' not in output.parts and not output.exists() and not output.is_symlink() and
         not output.is_relative_to(root) and not output.is_relative_to(context['root']) and
         not output.is_relative_to(Path(controller.native_out)) and
         all(stat.S_ISDIR(path.lstat().st_mode) for path in output.parents), 'output-invalid')
    deadline.remaining(1)
    output.mkdir(mode=0o700)
    result={'stage':'zsh-addon','status':'FAIL','provisional':True,'cleanup':{'status':'UNKNOWN'},
        'attempts':[],'comparison':None,'hardware_status':'NOT RUN','installation':'NOT RUN',
        'selected_for_release':False,'public':[],'source_packet_sha256':session.sources.grant_pin,
        'original_view_sha256':context['sha256']}
    configs=[]
    first=None
    try:
        contract_raw=session.sources.raw[CONTRACT]
        contract=addon.decode(contract_raw)
        need(type(contract['schema_version']) is int and contract['schema_version']==1 and contract['acceptance']=='strict-native-byte-pair' and
             contract['docker_adaptation']=='run-to-create-inspect-start-retain', 'contract-policy-refused')
        package=contract['package']
        deadline.remaining(1);validate_contract_session(addon,root,package,deadline);deadline.remaining(1)
        prerequisite=prerequisite_session(addon,session,controller,deadline)
        config=actor_config(addon,session,controller,output,prerequisite,actor_contract_raw,deadline)
        docker=SessionDocker(addon,config,deadline)
        daemon=addon.decode(docker.call(['info','--format','{{json .}}']))
        need(daemon.get('Architecture') in ('aarch64','arm64') and daemon.get('OSType')=='linux' and
             type(daemon.get('ID')) is str and 0 < len(daemon['ID']) <= 256,'native-daemon-required')
        config.update(daemon_id=daemon['ID'],runtime=daemon['DefaultRuntime'],
            daemon_binding={key:daemon[key] for key in ('ID','Architecture','OSType','ServerVersion','DockerRootDir','DefaultRuntime')})
        image=json.loads(docker.call(['image','inspect',config['image']]))
        need(len(image)==1 and image[0]['Id']==config['image'] and image[0]['Architecture']=='arm64' and
             image[0]['Os']=='linux','same-base-image-required')
        config.update(base_config=image[0]['Config'],entry=str(context['root']/'scripts/build/container-entry.sh'))
        result['source_binding']={'contract_sha256':sha(contract_raw),'recipe_inputs':package['build_helper_reviewed_inputs'],
            'packages_sha256':prerequisite['packages_sha256'],'source_commit':controller.commit}
        reviewed=output/'reviewed-inputs.json';save_session(addon,reviewed,package['build_helper_reviewed_inputs'],deadline)
        for number in (1,2):
            same_context(context,borrow_context(session,controller,root,deadline.work_end))
            lane=output/f'lane-{number}';lane.mkdir(mode=0o700)
            attempt=output/f'attempt-{number}'
            c={**config,'attempt':str(attempt),'cidfile':str(lane/'cid'),'owned':str(lane/'owned.json'),
               'gate_end':min(deadline.work_end,deadline.clock()+270)}
            configs.append(c)
            config_path=lane/'gate.json';save_session(addon,config_path,c,deadline)
            sources={name:{'path':str(root/relative),'data':session.sources.raw[relative]}
                for name,relative in (('zsh_addon',ADDON),('zsh_session',SELF))}
            launcher=(f'#!{config["python"]} -I\nimport sys,types\nM={sources!r}\n'
                'r=M["zsh_addon"];a=types.ModuleType("captured_zsh_addon");a.__file__=r["path"]\n'
                'exec(compile(r["data"],r["path"],"exec"),a.__dict__)\n'
                'r=M["zsh_session"];s={"__name__":"captured_zsh_session","__file__":r["path"]}\n'
                'exec(compile(r["data"],r["path"],"exec"),s)\n'
                f'sys.exit(s["child_gate"](a,{str(config_path)!r},{sha(read_session(addon,config_path,deadline))!r},sys.argv[1:],'
                f'stage_end={deadline.end!r},work_end={deadline.work_end!r}))\n').encode()
            shim=lane/'docker';write_bytes(shim,launcher,deadline,True)
            env={**config['actor_env'],'PATH':str(lane)+':/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'}
            bootstrap=output/f'build-{number}.py'
            write_bootstrap_session(bootstrap,session,context,context['root']/'scripts/build/build.py',deadline)
            argv=[sys.executable,'-I','-B',str(bootstrap),str(root/package['source_root']),
                '--image',config['image'],'--mode','native','--network','none','--source-date-epoch',str(config['epoch']),
                '--expected-packages',prerequisite['packages_lock'],'--reviewed-inputs',str(reviewed),
                '--timeout','300','--output',str(attempt)]
            code,_=supervised_session(addon,argv,env,deadline,360,output/f'attempt-{number}.log',quota_root=output)
            need(code==0,'native-build-failed')
            owned=addon.decode(read_session(addon,lane/'owned.json',deadline))
            archive=validate_attempt_session(addon,session,context,attempt,package,prerequisite,owned,deadline)
            result['attempts'].append({'status':'PASS','exit_code':code,'archive':archive,'shim_sha256':sha(launcher)})
            result['attempts'][-1]['cleanup']=cleanup_attempt_session(addon,c,deadline)
        need(result['attempts'][0]['archive']['cid']!=result['attempts'][1]['archive']['cid'] and
             result['attempts'][0]['archive']['clean_environment_id']!=result['attempts'][1]['archive']['clean_environment_id'],
             'clean-pair-identity-refused')
        compare=output/'compare.py'
        write_bootstrap_session(compare,session,context,context['root']/'scripts/build/compare.py',deadline)
        code,data=supervised_session(addon,[sys.executable,'-I','-B',str(compare),str(output/'attempt-1'),
            str(output/'attempt-2'),'--require-bytes'],{**config['actor_env'],'PYTHONDONTWRITEBYTECODE':'1'},deadline,120,
            output/'comparison.log',quota_root=output)
        need(code==0,'native-comparison-failed');comparison=addon.decode(data);addon.validate_pair(comparison)
        result['comparison']=comparison
        same_context(context,borrow_context(session,controller,root,deadline.work_end))
        result['status']='PASS'
    except BaseException as error:
        first=error
        result.update(status='FAIL',first_failure=str(error) if type(error) is Refusal else 'addon-refused',
                      process_cleanup=addon.process_cleanup_status(error))
    finally:
        try:
            finalize_stage_session(addon,session,controller,root,context,output,result,configs,deadline)
        except BaseException as error:
            result['status']='FAIL'
            first=first or error
    if isinstance(first,(KeyboardInterrupt,SystemExit)):
        raise first
    return result


def child_gate(addon, path, pin, argv, *, stage_end, work_end):
    """Private captured child entry; no Session loader or authority shim."""
    try:
        deadline=Budget(stage_end)
        need(type(work_end) in (int,float) and math.isfinite(work_end) and
             0 < work_end <= stage_end-120,'gate-deadline-refused')
        deadline.work_end=work_end
        raw=read_session(addon,path,deadline)
        need(addon.HEX.fullmatch(pin) and sha(raw)==pin,'gate-config-drift')
        config=addon.decode(raw)
        need(config['stage_end']==stage_end and config['work_end']==work_end and
             type(config['gate_end']) in (int,float) and math.isfinite(config['gate_end']) and
             config['gate_end'] <= work_end, 'gate-deadline-refused')
        code,data=gate_session(addon,config,argv)
        sys.stdout.buffer.write(data)
        return code
    except BaseException:
        sys.stderr.write('addon-session-gate-refused\n')
        return 125


def validate_contract_session(addon, root, contract, deadline):
    addon.need(contract.get('name') == addon.PACKAGE and contract.get('version') == '0.7.1-1' and (contract.get('arch') == 'any') and (contract.get('license') == ['MIT']) and (contract.get('depends') == ['zsh>=4.3.11']) and (contract.get('upstream_revision') == '85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5'), 'package-contract-invalid')
    addon.need(contract.get('source_root') == 'packages/shells/' + addon.PACKAGE, 'recipe-root-invalid')
    rows = contract.get('source_files', {})
    addon.need(len(rows) == 12 and set(rows) == {'.SRCINFO', 'PKGBUILD', 'LICENSE.project', 'LICENSE.upstream', 'NOTICE', 'README.md', 'check-module.py', 'integration-proposal.json', 'opt-in.zsh', 'source-provenance.json', 'usage.md', 'zsh-autosuggestions.zsh'}, 'recipe-file-set-invalid')
    actual = tree_session(addon, Path(root) / contract['source_root'], 12, 54910, deadline=deadline)
    addon.need(actual == rows and sum((v['bytes'] for v in rows.values())) == 54910, 'recipe-source-drift')
    addon.need(contract.get('build_helper_reviewed_inputs') == {k: v['sha256'] for k, v in rows.items()}, 'recipe-input-map-invalid')
    payload = contract.get('expected_payloads', {})
    expected = {'usr/share/cachy-asahi/zsh-autosuggestions/zsh-autosuggestions.zsh': 'zsh-autosuggestions.zsh', 'usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh': 'opt-in.zsh', 'usr/share/cachy-asahi/zsh-autosuggestions/README.md': 'usage.md', 'usr/share/licenses/' + addon.PACKAGE + '/LICENSE.upstream': 'LICENSE.upstream', 'usr/share/licenses/' + addon.PACKAGE + '/LICENSE.project': 'LICENSE.project', 'usr/share/licenses/' + addon.PACKAGE + '/NOTICE': 'NOTICE'}
    addon.need(set(payload) == set(expected), 'payload-map-invalid')
    for name, source in expected.items():
        addon.need(payload[name] == {'source': source, 'sha256': rows[source]['sha256'], 'bytes': rows[source]['bytes'], 'type': 'regular', 'mode': 420, 'uid': 0, 'gid': 0}, 'payload-map-invalid')
