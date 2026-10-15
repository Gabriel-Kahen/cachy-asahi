"""Seed93 helpers for the credential-isolated development harness in run.py.

The namespace worker checks the corrected Source and input pins before running
archive authentication. GNU timeout bounds the invocation; the supervisor owns
child cleanup. This module is a helper library, not a standalone command.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import types

PROFILE = '2f32684073cd945843a5685ca72d951435bb96c252d43344368193c5d3ca9155'
MANIFEST = 'bd72c0d2da36117071b0a1683ed96857c71e50f73a220488f5d20f6463ba906e'
ENV = {'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','LANG':'C.UTF-8'}
NETWORK = ['/etc/ssl','/etc/ca-certificates','/etc/resolv.conf','/etc/hosts','/etc/nsswitch.conf','/etc/gai.conf']
MAX_RECORD = 32*1024**2
MAX_RECORDS = 96
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def need(condition, label):
    if not condition:
        raise ValueError(label)


def document(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite-json'))


def pinned(path,digest,limit=4*1024**2):
    """Held dirfd traversal and finite postread checks; empty metadata permitted."""
    need(type(digest) is str and len(digest)==64 and all(c in '0123456789abcdef' for c in digest),'pin-format')
    path=Path(path).absolute();need('..' not in path.parts and len(path.parts)>1,'path-shape')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    handles=[];edges=[];fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
    try:
        parent=os.open(path.anchor,flags);handles.append(parent)
        for name in path.parts[1:-1]:
            child=os.open(name,flags,dir_fd=parent);handles.append(child);info=os.fstat(child)
            edges.append((parent,name,child,info.st_dev,info.st_ino));parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);handles.append(fd)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not before.st_mode&0o022 and 0<=before.st_size<=limit,'ordinary-pinned-file')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(limit+1)
        after=os.fstat(fd)
        need(all(getattr(before,k)==getattr(after,k) for k in fields) and len(raw)==before.st_size and sha(raw)==digest,'file-drift')
        for owner,name,child,device,inode in edges:
            held=os.fstat(child);named=os.stat(name,dir_fd=owner,follow_symlinks=False)
            need(stat.S_ISDIR(named.st_mode) and (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino)==(device,inode),'ancestor-drift')
        named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need(all(getattr(before,k)==getattr(named,k) for k in fields),'file-name-drift')
        return raw
    finally:
        for fd in reversed(handles):os.close(fd)


class Reports:
    """Exclusive numbered snapshots; incomplete writes remain .partial evidence."""
    def __init__(self, directory):
        self.path = Path(directory)
        need(self.path.is_absolute() and not any(p.is_symlink() for p in (self.path,*self.path.parents)), 'report-ancestry')
        self.count = self.total = 0
        self.cancelled = False
        self.path.mkdir(mode=0o700)  # exclusive; never resume a consumed journal
        self.sync_directory(self.path.parent)

    def close(self, fd, original):
        try:
            os.close(fd)
        except BaseException as error:
            if issubclass(type(error),(KeyboardInterrupt,SystemExit)):
                self.cancelled = True
            if original is None:
                raise
            # Keep the primary object; cancellation remains visible to run93.

    def sync_directory(self, path):
        fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        original = None
        try:
            os.fsync(fd)
        except BaseException as error:
            original = error
            raise
        finally:
            self.close(fd,original)

    def __call__(self, record):
        if type(record) is dict and record.get('schema') == 'seed93-authentication-report-v1' and record.get('cancelled') is True:
            self.cancelled = True
        need(self.count < MAX_RECORDS, 'report-count-budget')
        number = self.count
        self.count += 1  # failed writes consume their number; no actor/report retry
        partial = self.path / f'{number:03}.partial'
        final = self.path / f'{number:03}.json'
        fd = os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        original = None
        count = 0
        try:
            encoder = json.JSONEncoder(sort_keys=True,separators=(',',':'),allow_nan=False)
            def write(raw):
                nonlocal count
                need(count+len(raw) <= MAX_RECORD and self.total+len(raw) <= MAX_RECORDS*MAX_RECORD,'report-byte-budget')
                while raw:
                    size = os.write(fd,raw)
                    need(size > 0,'report-write-progress')
                    count += size
                    self.total += size
                    raw = raw[size:]
            for chunk in encoder.iterencode(record):
                for at in range(0,len(chunk),16384):
                    write(chunk[at:at+16384].encode('utf-8'))
            write(b'\n')
            os.fsync(fd)
        except BaseException as error:
            original = error
            raise
        finally:
            self.close(fd,original)
        # Single caller owns the fresh directory; final destination is never reused.
        need(not os.path.lexists(final), 'report-already-exists')
        partial.rename(final)
        self.sync_directory(self.path)


def load_source(layout):
    """Only a fresh single-invocation interpreter may initialize these modules."""
    root = Path(layout)
    raw = pinned(root/'source-manifest.json',MANIFEST)
    manifest = document(raw)
    expected = {'preview.py','source/common.py','source/helper_policy.py',
                'source/operations.py','source/seed93.py','source/composition.py'}
    need(set(manifest)=={'schema','files'} and manifest['schema']=='seed93-source-manifest-v1' and set(manifest['files'])==expected,'source-manifest')
    sources = {}
    for name,row in manifest['files'].items():
        body = pinned(root/name,row['sha256'])
        need(len(body)==row['bytes'] and stat.S_IMODE((root/name).stat().st_mode)==row['mode'],'source-bytes-mode')
        sources[name] = body
    names = ['common','helper_policy','seed93','operations']
    need(all(name not in sys.modules for name in names),'fresh-single-invocation-process-required')
    modules = {}
    for name in names:
        module = types.ModuleType(name)
        module.__file__ = str(root/'source'/f'{name}.py')
        sys.modules[name] = module
        exec(compile(sources[f'source/{name}.py'],module.__file__,'exec',dont_inherit=True),module.__dict__)
        modules[name] = module
    common = modules['common']
    profile = pinned(root/'profile.json',PROFILE)
    bundle = {role:pinned(root/row['filename'],row['sha256'],32*1024**2)
              for role,row in common.FIXED_INPUT_ROLES.items()}
    bundle.update(profile=profile,source_manifest=raw,
                  contract=pinned(root/'contract.json',common.CONTRACT_SHA256))
    bound = common.bind(profile,bundle,raw,PROFILE)
    return modules,bound,bundle


def run_kernel(kernel, bound, operations, reports, state, signals=signal):
    """No restarted timer. Caller is beneath the original external guardian."""
    state.update(status="FAIL",first_failure=None,cancelled=False,signal_restoration="UNKNOWN",secondary=[])
    cancelled = False
    previous = {}
    original = None
    result = None
    def interrupted(number,frame):
        nonlocal cancelled
        cancelled = True
        raise KeyboardInterrupt('seed93 invocation cancelled')
    try:
        for number in (signals.SIGINT,signals.SIGTERM):
            previous[number] = signals.signal(number,interrupted)
        result = kernel.run93(bound,operations,reports,lambda:cancelled or reports.cancelled)
    except BaseException as error:
        original = error
        state['first_failure'] = type.__dict__['__name__'].__get__(type(error))
        state['cancelled'] = cancelled or reports.cancelled or kernel.cancellation_error(error)
    finally:
        restored = True
        for number,handler in previous.items():
            try:
                signals.signal(number,handler)
            except BaseException as error:
                restored = False
                kind = type.__dict__['__name__'].__get__(type(error))
                state['cancelled'] = state['cancelled'] or issubclass(type(error),(KeyboardInterrupt,SystemExit))
                if original is None:
                    original = error
                    state['first_failure'] = kind
                else:
                    state['secondary'].append({'phase':'signal_restoration','kind':kind})
        state['signal_restoration'] = 'PASS' if restored else 'FAIL'
    if original is not None:
        raise original
    state['status'] = 'KERNEL_RETURNED_PENDING_PARENT_GUARDIAN_AND_ROOT_ADMISSION'
    return result


def authenticate_inside(layout, work, operational_plan_sha256):
    """Run pinned archive authentication inside the isolated worker namespace."""
    modules,bound,bundle = load_source(layout)
    operations = modules['operations'].RealOperations(bound,bundle,
        '/tmp/cachy-asahi-seed93-auth-cache',Path(layout)/'inputs',
        '/tmp/seed93-public-only-home',operational_plan_sha256)
    reports = Reports(Path(work)/'reports')
    caller_reports = Reports(Path(work)/'caller-state')
    state = dict(scope='SEED93_CALLER_ONLY',scoped_child_cleanup='PARENT_SUPERVISOR_REQUIRED',
                 whole_invocation_exit='EXTERNAL_ROOT_RETENTION_REQUIRED')
    original = None
    result = None
    try:
        result = run_kernel(modules['seed93'],bound,operations,reports,state)
    except BaseException as error:
        original = error
    finally:
        try:
            caller_reports(state)
        except BaseException as error:
            if original is None:
                original = error
    if original is not None:
        raise original
    return result


def guardian_argv(bound_entry, arguments):
    return ['/usr/bin/env','-i',*[f'{k}={v}' for k,v in ENV.items()],
        '/usr/bin/timeout','--signal=TERM','--kill-after=10s','1800s',
        '/usr/bin/python3','-I','-B',str(bound_entry),*arguments]


def namespace(runtime, layout, caller_directory, bound_worker_argv):
    runtime,layout,caller_directory = map(Path,(runtime,layout,caller_directory))
    need(all(p.is_absolute() and '..' not in p.parts for p in (runtime,layout,caller_directory)),'namespace-path-shape')
    argv = ['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-ipc',
        '--unshare-uts','--die-with-parent','--cap-drop','ALL','--ro-bind','/usr','/usr',
        '--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64',
        '--proc','/proc','--dev','/dev','--dir','/etc']
    for path in NETWORK:
        argv += ['--ro-bind',path,path]
    argv += ['--tmpfs','/etc/ssl/private','--ro-bind',str(layout),'/source',
        '--ro-bind',str(caller_directory),'/caller','--bind',str(runtime/'tmp'),'/tmp',
        '--bind',str(runtime/'work'),'/work','--chdir','/work','--clearenv']
    for name,value in dict(ENV,HOME='/tmp/home',GNUPGHOME='/tmp/seed93-public-only-home',
        XDG_RUNTIME_DIR='/tmp/runtime',PYTHONDONTWRITEBYTECODE='1').items():
        argv += ['--setenv',name,value]
    return argv+['--',*bound_worker_argv]


def supervise_selected(supervisor, argv, destination):
    # run.py creates the exclusive runtime and invokes this helper beneath GNU
    # timeout. The namespace worker checks Source pins before package actors.
    return supervisor.supervise(argv,destination,work_seconds=None,cleanup_seconds=10)


if __name__ == '__main__':
    raise SystemExit('UNBOUND_PREPARATION_ONLY: separate Root-selected entry/context/layout required')
