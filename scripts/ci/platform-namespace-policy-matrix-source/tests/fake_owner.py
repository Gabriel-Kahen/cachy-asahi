# SPDX-License-Identifier: MIT
"""Synthetic DATA ports for the sealed Source5ca owner. No native actors.

The complete proposed Source exists only as this in-memory storage table. Subject
functions are imported from authenticated retained bytes and run unchanged.
"""
import copy
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path as RealPath, PurePosixPath
import signal
import stat
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

HERE = RealPath(__file__).resolve().parent
FACTORY = HERE.parent
FIXTURES = HERE/'fixtures'
PARENT = None
PROFILE_SHA = '87c87e685a77609f09c1ba19a8e27c0fa2ede60b70ee3fff27707d5653020f35'
OVERLAY_SHA = '844228043b016d9411812cec0ce4d7fe70240b761c4d5569978cae4aec103cda'
CATALOG_SHA = '4e78bdb18ffab3565e6e8cca157dc604f313a78743c5ec61ecc17a1abf6bf6bf'


def authenticated(path, row):
    assert path.is_absolute() and path.resolve(strict=True) == path
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    body = path.read_bytes()
    assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256'], path
    if 'mode' in row: assert stat.S_IMODE(info.st_mode) == row['mode'], path
    if 'blob' in row: assert hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest() == row['blob'], path
    return body


def configure_basis(value):
    """Explicit existing actual05df199 DATA; never construct/repair/download it."""
    global PARENT
    candidate = RealPath(value)
    assert candidate.is_absolute() and candidate.resolve(strict=True) == candidate and candidate.is_dir()
    raw = (FACTORY/'parent-profile.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PROFILE_SHA
    profile = json.loads(raw)
    assert profile['parent'] == '05df8c71ea2bcb525bb1cfbc59983452062a1e97' and len(profile['files']) == 199
    leaves = set()
    for directory, dirs, files in os.walk(candidate, followlinks=False):
        current = RealPath(directory)
        if current == candidate:
            assert not (candidate/'.git').is_symlink()
            dirs[:] = [name for name in dirs if name != '.git']
            files = [name for name in files if name != '.git']
        for name in dirs: assert stat.S_ISDIR((current/name).lstat().st_mode)
        for name in files: leaves.add(str((current/name).relative_to(candidate)))
    assert leaves == set(profile['files'])
    for name,row in profile['files'].items(): authenticated(candidate/name,row)
    catalog_raw = (FIXTURES/'catalog.json').read_bytes()
    assert hashlib.sha256(catalog_raw).hexdigest() == CATALOG_SHA
    catalog = json.loads(catalog_raw)
    assert set(catalog['files']) == {'context.json','source-full-map.json','source-map.json','raw-source.txt'}
    assert {p.name for p in FIXTURES.iterdir()} == set(catalog['files'])|{'catalog.json'}
    for name,row in catalog['files'].items(): authenticated(FIXTURES/name,row)
    overlay_raw = (FACTORY/'overlay-manifest.json').read_bytes()
    assert hashlib.sha256(overlay_raw).hexdigest() == OVERLAY_SHA
    for name,row in json.loads(overlay_raw)['files'].items(): authenticated(FACTORY/'payload'/name,row)
    authenticated(FACTORY/'parent-commit.raw',profile['parent_raw'])
    PARENT = candidate
VROOT = '/VIRTUAL-SOURCE-SYNTHETIC-DATA'
SOURCE = '38601d671319dde4e9db8466b330153ca05e291a'
MAP = 'cc2d1aaee89bf8c8ff921b8d764572f94c29bcf76a625e501038d6413efb1cab'
MODULE_SHA = 'f4d9630e268ea7973f369d874b019c65e830bc3814b86a2f8b4cfe4516222918'
_ACTIVE = None
_GUARD = False
DENIED = []


def _audit(event, args):
    if _GUARD and (event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.posix_spawn'))
                   or event in {'os.system', 'os.fork', 'os.forkpty', 'os.kill', 'os.killpg', 'os.startfile',
                                'fcntl.ioctl', 'resource.setrlimit', 'resource.prlimit'}):
        DENIED.append(event)
        raise RuntimeError('DATA fixture forbids external effect: '+event)


sys.addaudithook(_audit)


def denied(*args, **kwargs):
    DENIED.append('direct process/signal API')
    raise RuntimeError('DATA fixture forbids process, signal, or FFI effect')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def load(path):
    return json.loads(RealPath(path).read_bytes())


def owned_child():
    assert _ACTIVE is not None
    return _ACTIVE.supervisor


class Actor:
    def __init__(self, directory):
        self.directory = directory
        self.deadline = time.monotonic()+10000
        self.rows = []

    def run(self, *args, **kwargs):
        # owner_matrix deliberately obtains the separate original-supervisor port.
        owned_child()
        raise AssertionError('unexpected actor.run fallback')


class VPath(PurePosixPath):
    def _name(self):
        return self.relative_to(VROOT).as_posix()

    def resolve(self, *args, **kwargs):
        return self

    def absolute(self):
        return self

    def stat(self, *args, **kwargs):
        name = self._name()
        if name not in _ACTIVE.bodies:
            raise FileNotFoundError(str(self))
        return SimpleNamespace(st_mode=stat.S_IFREG|_ACTIVE.modes[name], st_nlink=1,
                               st_size=len(_ACTIVE.bodies[name]))

    lstat = stat

    def read_bytes(self):
        return _ACTIVE.bodies[self._name()]

    def is_symlink(self):
        return False

    def exists(self):
        name = self._name()
        return name in _ACTIVE.bodies or any(n.startswith(name.rstrip('/')+'/') for n in _ACTIVE.bodies)


def path_port(value='.', *parts):
    raw = str(value)
    return VPath(value, *parts) if raw == VROOT or raw.startswith(VROOT+'/') else RealPath(value, *parts)


def _import(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Supervisor:
    __file__ = VROOT+'/bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py'

    def __init__(self, fixture):
        self.fixture = fixture

    def run(self, argv, *, stdin, stdout, stderr, timeout, lifecycle, allowed_uids,
            stdout_limit, stderr_limit):
        f = self.fixture
        assert 0 < timeout <= 600 and stdout_limit == stderr_limit
        assert stdout_limit in (65536, 1024**2, 16*1024**2)
        assert allowed_uids == {os.geteuid()}
        body, rc = f.respond(argv)
        assert len(body) <= stdout_limit
        call = dict(argv=list(argv), timeout=timeout, stdout_limit=stdout_limit,
                    stderr_limit=stderr_limit, body=body, returncode=rc)
        f.calls.append(call)
        stdout.write(body)
        lifecycle.update(pid=424242, exit=rc, natural_exit=True, group_absent=True,
                         leader_held_until_group_inspection=True, exit_observed_via_waitpid=True,
                         ownership_lost=False, forced_cleanup=False, retirement='REAPED',
                         elapsed_seconds=0.001, cleanup_member_uids=[])
        if f.fault == 'unknown_lifecycle' and argv[2:3] == ['build']:
            lifecycle['ownership_lost'] = True
        return SimpleNamespace(returncode=rc)


class Fixture:
    """One isolated work directory and one synthetic daemon, never real names/PIDs.

    Use ``with fixture.ports(): fixture.run()``. ``fault`` is one of
    foreign_image, foreign_labels, running_retire, unknown_lifecycle,
    context_mismatch, policy_mismatch, removal_error, or None.
    """
    def __init__(self, work, fault=None):
        self.work = RealPath(work).absolute()
        self.work.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.fault = fault
        assert PARENT is not None, 'explicit --basis admission required before any fixture'
        self.metadata = load(FIXTURES/'source-full-map.json')
        self.bodies = {}
        self.modes = {}
        for name, row in self.metadata.items():
            candidate = FACTORY/'payload'/name
            if name == 'native/source-map.json':
                candidate = FIXTURES/'source-map.json'
            elif not candidate.is_file():
                candidate = PARENT/name
            body = candidate.read_bytes()
            assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256'], name
            assert hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest() == row['blob'], name
            self.bodies[name] = body
            self.modes[name] = row['mode']
        assert len(self.bodies) == 201
        assert hashlib.sha256(self.bodies['native/source-map.json']).hexdigest() == MAP
        assert hashlib.sha256(self.bodies['native/platform_namespace_policy_v1.py']).hexdigest() == MODULE_SHA
        self.manifest = json.loads(self.bodies['native/source-map.json'])
        self.own = dict(source=SOURCE, ref='refs/heads/codex/SYNTHETIC-DATA-ONLY', run='9000000001', attempt=1)
        self.own['token'] = hashlib.sha256((SOURCE+':'+self.own['ref']+':'+self.own['run']).encode()).hexdigest()[:24]
        self.root = VPath(VROOT)
        self.args = SimpleNamespace(work=self.work, map_sha256=MAP)
        self.context = self.work/'overlay/context'
        self.context.mkdir(mode=0o700, parents=True)
        (self.work/'public').mkdir(mode=0o700)
        self.actor = Actor(self.work/'matrix-actors')
        self.actor.directory.mkdir(mode=0o700)
        self.base_id = 'sha256:'+'a'*64
        self.image = 'sha256:'+'b'*64
        self.base_alias = 'native-developer-base:'+self.own['token']
        self.alias = 'native-namespace-policy-prepared:'+self.own['token']
        self.legacy = 'org.cachy-asahi.native-developer'
        self.ledger = dict(binding=self.own, source_map_sha256=MAP,
                           aliases=dict(base=self.base_alias, tools='native-developer-tools:'+self.own['token']),
                           created=dict(base=dict(image_id=self.base_id)))
        self.source_proof = dict(binding=self.own, files={n:dict(mode=r['git_mode'], blob=r['blob'], bytes=r['bytes'], sha256=r['sha256']) for n,r in self.metadata.items()})
        self.calls = []; self.callback_calls = 0; self.containers = {}; self.inspect_counts = {}
        self.build_receipts = []
        self.image_exists = False; self.image_labels = {}; self.supervisor = Supervisor(self)
        self.base_env = ['PATH=/usr/bin:/bin']
        self.template = load(FIXTURES/'context.json')
        prefix = ('USER root\nCOPY deps/ /tmp/developer-deps/\nCOPY tools/ /opt/native-developer-tools/\nCOPY disabled-hooks.txt /tmp/developer-hooks.txt\n'
                  'RUN while IFS= read -r hook; do ln -sf /dev/null "/builder-disabled-hooks/$hook"; done < /tmp/developer-hooks.txt '
                  '&& pacman -U --noconfirm --noscriptlet /tmp/developer-deps/*.pkg.tar.xz && ldconfig '
                  '&& rm -rf /tmp/developer-deps /tmp/developer-hooks.txt /var/cache/pacman/pkg/* '
                  '&& pacman -Q | LC_ALL=C sort > /builder-packages.lock\n')
        self.dockerfile = ('FROM '+self.base_alias+'\n'+prefix+'COPY platform-alpm-v1/source/ /opt/native-platform-tools-alpm-v1/source/\n'
                           'RUN /usr/bin/python3 -I -B /opt/native-platform-tools-alpm-v1/source/native/platform_alpm_v1.py --inside-image --retain-failure-image --map-sha256 '+MAP+'\nUSER alarm\nWORKDIR /tmp\n').encode()

    def verify_source(self, root, checksum):
        assert str(root) == VROOT and checksum == MAP, 'virtual storage authority'
        assert hashlib.sha256(self.bodies['native/source-map.json']).hexdigest() == checksum
        assert set(self.bodies) == set(self.manifest['files'])|{'native/source-map.json'}
        for name, row in self.manifest['files'].items():
            body = self.bodies[name]
            assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256'], name
        return copy.deepcopy(self.manifest)

    def source_bytes(self, root, name):
        assert str(root) == VROOT
        return self.bodies[name]

    @contextmanager
    def ports(self):
        global _ACTIVE, _GUARD
        assert _ACTIVE is None, 'one synthetic fixture at a time'
        _ACTIVE = self; _GUARD = True
        old_path = list(sys.path)
        names = ('common', 'capsule', 'public_projection', 'privacy_diagnostics', 'platform_namespace_policy_v1', '_qualification_provision')
        old_modules = {name:sys.modules.get(name) for name in names}
        try:
            with ExitStack() as stack:
                for module, functions in ((os, ('system','fork','forkpty','kill','killpg','posix_spawn','posix_spawnp',
                        'unshare','setns','chroot','setuid','setgid','seteuid','setegid','setreuid','setregid',
                        'setresuid','setresgid','setgroups','setsid','setpgid','waitpid','waitid','pidfd_open')),
                        (signal, ('signal','pthread_kill','raise_signal','alarm','setitimer'))):
                    for name in functions:
                        if hasattr(module, name): stack.enter_context(patch.object(module, name, denied))
                sys.path.insert(0, str(PARENT/'native'))
                self.common = _import('common', PARENT/'native/common.py')
                self.capsule = _import('capsule', PARENT/'native/capsule.py')
                _import('privacy_diagnostics', PARENT/'native/privacy_diagnostics.py')
                self.public_projection = _import('public_projection', PARENT/'native/public_projection.py')
                self.common.Path = path_port
                self.common.verify_source = self.verify_source
                self.common.source_bytes = self.source_bytes
                self.module = _import('platform_namespace_policy_v1', FACTORY/'payload/native/platform_namespace_policy_v1.py')
                self.module.Path = path_port
                self.provision = _import('_qualification_provision', FACTORY/'payload/native/provision.py')
                self.provision.Path = path_port
                # Only the inert trusted-local-root path selector is virtualized.
                self.provision.__file__ = VROOT+'/native/provision.py'
                yield self
        finally:
            sys.path[:] = old_path
            for name, previous in old_modules.items():
                if previous is None: sys.modules.pop(name, None)
                else: sys.modules[name] = previous
            _GUARD = False; _ACTIVE = None

    def verify_base(self):
        self.callback_calls += 1
        return self.base_alias

    def run(self):
        assert _ACTIVE is self
        self.diagnostic = self.module.owner_matrix(self.actor, self.root, self.args, self.own,
            self.context, self.dockerfile, self.ledger, self.verify_base, self.source_proof)
        self.owner = load(self.work/'public/namespace-policy/owner.json')
        result = self.work/'public/namespace-policy/result.json'
        self.result = load(result) if result.exists() else None
        return self.diagnostic

    @contextmanager
    def capsule_view(self, payloads, entries=None):
        """Explicit fake transport port; real retained View validation stays active."""
        if entries is None:
            entries = {n:dict(kind='file', mode=0o600, bytes=len(b), sha256=hashlib.sha256(b).hexdigest()) for n,b in payloads.items()}
            for name in list(entries):
                for parent in PurePosixPath(name).parents:
                    if str(parent) != '.': entries.setdefault(str(parent), dict(kind='directory', mode=0o700,
                        bytes=0, sha256=hashlib.sha256(b'').hexdigest()))
        view = self.capsule.View(entries, payloads, 0o700)
        with patch.object(self.capsule, 'open_capsule', lambda _:view):
            yield view

    def respond(self, argv):
        """Return synthetic actor bytes only; no subject decision functions here."""
        if argv[0] == '/usr/bin/git':
            if argv[-3:-1] == ['cat-file','commit']:
                return ((FIXTURES/'raw-source.txt') if argv[-1] == SOURCE else (FACTORY/'parent-commit.raw')).read_bytes(), 0
            if argv[-4:-1] == ['ls-tree','-rz','--full-tree']:
                rows = load(FACTORY/'parent-profile.json')['files']
                return b''.join((('100755' if r['mode'] == 0o755 else '100644')+' blob '+r['blob']+'\t'+n+'\0').encode() for n,r in sorted(rows.items())), 0
            raise AssertionError(('unhandled Git DATA request', argv))
        assert argv[:2] == ['/usr/bin/docker','--host=unix:///var/run/docker.sock']
        a = argv[2:]
        def output(value): return encoded(value), 0
        def options(flag): return [a[i+1] for i,v in enumerate(a[:-1]) if v == flag]
        if a[0] == 'info': return output(dict(id='SYNTHETIC_DATA_ENGINE', version='DATA_ONLY_1', arch='aarch64'))
        if a[:2] == ['image','ls']:
            return ((self.image+'\n').encode() if self.image_exists else b''), 0
        if a[:2] == ['image','inspect']:
            if a[2] == self.base_id:
                return output([dict(Id=self.base_id, Architecture='arm64', Os='linux', RepoTags=[self.base_alias], Config=dict(Labels={self.legacy:self.own['token'],self.legacy+'.source':SOURCE}, Env=self.base_env, User='alarm'))])
            assert a[2] == self.image
            labels = dict(self.image_labels)
            if self.fault == 'foreign_labels': labels[self.module.LABEL] = 'FOREIGN_SYNTHETIC_DATA'
            return output([dict(Id=('sha256:'+'c'*64 if self.fault == 'foreign_image' else self.image), Architecture='arm64', Os='linux', RepoTags=[self.alias], RepoDigests=[], Config=dict(Labels=labels, Env=self.base_env, User='root'))])
        if a[0] == 'build':
            self.image_labels = dict(v.split('=',1) for v in options('--label'))
            iid = RealPath(options('--iidfile')[0]); assert iid.parent == self.work
            dockerfile = RealPath(options('--file')[0])
            assert dockerfile.parent == self.context and RealPath(a[-1]) == self.context
            self.build_receipts.append(dict(argv=list(argv), dockerfile=dockerfile.read_bytes(),
                                            iidfile=str(iid), synthetic=True))
            iid.write_text(self.image+'\n')
            self.image_exists = True
            return b'SYNTHETIC PREFIX BUILD DATA ONLY\n', 0
        if a[:2] == ['image','rm']:
            assert a[2] in (self.alias,self.image)
            self.image_exists = False
            return (a[2]+'\n').encode(), 0
        if a[0] == 'ps':
            filt = options('--filter')[0]
            cids = list(self.containers)
            if filt.startswith('id='): cids = [c for c in cids if c == filt[3:]]
            if filt.startswith('name='): cids = [c for c in cids if self.containers[c]['Name'] == filt[6:-1]]
            return ''.join(c+'\n' for c in cids).encode(), 0
        if a[0] == 'create':
            cid = '%064x'%(len(self.inspect_counts)+1)
            labels = dict(self.image_labels); labels.update(v.split('=',1) for v in options('--label'))
            policy = options('--security-opt')
            env = dict(e.split('=',1) for e in self.base_env); env.update(v.split('=',1) for v in options('--env'))
            host = dict(Privileged=False, NetworkMode='none', SecurityOpt=policy, CapAdd=None, CapDrop=None, GroupAdd=['998','1001'], ReadonlyRootfs=False, Binds=None, Mounts=[], Memory=536870912, MemorySwap=536870912, NanoCpus=1000000000, PidsLimit=32, Ulimits=[dict(Name='nofile',Soft=128,Hard=128)])
            if self.fault == 'policy_mismatch': host['NetworkMode'] = 'bridge'
            self.containers[cid] = dict(Id=cid, Image=self.image, Name='/'+options('--name')[0], Config=dict(User='1001:1001', Labels=labels, Entrypoint=['/usr/bin/python3'], Cmd=a[a.index(self.image)+1:], WorkingDir='/tmp', Env=[k+'='+v for k,v in sorted(env.items())]), HostConfig=host, AppArmorProfile='unconfined' if 'apparmor=unconfined' in policy else 'docker-default', State=dict(Status='created', Running=False, Dead=False, OOMKilled=False, Error='', ExitCode=0))
            self.inspect_counts[cid] = 0
            return (cid+'\n').encode(), 0
        if a[0] == 'inspect':
            cid = a[1]; self.inspect_counts[cid] += 1
            value = copy.deepcopy(self.containers[cid])
            if self.fault == 'running_retire' and self.inspect_counts[cid] >= 3:
                value['State'].update(Status='running', Running=True)
            return output([value])
        if a[:2] == ['start','-a']:
            cid = a[2]; case = self.containers[cid]['Config']['Labels'][self.module.LABEL+'.case']
            rc = 0 if case in ('apparmor_only','both') else 1
            self.containers[cid]['State'].update(Status='exited', ExitCode=rc)
            ctx = copy.deepcopy(self.template)
            ctx.update(kind='platform-namespace-policy-probe-context-v1', position='SAME_PROCESS_BEFORE_SINGLE_BWRAP_EXEC', cwd='/tmp', source_map_sha256=MAP)
            if case in ('apparmor_only','both'): ctx['lsm'] = dict(status='OBSERVED',label='unconfined')
            if case in ('seccomp_only','both'):
                ctx['status']['Seccomp'] = dict(status='OBSERVED',value=0)
                ctx['status']['Seccomp_filters'] = dict(status='OBSERVED',value=0)
            if self.fault == 'context_mismatch' and case == 'apparmor_only': ctx['status']['NoNewPrivs']['value'] = 1
            return self.module.PREFIX+encoded(ctx)+b'\n'+(b'bwrap: No permissions to create a new namespace\n' if rc else b''), rc
        if a[0] == 'rm':
            assert len(a) == 2 and a[1] in self.containers
            if self.fault == 'removal_error': return b'SYNTHETIC removal uncertainty\n', 1
            del self.containers[a[1]]
            return (a[1]+'\n').encode(), 0
        raise AssertionError(('unhandled synthetic actor request', argv))
