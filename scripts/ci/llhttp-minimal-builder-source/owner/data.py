# SPDX-License-Identifier: MIT
"""Finite Fish-only policy, namespace and domain joins; no actor on import."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

PREFIX = 'scripts/ci/llhttp-minimal-builder-source/owner/'
BASE_PREFIX = 'scripts/ci/llhttp-minimal-builder-source/base/'

s=importlib.util.spec_from_file_location('minimal206_managed_containerd',Path(__file__).with_name('managed_containerd.py'));M=importlib.util.module_from_spec(s);s.loader.exec_module(M)

def base_binding(root):
    return decode(read(root/PREFIX/'base-binding.json'))

ENV_ANCHOR = "                    if env:clean.update(env)"
ENV_PROJECTION = "                    clean['DOCKER_HOST']=os.environ['CACHY_LLHTTP_MINIMAL_BUILDER_OWNED_DOCKER_HOST']\n                    clean['DOCKER_BUILDKIT']='0'\n                    clean['TMPDIR']=os.environ['CACHY_LLHTTP_MINIMAL_BUILDER_OWNED_TMPDIR']\n" + ENV_ANCHOR


def need(value, why):
    if not value: raise ValueError(why)


def pin(body): return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def decode(body):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key'); value[key] = item
        return value
    return json.loads(body, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read(path, cap=2*1024**2, empty=False):
    need(path.is_absolute() and path == path.resolve() and not path.is_symlink(), 'canonical DATA path')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and (0 if empty else 1) <= info.st_size <= cap
         and not info.st_mode & 0o022, 'bounded ordinary DATA body')
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    body = path.read_bytes(); need(len(body) == info.st_size and identity(path.lstat()) == identity(info), 'unchanged whole DATA')
    return body


def source(root, expected):
    root = Path(root)
    need(root.is_absolute() and root == root.resolve(), 'canonical complete Source')
    body = read(root/'source-map.json'); need(pin(body)['sha256'] == expected, 'external successor map pin')
    value = decode(body); rows = value['files']
    need(value['kind'] == 'LLHTTP_MINIMAL206_BUILD_ONLY_OWNED_HOSTED_SOURCE_V2' and len(rows) == 97
         and all(v is None for v in value['actual'].values()), 'finite prospective successor namespace')
    found = {str(p.relative_to(root)) for p in root.rglob('*') if p.relative_to(root).parts[0] != '.git'
             and (p.is_file() or p.is_symlink())}
    need(found == set(rows)|{'source-map.json'}, 'complete closed successor namespace')
    for name, row in rows.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'safe Source name')
        path = root/name
        need(dict(pin(read(path)), mode=stat.S_IMODE(path.stat().st_mode)) == row and row['mode'] == 0o644,
             'whole successor body/mode: '+name)
    base = root/'held-source'; raw = read(base/BASE_PREFIX/'source-map.json')
    binding=base_binding(root)
    need(pin(raw) == binding['map'], 'whole exact newly constructed base map')
    prior = decode(raw)
    subset = {n[len('held-source/'):]:r for n,r in rows.items() if n.startswith('held-source/')}
    need(subset == dict(prior['files'], **{BASE_PREFIX+'source-map.json':dict(pin(raw),mode=0o644)})
         and len(subset) == binding['files'] and sum(r['bytes'] for r in subset.values()) == binding['bytes'],
         'exact unchanged whole Source32 subtree')
    program = decode(read(root/PREFIX/'owner-program.json'))
    need(program['base_source_map_sha256'] == binding['map']['sha256'] and program['schema'] == 1, 'explicit held Source32 delegation')
    need(set(program['files']) == {n for n in rows if not n.startswith('held-source/') and n != PREFIX+'owner-program.json'}, 'complete owner-program namespace')
    for name, row in program['files'].items():
        need(rows[name] == row, 'whole owner-program closure')
    return value



def source_documents(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha, source_sha, source_ref, now):
    need(0 < len(admission_raw) <= 16384 and 0 < len(runtime_raw) <= 16384
         and pin(admission_raw)['sha256'] == admission_sha and pin(runtime_raw)['sha256'] == runtime_sha,
         'two separately pinned whole Root documents')
    source(root,map_sha); a,r = decode(admission_raw),decode(runtime_raw)
    for value, template in ((a,'admission.TEMPLATE.json'), (r,'runtime.TEMPLATE.json')):
        need(type(value) is dict and set(value) == set(decode(read(root/PREFIX/template))),
             'closed Root dispatch document schema')
    profile = decode(read(root/'held-source'/BASE_PREFIX/'profile.json'))
    for value,kind in ((a,'ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_HOSTED_ADMISSION_V1'),(r,'ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_HOSTED_RUNTIME_V1')):
        need(value['kind'] == kind and value['issued_by'] == 'Root' and value['accepted'] is True,
             'separate actual Root issuance')
        need(re.fullmatch('[0-9a-f]{40}',value['source'] or '') and value['source'] == source_sha
             and value['ref'] == source_ref == 'refs/heads/codex/llhttp-minimal206-authenticated-source-20261118-r11'
             and value['source_map_sha256'] == map_sha and value['resources'] == profile['resources'],
             'exact actual Source/ref/map/held pair policy')
        need(type(value['created_utc']) is int and type(value['expires_utc']) is int
             and value['created_utc'] <= now < value['expires_utc'] and value['expires_utc']-value['created_utc'] <= 3600
             and re.fullmatch('[0-9a-f]{32}',value['nonce'] or ''), 'fresh bounded Root delegation')
    policy=decode(read(root/PREFIX/'policy.json'))
    need(r.get('host_tools')==policy['host_tools'], 'separate explicit Root existing-host no-install policy admission required')
    need(a['nonce'] == r['nonce'], 'same Root admission/runtime nonce')
    need(r['external_supervision'] == pin(read(root/PREFIX/'owner-program.json'))
         and r['bootstrap_resource_domain'] == pin(read(root/PREFIX/'policy.json')),
         'loaded actual owner-program and new separate resource policy pins')
    spec=__import__('importlib.util',fromlist=['']).spec_from_file_location('minimal206_input_gate',root/'held-source'/BASE_PREFIX/'contract.py');gate=__import__('importlib.util',fromlist=['']).module_from_spec(spec);spec.loader.exec_module(gate)
    gate.minimal_inputs(a,r,profile)
    return a,r


def admission(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha, env, now):
    need(env.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
         and env.get('GITHUB_WORKFLOW_REF') == 'Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-llhttp-minimal-builder-source.yml@refs/heads/codex/llhttp-minimal206-authenticated-source-20261118-r11'
         and env.get('GITHUB_JOB') == 'pair' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_RUN_ATTEMPT') == '1' and re.fullmatch('[1-9][0-9]{1,19}', env.get('GITHUB_RUN_ID', '')),
         'exact minimal206 hosted workflow/job and first dispatch attempt')
    return source_documents(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha,
                            env.get('GITHUB_SHA'), env.get('GITHUB_REF'), now)


def projected_entry(body):
    text = body.decode(); need(text.count(ENV_ANCHOR) == 1, 'finite Docker endpoint/backend seam')
    projected = text.replace(ENV_ANCHOR,ENV_PROJECTION)
    need(projected.count(ENV_PROJECTION) == 1 and projected.replace(ENV_PROJECTION,ENV_ANCHOR).encode() == body,
         'whole held entry inverse')
    audit = "        native.audit(inputs, output/'cache', output/'bootstrap')"
    inventory = "        C.need((output/'bootstrap/packages.lock').read_bytes()==C.read(HERE/'expected206.lock'),'genuine exact freshly provisioned206 BUILD_ONLY inventory')"
    edits = (
        (audit, audit+"\n        cache_handoff=PINNED_STORAGE.install_context_handoff(native,inputs,output/'cache',output/'bootstrap')"),
        (inventory, inventory+"\n        cache_handoff.retire_context()"),
    )
    for old,new in edits:
        need(projected.count(old)==1,'exact held storage projection anchor')
        projected=projected.replace(old,new)
    inverse=projected
    for old,new in reversed(edits):
        need(inverse.count(new)==1,'exact held storage inverse anchor')
        inverse=inverse.replace(new,old)
    need(inverse.replace(ENV_PROJECTION,ENV_ANCHOR).encode()==body,'whole held storage and endpoint inverse')
    return projected


EMPTY_REVOKED_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
HELD_NATIVE_BUILD = '238f8a8a14af23e2f02ad0fd5d1522f984ef38f7114edd9b1b27c45f98789e4e'


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary-path')
    return path


def owned_leaf(path, size):
    info = ordinary(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
         and info.st_nlink == 1 and info.st_size == size and not info.st_mode & 0o022,
         'exact owned single-link input leaf')
    return info


def owned_handoff(source, destination, size):
    """Transfer one single-link input inode to a fresh name on the same quota."""
    before = owned_leaf(source, size)
    parent = ordinary(destination.parent).lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and not parent.st_mode & 0o022
         and parent.st_dev == before.st_dev, 'same owned input quota and destination directory')
    os.link(source, destination, follow_symlinks=False)
    def file_id(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns)
    linked = destination.lstat()
    need(linked.st_nlink == 2 and file_id(before) == file_id(linked)
         and identity(source.lstat()) == identity(linked), 'exact two-name handoff before retiring original')
    source.unlink()
    need(file_id(owned_leaf(destination, size)) == file_id(before), 'single original inode at its fresh destination')


def install_context_handoff(native, inputs, cache, out):
    """Project only the three copies in the authenticated legacy build handoff."""
    cache,out=ordinary(cache),ordinary(out)
    need(cache.name=='cache' and out.name=='bootstrap' and cache.parent==out.parent
         and cache.parent.name=='llhttp-minimal-builder-native','exact owned bootstrap staging roots')
    text=read(Path(native.__file__)).decode()
    node,=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='build']
    original=ast.get_source_segment(text,node)
    need(hashlib.sha256(original.encode()).hexdigest()==HELD_NATIVE_BUILD
         and original.count('shutil.copyfile(')==3
         and 'PINNED_CONTEXT_TRANSFER' not in native.__dict__, 'exact held three-copy bootstrap')
    projected=original.replace('shutil.copyfile(', 'PINNED_CONTEXT_TRANSFER(')
    need(projected.replace('PINNED_CONTEXT_TRANSFER(', 'shutil.copyfile(')==original,
         'whole unchanged authenticated build inverse')
    handoff=ContextHandoff(inputs,cache,out)
    native.PINNED_CONTEXT_TRANSFER=handoff.transfer
    exec(compile(projected,native.__file__,'exec'),native.__dict__)
    return handoff


class ContextHandoff:
    """Keep one owned ext4 inode per already authenticated build operand."""
    def __init__(self, inputs, cache, out):
        self.cache=cache
        self.context=out/'context'
        self.pending={}
        self.verified={}
        self.total=0
        self.allocated=0
        checks={}
        root=inputs['rootfs']
        self.rootfs=self.context/'rootfs.tar.gz'
        self.plan(root,self.rootfs,checks)
        need(type(root['signature_size']) is int and root['signature_size']>0,
             'positive exact signed rootfs detached signature')
        checks[root['filename']+'.sig']=root['signature_sha256']
        for item in inputs['packages']:
            name=item['filename']
            self.plan(item,self.context/'deps'/name,checks)
            sig=dict(filename=name+'.sig',size=item['signature_size'],sha256=item['signature_sha256'])
            self.plan(sig,self.context/'deps'/sig['filename'],checks)
        for item in inputs['keyring_files']:
            self.plan(item,self.context/'keys'/item['filename'],checks)
        need(len(self.pending)==416 and len(checks)==417 and decode(read(out/'cache-checksums.json'))==checks,
             'complete exact original 417 audit checksum join before owned cache handoff')

    def plan(self, item, destination, checks):
        name=item['filename']
        size=item['size']
        need(re.fullmatch(r'[A-Za-z0-9_+:.@-]+',name) and name not in ('.','..') and name not in checks
             and type(size) is int, 'unique exact bounded authenticated operand')
        if name=='archlinuxarm-revoked':
            need(destination==self.context/'keys'/name and size==0 and item['sha256']==EMPTY_REVOKED_SHA256,
                 'exact authenticated empty archlinuxarm revocations list')
        else:
            need(size>0, 'positive authenticated archives, signatures and other keyring inputs')
        self.pending[self.cache/name]=(destination,item['size'])
        checks[name]=item['sha256']

    def transfer(self, source, destination):
        planned=self.pending.get(source)
        need(planned is not None and planned[0]==destination,'only exact authenticated context copy operand')
        owned_handoff(source,destination,planned[1])
        # The held entry sets umask 077, so its former copy created mode 0600.
        destination.chmod(0o600)
        info=owned_leaf(destination,planned[1])
        self.verified[destination]=identity(info)
        self.total+=info.st_size
        self.allocated+=info.st_blocks*512
        del self.pending[source]

    def retire_context(self):
        # The completed build has already uploaded the context and checked the image inventory.
        need(not self.pending and not self.rootfs.exists() and not self.rootfs.is_symlink(),
             'complete original build and inspected rootfs context retired after import')
        for item, before in self.verified.items():
            if item!=self.rootfs:
                need(identity(item.lstat())==before,'same exact uploaded context input before retirement')
                item.unlink()
        (self.context/'deps').rmdir()
        (self.context/'keys').rmdir()
        print(json.dumps(dict(kind='EXACT_AUDITED_CONTEXT_HANDOFF_V1',files=len(self.verified),
                              bytes=self.total,allocated_bytes=self.allocated,accepting=False)),flush=True)


def unit(nonce, kind):
    need(re.fullmatch('[0-9a-f]{32}',nonce or '') and kind in ('owner','daemon'), 'fixed operation identity')
    return 'cachy-llhttp-minimal-builder-'+nonce+'-'+kind+'.service'


def service_args(nonce, kind, limits, command, log, uid=None, gid=None):
    args = ['/usr/bin/systemd-run','--quiet','--no-block','--unit='+unit(nonce,kind),
            '--property=Type=exec','--property=OOMPolicy=kill','--property=Restart=no','--property=KillMode=control-group',
            '--property=TimeoutStopSec=5s','--property=RuntimeMaxSec=1290s',
            '--property=MemoryMax='+str(limits['memory_bytes']),'--property=MemorySwapMax=0',
            '--property=CPUQuota='+str(limits['cpus']*100)+'%','--property=CPUQuotaPeriodSec=100ms',
            '--property=TasksMax='+str(limits['pids']), '--property=LimitCORE=0',
            '--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log)]
    volume=log.parent
    args += ['--property=ProtectSystem=strict','--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup']
    if kind == 'daemon':
        args += ['--property=Delegate=yes','--property=DelegateSubgroup=daemon',
                 '--property=ReadWritePaths='+str(volume)+' /sys/fs/cgroup/system.slice/'+unit(nonce,kind),
                 '--property=Environment=DOCKER_TMPDIR='+str(volume/'exec/tmp')+' TMPDIR='+str(volume/'exec/tmp')]
    else:
        need(type(uid) is int and uid > 0 and type(gid) is int and gid > 0, 'ordinary fixed runner IDs')
        args += ['--uid='+str(uid),'--gid='+str(gid),'--property=NoNewPrivileges=yes',
                 '--property=LimitAS='+str(limits['AS_bytes']),'--property=RemainAfterExit=yes',
                 '--property=ReadWritePaths='+str(volume/'work')]
    return args+['--',*command]


def domain(values, limits):
    expected = {'memory.max':str(limits['memory_bytes']), 'memory.swap.max':'0',
                'pids.max':str(limits['pids']), 'cpu.max':str(limits['cpus']*100000)+' 100000'}
    need(values == expected, 'actual kernel domain must equal separately reviewed maxima')
    return expected


def observation(value, a, map_sha, policy, self_pid, self_start, self_cgroup):
    need(value['kind'] == 'LLHTTP_MINIMAL206_BUILD_ONLY_ACTUAL_HOSTED_DOMAINS_V2'
         and value['source'] == a['source'] and value['ref'] == a['ref'] and value['nonce'] == a['nonce']
         and value['source_map_sha256'] == map_sha and value['owner']['pid'] == self_pid
         and value['owner']['starttime'] == self_start and value['owner']['cgroup'] == self_cgroup,
         'actual post-dispatch Source/PID/start/cgroup observation join')
    existing_host(value.get('host_policy',{}),policy,receipt=True)
    domain(value['owner']['limits'],policy['owner']);domain(value['daemon']['limits'],policy['daemon'])
    daemon=value['daemon']
    M.managed_receipt(daemon.get('managed_containerd'),daemon['pid'],daemon['starttime'],daemon['cgroup']+'/daemon')
    need(value['daemon']['cgroup'] != self_cgroup and value['endpoint'].startswith('unix:///')
         and value['storage_bytes'] == policy['storage_bytes'] and value['backend'] == policy['bootstrap_backend'],
         'distinct finite owned daemon/storage/backend')
    return value


def existing_host(value,policy,receipt=False):
    need(value.get('status')=='PASS_EXISTING_HOST_TOOLS_ONLY' and value.get('declaration')==policy['host_tools']
         and value.get('commands')==[] and type(value.get('package_manager_invocations')) is int and value['package_manager_invocations']==0
         and type(value.get('host_package_mutations')) is int and value['host_package_mutations']==0
         and value.get('tools')==sorted(policy['host_tools']['names']), 'existing qualified host tools only; zero package-manager commands/mutations')
    if receipt:
        row=value.get('receipt',{})
        need(type(row.get('bytes')) is int and 0<row['bytes']<=1024**2 and re.fullmatch('[0-9a-f]{64}',row.get('sha256','')), 'whole actual existing-host receipt pin')
    return value
