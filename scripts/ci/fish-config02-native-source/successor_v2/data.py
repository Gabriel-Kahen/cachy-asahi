# SPDX-License-Identifier: MIT
"""Finite Fish-only policy, namespace and domain joins; no actor on import."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PREFIX = 'scripts/ci/fish-config02-native-source/successor_v2/'
ORIGIN_MAP = dict(bytes=10226, sha256='33a9380a24c5cd0e233ae0a3ed6a937cbfdfeaccbe0622a6f27a7c5ae3800576')
ORIGIN_TREE = 'cf3c4c4cd4fa6f9dd17463bb033a3650256c7e6e'
ORIGIN_SOURCE = '463377ba9c0b48c58dc112386c9b0203efd39b6e'
BASE_PREFIX = 'scripts/ci/fish-config02-native-source/'
ENV_ANCHOR = "                    if env:clean.update(env)"
ENV_PROJECTION = "                    clean['DOCKER_HOST']=os.environ['CACHY_FISH02_OWNED_DOCKER_HOST']\n                    clean['DOCKER_BUILDKIT']='0'\n                    clean['TMPDIR']=os.environ['CACHY_FISH02_OWNED_TMPDIR']\n" + ENV_ANCHOR


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


def git_tree(bodies):
    """Compute the physical Git tree from finite in-memory ordinary 0644 files."""
    def oid(kind, raw):
        return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
    def tree(prefix):
        names={n[len(prefix):].split('/')[0] for n in bodies if n.startswith(prefix)}
        rows=[]
        for name in names:
            full=prefix+name
            if full in bodies:
                mode,key,digest=b'100644',name.encode(),oid('blob',bodies[full])
            else:
                mode,key,digest=b'40000',(name+'/').encode(),tree(full+'/')
            rows.append((key,mode+b' '+name.encode()+b'\0'+digest))
        return oid('tree',b''.join(v for _,v in sorted(rows)))
    return tree('').hex()


def base_binding(root):
    value=decode(read(Path(root)/PREFIX/'base-binding.json'))
    need(set(value)=={'kind','map','files','bytes','actual'} and
         value['kind']=='FISH02_DERIVED_BASE33_BINDING_V4' and value['actual'] is None and
         value['files']==33 and type(value['bytes']) is int and 0<value['bytes']<2*1024**2,
         'explicit derived base33 binding, never unchanged Source32')
    raw=read(Path(root)/'held-source32'/BASE_PREFIX/'source-map.json')
    need(pin(raw)==value['map'], 'whole derived base33 map binding')
    return value


def inverse_source48(root, bodies):
    proof=decode(bodies[PREFIX+'source48-inverse.json'])
    need(set(proof)=={'kind','actual','origin','before_utf8','after','added'} and
         proof['kind']=='FISH02_COMPLETE_SOURCE48_INVERSE_V4' and proof['actual'] is None and
         proof['origin']==dict(source=ORIGIN_SOURCE,map=ORIGIN_MAP,tree=ORIGIN_TREE,files=48,bytes=724556),
         'explicit exact Source48 inverse domain')
    before=proof['before_utf8'];need(type(before)is dict and all(type(v)is str for v in before.values()),
                                   'whole UTF8 predecessor bodies only')
    need('source-map.json' in before and pin(before['source-map.json'].encode())==ORIGIN_MAP,
         'whole exact predecessor root map')
    old=decode(before['source-map.json'].encode());original={**old['files'],'source-map.json':dict(ORIGIN_MAP,mode=0o644)}
    need(len(original)==48 and old['kind']=='FISH02_OWNED_HOSTED_SOURCE_V2' and
         all(v is None for v in old['actual'].values()), 'exact predecessor namespace/schema')
    changed={n for n,row in original.items() if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added, 'complete changed/removed/new predecessor inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source48-inverse.json'}
    after={n:dict(pin(raw),mode=0o644) for n,raw in bodies.items() if n not in excluded and (n in added or n in changed)}
    need(proof['after']==after, 'whole current nonrecursive changed/new inverse bindings')
    restored={n:before[n].encode() if n in before else bodies[n] for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute() and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row, 'whole restored Source48 body/mode')
    need(sum(map(len,restored.values()))==724556 and git_tree(restored)==ORIGIN_TREE,
         'complete exact48 physical tree inverse')
    return dict(files=48,bytes=724556,tree=ORIGIN_TREE,map=ORIGIN_MAP)


def source(root, expected):
    root=Path(root);need(root.is_absolute() and root==root.resolve(), 'canonical complete Source')
    body=read(root/'source-map.json');need(pin(body)['sha256']==expected, 'external successor map pin')
    value=decode(body);rows=value['files']
    need(value['kind']=='FISH02_SIGNED_ROOTFS_SOURCE_V5' and len(rows)==66 and
         set(value['actual'])=={'source','ref','run','job','Root_admission','runtime','image','owner_domain','daemon_domain'} and
         all(v is None for v in value['actual'].values()), 'finite prospective v4 namespace')
    found=set();pending=[root];count=0
    while pending:
        directory=pending.pop()
        with os.scandir(directory)as entries:
            for entry in entries:
                if directory==root and entry.name=='.git':continue
                count+=1;need(count<=256,'bounded complete Source namespace')
                path=Path(entry.path);need(not path.is_symlink(),'unaliased complete Source')
                if path.is_dir():pending.append(path)
                else:
                    need(path.is_file(),'ordinary complete Source leaf');found.add(path.relative_to(root).as_posix())
    need(found==set(rows)|{'source-map.json'}, 'complete closed v4 namespace')
    bodies={'source-map.json':body}
    for name,row in rows.items():
        need(not Path(name).is_absolute() and '..'not in Path(name).parts, 'safe Source name')
        raw=read(root/name);need(dict(pin(raw),mode=stat.S_IMODE((root/name).stat().st_mode))==row and row['mode']==0o644,
                               'whole successor body/mode')
        bodies[name]=raw
    need(sum(map(len,bodies.values()))<2*1024**2, 'bounded complete Source50 bytes')
    binding=base_binding(root);base_raw=bodies['held-source32/'+BASE_PREFIX+'source-map.json'];prior=decode(base_raw)
    subset={n[len('held-source32/'):]:r for n,r in rows.items() if n.startswith('held-source32/')}
    need(prior['kind']=='FISH02_MINIMAL_HOSTED_SOURCE_MAP_V1' and all(v is None for v in prior['actual'].values()) and
         subset==dict(prior['files'],**{BASE_PREFIX+'source-map.json':dict(pin(base_raw),mode=0o644)}) and
         len(subset)==binding['files'] and sum(r['bytes']for r in subset.values())==binding['bytes'],
         'complete derived base33 namespace/body join')
    program=decode(bodies[PREFIX+'owner-program.json'])
    need(program['schema']==1 and program['base_source_map_sha256']==binding['map']['sha256'] and
         program['files']=={n:r for n,r in rows.items() if not n.startswith('held-source32/') and n!=PREFIX+'owner-program.json'},
         'complete no-APT owner-program/base33 delegation')
    prior63 = inverse_source63(inverse_source64(inverse_source65(bodies)))
    inverse_source48(root,inverse_source50(inverse_source53(inverse_source57(inverse_source60(inverse_source62(inverse_carrier_source62(prior63)))))))
    return value


def admission(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha, env, now):
    need(0 < len(admission_raw) <= 16384 and 0 < len(runtime_raw) <= 16384
         and pin(admission_raw)['sha256'] == admission_sha and pin(runtime_raw)['sha256'] == runtime_sha,
         'two separately pinned whole Root documents')
    source(root,map_sha); a,r = decode(admission_raw),decode(runtime_raw)
    profile = decode(read(root/'held-source32'/BASE_PREFIX/'profile.json'))
    for value,kind in ((a,'ROOT_FISH02_NO_HOST_APT_ADMISSION_V4'),(r,'ROOT_FISH02_NO_HOST_APT_RUNTIME_V4')):
        need(value['kind'] == kind and value['issued_by'] == 'Root' and value['accepted'] is True,
             'separate actual Root issuance')
        need(re.fullmatch('[0-9a-f]{40}',value['source'] or '') and value['source'] == env.get('GITHUB_SHA')
             and value['ref'] == env.get('GITHUB_REF') and value['ref'].startswith('refs/heads/codex/')
             and value['source_map_sha256'] == map_sha and value['resources'] == profile['resources'],
             'exact actual Source/ref/map/held pair policy')
        need(type(value['created_utc']) is int and type(value['expires_utc']) is int
             and value['created_utc'] <= now < value['expires_utc'] and value['expires_utc']-value['created_utc'] <= 3600
             and re.fullmatch('[0-9a-f]{32}',value['nonce'] or ''), 'fresh bounded Root delegation')
    policy=decode(read(root/PREFIX/'policy.json'))
    need(r.get('host_tools')==policy['host_tools'] and 'host_prerequisites'not in r, 'separate explicit Root existing-host no-APT admission required')
    need(a['nonce'] == r['nonce'] and env.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
         and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and env.get('GITHUB_RUN_ATTEMPT') == '1'
         and re.fullmatch('[1-9][0-9]{1,19}',env.get('GITHUB_RUN_ID','')), 'single hosted attempt/nonce')
    need(r['external_supervision'] == pin(read(root/PREFIX/'owner-program.json'))
         and r['bootstrap_resource_domain'] == pin(read(root/PREFIX/'policy.json')),
         'loaded actual owner-program and new separate resource policy pins')
    return a,r


def projected_entry(body):
    text = body.decode(); need(text.count(ENV_ANCHOR) == 1, 'finite Docker endpoint/backend seam')
    projected = text.replace(ENV_ANCHOR,ENV_PROJECTION)
    need(projected.count(ENV_PROJECTION) == 1 and projected.replace(ENV_PROJECTION,ENV_ANCHOR).encode() == body,
         'whole held entry inverse')
    return projected


def unit(nonce, kind):
    need(re.fullmatch('[0-9a-f]{32}',nonce or '') and kind in ('owner','daemon'), 'fixed operation identity')
    return 'cachy-fish02-'+nonce+'-'+kind+'.service'


def service_args(nonce, kind, limits, command, log, uid=None, gid=None, *, source_root):
    args = ['/usr/bin/systemd-run','--quiet','--no-block','--unit='+unit(nonce,kind),
            '--property=Type=exec','--property=OOMPolicy=kill','--property=Restart=no','--property=KillMode=control-group',
            '--property=TimeoutStopSec=5s','--property=RuntimeMaxSec=1290s',
            '--property=MemoryMax='+str(limits['memory_bytes']),'--property=MemorySwapMax=0',
            '--property=CPUQuota='+str(limits['cpus']*100)+'%','--property=CPUQuotaPeriodSec=100ms',
            '--property=TasksMax='+str(limits['pids']), '--property=LimitCORE=0',
            '--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log)]
    volume=log.parent
    need(isinstance(source_root,Path) and source_root.is_absolute() and source_root!=Path('/')
         and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(source_root)) and source_root==source_root.resolve(strict=True)
         and source_root.is_dir(),'required exact canonical Source root for read-only unit binding')
    need(volume.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(volume))
         and volume==volume.resolve(strict=True) and volume.is_dir(),'canonical existing quota volume for source disjointness')
    need(not source_root.is_relative_to(volume) and not volume.is_relative_to(source_root),
         'Source root and whole quota volume must be disjoint')
    args += ['--property=ProtectSystem=strict','--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup',
             '--property=BindReadOnlyPaths='+str(source_root)]
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
    need(value['kind'] == 'FISH02_NO_HOST_APT_ACTUAL_DOMAINS_V4'
         and value['source'] == a['source'] and value['ref'] == a['ref'] and value['nonce'] == a['nonce']
         and value['source_map_sha256'] == map_sha and value['owner']['pid'] == self_pid
         and value['owner']['starttime'] == self_start and value['owner']['cgroup'] == self_cgroup,
         'actual post-dispatch Source/PID/start/cgroup observation join')
    host=value.get('host_policy',{});existing_host(host,policy)
    need(type(host.get('receipt',{}).get('bytes'))is int and 0<host['receipt']['bytes']<=1024**2 and
         re.fullmatch('[0-9a-f]{64}',host['receipt']['sha256']), 'actual recorded existing-host receipt before native seed')
    domain(value['owner']['limits'],policy['owner']);domain(value['daemon']['limits'],policy['daemon'])
    need(value['daemon']['cgroup'] != self_cgroup and value['endpoint'].startswith('unix:///')
         and value['storage_bytes'] == policy['storage_bytes'] and value['backend'] == policy['bootstrap_backend'],
         'distinct finite owned daemon/storage/backend')
    return value


HOST_NAMES=('systemd-run','systemctl','dockerd','docker','fallocate','losetup','mkfs.ext4','mount','umount','python3','gpg','zstd')
CONTEXT_CHECKS={'ROOT_UID','MACHINE_ARM64','CI_ACTIONS','CI_RUNNER_OS','CI_RUNNER_ARCH','CI_REPOSITORY','CI_DISPATCH',
                'CI_FIRST_ATTEMPT','CI_RUN_ID','CI_SOURCE_SHA','CI_SOURCE_REF','CI_JOB_PAIR','OS_RELEASE_FORMAT','OS_UBUNTU','OS_VERSION24_04'}


def existing_host(value, policy):
    declaration=policy['host_tools'];context=value.get('context',{})
    need(declaration.get('kind')=='EXISTING_NATIVE_HOST_TOOLS_ONLY_V1' and declaration.get('names')==list(HOST_NAMES) and
         declaration.get('package_manager_invocations')==0 and declaration.get('host_package_mutations')==0 and
         declaration.get('package_format')=='.pkg.tar.xz' and declaration.get('member_inspection')=='PYTHON_STDLIB_TARFILE_XZ_ONLY',
         'fixed twelve existing tools and XZ-only no-host-package policy')
    need(value.get('status')=='PASS_EXISTING_HOST_TOOLS_ONLY' and value.get('declaration')==declaration and
         value.get('commands')==[] and type(value.get('package_manager_invocations'))is int and value['package_manager_invocations']==0 and
         type(value.get('host_package_mutations'))is int and value['host_package_mutations']==0 and value.get('tools')==sorted(HOST_NAMES) and
         context.get('kind')=='PUBLIC_UBUNTU24_ARM_CI_CONTEXT_V1' and context.get('reason_codes')==[] and
         type(context.get('checks'))is dict and set(context['checks'])==CONTEXT_CHECKS and all(v is True for v in context['checks'].values()),
         'actual complete context/existing-host receipt, zero package commands/mutations')
    return value

# SPDX-License-Identifier: MIT
"""Inert exact Source50 inverse shared by constructor and emitted validator."""
SOURCE50 = dict(source='c5db06eb66e9df7bf33f5be1695e28fb012be953',
                tree='dff997f10bd4e917709f2b76d4c32f07ed379a03',files=50,bytes=892625,
                map=dict(bytes=10661,sha256='93bd88bf41da2a067cc7f04ebaa70374963bfda350cb821a7e6cf9278235c021'))


def inverse_source50(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source50-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE50_INVERSE_V5' and proof['origin']==SOURCE50 and proof['actual'] is None,
         'exact Source50 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE50['map'],
         'whole immutable Source50 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE50['map'],mode=0o644)})
    need(len(original)==50 and manifest['kind']=='FISH02_NO_HOST_APT_SOURCE_V4' and
         all(v is None for v in manifest['actual'].values()),'original complete50 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete50 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source50-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source50 body/mode')
    need(sum(map(len,restored.values()))==SOURCE50['bytes']and git_tree(restored)==SOURCE50['tree'],
         'complete original50 bytes and physical Git tree')
    return restored

# SPDX-License-Identifier: MIT
"""Inert exact Source53 inverse shared by constructor and emitted validator."""
SOURCE53 = dict(source='7ac1c330d2a2c19d4f353cf6f271730f20aa2771',
                tree='4f10cc1cdb48d946b6a0af8bd4051b54308c34f5',files=53,bytes=967199,
                map=dict(bytes=11296,sha256='ef50c6185a228cefcc4b241863221eb3bf9d44959b4b312b422887bdf6dc3db5'))


def inverse_source53(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source53-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE53_INVERSE_V6' and proof['origin']==SOURCE53 and proof['actual'] is None,
         'exact Source53 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE53['map'],
         'whole immutable Source53 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE53['map'],mode=0o644)})
    need(len(original)==53 and manifest['kind']=='FISH02_FINITE_DOCKER_VA_SOURCE_V5' and
         all(v is None for v in manifest['actual'].values()),'original complete53 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete53 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source53-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source53 body/mode')
    need(sum(map(len,restored.values()))==SOURCE53['bytes']and git_tree(restored)==SOURCE53['tree'],
         'complete original53 bytes and physical Git tree')
    return restored

# SPDX-License-Identifier: MIT
"""Inert exact Source57 inverse shared by constructor and emitted validator."""
SOURCE57 = dict(source='198db17eb3a16714f2530334c24be8512feaa03f',
                tree='4e06d52d001a504916fab131104b39014fd2338c',files=57,bytes=1066965,
                map=dict(bytes=12161,sha256='f98da639c80ae35423f7c33a66df12bd5f70ea9fc15ecbaabb93c6569f3a6150'))


def inverse_source57(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source57-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE57_INVERSE_V7' and proof['origin']==SOURCE57 and proof['actual'] is None,
         'exact Source57 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE57['map'],
         'whole immutable Source57 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE57['map'],mode=0o644)})
    need(len(original)==57 and manifest['kind']=='FISH02_PAYLOAD_RETIREMENT_SOURCE_V6' and
         all(v is None for v in manifest['actual'].values()),'original complete57 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete57 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source57-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source57 body/mode')
    need(sum(map(len,restored.values()))==SOURCE57['bytes']and git_tree(restored)==SOURCE57['tree'],
         'complete original57 bytes and physical Git tree')
    return restored

# SPDX-License-Identifier: MIT
"""Inert exact Source60 inverse shared by constructor and emitted validator."""
SOURCE60 = dict(source='1b4186b8e069abd39725a0b054e59999e8f40f0f',
                tree='8e7d42d9a25eeef1bd80389d198fedf84a5902ac',files=60,bytes=1130628,
                map=dict(bytes=12826,sha256='c604399d2472fb5dd0a5e97a299b1017a697426ebd47454c5a43c72ce05892d5'))


def inverse_source60(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source60-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE60_INVERSE_V8' and proof['origin']==SOURCE60 and proof['actual'] is None,
         'exact Source60 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE60['map'],
         'whole immutable Source60 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE60['map'],mode=0o644)})
    need(len(original)==60 and manifest['kind']=='FISH02_FIXED_FILESYSTEM_DIAGNOSTIC_SOURCE_V7' and
         all(v is None for v in manifest['actual'].values()),'original complete60 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete60 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source60-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source60 body/mode')
    need(sum(map(len,restored.values()))==SOURCE60['bytes']and git_tree(restored)==SOURCE60['tree'],
         'complete original60 bytes and physical Git tree')
    return restored

# SPDX-License-Identifier: MIT
"""Inert complete frozen Source62 inverse; appended to the admitted validator."""
SOURCE62=dict(files=62,bytes=1220725,tree='3c8a238723718c6c6534f6adc5cf020e2275ecc4',map=dict(bytes=13251,sha256='399d833c468d1d932d1e689cc634ca0be50cd0b32dd674fce3e9b0ce17dd66b3'))


def inverse_source62(bodies):
    proof=decode(bodies[PREFIX+'source-ro-binding.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and proof['kind']=='FISH02_COMPLETE_SOURCE62_CARRIER_INVERSE_V1'and proof['origin']==SOURCE62 and proof['actual']is None,'complete original62 inverse declaration')
    before=proof['before_utf8'];need(type(before)is dict and all(type(r)is str for r in before.values())and 'source-map.json'in before,'whole62 original bodies')
    raw=before['source-map.json'].encode();need(pin(raw)==SOURCE62['map'],'whole immutable62 map')
    old=decode(raw);rows=dict(old['files'],**{'source-map.json':dict(SOURCE62['map'],mode=0o644)})
    need(len(rows)==62 and old['kind']=='FISH02_EXPLICIT_SOURCE_READONLY_SOURCE_V8'and all(v is None for v in old['actual'].values()),'complete original62 schema')
    changed={n for n,r in rows.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=r};added=set(bodies)-set(rows)
    need(set(before)==changed and set(proof['added'])==added and len(proof['added'])==len(added),'complete original62 changed/new namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source-ro-binding.json'}
    need(proof['after']=={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},'whole finite after-bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in rows}
    need(all(dict(pin(restored[n]),mode=0o644)==r for n,r in rows.items())and sum(map(len,restored.values()))==SOURCE62['bytes']and git_tree(restored)==SOURCE62['tree'],'whole complete original62 body/mode/tree inverse')
    return restored

# SPDX-License-Identifier: MIT
"""Inert complete frozen Fish carrier62 inverse."""
SOURCE_CARRIER62=dict(files=62,bytes=1431202,tree='9db85398af8cd52b43adcf5925568b7bcf54cbc7',map=dict(bytes=13276,sha256='44a5c63ae729a9eb0fb83280659e987fc29dee0b105e5125ab12975a6a1d2507'))


def inverse_carrier_source62(bodies):
    proof=decode(bodies[PREFIX+'source-ro-binding.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'}and proof['kind']=='FISH02_COMPLETE_CARRIER62_BOUND512_HOLD_INVERSE_V2'and proof['origin']==SOURCE_CARRIER62 and proof['actual']is None,'complete carrier62 inverse declaration')
    before=proof['before_utf8'];raw=before['source-map.json'].encode();need(pin(raw)==SOURCE_CARRIER62['map'],'whole fixed carrier62 map')
    value=decode(raw);rows=dict(value['files'],**{'source-map.json':dict(SOURCE_CARRIER62['map'],mode=0o644)})
    need(len(rows)==62 and value['kind']=='FISH02_EXACT_PINNED_INPUT_CARRIER_SOURCE_V1'and all(v is None for v in value['actual'].values()),'complete frozen carrier62 frame')
    changed={n for n,r in rows.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=r};added=set(bodies)-set(rows)
    need(set(before)==changed and set(proof['added'])==added and len(proof['added'])==len(added),'whole carrier62 inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source-ro-binding.json'}
    need(proof['after']=={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},'complete literal after-bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in rows}
    need(all(dict(pin(restored[n]),mode=0o644)==r for n,r in rows.items())and sum(map(len,restored.values()))==SOURCE_CARRIER62['bytes']and git_tree(restored)==SOURCE_CARRIER62['tree'],'whole frozen carrier62 body/mode/tree inverse')
    return restored


SOURCE63 = dict(source='7793ed128057cabfa116e4b7e9cde796191f4b0f',
                files=63, bytes=1699074, tree='a4bf7948a2ea3edc047d80117b15f72fc64622ff',
                map=dict(bytes=13482, sha256='e3fb8ecce03a31beee6aabad8844b06743f3e55afe4b463d9086d7f1c8ec3245'))
CARRIER_ADMISSION_INVERSE = PREFIX + 'carrier-admission-inverse.json'


def inverse_source63(bodies):
    proof = decode(bodies[CARRIER_ADMISSION_INVERSE])
    need(set(proof) == {'kind', 'origin', 'before_utf8', 'after', 'added', 'actual'} and
         proof['kind'] == 'FISH02_CARRIER_ADMISSION_SOURCE63_INVERSE_V1' and
         proof['origin'] == SOURCE63 and proof['actual'] is None, 'exact Source63 inverse frame')
    before = proof['before_utf8']
    needs_prior = {'source-map.json', PREFIX+'owner-program.json', PREFIX+'data.py', PREFIX+'payload.py',
                   PREFIX+'native349_carrier_case.py'}
    need(type(before) is dict and set(before) == needs_prior and
         all(type(body) is str for body in before.values()), 'exact Source63 changed leaves')
    need(pin(before['source-map.json'].encode()) == SOURCE63['map'], 'whole published Source63 map')
    old = decode(before['source-map.json'])
    rows = dict(old['files'], **{'source-map.json': dict(SOURCE63['map'], mode=0o644)})
    need(old['kind'] == 'FISH02_BOUND512_PUBLIC_HOLD_SOURCE_V2' and
         len(rows) == SOURCE63['files'] and all(v is None for v in old['actual'].values()),
         'published bound512 Source63 map frame')
    added = set(bodies) - set(rows)
    changed = {n for n, r in rows.items() if n not in bodies or dict(pin(bodies[n]), mode=0o644) != r}
    need(added == {CARRIER_ADMISSION_INVERSE} and proof['added'] == [CARRIER_ADMISSION_INVERSE] and
         changed == needs_prior, 'only audited Source63 delta')
    checked = needs_prior - {'source-map.json', PREFIX+'owner-program.json'}
    need(proof['after'] == {n: dict(pin(bodies[n]), mode=0o644) for n in checked},
         'whole new Fish carrier, admission validator and payload')
    restored = {n: before[n].encode() if n in before else bodies[n] for n in rows}
    need(all(dict(pin(restored[n]), mode=0o644) == r for n, r in rows.items()) and
         sum(map(len, restored.values())) == SOURCE63['bytes'] and git_tree(restored) == SOURCE63['tree'],
         'whole published Source63 inverse')
    return restored


SOURCE64 = dict(source='16da423c68cda2b2e429e1b71d8395ced0ec2898',
                files=64, bytes=1875041, tree='1b4dc6e4b9bef83610b35b8d0cbeecc6c9f876dc',
                map=dict(bytes=13703, sha256='acf0e5bf476f7dce5fe5d1602ff27a88f12315b888b5f8b276028839ceab0dab'))
LIBFFI_RECOVERY_INVERSE = PREFIX + 'libffi-recovery-inverse.json'


def inverse_source64(bodies):
    proof = decode(bodies[LIBFFI_RECOVERY_INVERSE])
    need(set(proof) == {'kind', 'origin', 'before_utf8', 'after', 'added', 'actual'} and
         proof['kind'] == 'FISH02_LIBFFI_RECOVERY_SOURCE64_INVERSE_V1' and
         proof['origin'] == SOURCE64 and proof['actual'] is None, 'exact published Source64 inverse frame')
    before = proof['before_utf8']
    projected = {PREFIX+'data.py', PREFIX+'native349_carrier_case.py'}
    rewritten = projected | {'source-map.json', PREFIX+'owner-program.json'}
    need(type(before) is dict and set(before) == rewritten and
         all(type(body) is str for body in before.values()), 'exact Source64 changed leaves')
    map_raw = before['source-map.json'].encode()
    need(pin(map_raw) == SOURCE64['map'], 'whole published Source64 map')
    old = decode(map_raw)
    rows = dict(old['files'], **{'source-map.json': dict(SOURCE64['map'], mode=0o644)})
    need(old['kind'] == 'FISH02_CARRIER_ADMISSION_SOURCE_V3' and
         len(rows) == SOURCE64['files'] and all(value is None for value in old['actual'].values()),
         'published Source64 map frame')
    added = set(bodies) - set(rows)
    changed = {n for n, row in rows.items() if n not in bodies or dict(pin(bodies[n]), mode=0o644) != row}
    need(added == {LIBFFI_RECOVERY_INVERSE} and proof['added'] == [LIBFFI_RECOVERY_INVERSE] and
         changed == rewritten, 'only audited Source64 delta')
    need(proof['after'] == {n: dict(pin(bodies[n]), mode=0o644) for n in projected},
         'whole new Fish carrier and Source validator')
    restored = {n: before[n].encode() if n in before else bodies[n] for n in rows}
    need(all(dict(pin(restored[n]), mode=0o644) == row for n, row in rows.items()) and
         sum(map(len, restored.values())) == SOURCE64['bytes'] and git_tree(restored) == SOURCE64['tree'],
         'whole published Source64 inverse')
    return restored


# Compact Source65 inverse begins here.
SOURCE65 = dict(files=65, bytes=2049607, tree='1aec62ab8782feee358305daf183125254ac535e',
                map=dict(bytes=13929, sha256='828a12bb1be74b2d60a5bd2ceeedb6a04bf7bac2d6aca297b1f52a0ae2d2bd04'))
ROOTFS_NEW = {PREFIX+'fish_rootfs_binding.py', PREFIX+'signed_rootfs_bootstrap.py'}
ROOTFS_DATA_INVERSE = (
    (b"    need(value['kind']=='FISH02_SIGNED_ROOTFS_SOURCE_V5' and len(rows)==66 and\n",
     b"    need(value['kind']=='FISH02_EXACT_LIBFFI_RECOVERY_SOURCE_V4' and len(rows)==64 and\n"),
    (b"    prior63 = inverse_source63(inverse_source64(inverse_source65(bodies)))\n",
     b"    prior63 = inverse_source63(inverse_source64(bodies))\n"),
)
ROOTFS_PAYLOAD_INVERSE = (
    (b"q = importlib.util.spec_from_file_location('fish02_signed_rootfs_binding',HERE/'fish_rootfs_binding.py');Q=importlib.util.module_from_spec(q);q.loader.exec_module(Q)\n", b''),
    (b"PINNED_INPUTS=Path(config['pinned_inputs']),FISH_ROOTFS=Q)",
     b"PINNED_INPUTS=Path(config['pinned_inputs']))"),
    (b"exec(compile(Q.project_entry(N.project_entry(projected)),str(entry_path),'exec'),namespace)",
     b"exec(compile(N.project_entry(projected),str(entry_path),'exec'),namespace)"),
)


def inverse_source65(bodies):
    """Reconstruct the four changed prior bodies without storing a second copy."""
    marker = b'\n\n# Compact Source65 inverse begins here.\n'
    map_name, program_name = 'source-map.json', PREFIX+'owner-program.json'
    data_name, payload_name = PREFIX+'data.py', PREFIX+'payload.py'
    need(ROOTFS_NEW <= set(bodies) and bodies[data_name].count(marker) == 1, 'exact Fish rootfs delta frame')
    restored = {name: raw for name, raw in bodies.items() if name not in ROOTFS_NEW}
    restored[data_name] = restored[data_name].split(marker, 1)[0]
    for name, seams in ((data_name, ROOTFS_DATA_INVERSE), (payload_name, ROOTFS_PAYLOAD_INVERSE)):
        for after, before in seams:
            need(restored[name].count(after) == 1, 'one exact Source65 reversal seam')
            restored[name] = restored[name].replace(after, before, 1)

    def row(raw):
        return dict(pin(raw), mode=0o644)

    def encoded(value):
        return (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()

    program = decode(restored[program_name])
    program['files'] = {name: row(raw) for name, raw in restored.items()
                        if name not in (map_name, program_name) and not name.startswith('held-source32/')}
    restored[program_name] = encoded(program)
    prior = decode(restored[map_name])
    prior['kind'] = 'FISH02_EXACT_LIBFFI_RECOVERY_SOURCE_V4'
    prior['files'] = {name: row(raw) for name, raw in restored.items() if name != map_name}
    restored[map_name] = encoded(prior)
    changed = {name for name, raw in restored.items() if raw != bodies[name]}
    need(changed == {map_name, program_name, data_name, payload_name} and
         len(restored) == SOURCE65['files'] and sum(map(len, restored.values())) == SOURCE65['bytes'] and
         pin(restored[map_name]) == SOURCE65['map'] and git_tree(restored) == SOURCE65['tree'],
         'whole published Source65 body and tree inverse')
    return restored
