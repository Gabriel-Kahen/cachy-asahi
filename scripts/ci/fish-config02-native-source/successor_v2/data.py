# SPDX-License-Identifier: MIT
"""Finite Fish-only policy, namespace and domain joins; no actor on import."""
import hashlib
import json
from pathlib import Path
import re
import stat

PREFIX = 'scripts/ci/fish-config02-native-source/successor_v2/'
BASE_MAP = 'c1ac908dade524987e4b24fbde5d808ade2629edfa8b965b37f85a798abafd64'
BASE_MAP_BYTES = 6521
BASE_BYTES = 592443
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


def source(root, expected):
    root = Path(root)
    need(root.is_absolute() and root == root.resolve(), 'canonical complete Source')
    body = read(root/'source-map.json'); need(pin(body)['sha256'] == expected, 'external successor map pin')
    value = decode(body); rows = value['files']
    need(value['kind'] == 'FISH02_OWNED_HOSTED_SOURCE_V2' and 32 < len(rows) < 48
         and all(v is None for v in value['actual'].values()), 'finite prospective successor namespace')
    found = {str(p.relative_to(root)) for p in root.rglob('*') if p.relative_to(root).parts[0] != '.git'
             and (p.is_file() or p.is_symlink())}
    need(found == set(rows)|{'source-map.json'}, 'complete closed successor namespace')
    for name, row in rows.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'safe Source name')
        path = root/name
        need(dict(pin(read(path)), mode=stat.S_IMODE(path.stat().st_mode)) == row and row['mode'] == 0o644,
             'whole successor body/mode: '+name)
    base = root/'held-source32'; raw = read(base/BASE_PREFIX/'source-map.json')
    need(pin(raw) == dict(bytes=BASE_MAP_BYTES,sha256=BASE_MAP), 'whole immutable Source32 map')
    prior = decode(raw)
    subset = {n[len('held-source32/'):]:r for n,r in rows.items() if n.startswith('held-source32/')}
    need(subset == dict(prior['files'], **{BASE_PREFIX+'source-map.json':dict(pin(raw),mode=0o644)})
         and len(subset) == 32 and sum(r['bytes'] for r in subset.values()) == BASE_BYTES,
         'exact unchanged whole Source32 subtree')
    original_base(root, prior)
    program = decode(read(root/PREFIX/'owner-program.json'))
    need(program['base_source_map_sha256'] == BASE_MAP and program['schema'] == 1, 'explicit held Source32 delegation')
    need(set(program['files']) == {n for n in rows if not n.startswith('held-source32/') and n != PREFIX+'owner-program.json'}, 'complete owner-program namespace')
    for name, row in program['files'].items():
        need(rows[name] == row, 'whole owner-program closure')
    return value



def original_base(root, current):
    proof = decode(read(root/PREFIX/'base-read-delta.json'))
    need(proof['kind'] == 'FISH02_BASE32_READ_STABILITY_SUCCESSOR_DELTA' and proof['actual'] is None,
         'explicit read-stability successor, no original Source relabel')
    prior = dict(current, files=dict(current['files']))
    for change in proof['changes']:
        body = read(root/'held-source32'/change['path'])
        need(dict(pin(body), mode=0o644) == change['after'], 'exact updated base leaf')
        text = body.decode()
        for seam in reversed(change['seams']):
            need(text.count(seam['after']) == 1, 'one exact base-read inverse seam')
            text = text.replace(seam['after'], seam['before'])
        need(dict(pin(text.encode()), mode=0o644) == change['before'], 'whole original base leaf inverse')
        prior['files'][change['path']] = change['before']
    raw = (json.dumps(prior, indent=2, sort_keys=True)+'\n').encode()
    need(pin(raw) == proof['original_source_map'] == dict(bytes=6521,sha256='dfd91945cef9a3d3c7ffc73ac06252d6f54514f880071b2951b4e698fc5d6909')
         and len(prior['files'])+1 == proof['original_source_files'] == 32
         and sum(r['bytes'] for r in prior['files'].values())+len(raw) == proof['original_source_bytes'] == 591897,
         'complete original Source32 map/body reconstruction; frozen exports unchanged')


def admission(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha, env, now):
    need(0 < len(admission_raw) <= 16384 and 0 < len(runtime_raw) <= 16384
         and pin(admission_raw)['sha256'] == admission_sha and pin(runtime_raw)['sha256'] == runtime_sha,
         'two separately pinned whole Root documents')
    source(root,map_sha); a,r = decode(admission_raw),decode(runtime_raw)
    profile = decode(read(root/'held-source32'/BASE_PREFIX/'profile.json'))
    for value,kind in ((a,'ROOT_FISH02_HOSTED_ADMISSION_V1'),(r,'ROOT_FISH02_HOSTED_RUNTIME_V1')):
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
    need(r.get('host_prerequisites')==policy['host_prerequisites'], 'separate explicit Root Ubuntu CI prerequisite admission required')
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
    need(value['kind'] == 'FISH02_ACTUAL_HOSTED_DOMAINS_V2'
         and value['source'] == a['source'] and value['ref'] == a['ref'] and value['nonce'] == a['nonce']
         and value['source_map_sha256'] == map_sha and value['owner']['pid'] == self_pid
         and value['owner']['starttime'] == self_start and value['owner']['cgroup'] == self_cgroup,
         'actual post-dispatch Source/PID/start/cgroup observation join')
    prerequisite=value.get('host_prerequisite',{})
    need(prerequisite.get('status')=='PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY'and prerequisite.get('declaration')==policy['host_prerequisites']and
         prerequisite.get('package')=='libarchive-tools'and prerequisite.get('installed')==dict(package='libarchive-tools',state='install ok installed',version=prerequisite.get('selected_version'),architecture='arm64')and
         type(prerequisite.get('selected_version'))is str and re.fullmatch('[A-Za-z0-9.+:~_-]{1,128}',prerequisite['selected_version'])and
         type(prerequisite.get('receipt',{}).get('bytes'))is int and 0<prerequisite['receipt']['bytes']<=1024**2 and re.fullmatch('[0-9a-f]{64}',prerequisite['receipt']['sha256']),
         'actual recorded CI prerequisite before any native seed')
    domain(value['owner']['limits'],policy['owner']);domain(value['daemon']['limits'],policy['daemon'])
    need(value['daemon']['cgroup'] != self_cgroup and value['endpoint'].startswith('unix:///')
         and value['storage_bytes'] == policy['storage_bytes'] and value['backend'] == policy['bootstrap_backend'],
         'distinct finite owned daemon/storage/backend')
    return value
