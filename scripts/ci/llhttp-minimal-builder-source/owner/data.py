# SPDX-License-Identifier: MIT
"""Finite Fish-only policy, namespace and domain joins; no actor on import."""
import hashlib
import importlib.util
import json
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
             and value['ref'] == source_ref == 'refs/heads/codex/llhttp-minimal206-authenticated-source-20261118-r8'
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
         and env.get('GITHUB_WORKFLOW_REF') == 'Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-llhttp-minimal-builder-source.yml@refs/heads/codex/llhttp-minimal206-authenticated-source-20261118-r8'
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
    return projected


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
