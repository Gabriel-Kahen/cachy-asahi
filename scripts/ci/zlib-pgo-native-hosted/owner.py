#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-bound CI owner; --execute admits actors only on a disposable native ARM runner."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LANE = 'scripts/ci/zlib-pgo-native-hosted'
MAP = LANE + '/source-map.json'
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-zlib-pgo.yml')
INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
PACKAGES = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
DOCKER = ('docker', '--host=unix:///var/run/docker.sock')
LABEL = 'org.cachy-asahi.pgo-hosted-owner'
CAPS = ('CHOWN', 'FOWNER', 'DAC_OVERRIDE', 'SETUID', 'SETGID')

def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read(path, limit=16 * 1024**2):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit
         and not any(p.is_symlink() for p in path.parents), 'bounded ordinary file: ' + str(path))
    return path.read_bytes()

def load(path):
    return json.loads(read(path))

def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def safe_path(path):
    path = Path(path).absolute()
    need(not path.is_symlink() and not any(p.is_symlink() for p in path.parents), 'symlink ancestry refused')
    return path

def fresh(path):
    path = safe_path(path)
    need(not path.exists(), 'fresh owned path required: ' + str(path))
    path.mkdir(mode=0o755)
    return path

def source(root, pin, *, allow_carriers=False):
    root = safe_path(root)
    body = read(root / MAP)
    need(re.fullmatch('[0-9a-f]{64}', pin or '') and sha(body) == pin, 'whole source-map pin')
    manifest = json.loads(body)
    need(manifest['schema'] == 1 and manifest['actual'] is None, 'source-only finite manifest')
    need(all(stat.S_IMODE((root / p).stat().st_mode) == 0o644 for p in (MAP, *ALIASES)), 'map/alias fixed modes')
    files = manifest['files']
    need(MAP not in files and not set(ALIASES) & set(files), 'nonrecursive map contract')
    for relative, row in files.items():
        p = Path(relative)
        need(not p.is_absolute() and '..' not in p.parts and p.as_posix() == relative, 'map path')
        data = read(root / p)
        need(len(data) == row['bytes'] and sha(data) == row['sha256']
             and stat.S_IMODE((root / p).stat().st_mode) == row['mode'], 'source drift: ' + relative)
    expected = set(files) | {MAP, *ALIASES}
    actual = set()
    actual_dirs = set()
    expected_dirs = {p.as_posix() for name in expected for p in Path(name).parents if p != Path('.')}
    for directory, dirs, names in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in tuple(dirs):
            p = base / name
            need(not p.is_symlink(), 'source directory symlink')
            if base == root and (name == '.git' or (allow_carriers and name in ('source-public14',))):
                dirs.remove(name)
            else:
                actual_dirs.add(p.relative_to(root).as_posix())
        for name in names:
            actual.add((base / name).relative_to(root).as_posix())
    need(actual_dirs == expected_dirs, 'source directory namespace differs')
    need(actual == expected, 'source namespace differs: ' + str(sorted(actual ^ expected))[:1000])
    template = read(root / LANE / 'workflow.yml.in').decode()
    rendered = template.replace('@OWNER_SHA@', files[LANE + '/owner.py']['sha256']).replace('@MAP_SHA@', pin).encode()
    need(all(read(root / p) == rendered for p in ALIASES), 'workflow aliases differ from reviewed template')
    reviewed = load(root / LANE / 'reviewed11.json')
    need(len(reviewed) == 11, 'original eleven-file contract')
    for path, row in reviewed.items():
        need(files[path]['sha256'] == row['sha256'] and files[path]['bytes'] == row['bytes']
             and files[path]['mode'] == int(row['mode'], 8), 'original packaging input changed')
    need(sha(read(root / 'scripts/ci/inputs.lock.json')) == INPUTS
         and sha(read(root / LANE / 'expected-packages.lock')) == PACKAGES, 'original341 pins')
    return manifest

def identity(source_sha, env=None):
    env = os.environ if env is None else env
    need(re.fullmatch('[0-9a-f]{40}', source_sha or ''), 'exact source SHA')
    need(env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') == source_sha,
         'product/workflow/input SHA mismatch')
    need(env.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
         and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_RUN_ATTEMPT') == '1'
         and re.fullmatch('[1-9][0-9]*', env.get('GITHUB_RUN_ID', '')), 'manual first-attempt identity')
    prefix = env['GITHUB_REPOSITORY'] + '/'
    ref = env.get('GITHUB_WORKFLOW_REF', '')
    need(any(ref.startswith(prefix + p + '@') and len(ref) > len(prefix + p + '@') for p in ALIASES),
         'registered workflow or exact dedicated alias required')
    run = env['GITHUB_RUN_ID']
    token = sha((source_sha + ':' + run + ':1').encode())[:24]
    return {'source_sha': source_sha, 'run_id': run, 'attempt': 1, 'workflow_ref': ref,
            'token': token, 'tag': 'cachy-asahi-pgo-hosted:' + token,
            'probe': 'pgo-hosted-lock-' + token, 'consumer': 'pgo-hosted-' + token}

def admitted(args):
    need(args.execute and platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
         and os.getuid() == os.geteuid() != 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
         and os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('RUNNER_ARCH') == 'ARM64',
         'explicit non-root GitHub native ARM owner required')
    need(not any(k.startswith(('DOCKER_', 'LD_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_')) for k in os.environ),
         'Docker/loader/private transport environment refused')
    work, cache, public, proof = (safe_path(p) for p in (args.work, args.cache, args.public, args.proof))
    temp = safe_path(os.environ['RUNNER_TEMP'])
    need(work == temp / 'pgo-hosted-work' and cache == temp / 'alarm-cache'
         and public == temp / 'pgo-hosted-public' and proof == temp / 'pgo-hosted-proof.json'
         and not temp.is_relative_to(ROOT) and not ROOT.is_relative_to(temp), 'fixed disjoint runner paths')
    need(cache.is_dir() and cache.stat().st_uid == os.getuid()
         and stat.S_IMODE(cache.stat().st_mode) == 0o700, 'existing private cache required')
    return binding(args)

_OWNED = None

def owned_child():
    global _OWNED
    if _OWNED is None:
        name='_pgo_host_owned_child'
        spec=importlib.util.spec_from_file_location(name,HERE/'owned_child.py')
        _OWNED=importlib.util.module_from_spec(spec);sys.modules[name]=_OWNED;spec.loader.exec_module(_OWNED)
    return _OWNED

def owned_subprocess_run(argv,**kwargs):
    """Only the pinned full-carrier blob proof may exceed ordinary stdout caps."""
    need('stdout_limit'not in kwargs,'global subprocess callers cannot select an owned stdout cap')
    if type(argv)in(list,tuple)and len(argv)==7 and list(argv[:1])==['/usr/bin/git'] and list(argv[2:6])==['-c','protocol.allow=never','cat-file','blob'] and type(os.environ.get('RUNNER_TEMP'))is str and os.environ['RUNNER_TEMP']:
        source='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
        carrier=safe_path(os.environ['RUNNER_TEMP'])/'pgo-hosted-retained'
        if argv[1]=='--git-dir='+str(carrier/'.git') and type(argv[6])is str and argv[6].startswith(source+':'):
            profile_raw=read(ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json')
            need(sha(profile_raw)=='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c','whole full-carrier proof profile')
            profile=json.loads(profile_raw);name=argv[6][len(source)+1:]
            need(profile['source']==source and len(profile['files'])==1154,'fixed whole-carrier blob proof source')
            if name in profile['files']:
                environment={'PATH':os.defpath,'LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0'}
                need(set(kwargs)=={'capture_output','timeout','env','check'} and kwargs['capture_output']is True
                     and kwargs['check']is False and type(kwargs['env'])is dict and kwargs['env']==environment,
                     'exact binary read-only captured Git proof contract required')
                size=profile['files'][name]['bytes']
                need(type(size)is int and 0<size<=128*1024**2,'original per-blob proof byte bound required')
                kwargs['stdout_limit']=size
    return owned_child().run(argv,**kwargs)

class Actors:
    """Owned-child utility retains direct wait status through retirement."""
    def __init__(self,directory,seconds):
        self.directory=fresh(directory);self.deadline=time.monotonic()+seconds;self.rows=[]

    def run(self,argv,log=None,timeout=60,*,allowed=(0,)):
        need(time.monotonic()<self.deadline,'owner deadline reached')
        argv=list(map(str,argv));log=Path(log)if log is not None else self.directory/(f'{len(self.rows):04d}.log')
        need(log.parent.is_dir()and not log.exists(),'fresh actor log')
        row=dict(argv=argv,log=str(log),status='FAIL',exit=None,natural_exit=False,group_absent=False)
        lifecycle={};self.rows.append(row)
        try:
            budget=min(timeout,self.deadline-time.monotonic());need(budget>0,'owner deadline reached')
            with log.open('wb')as stream:
                completed=owned_child().run(argv,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,
                    timeout=budget,lifecycle=lifecycle,allowed_uids={os.geteuid()})
            need(log.stat().st_size<=16*1024**2,'bounded actor log')
            need(completed.returncode==lifecycle.get('exit') and completed.returncode in allowed,'actor direct waitpid exit: '+str(completed.returncode))
            need(lifecycle.get('natural_exit')is True and lifecycle.get('group_absent')is True
                 and lifecycle.get('leader_held_until_group_inspection')is True
                 and lifecycle.get('exit_observed_via_waitpid')is True and lifecycle.get('ownership_lost')is False and lifecycle.get('forced_cleanup')is False
                 and lifecycle.get('retirement')=='REAPED','owned natural actor retirement')
            row['status']='PASS'
        finally:
            row.update({k:v for k,v in lifecycle.items()if k!='status'})
            row['owned_child']=lifecycle
            save(self.directory/'actors.json',self.rows)
        need(row['status']=='PASS','owned actor completion required')
        return read(log).decode().strip()

    def docker(self,*argv,**kwargs):return self.run([*DOCKER,*argv],**kwargs)

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def queried_ids(actor, kind, own):
    flag = ('ps', '-aq', '--no-trunc') if kind == 'containers' else ('image', 'ls', '-aq', '--no-trunc')
    return actor.docker(*flag, '--filter', 'label=' + LABEL + '=' + own['token']).split()

def absent_names(actor, own):
    for name in (own['probe'], own['consumer']):
        need(not actor.docker('ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'),
             'owned name already exists')

def require_image(row, own):
    need(row['Architecture'] == 'arm64' and row['Os'] == 'linux'
         and row['Config']['Labels'].get(LABEL) == own['token']
         and row['Config']['Labels'].get(LABEL + '.source') == own['source_sha']
         and row['Config']['Labels'].get(LABEL + '.run') == own['run_id'], 'owned native image identity')
    need(own['tag'] in row.get('RepoTags', []), 'fresh image tag binding')
    return row['Id']

def transport(args):
    """One complete retained-source transfer outside ROOT; original audit is mandatory."""
    _,own=admitted(args)
    work=Path(args.work);carrier=safe_path(args.carrier)
    expected=safe_path(os.environ['RUNNER_TEMP'])/'pgo-hosted-retained'
    need(carrier==expected and not os.path.lexists(carrier),'fresh fixed external retained DATA path required')
    need(not carrier.is_relative_to(ROOT) and not ROOT.is_relative_to(carrier),'retained DATA must be disjoint from closed source')
    need(carrier.parent.stat().st_uid==os.getuid() and not carrier.parent.stat().st_mode&0o022,
         'owned external retained DATA parent required')
    need(not(work/'input-transport-owner.json').exists(),'fresh one-shot input transport receipt required')
    profile_path=ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json'
    profile_raw=read(profile_path);profile=json.loads(profile_raw)
    need(sha(profile_raw)=='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
         and profile['source']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad' and len(profile['files'])==1154
         and sum(row['bytes']for row in profile['files'].values())==1046432165,
         'unchanged full retained carrier profile required')
    actor=Actors(work/'input-transport-actors',480)
    report=dict(status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',identity=own,manifest_sha256=args.manifest_sha256,
        role='RETAINED_INPUT_TRANSPORT_DATA',runtime_temp=str(expected.parent),source_root=str(ROOT),carrier_path=str(carrier),
        carrier_source=profile['source'],profile_sha256=sha(profile_raw),expected_carrier_files=1154,
        expected_carrier_bytes=sum(row['bytes']for row in profile['files'].values()),
        budget_seconds=480,retry=False,partial_data_retained=True,native='NOT_RUN',acceptance=False,
        authentication='ORIGINAL_COMPLETE_PREPARE_AND_NATIVE_SIGNATURE_AUDIT_STILL_REQUIRED')
    try:
        fresh(carrier).chmod(0o700)
        git=['git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true',
             '-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-c','protocol.https.allow=always']
        actor.run([*git,'init','--template=',str(carrier)],timeout=10)
        actor.run([*git,'-C',str(carrier),'-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60',
            'fetch','--depth=1','--no-tags','--no-recurse-submodules',
            'https://github.com/Gabriel-Kahen/cachy-asahi.git',profile['source']],timeout=400)
        fetched=actor.run([*git,'-C',str(carrier),'rev-parse','--verify','FETCH_HEAD'],timeout=10)
        need(fetched==profile['source'],'exact fetched retained commit required')
        actor.run([*git,'-C',str(carrier),'checkout','--detach',profile['source']],timeout=45)
        head=actor.run([*git,'-C',str(carrier),'rev-parse','--verify','HEAD'],timeout=10)
        need(head==profile['source'],'exact retained DATA checkout HEAD required')
        report.update(status='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY',carrier_head=head)
    except(Exception,KeyboardInterrupt)as error:
        report['error']=type(error).__name__+': '+str(error)[:2048]
        raise
    finally:
        # Preserve even incomplete DATA outside the sealed source; no retry or deletion.
        save(work/'input-transport-owner.json',report)

def bootstrap(args):
    _, own = admitted(args)
    work = Path(args.work)
    out = fresh(work / 'bootstrap')
    actor = Actors(work / 'bootstrap-actors', 2250)
    report = {'status': 'FAIL', 'identity': own, 'manifest_sha256': args.manifest_sha256}
    try:
        absent_names(actor, own)
        need(not queried_ids(actor, 'images', own) and not actor.docker('image', 'ls', '-q', own['tag']),
             'fresh owned image/tag required')
        native = module(ROOT / 'scripts/ci/native_arm.py', '_c01_native')
        sys.path.insert(0, str(ROOT / 'scripts/ci/setup6-retained-helpers'))
        seed = module(ROOT / 'scripts/ci/setup6-retained-helpers/prepare.py', '_c01_retained')
        carrier = safe_path(args.carrier)
        need(carrier == safe_path(os.environ['RUNNER_TEMP']) / 'pgo-hosted-retained', 'fixed retained carrier checkout')
        save(out / 'retained-preparation.json', seed.prepare(carrier, args.cache, 'native248',
             ROOT / 'scripts/ci/inputs.lock.json', actor.deadline, carrier / '.git'))
        def native_run(argv, log=None, timeout=1800):
            command = list(map(str, argv))
            if command[0] == 'docker':
                command = [*DOCKER, *command[1:]]
                if command[len(DOCKER)] == 'build':
                    command[len(DOCKER) + 1:len(DOCKER) + 1] = [
                        '--no-cache', '--tag', own['tag'], '--label', LABEL + '=' + own['token'],
                        '--label', LABEL + '.source=' + own['source_sha'], '--label', LABEL + '.run=' + own['run_id']]
                    save(out / 'build-started.json', {'command': command, 'identity': own})
                elif command[len(DOCKER)] == 'run':
                    command[len(DOCKER) + 1:len(DOCKER) + 1] = [
                        '--name', own['probe'], '--label', LABEL + '=' + own['token'],
                        '--cpus=1', '--memory=128m', '--pids-limit=32']
            value = actor.run(command, log, timeout)
            return value if log is None else None
        native.run = native_run
        shutil.copyfile(ROOT / 'scripts/ci/inputs.lock.json', out / 'inputs.lock.json')
        inputs = native.load_pinned(out / 'inputs.lock.json', INPUTS)
        native.probe(out)
        need(native.audit(inputs, Path(args.cache), out) == 248, 'original 248-package audit')
        image = native.build(inputs, Path(args.cache), out, {})
        need(read(out / 'packages.lock') == read(HERE / 'expected-packages.lock'), 'fresh exact341 inventory')
        details = json.loads(actor.docker('image', 'inspect', image))[0]
        need(require_image(details, own) == image, 'immutable bootstrap image')
        save(out / 'image-inspect.json', details)
        absent_names(actor, own)
        report.update(status='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP', image=image,
                      packages_sha256=PACKAGES, package_count=341)
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=type(error).__name__ + ': ' + str(error)[:2048])
        raise
    finally:
        save(work / 'bootstrap-owner.json', report)

def cleanup(args):
    work=Path(args.work)
    transport_receipt=work/'input-transport-owner.json'
    transport_files={'input-transport-owner.json','input-transport-actors',
        'input-transport.stdout','input-transport.stderr','input-transport.exit-code'}
    if transport_receipt.exists() and load(transport_receipt).get('status')=='FAIL_RETAINED_INPUT_TRANSPORT_DATA' and {p.name for p in work.iterdir()}<=transport_files:
        # This is DATA-only diagnosis, never a native process/image absence proof.
        need(args.execute,'explicit transport diagnostic request required')
        temp=safe_path(os.environ['RUNNER_TEMP'])
        need(safe_path(args.work)==temp/'pgo-hosted-work' and safe_path(args.cache)==temp/'alarm-cache'
             and safe_path(args.public)==temp/'pgo-hosted-public' and safe_path(args.proof)==temp/'pgo-hosted-proof.json'
             and not temp.is_relative_to(ROOT) and not ROOT.is_relative_to(temp),
             'fixed disjoint transport diagnostic paths required')
        _,own=binding(args)
        transferred=load(transport_receipt);carrier=temp/'pgo-hosted-retained'
        profile_raw=read(ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json')
        need(transferred['identity']==own and transferred['manifest_sha256']==args.manifest_sha256
             and transferred['role']=='RETAINED_INPUT_TRANSPORT_DATA'
             and transferred['runtime_temp']==str(temp) and transferred['source_root']==str(ROOT)
             and transferred['carrier_path']==str(carrier) and not carrier.is_relative_to(ROOT)
             and transferred['carrier_source']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
             and transferred['profile_sha256']==sha(profile_raw)=='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
             and transferred['expected_carrier_files']==1154 and transferred['expected_carrier_bytes']==1046432165
             and transferred['budget_seconds']==480 and transferred['retry']is False
             and transferred['partial_data_retained']is True and transferred['native']=='NOT_RUN'
             and transferred['acceptance']is False,'same-owner external failed transport DATA required')
        need(not(work/'cleanup-owner.json').exists(),'fresh transport-only diagnostic receipt required')
        save(work/'cleanup-owner.json',dict(status='INPUT_TRANSPORT_FAILED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY',
            identity=own,transport_receipt_sha256=sha(read(transport_receipt)),partial_carrier_path=str(carrier),
            role='RETAINED_INPUT_TRANSPORT_FAILURE_DIAGNOSTIC_DATA',partial_data_preserved=True,
            native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',acceptance=False,
            transport_process_scope='CONSULT_RETAINED_ACTOR_RECEIPTS_NO_LIVE_RECHECK_OR_NATIVE_ABSENCE_CREDIT'))
        return
    _, own = admitted(args)
    pair_cleanup(args, own)
    work = Path(args.work)
    actor = Actors(work / 'cleanup-actors', 160)
    report = {'status': 'FAIL', 'identity': own, 'removed_containers': [], 'removed_images': []}
    try:
        # Consumer removal and observed absence precede every image-removal operation.
        ids = queried_ids(actor, 'containers', own)
        if ids:
            rows = json.loads(actor.docker('inspect', *ids))
            need(all(r['Config']['Labels'].get(LABEL) == own['token']
                 and r['Name'].lstrip('/') in (own['consumer'], own['probe']) for r in rows), 'finite owned consumers only')
            for row in rows:
                actor.docker('rm', '-f', row['Id'])
                report['removed_containers'].append(row['Id'])
        need(not queried_ids(actor, 'containers', own), 'owned consumer absence')
        absent_names(actor, own)
        report['consumer_absence_verified'] = True
        keyhome = work / 'bootstrap/gpg'
        if keyhome.exists():
            actor.run(['gpgconf', '--homedir', str(keyhome), '--kill', 'gpg-agent'], timeout=15)
        images = sorted(set(queried_ids(actor, 'images', own)))
        need(len(images) <= 1, 'at most one fresh owned image')
        for image in images:
            row = json.loads(actor.docker('image', 'inspect', image))[0]
            need(require_image(row, own) == image and row['RepoTags'] == [own['tag']], 'owned cleanup image/tag')
            actor.docker('image', 'rm', '--no-prune', own['tag'], timeout=60)
            report['removed_images'].append(image)
        need(not queried_ids(actor, 'images', own) and not actor.docker('image', 'ls', '-q', own['tag']), 'owned image/tag absence')
        # Failed bootstrap may leave daemon-side work; never certify it by CLI absence alone.
        if (work / 'bootstrap/build-started.json').exists():
            need(load(work / 'bootstrap/bootstrap.json').get('status') == 'image-provisioned',
                 'unfinished bootstrap daemon work: cleanup cannot be admitted')
        report.update(status='PASS_ORDERED_OWNED_CONSUMER_THEN_IMAGE_ABSENCE', image_absence_verified=True)
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=type(error).__name__ + ': ' + str(error)[:2048])
        raise
    finally:
        save(work / 'cleanup-owner.json', report)


# New composition; producer and held-leader actor code above remains reused.
base_source = source

def pin(raw): return dict(bytes=len(raw), sha256=sha(raw))

def source(root, checksum, *, allow_carriers=False):
    manifest = base_source(root, checksum, allow_carriers=allow_carriers)
    pgo = Path(root)/'pgo-source'; body = read(pgo/'PGO-SOURCE.json')
    need(body == read(Path(root)/LANE/'pgo-source-pins.json') and sha(body) == '554b7401e32c4baa8396686576ca2745dd2e98502b4ced7e58646b3ef8ed3615', 'closed corrected whole39 PGO map')
    mapping=json.loads(body);need(mapping['actual'] is None and len(mapping['files'])==38,'PGO39 NULL source')
    need({p.relative_to(pgo).as_posix()for p in pgo.rglob('*')if not p.is_dir()}==set(mapping['files'])|{'PGO-SOURCE.json'},'closed nested PGO39')
    for name,row in mapping['files'].items():need(dict(**pin(read(pgo/name)),mode=stat.S_IMODE((pgo/name).stat().st_mode))==row,'held PGO source: '+name)
    return manifest

def git_source(root,manifest,source_sha):
    root=Path(root);head=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True,timeout=10).strip();need(head==source_sha,'published checkout HEAD')
    raw=subprocess.check_output(['git','-C',str(root),'ls-tree','-rz','--full-tree','HEAD'],timeout=15);entries={}
    for record in raw.split(b'\0'):
        if not record:continue
        meta,name=record.split(b'\t',1);mode,kind,digest=meta.decode().split();name=name.decode()
        need(kind=='blob'and name not in entries,'unique source Git blob');entries[name]=(mode,digest)
    expected=set(manifest['files'])|{MAP,*ALIASES};need(set(entries)==expected,'complete Git source/workflow namespace');joined={}
    for name in sorted(expected):
        body=read(root/name);mode='100755'if stat.S_IMODE((root/name).stat().st_mode)&0o111 else'100644';blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
        need(entries[name]==(mode,blob),'full Git byte/mode join: '+name);joined[name]=dict(mode=mode,blob=blob,**pin(body))
    return joined

def binding(args,*,first=False,feature_required=False):
    manifest=source(args.source_root,args.manifest_sha256,allow_carriers=not first);own=identity(args.source_sha)
    need(Path(args.source_root).resolve()==ROOT,'executing source root differs');joined=git_source(ROOT,manifest,args.source_sha)
    if not first:
        proof=load(args.proof);need(proof['status']=='PASS_PRESECRET_SOURCE_PROOF'and proof['identity']==own and proof['manifest_sha256']==args.manifest_sha256 and proof['git_files']==joined,'complete presecret Git/source proof')
    return manifest,own

def proof(args):
    manifest,own=binding(args,first=True);need(not Path(args.proof).exists(),'fresh presecret proof')
    save(args.proof,dict(status='PASS_PRESECRET_SOURCE_PROOF',identity=own,manifest_sha256=args.manifest_sha256,files=manifest['files'],git_files=git_source(ROOT,manifest,args.source_sha),pgo_source_files=39,native='NOT RUN',training='NOT RUN',hardware='NOT RUN'))
    fresh(args.work).chmod(0o700);fresh(safe_path(os.environ['RUNNER_TEMP'])/'pgo-hosted-home').chmod(0o700)

def producer_binding(args,actor,own,suffix=''):
    work=Path(args.work);base_raw=read(work/'bootstrap-owner.json');base=json.loads(base_raw)
    need(base['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP'and base['identity']==own and base['manifest_sha256']==args.manifest_sha256 and base['package_count']==341,'fresh same-source/run original341 receipt')
    lock=read(work/'bootstrap/packages.lock');need(lock==read(HERE/'expected-packages.lock')and sha(lock)==PACKAGES and len(lock.splitlines())==341,'genuine emitted full341 lock')
    need(read(work/'bootstrap/image-id').decode().strip()==base['image'],'producer emitted immutable image ID')
    rows=json.loads(actor.docker('image','inspect',base['image']));need(len(rows)==1 and require_image(rows[0],own)==base['image'],'live same owned producer image')
    need(load(work/'bootstrap/bootstrap.json')['status']=='image-provisioned','completed producer before consumer')
    save(work/('producer-inspect'+suffix+'.json'),rows[0]);report=dict(schema=1,status='PASS_FRESH_OWNED_RUNTIME_IMAGE_AND_FULL341_LOCK',identity=own,image=base['image'],packages=pin(lock),package_count=341,bootstrap_owner=pin(base_raw),inspection=pin(read(work/('producer-inspect'+suffix+'.json'))))
    save(work/('producer-binding'+suffix+'.json'),report);return report
def nested_pgo(output):
    nested=Path(output)/'artifacts/pgo-v1-evidence';receipt=load(nested/'receipt.json')
    need(receipt['schema']==1 and receipt['acceptance']is False and receipt['status']=='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY','complete real PGO receipt')
    leaves={p.relative_to(nested).as_posix():pin(read(p,64*1024**2))for p in nested.rglob('*')if not p.is_dir()and p!=nested/'receipt.json'}
    need(receipt['files']==leaves and len(leaves)<=4096 and sum(r['bytes']for r in leaves.values())<=128*1024**2,'whole nested PGO evidence closure')
    result=load(nested/'result.json')
    payload={'libz.a','minigzip','example','probe','strict-gzip','zlib.h','zconf.h','LICENSE'}
    need(type(result['outputs'])is list and len(result['outputs'])==2 and all(set(row)==payload for row in result['outputs']),'complete two optimized payload inventories')
    need(result['status']==receipt['status']and result['training_attempts']==1 and result['optimized_clean_builds']==2 and result['profile_use']=='SAME_SEALED_PROFILE_BOTH_BUILDS_NO_FALLBACK'and result['outputs'][0]==result['outputs'][1],'same sealed two-clean-build result')
    need(all(result['correctness'][k]==v for k,v in dict(encodes=48,cross_decodes=96,strict_rejections=6,probes=2).items()),'full candidate correctness counts')
    need(result['binding']['source_sha256']=='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'and result['binding']['isa']=='armv8-a/generic'and result['binding']['build_path']=='/tmp/build'and result['binding']['profile_path']=='/tmp/profile','exact source/ISA/profile path')
    validator=module(ROOT/'pgo-source/packages/experiments/cachy-asahi-zlib-pgo-v1/profile_seal.py','_hosted_pgo_seal');validator.verify(nested/'profiles',result['binding'],nested/'profile-seal.json',expected_sha256=result['profile_seal_sha256'])
    for attempt,expected in enumerate(result['outputs'],1):need({name:pin(read(nested/('optimized-'+str(attempt))/name))for name in expected}==expected,'actual optimized payload')
    return result

def validate_pair_records(outputs,image,own=None):
    need(len(outputs)==2,'two independent candidate builds');records=[load(Path(out)/'provenance.json')for out in outputs]
    need(len({r['clean_environment_id']for r in records})==2,'distinct genuine fresh consumers')
    for output,record in zip(outputs,records):
        need(record['status']=='built-package-static-pass'and record['mode']=='native'and record['network']=='none'and record['image']==record['image_id']==image and record['expected_packages_sha256']==PACKAGES,'actual image/full runtime lock/native offline provenance')
        prep=Path(output).parent
        need(record['recipe_inputs']==load(prep/'reviewed-inputs.json')and record['source_material']['plan_sha256']==sha(read(prep/'source-plan.json')),'reviewed PGO recipe/source plan')
        need(read(Path(output)/'expected-packages.lock')==read(HERE/'expected-packages.lock'),'whole actual consumed341 lock')
        result=nested_pgo(output);need(result['recipe_policy']==pin(read(ROOT/'pgo-source/packages/experiments/cachy-asahi-zlib-pgo-v1/recipe-policy.json')),'frozen PGO39 recipe policy')
    return records

def validate_observations(work,records,own):
    driver=module(HERE/'execute_builder.py','_hosted_pgo_driver')
    for number,record in enumerate(records,1):
        row=load(Path(work)/'build-observations'/(str(number)+'.json'))
        need(row['status']=='PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED'and row['observer_joined']is True and row['observer_kind']=='SYNCHRONOUS_OWNED_CHILD_PULSE'and row['python_socket_events']==[]and row['name']==record['clean_environment_id']and row['source_sha']==own['source_sha']and row['image']==record['image_id']and row['command']==record['command']and row['forwarded_command']==[*driver.DOCKER,*record['command'][1:]],'same-source actual consumer inspection')
        children=[row['consumer_child'],*row['inspection_children']]
        need(row['consumer_child']['exit']==0 and row['inspection_children']
             and any(c.get('exit')==0 for c in row['inspection_children'])
             and all(c.get('natural_exit')is True and c.get('group_absent')is True
                 and c.get('leader_held_until_group_inspection')is True
                 and c.get('exit_observed_via_waitpid')is True and c.get('ownership_lost')is False
                 and c.get('forced_cleanup')is False and c.get('retirement')=='REAPED' for c in children),
             'all synchronous consumer/inspection children directly reaped while owned')
        packages=row['package_inspections']
        need(packages and len(packages)==len(record['artifacts'])
             and {p['artifact']for p in packages}==set(record['artifacts']),
             'every produced package has one bounded owned or pure inspection')
        for item in packages:
            need(item['status']=='PASS' and item['original_unchanged']is True
                 and item['original']==item['original_after']
                 and item['reported_artifact']==item['artifact']
                 and item['reported_sha256']==item['original']['sha256']==record['artifacts'][item['artifact']],
                 'original package name/hash preserved through safe inspection')
            if item['parser_kind']=='OWNED_ZSTD_THEN_ORIGINAL_PURE_TAR':
                driver.require_retired(item['owned_child'])
                need(item['owned_child']['exit']==0 and item['stdout_limit']==512*1024**2
                     and item['timeout_seconds']==120 and item['parser_input_suffix']=='.tar'
                     and item['decoded_tar']['bytes']<=512*1024**2,'bounded directly observed zstd decode')
            else:need(item['parser_kind']=='PURE_PYTHON_PACKAGE_PARSE' and not item['artifact'].endswith('.zst'),'pure package branch only')
        driver.check_inspection(row['inspection'],row)

def cache_snapshot(path):
    return {p.relative_to(path).as_posix():dict(**pin(read(p)),mode=stat.S_IMODE(p.stat().st_mode))for p in sorted(Path(path).rglob('*'))if p.is_file()}

def pairs(args):
    _,own=admitted(args);work=Path(args.work);actor=Actors(work/'pairs-actors',3800)
    report=dict(status='FAIL',identity=own,manifest_sha256=args.manifest_sha256,hardware='NOT RUN',performance='NOT MEASURED',release='NOT_ADMITTED')
    try:
        producer=producer_binding(args,actor,own);report['image']=producer['image'];fresh(work/'build-observations');outputs=[]
        for number in(1,2):
            producer_binding(args,actor,own,'-'+str(number));prep=work/('attempt-'+str(number));output=prep/'native-build';outputs.append(output)
            save(work/('build-intent-'+str(number)+'.json'),dict(identity=own,image=producer['image'],preparation=str(prep),output=str(output),lock=pin(read(work/'bootstrap/packages.lock'))))
            command=[sys.executable,'-I','-B',str(HERE/'execute_builder.py'),'--execute','--feature-root',str(ROOT/'pgo-source'),'--source-sha',args.source_sha,'--preparation',str(prep),'--lock',str(work/'bootstrap/packages.lock'),'--producer-binding',str(work/('producer-binding-'+str(number)+'.json')),'--image',producer['image'],'--observation',str(work/'build-observations'/(str(number)+'.json'))]
            actor.run(command,timeout=1870)
        records=validate_pair_records(outputs,producer['image'],own);validate_observations(work,records,own)
        before=[load(work/('attempt-'+str(n))/'source-cache-before.json')for n in(1,2)];after=[load(work/('attempt-'+str(n))/'source-cache-after.json')for n in(1,2)]
        need(all(b==a for b,a in zip(before,after)),'independent offline source caches unchanged');results=[nested_pgo(out)for out in outputs]
        comparison=dict(payloads_equal=results[0]['outputs'][0]==results[1]['outputs'][0],profile_seals_equal=results[0]['profile_seal_sha256']==results[1]['profile_seal_sha256'],archives_equal=records[0]['artifacts']==records[1]['artifacts'],scope='DESCRIPTIVE_OUTER_RETRAINING_OBSERVATION_ONLY_NO_ARCHIVE_OR_PERFORMANCE_ADMISSION')
        save(work/'comparison.json',comparison)
        report.update(status='PASS_TWO_INDEPENDENT_NATIVE_PGO_BUILDS_PENDING_CLEANUP',clean_environment_ids=[r['clean_environment_id']for r in records],source_cache_unchanged=True,independent_payload_comparison=comparison,qualification='GENERIC_HOSTED_NATIVE_PGO_CONSTRUCTION_DATA_ONLY',installed='NOT RUN',generic16k_execution='NOT RUN')
    except(Exception,KeyboardInterrupt)as error:report.update(error=type(error).__name__+': '+str(error)[:2048]);raise
    finally:save(work/'pairs-owner.json',report)

def pair_cleanup(args,own):
    work=Path(args.work);actor=Actors(work/'pair-cleanup-actors',100);report=dict(status='FAIL',identity=own,removed=[],observed_absent=[])
    try:
        driver=module(HERE/'execute_builder.py','_cleanup_actual_pgo_driver');paths=sorted((work/'build-observations').glob('*.json'));need({p.name for p in paths}<={'1.json','2.json'},'two finite observations')
        for path in paths:
            row=load(path);name=row['name'];number=int(path.stem)
            need(re.fullmatch('cachy-asahi-[0-9a-f]{16}',name)and row['source_sha']==own['source_sha']and row['feature_root']==str(ROOT/'pgo-source')and row['output']==str(work/('attempt-'+str(number))/'native-build'),'same-run observed consumer')
            ids=actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$').split();need(len(ids)<=1,'one consumer')
            if ids:
                actual=json.loads(actor.docker('inspect',ids[0]));need(len(actual)==1,'one consumer inspection');driver.check_inspection(actual[0],row);actor.docker('rm','-f',ids[0]);report['removed'].append(ids[0])
            need(not actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$'),'consumer absent before producer');report['observed_absent'].append(name)
        report['status']='PASS_ACTUAL_BUILD_CONSUMERS_ABSENT_BEFORE_IMAGE'
    finally:save(work/'pair-cleanup-owner.json',report)

def retain(args):
    return module(HERE/'retention.py','_pgo_host_retention').retain(args,sys.modules[__name__])

def main():
    parser=argparse.ArgumentParser(description='Fresh owned original341 plus offline native PGO');parser.add_argument('mode',choices=('proof','transport','bootstrap','pairs','cleanup','retain'))
    for name in('source-root','proof','work','cache','public'):parser.add_argument('--'+name,type=Path,required=True)
    for name in('source-sha','manifest-sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--carrier',type=Path);parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    def cancel(*_):raise KeyboardInterrupt()
    for number in(signal.SIGTERM,signal.SIGINT):signal.signal(number,cancel)
    original_run=subprocess.run
    try:
        need(Path(args.source_root).resolve()==ROOT,'executing source root differs')
        source(args.source_root,args.manifest_sha256,allow_carriers=args.mode!='proof')
        # check_output delegates to subprocess.run, so Git/helper captures use the
        # same owned-child waitpid path. Pure source imports do not patch globals.
        subprocess.run=owned_subprocess_run
        return globals()[args.mode](args)or 0
    except(Exception,KeyboardInterrupt)as error:
        print(type(error).__name__+': '+str(error)[:2048],file=sys.stderr);return 1
    finally:subprocess.run=original_run

if __name__=='__main__':raise SystemExit(main())
