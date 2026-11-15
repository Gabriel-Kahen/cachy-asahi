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
LANE = 'scripts/ci/c01-native-paired-runtime'
MAP = LANE + '/source-map.json'
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-c01-paired-runtime.yml')
INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
PACKAGES = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
DOCKER = ('docker', '--host=unix:///var/run/docker.sock')
LABEL = 'org.cachy-asahi.c01-runtime-owner'
CAPS = ('CHOWN', 'FOWNER', 'DAC_OVERRIDE', 'SETUID', 'SETGID')
PHASES = [('install-baseline', {'baseline': 1}), ('coexist', {'baseline': 1, 'lto': 1}),
          ('upgrade', {'baseline': 2, 'lto': 2}), ('repeat', {'baseline': 2, 'lto': 2}),
          ('remove-baseline', {'lto': 2}), ('remove-lto', {}),
          ('reinstall', {'baseline': 2, 'lto': 2}), ('final-remove', {})]


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
            if base == root and (name == '.git' or (allow_carriers and name == 'source-public14')):
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
            'token': token, 'tag': 'cachy-asahi-c01-runtime:' + token,
            'probe': 'c01-runtime-lock-' + token, 'consumer': 'c01-runtime-' + token}

def binding(args, *, first=False):
    manifest = source(args.source_root, args.manifest_sha256, allow_carriers=not first)
    own = identity(args.source_sha)
    need(Path(args.source_root).resolve() == ROOT, 'executing source root differs')
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    need(head == args.source_sha, 'checkout HEAD mismatch')
    if not first:
        proof = load(args.proof)
        need(proof['status'] == 'PASS_PRESECRET_SOURCE_PROOF' and proof['identity'] == own
             and proof['manifest_sha256'] == args.manifest_sha256, 'presecret source proof required')
    return manifest, own

def admitted(args):
    need(args.execute and platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
         and os.getuid() == os.geteuid() != 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
         and os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('RUNNER_ARCH') == 'ARM64',
         'explicit non-root GitHub native ARM owner required')
    need(not any(k.startswith(('DOCKER_', 'LD_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_')) for k in os.environ),
         'Docker/loader/private transport environment refused')
    work, cache, public, proof = (safe_path(p) for p in (args.work, args.cache, args.public, args.proof))
    temp = safe_path(os.environ['RUNNER_TEMP'])
    need(work == temp / 'c01-runtime-work' and cache == temp / 'alarm-cache'
         and public == temp / 'c01-runtime-public' and proof == temp / 'c01-runtime-proof.json'
         and not temp.is_relative_to(ROOT) and not ROOT.is_relative_to(temp), 'fixed disjoint runner paths')
    need(cache.is_dir() and cache.stat().st_uid == os.getuid()
         and stat.S_IMODE(cache.stat().st_mode) == 0o700, 'existing private cache required')
    return binding(args)

def group_members(pgid, leader):
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) == leader:
            continue
        try:
            fields = (entry / 'stat').read_text().rpartition(') ')[2].split()
        except FileNotFoundError:
            continue
        if len(fields) >= 3 and int(fields[2]) == pgid:
            members.append(int(entry.name))
    return members

class Actors:
    """Bound local child groups; preserve logs and natural-exit facts."""
    def __init__(self, directory, seconds):
        self.directory = fresh(directory)
        self.deadline = time.monotonic() + seconds
        self.rows = []

    def run(self, argv, log=None, timeout=60, *, allowed=(0,)):
        need(time.monotonic() < self.deadline, 'owner deadline reached')
        argv = list(map(str, argv))
        log = Path(log) if log is not None else self.directory / (f'{len(self.rows):04d}.log')
        need(log.parent.is_dir() and not log.exists(), 'fresh actor log')
        row = {'argv': argv, 'log': str(log), 'status': 'FAIL', 'exit': None,
               'natural_exit': False, 'group_absent': False}
        self.rows.append(row)
        process = None
        try:
            with log.open('wb') as stream:
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                row['pid'] = process.pid
                end = min(self.deadline, time.monotonic() + timeout)
                # WNOWAIT retains the leader PID until owned group inspection/kill.
                while True:
                    state = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if state is not None:
                        row['natural_exit'] = True
                        row['exit'] = state.si_status if state.si_code == os.CLD_EXITED else -state.si_status
                        break
                    if time.monotonic() >= end:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    time.sleep(.05)
            need(log.stat().st_size <= 16 * 1024**2, 'bounded actor log')
            need(row['exit'] in allowed, 'actor exit: ' + str(row['exit']))
            row['status'] = 'PASS'
        finally:
            if process is not None:
                # Never reap first and then signal a possibly reused process-group ID.
                members = group_members(process.pid, process.pid)
                if not row['natural_exit'] or members:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    row['status'] = 'FAIL'
                    for _ in range(40):
                        if not group_members(process.pid, process.pid):
                            break
                        time.sleep(.05)
                row['leader_held_until_group_inspection'] = True
                row['group_absent'] = not group_members(process.pid, process.pid)
                row['exit'] = process.wait(timeout=10)
            save(self.directory / 'actors.json', self.rows)
        need(row['status'] == 'PASS' and row['natural_exit'] and row['group_absent'], 'natural actor group absence required')
        return read(log).decode().strip()

    def docker(self, *argv, **kwargs):
        return self.run([*DOCKER, *argv], **kwargs)

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

def proof(args):
    manifest, own = binding(args, first=True)
    need(not Path(args.proof).exists(), 'fresh presecret proof')
    save(args.proof, {'status': 'PASS_PRESECRET_SOURCE_PROOF', 'identity': own,
                      'manifest_sha256': args.manifest_sha256, 'files': manifest['files'],
                      'native': 'NOT RUN', 'installed': 'NOT RUN', 'hardware': 'NOT RUN'})
    fresh(args.work)
    home = safe_path(os.environ['RUNNER_TEMP']) / 'c01-runtime-home'
    fresh(home).chmod(0o700)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('proof=passed\n')

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
        need(carrier == safe_path(os.environ['RUNNER_TEMP']) / 'c01-runtime-retained', 'fixed retained carrier checkout')
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

def check_consumer(row, own, image, context, output):
    host = row['HostConfig']
    need(row['Name'] == '/' + own['consumer'] and row['Config']['Labels'].get(LABEL) == own['token']
         and row['Image'] == image and row['Config']['User'] == '0:0'
         and row['State']['Status'] == 'exited' and row['State']['ExitCode'] == 0
         and row['State']['OOMKilled'] is False, 'owned successful consumer identity')
    need(host['NetworkMode'] == 'none' and host['IpcMode'] == 'private' and host['PidMode'] == ''
         and host['Privileged'] is False and host['NanoCpus'] == 2_000_000_000
         and host['Memory'] == host['MemorySwap'] == 4 * 1024**3 and host['PidsLimit'] == 256
         and set(host['CapDrop']) == {'ALL'} and set(host['CapAdd']) == {'CAP_' + cap for cap in CAPS}
         and host['SecurityOpt'] == ['no-new-privileges'] and not host.get('Devices')
         and not host.get('DeviceRequests') and not host.get('VolumesFrom'), 'consumer isolation/limits')
    mounts = {(m['Destination'], m['Source'], m['RW'], m['Type']) for m in row['Mounts'] if m['Type'] == 'bind'}
    need(mounts == {('/inputs', str(context), False, 'bind'), ('/out', str(output), True, 'bind')}
         and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in row['Mounts'])
         and len(row['Mounts']) in (2, 3) and set(host['Tmpfs']) == {'/tmp'}
         and set(host['Tmpfs']['/tmp'].split(',')) == {'rw', 'exec', 'nosuid', 'nodev', 'size=2g', 'mode=1777'}
         and host['CgroupnsMode'] == 'private', 'consumer exact private mounts')

def cleanup(args):
    _, own = admitted(args)
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


def measurement_argv(own,image,output,manifest):
    return [*DOCKER,'run','--pull=never','--name',own['consumer'],'--label',LABEL+'='+own['token'],
        '--platform=linux/arm64','--network=none','--ipc=private','--cgroupns=private','--user=0:0',
        '--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256','--security-opt=no-new-privileges','--cap-drop=ALL',
        *['--cap-add='+c for c in CAPS],'--tmpfs=/tmp:rw,exec,nosuid,nodev,size=2g,mode=1777',
        '--mount','type=bind,src='+str(ROOT)+',dst=/inputs,readonly','--mount','type=bind,src='+str(output)+',dst=/out',
        '--env=CACHY_ASAHI_DISPOSABLE_BENCHMARK=1','--entrypoint=/usr/bin/python3',image,'-I','-B',
        '/inputs/'+LANE+'/guest.py','run','--source-sha',own['source_sha'],'--run-id',own['run_id'],'--manifest-sha256',manifest]


def validate_measurement(output,own):
    output=Path(output);report=load(output/'result.json')
    need(report['status']=='COMPLETE_GENERIC_HOSTED_ARM_PAIRED_EXPERIMENT' and report['source_sha']==own['source_sha']
         and report['run_id']==own['run_id'] and report['measurement_scope']=='GENERIC_HOSTED_ARM_C01_INSTALLABLE'
         and report['package_removal']=='PASS_EXACT341_RESTORED' and report['completed_slots']==18 and report['measured_slots']==12
         and report['machine']=='aarch64' and report['zombie_absence']=='NOT_ESTABLISHED'
         and report['hardware']==report['generic16k_execution']==report['optimization_acceptance']=='NOT RUN','complete generic experiment and original341 restoration')
    for name in ('initial-inventory.lock','final-inventory.lock'):
        need(read(output/name)==read(HERE/'expected-packages.lock'),'exact original341 before/after')
    session=load(output/'session/session.json')
    need(session['scope']=='GENERIC_HOSTED_ARM_C01_INSTALLABLE' and session['status']=='COMPLETE_GENERIC_HOSTED_ARM_C01_INSTALLABLE_MEASUREMENT_PENDING_REVIEW'
         and len(session['completed'])==18 and session['warmups_excluded'] is True,'complete paired schedule')
    need(session['hardware_validation']==session['optimization_acceptance']=='NOT RUN','no hardware/optimization admission')
    phases=[r['phase'] for r in session['completed']]
    need(phases==['correctness']*2+['warmup']*4+['measured']*12,'excluded correctness/warmup order')
    for row in session['completed']:
        r=row['workload'];need(r['status']=='PASS' and r['material_profile']==session['scope'] and r['iterations']==4
            and len(r['checks'])==4 and len(r['phase_timings'])==8 and r['payload_bytes']==16*1024**2,'every complete fixed workload')
        need(all(c['decoded_sha256']==r['payload_sha256'] and c['independent_python_decode']=='PASS' for c in r['checks']),'all roundtrip output checks')
        for timing in r['phase_timings']:
            need(timing['returncode']==0 and timing['monotonic_end_ns']-timing['monotonic_start_ns']==timing['elapsed_ns']
                 and timing['elapsed_ns']>0 and timing['waited_children_user_seconds']>=0 and timing['waited_children_system_seconds']>=0,'raw codec wall/CPU observations')
    comparison=load(output/'session/comparison.json');need(comparison['optimization_acceptance']=='NOT RUN','comparison is preliminary only')
    return report


def measure(args):
    _,own=admitted(args);work=Path(args.work);base=load(work/'bootstrap-owner.json')
    need(base['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP' and base['identity']==own,'fresh same-job original341 base')
    actor=Actors(work/'measurement-actors',1160);report=dict(status='FAIL',identity=own,manifest_sha256=args.manifest_sha256,image=base['image'],performance='NOT MEASURED',optimization_acceptance='NOT RUN',hardware='NOT RUN')
    try:
        absent_names(actor,own);detail=json.loads(actor.docker('image','inspect',base['image']))[0];need(require_image(detail,own)==base['image'],'fresh owned image')
        output=fresh(work/'measurement-output');argv=measurement_argv(own,base['image'],output,args.manifest_sha256)
        save(work/'consumer-command.json',dict(argv=argv,source_sha=own['source_sha'],manifest_sha256=args.manifest_sha256))
        actor.run(argv,timeout=1100)
        detail=json.loads(actor.docker('inspect',own['consumer']))[0];save(work/'consumer-inspect.json',detail)
        check_consumer(detail,own,base['image'],ROOT,output)
        validate_measurement(output,own)
        report.update(status='COMPLETE_GENERIC_HOSTED_ARM_MEASUREMENT_AWAITING_ORDERED_CLEANUP',performance='RAW_EXPERIMENT_DATA_PENDING_REVIEW')
    except (Exception,KeyboardInterrupt) as error:report.update(error=type(error).__name__+': '+str(error)[:2048]);raise
    finally:save(work/'measurement-owner.json',report)


def retain(args):
    manifest,own=binding(args);work=Path(args.work);public=fresh(args.public);copied={};excluded=[];total=0
    def copy(path,name):
        nonlocal total
        raw=read(path);total+=len(raw);need(total<=128*1024**2,'bounded public experiment evidence')
        target=public/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        copied[name]=dict(bytes=len(raw),sha256=sha(raw))
    copy(args.proof,'presecret-source-proof.json')
    for name in [*manifest['files'],MAP,*ALIASES]:copy(ROOT/name,'source/'+name)
    for name in ('bootstrap-owner.json','measurement-owner.json','cleanup-owner.json','consumer-command.json','consumer-inspect.json'):
        if(work/name).is_file():copy(work/name,name)
    names=('inputs.lock.json','runner.json','bootstrap.json','bootstrap.log','packages.lock','image-id','image-inspect.json','signatures.json','rootfs-inventory.json','rootfs-hooks.json','package-audit.json','cache-checksums.json','acquisition.json','key-import.log','retained-preparation.json','build-started.json','context/Dockerfile','context/disabled-hooks.txt','context/pacman.conf')
    for name in names:
        if(work/'bootstrap'/name).is_file():copy(work/'bootstrap'/name,'bootstrap/'+name)
    for directory in ('bootstrap-actors','measurement-actors','cleanup-actors','measurement-output'):
        path=work/directory
        if not path.is_dir():continue
        for p in sorted(path.rglob('*')):
            need(not p.is_symlink(),'public evidence alias refused')
            if not p.is_file():continue
            relative=p.relative_to(path)
            if directory=='measurement-output' and p.name in ('payload.bin','encoded.gz','decoded.bin'):
                excluded.append(dict(path=directory+'/'+relative.as_posix(),bytes=p.stat().st_size,reason='partial disposable work intermediate; fixed payload derivation pinned, never completeness credit'))
                continue
            copy(p,directory+'/'+relative.as_posix())
    receipt=dict(status='FAIL_OR_PARTIAL_EXPERIMENT_DATA',identity=own,manifest_sha256=args.manifest_sha256,files=copied,excluded_work_intermediates=excluded,measurement_scope='GENERIC_HOSTED_ARM_C01_INSTALLABLE',hardware='NOT RUN',generic16k_execution='NOT RUN',optimization_acceptance='NOT RUN',performance_acceptance='NOT GRANTED',release='NOT_ADMITTED')
    try:
        b,m,c=(load(work/name) for name in ('bootstrap-owner.json','measurement-owner.json','cleanup-owner.json'))
        need(b['identity']==m['identity']==c['identity']==own and b['image']==m['image'],'same source/run/owned image')
        need(b['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP' and m['status']=='COMPLETE_GENERIC_HOSTED_ARM_MEASUREMENT_AWAITING_ORDERED_CLEANUP'
             and c['status']=='PASS_ORDERED_OWNED_CONSUMER_THEN_IMAGE_ABSENCE','completed environment/experiment/ordered cleanup')
        inspected=load(work/'consumer-inspect.json')
        need(c['removed_containers']==[inspected['Id']] and c['removed_images']==[b['image']]
             and c['consumer_absence_verified'] is True and c['image_absence_verified'] is True,'same final owned consumer/image retirement')
        for phase in ('bootstrap','measurement','cleanup'):
            rows=load(work/(phase+'-actors/actors.json'))
            need(rows and all(r['status']=='PASS' and r['natural_exit'] and r['group_absent'] and r['leader_held_until_group_inspection'] for r in rows),'complete supervised host actor records')
        report=validate_measurement(work/'measurement-output',own)
        receipt.update(status='COMPLETE_GENERIC_HOSTED_ARM_EXPERIMENT_DATA_PENDING_REVIEW',preliminary_result=report['preliminary_result'],zombie_absence='NOT_ESTABLISHED',cleanup='SOURCE_BOUND_FINAL_OWNED_CONSUMER_THEN_IMAGE_RECEIPTS')
    except (Exception,KeyboardInterrupt) as error:receipt['error']=type(error).__name__+': '+str(error)[:2048]
    save(public/'receipt.json',receipt)
    return 0 if receipt['status']=='COMPLETE_GENERIC_HOSTED_ARM_EXPERIMENT_DATA_PENDING_REVIEW' else 1


def main():
    p=argparse.ArgumentParser(description='Fixed generic hosted ARM paired runtime experiment owner')
    p.add_argument('mode',choices=('proof','bootstrap','measure','cleanup','retain'))
    for name in ('source-root','proof','work','cache','public'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-sha',required=True);p.add_argument('--manifest-sha256',required=True);p.add_argument('--carrier',type=Path);p.add_argument('--execute',action='store_true');a=p.parse_args()
    def cancel(*_):raise KeyboardInterrupt()
    for s in (signal.SIGTERM,signal.SIGINT):signal.signal(s,cancel)
    try:return globals()[a.mode](a) or 0
    except (Exception,KeyboardInterrupt) as error:print(type(error).__name__+': '+str(error)[:2048],file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
