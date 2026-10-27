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
LANE = 'scripts/ci/offline-source-builder-native'
MAP = LANE + '/source-map.json'
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-offline-build-batch-v2.yml')
INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
PACKAGES = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
DOCKER = ('docker', '--host=unix:///var/run/docker.sock')
LABEL = 'org.cachy-asahi.offline-source-builder-owner'
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
            if base == root and (name == '.git' or (allow_carriers and name in ('source-public14', 'source-feature-code'))):
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
            'token': token, 'tag': 'cachy-asahi-offline-source:' + token,
            'probe': 'offline-source-lock-' + token, 'consumer': 'offline-source-' + token}

def admitted(args):
    need(args.execute and platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
         and os.getuid() == os.geteuid() != 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
         and os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('RUNNER_ARCH') == 'ARM64',
         'explicit non-root GitHub native ARM owner required')
    need(not any(k.startswith(('DOCKER_', 'LD_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_')) for k in os.environ),
         'Docker/loader/private transport environment refused')
    work, cache, public, proof = (safe_path(p) for p in (args.work, args.cache, args.public, args.proof))
    temp = safe_path(os.environ['RUNNER_TEMP'])
    need(work == temp / 'offline-source-work' and cache == temp / 'alarm-cache'
         and public == temp / 'offline-source-public' and proof == temp / 'offline-source-proof.json'
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

def transport(args):
    """One complete retained-source transfer outside ROOT; original audit is mandatory."""
    _,own=admitted(args)
    work=Path(args.work);carrier=safe_path(args.carrier)
    expected=safe_path(os.environ['RUNNER_TEMP'])/'offline-source-retained'
    need(carrier==expected and not os.path.lexists(carrier),'fresh fixed external retained DATA path required')
    need(not carrier.is_relative_to(ROOT) and not ROOT.is_relative_to(carrier),'retained DATA must be disjoint from closed source')
    need(carrier.parent.stat().st_uid==os.getuid() and not carrier.parent.stat().st_mode&0o022,
         'owned external retained DATA parent required')
    need(not(work/'input-transport-owner.json').exists(),'fresh one-shot input transport receipt required')
    profile_path=ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json'
    profile_raw=read(profile_path);profile=json.loads(profile_raw)
    need(sha(profile_raw)=='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
         and profile['source']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad' and len(profile['files'])==1154,
         'unchanged full retained carrier profile required')
    actor=Actors(work/'input-transport-actors',480)
    report=dict(status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',identity=own,carrier_path=str(carrier),
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
        need(carrier == safe_path(os.environ['RUNNER_TEMP']) / 'offline-source-retained', 'fixed retained carrier checkout')
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

def producer_cleanup(args):
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

def feature_root():
    return safe_path(os.environ['RUNNER_TEMP']) / 'offline-source-feature-code'

def held_helpers(root):
    root = safe_path(root); expected = load(HERE / 'held-original-builder-files.json')
    need(set(expected) == {'scripts/build/build.py', 'scripts/build/compare.py', 'scripts/build/container-entry.sh'},
         'exact three unchanged original builder helpers')
    for name, row in expected.items():
        raw = read(root / name)
        need(dict(bytes=len(raw), sha256=sha(raw), mode=stat.S_IMODE((root / name).stat().st_mode)) == row,
             'original builder bytes changed: ' + name)
    return expected

def basis_binding(args, *, first=False, feature_required=True):
    manifest = source(args.source_root, args.manifest_sha256, allow_carriers=not first)
    own = identity(args.source_sha)
    need(re.fullmatch('[0-9a-f]{40}', args.feature_code_sha or '')
         and os.environ.get('FEATURE_CODE_SHA') == args.feature_code_sha, 'mandatory exact canonical feature SHA')
    own['feature_code_sha'] = args.feature_code_sha
    need(Path(args.source_root).resolve() == ROOT, 'executing source root differs')
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    need(head == args.source_sha, 'checkout HEAD mismatch')
    if not first:
        proof = load(args.proof)
        need(proof['status'] == 'PASS_PRESECRET_SOURCE_PROOF' and proof['identity'] == own
             and proof['manifest_sha256'] == args.manifest_sha256, 'presecret context proof required')
        if feature_required and args.mode not in ('feature-proof', 'cleanup'):
            feature = load(Path(args.work) / 'feature-proof.json')
            need(feature['status'] == 'PASS_EXACT_FUTURE_CANONICAL_FEATURE_CODE'
                 and feature['identity'] == own and feature['files'] == feature_files(feature_root()),
                 'presecret selected canonical feature proof required')
            selected = subprocess.check_output(['git', '-C', str(feature_root()), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
            need(selected == args.feature_code_sha, 'selected canonical code checkout changed')
    return manifest, own

def basis_proof(args):
    manifest, own = binding(args, first=True)
    need(not Path(args.proof).exists(), 'fresh presecret proof')
    plan = load(HERE / 'source-plan.json'); reviewed = load(HERE / 'recipe-inputs.json')
    need(plan['recipe_inputs'] == reviewed and plan['catalog_sha256'] == sha(read(HERE / 'source-inputs.json')),
         'reviewed source plan/catalog binding')
    recipe = ROOT / 'packages/experiments/cachy-asahi-zlib-baseline'
    need({p.name: sha(read(p)) for p in recipe.iterdir() if p.is_file()} == reviewed,
         'exact original C01 baseline recipe inputs')
    save(args.proof, dict(status='PASS_PRESECRET_SOURCE_PROOF', identity=own,
        manifest_sha256=args.manifest_sha256, files=manifest['files'], native='NOT RUN', installed='NOT RUN', hardware='NOT RUN'))
    fresh(args.work).chmod(0o700)
    fresh(safe_path(os.environ['RUNNER_TEMP']) / 'offline-source-home').chmod(0o700)

def cache_snapshot(path):
    return {p.relative_to(path).as_posix(): dict(bytes=p.stat().st_size, sha256=sha(read(p)),
            mode=stat.S_IMODE(p.stat().st_mode)) for p in sorted(Path(path).rglob('*')) if p.is_file()}

def seed_source_cache(feature, work):
    cache_api = module(Path(feature) / 'scripts/maintenance/source_cache.py', '_selected_source_cache')
    descriptor = HERE / 'source-inputs.json'; descriptor_sha = sha(read(descriptor))
    rows = cache_api.inputs(descriptor, descriptor_sha, ['zlib-1.3.2'], 2 * 1024**2)
    row = rows[0]; material = row['material']; raw = read(HERE / 'zlib-1.3.2.tar.gz')
    need((len(raw), sha(raw)) == (material['bytes'], material['sha256']), 'retained zlib object mismatch')
    path = Path(work) / 'source-cache'; cache_api.initialize(path)
    target = path / 'objects' / material['sha256']; target.write_bytes(raw); target.chmod(0o600)
    receipt = dict(schema_version=1, purpose='source-cache-receipt', inputs_sha256=descriptor_sha,
        source=row, object_path='objects/' + material['sha256'], legal_acceptance=False,
        source_completeness_accepted=False)
    target = path / 'receipts' / (descriptor_sha + '-' + material['id'] + '.json')
    target.write_bytes(cache_api.encoded(receipt)); target.chmod(0o600)
    verified = cache_api.run(path, descriptor, descriptor_sha, ['zlib-1.3.2'], offline=True)
    save(Path(work) / 'source-cache-origin.json', dict(status='IMPORTED_RETAINED_PINNED_BYTES_OFFLINE',
        retained_path=LANE + '/zlib-1.3.2.tar.gz', material=material, catalog_sha256=descriptor_sha,
        no_source_download=True, verified=verified, legal_acceptance=False))
    return path

FEATURES = {'scripts/build/build_v2.py','scripts/build/compare_v2.py','scripts/build/container-entry-v2.sh',
    'scripts/build/source_materials.py','scripts/checks/package_checks.py','scripts/maintenance/source_cache.py',
    'scripts/release/source_delivery.py','scripts/maintenance/build_batch_v2.py','scripts/maintenance/build_outputs_v2.py',
    'scripts/maintenance/build_batch.py','scripts/maintenance/rebuild_plan.py','scripts/release/check_source_pins.py','scripts/release/release.py'}


def feature_files(root):
    root=safe_path(root);held_helpers(root);expected=load(HERE/'required-feature-files.json')
    need(set(expected)==FEATURES,'exact thirteen-file batch feature execution closure')
    for name,row in expected.items():
        raw=read(root/name)
        need(dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE((root/name).stat().st_mode))==row,'selected batch feature changed: '+name)
    binding=load(HERE/'feature-binding.json')
    need(binding['files']==expected and binding['held_original_helpers']==held_helpers(root),'feature binding map differs')
    need(sha(read(HERE/'feature-git-proof.json'))==binding['proof_sha256'],'selected feature Git-file proof differs')
    return expected


def binding(args, *, first=False, feature_required=True):
    manifest,own=basis_binding(args,first=first,feature_required=feature_required)
    selected=load(HERE/'feature-binding.json')
    need(selected['selected_feature_code_sha']==args.feature_code_sha and selected['actual'] is None,'exact constructor-selected feature SHA required')
    return manifest,own


def proof(args):
    binding(args,first=True)
    graph=module(HERE/'batch_graph.py','_batch_presecret_graph')
    review=graph.graph_review(ROOT)
    need(not review['missing_rootfs_source_provenance'],'ROOTFS_SOURCE_PROVENANCE_INPUT_HOLD: '+','.join(r['name'] for r in review['missing_rootfs_source_provenance']))
    basis_proof(args)
    for variant,name in (('baseline','cachy-asahi-zlib-baseline'),('lto','cachy-asahi-zlib-lto')):
        expected=load(HERE/(variant+'-reviewed-inputs.json'))
        plan=load(HERE/(variant+'-source-plan.json'))
        actual={p.name:sha(read(p)) for p in (ROOT/'packages/experiments'/name).iterdir() if p.is_file()}
        need(actual==expected==plan['recipe_inputs'] and plan['catalog_sha256']==sha(read(HERE/'source-inputs.json')),'exact two-variant source plan required')
    save(Path(args.work)/'source-input-review.json',review)


def feature_proof(args):
    _,own=binding(args);files=feature_files(feature_root())
    head=subprocess.check_output(['git','-C',str(feature_root()),'rev-parse','HEAD'],text=True,timeout=10).strip()
    need(head==args.feature_code_sha,'selected feature checkout HEAD differs')
    target=Path(args.work)/'feature-proof.json';need(not target.exists(),'fresh batch feature proof')
    save(target,dict(status='PASS_EXACT_FUTURE_CANONICAL_FEATURE_CODE',identity=own,observed_head=head,files=files,
        held_original_helpers=held_helpers(feature_root()),builder_interface='offline-build-v2',
        scope='THIRTEEN_BATCH_EXECUTION_FILES_AND_THREE_HELD_ORIGINALS',native='NOT_RUN'))


def batches(args):
    consumer=module(HERE/'batch_consumer.py','_native_batch_consumer')
    consumer.run(args,__import__('types').SimpleNamespace(**globals()))
    return 0


def pair_cleanup(args,own):
    consumer=module(HERE/'batch_consumer.py','_native_batch_cleanup')
    return consumer.cleanup(args,__import__('types').SimpleNamespace(**globals()),own)


def cleanup(args):
    work=Path(args.work)
    transport_receipt=work/'input-transport-owner.json'
    native_paths=('bootstrap','bootstrap-actors','bootstrap-owner.json','batch-actors','batch-graph-actors',
        'batch-observation-actors','batch-cleanup-actors','cleanup-actors','batch-a','batch-b',
        'batches-owner.json','pair-cleanup-owner.json','batch-observations','batch-graph','batch-capture-commands',
        'candidate-manifests','installed-provider-runtime-proof.json','source-cache-before.json','source-cache-after.json')
    if transport_receipt.exists() and load(transport_receipt).get('status')=='FAIL_RETAINED_INPUT_TRANSPORT_DATA' and not any(os.path.lexists(work/name)for name in native_paths):
        _,own=binding(args,feature_required=False)
        transferred=load(transport_receipt)
        carrier=safe_path(os.environ['RUNNER_TEMP'])/'offline-source-retained'
        need(transferred['identity']==own and transferred['carrier_path']==str(carrier)
             and not carrier.is_relative_to(ROOT),'same-owner outside-source failed transport DATA required')
        need(not(work/'cleanup-owner.json').exists(),'fresh transport-only diagnostic receipt required')
        save(work/'cleanup-owner.json',dict(status='INPUT_TRANSPORT_FAILED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY',
            identity=own,transport_receipt_sha256=sha(read(transport_receipt)),partial_carrier_path=str(carrier),
            partial_data_preserved=True,native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',acceptance=False,
            transport_process_scope='CONSULT_RETAINED_ACTOR_RECEIPTS_NO_LIVE_RECHECK_OR_NATIVE_ABSENCE_CREDIT'))
        return
    if not(work/'feature-proof.json').exists():
        _,own=binding(args,feature_required=False)
        need(not any(os.path.lexists(work/name)for name in native_paths),'missing feature proof cannot hide native actors')
        save(work/'cleanup-owner.json',dict(status='NO_NATIVE_ACTORS_ADMITTED',identity=own,native='NOT_RUN'));return
    return producer_cleanup(args)


def retain(args):
    manifest,own=binding(args,feature_required=False)
    work=Path(args.work);public=fresh(args.public);files={};total=0
    def copy(path,name):
        nonlocal total
        raw=read(path);total+=len(raw)
        need(total<=128*1024**2 and len(files)<2048,'bounded complete batch public evidence')
        target=public/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        files[name]=dict(bytes=len(raw),sha256=sha(raw))
    copy(args.proof,'presecret-source-proof.json')
    for name in (*manifest['files'],MAP,*ALIASES):copy(ROOT/name,'source/'+name)
    feature_error=None
    try:
        binding(args)
        for name in feature_files(feature_root()):copy(feature_root()/name,'selected-feature-code/'+name)
        for name in held_helpers(feature_root()):copy(feature_root()/name,'held-original-builder-code/'+name)
    except (OSError,ValueError,KeyError,subprocess.SubprocessError)as error:feature_error=str(error)
    for path in sorted(work.glob('*.json')):copy(path,path.name)
    bootstrap_names=('inputs.lock.json','runner.json','bootstrap.json','bootstrap.log','packages.lock','image-id','image-inspect.json',
        'signatures.json','rootfs-inventory.json','rootfs-hooks.json','package-audit.json','cache-checksums.json','acquisition.json','key-import.log',
        'retained-preparation.json','build-started.json','context/Dockerfile','context/disabled-hooks.txt','context/pacman.conf')
    for name in bootstrap_names:
        if(work/'bootstrap'/name).is_file():copy(work/'bootstrap'/name,'bootstrap/'+name)
    directories=('input-transport-actors','bootstrap-actors','batch-actors','batch-graph-actors','batch-observation-actors','batch-cleanup-actors','cleanup-actors',
        'batch-observations','batch-graph','batch-capture-commands','batch-a','batch-b','candidate-manifests')
    for directory in directories:
        if not(work/directory).exists():continue
        for path in sorted((work/directory).rglob('*')):
            need(not path.is_symlink(),'batch public alias refused')
            if path.is_file():copy(path,directory+'/'+path.relative_to(work/directory).as_posix())
            else:need(path.is_dir(),'batch public special entry refused')
    receipt=dict(status='FAIL_OR_PARTIAL_NATIVE_BATCH_COMPONENT',identity=own,manifest_sha256=args.manifest_sha256,files=files,
        native_component='NOT_QUALIFIED',installed='NOT_RUN',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
    if feature_error:receipt['feature_proof_error']=feature_error
    try:
        need(feature_error is None,'complete selected feature proof required')
        base,batch,consumers,clean=(load(work/n)for n in('bootstrap-owner.json','batches-owner.json','pair-cleanup-owner.json','cleanup-owner.json'))
        need(all(r['identity']==own for r in(base,batch,consumers,clean)),'same source/feature/run identity required')
        need(base['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP' and batch['status']=='PASS_TWO_NATIVE_V2_BATCHES_REAL_FAILURE_RESUME_AND_OUTPUT_ADMISSION', 'complete finite native batch result required')
        transferred=load(work/'input-transport-owner.json')
        need(transferred['status']=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
             and transferred['identity']==own and transferred['carrier_source']==transferred['carrier_head']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
             and transferred['carrier_path']==str(safe_path(os.environ['RUNNER_TEMP'])/'offline-source-retained')
             and transferred['profile_sha256']==sha(read(ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json'))
             and transferred['expected_carrier_files']==1154 and transferred['budget_seconds']==480
             and transferred['retry']is False and transferred['acceptance']is False,
             'same-owner complete retained input transport DATA required')
        prepared=load(work/'bootstrap/retained-preparation.json')
        need(prepared['source']==prepared['carrier']['source']==transferred['carrier_source']
             and prepared['carrier']['files']==prepared['carrier']['blob_joins']==1154
             and prepared['mode']=='native248' and prepared['actual']is None,
             'unchanged whole retained Git/blob preparation required after DATA transfer')
        runtime=load(work/'installed-provider-runtime-proof.json')
        consumer=module(HERE/'batch_consumer.py','_retained_runtime_replay')
        consumer.verify_retained_runtime(args,__import__('types').SimpleNamespace(**globals()),own,runtime,public)
        need(runtime['status']=='PASS_OWNED_IMAGE_AND_INSTALLED341_RUNTIME_JOINS' and runtime['identity']==own
             and runtime['image']==base['image'] and runtime['package_count']==341
             and runtime['source_pin_acceptance']=='NOT_ESTABLISHED' and runtime['recipe_buildinfo_holds_unchanged']is True
             and batch['runtime_proof']['sha256']==sha(read(work/'installed-provider-runtime-proof.json')),
             'same-owner post-producer image/ALPM runtime join required')
        need(consumers['status']=='PASS_ACTUAL_BUILD_CONSUMERS_ABSENT_BEFORE_IMAGE' and set(consumers['observed_absent'])==set(batch['all_container_names']), 'all five consumer absences before image required')
        need(clean['status']=='PASS_ORDERED_OWNED_CONSUMER_THEN_IMAGE_ABSENCE' and clean['removed_images']==[base['image']] and clean['image_absence_verified'] is True,'exact producer retirement required')
        need(load(work/'source-cache-before.json')==load(work/'source-cache-after.json')==cache_snapshot(work/'source-cache'),'source cache unchanged')
        for phase in('input-transport','bootstrap','batch','batch-graph','batch-observation','batch-cleanup','cleanup'):
            rows=load(work/(phase+'-actors/actors.json'))
            need(rows and all(r['status']=='PASS' and r['natural_exit'] and r['group_absent'] and r['leader_held_until_group_inspection'] for r in rows),'all finite actor groups naturally retired')
            for row in rows:
                log=safe_path(row['log'])
                need(log.is_relative_to(work),'actor log must remain in the owned work tree')
                relative=log.relative_to(work).as_posix()
                need(relative in files and files[relative]==dict(bytes=len(read(public/relative)),sha256=sha(read(public/relative))),
                     'complete retained original actor log required')
        receipt.update(status='PASS_NATIVE_OFFLINE_BATCH_COMPONENT_PENDING_PHASE_LOG_SEAL',native_component='TWO_BATCHES_FOUR_SUCCESSES_ONE_CONTROLLED_FAILURE',
            baseline_archive_replay='ROOTFS_SOURCE_WITNESSES_AND_SELECTED_BINARY_PINS_ONLY',cleanup_scope='PASSIVE_RECEIPTS_AND_ORDERED_JOB_STEPS; NO_READER_LIVE_DAEMON_RECHECK')
    except (Exception,KeyboardInterrupt)as error:receipt['error']=type(error).__name__+': '+str(error)[:4096]
    save(public/'receipt.json',receipt)
    return 0 if receipt['status']=='PASS_NATIVE_OFFLINE_BATCH_COMPONENT_PENDING_PHASE_LOG_SEAL'else 1


def main():
    parser=argparse.ArgumentParser(description='Finite original341 native offline batch consumer')
    parser.add_argument('mode',choices=('proof','feature-proof','transport','bootstrap','batches','cleanup','retain'))
    for name in('source-root','proof','work','cache','public'):parser.add_argument('--'+name,type=Path,required=True)
    for name in('source-sha','feature-code-sha','manifest-sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--carrier',type=Path);parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    def cancel(*_):raise KeyboardInterrupt()
    for number in(signal.SIGTERM,signal.SIGINT):signal.signal(number,cancel)
    try:return(feature_proof if args.mode=='feature-proof'else globals()[args.mode])(args)or 0
    except(Exception,KeyboardInterrupt)as error:print(type(error).__name__+': '+str(error)[:4096],file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
