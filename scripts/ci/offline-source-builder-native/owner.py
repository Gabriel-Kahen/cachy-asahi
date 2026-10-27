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
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-offline-source-builder.yml')
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

def cleanup(args):
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


# SPDX-License-Identifier: MIT
"""Author-time additions to the reused C01 bootstrap owner."""

def feature_root():
    return safe_path(os.environ['RUNNER_TEMP']) / 'offline-source-feature-code'

def feature_files(root):
    root = safe_path(root); held_helpers(root); expected = load(HERE / 'required-feature-files.json')
    need(set(expected) == {'scripts/build/build_v2.py', 'scripts/build/compare_v2.py',
        'scripts/build/container-entry-v2.sh', 'scripts/build/source_materials.py',
        'scripts/maintenance/source_cache.py', 'scripts/release/source_delivery.py',
        'scripts/checks/package_checks.py'}, 'exact seven-file feature execution closure')
    for name, row in expected.items():
        raw = read(root / name)
        need(dict(bytes=len(raw), sha256=sha(raw), mode=stat.S_IMODE((root / name).stat().st_mode)) == row,
             'selected feature code differs: ' + name)
    return expected

def held_helpers(root):
    root = safe_path(root); expected = load(HERE / 'held-original-builder-files.json')
    need(set(expected) == {'scripts/build/build.py', 'scripts/build/compare.py', 'scripts/build/container-entry.sh'},
         'exact three unchanged original builder helpers')
    for name, row in expected.items():
        raw = read(root / name)
        need(dict(bytes=len(raw), sha256=sha(raw), mode=stat.S_IMODE((root / name).stat().st_mode)) == row,
             'original builder bytes changed: ' + name)
    return expected

def binding(args, *, first=False, feature_required=True):
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

def proof(args):
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

def feature_proof(args):
    _, own = binding(args); files = feature_files(feature_root())
    head = subprocess.check_output(['git', '-C', str(feature_root()), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    need(head == args.feature_code_sha, 'future canonical checkout SHA differs')
    target = Path(args.work) / 'feature-proof.json'; need(not target.exists(), 'fresh feature proof')
    save(target, dict(status='PASS_EXACT_FUTURE_CANONICAL_FEATURE_CODE', identity=own, observed_head=head,
        files=files, held_original_helpers=held_helpers(feature_root()), builder_interface='VERSIONED_V2',
        scope='SEVEN_V2_EXECUTION_FILES_AND_THREE_HELD_ORIGINALS_FROM_EXACT_CANONICAL_COMMIT', native='NOT RUN'))

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

def validate_pair_records(outputs, image):
    records = [load(Path(out) / 'provenance.json') for out in outputs]
    need(len(records) == 2 and len({r['clean_environment_id'] for r in records}) == 2,
         'two distinct actual fresh builder containers')
    for out, r in zip(outputs, records):
        need(r['status'] == 'built-package-static-pass' and r['mode'] == 'native'
             and r['network'] == 'none' and r['image'] == r['image_id'] == image
             and r['expected_packages_sha256'] == PACKAGES
             and r['recipe_inputs'] == load(HERE / 'recipe-inputs.json')
             and r['source_material']['plan_sha256'] == sha(read(HERE / 'source-plan.json')),
             'actual selected native builder provenance')
        mounts = [r['command'][i + 1] for i, v in enumerate(r['command']) if v == '--mount']
        expected = 'type=bind,src=' + str(Path(out) / 'source-material/srcdest') + ',dst=/offline-sources,readonly'
        need(len(mounts) == 5 and expected in mounts and not any('/source-cache' in m for m in mounts),
             'provenance has only readonly selected source mount and no cache bind')
    return records

def validate_observations(work, records, own):
    driver = module(HERE / 'execute_builder.py', '_retained_actual_inspection')
    for number, record in enumerate(records, 1):
        observation = load(Path(work) / 'build-observations' / (str(number) + '.json'))
        need(observation['status'] == 'PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED'
             and observation['observer_joined'] is True and observation['python_socket_events'] == []
             and observation['name'] == record['clean_environment_id']
             and observation['image'] == record['image_id']
             and observation['command'] == record['command']
             and observation['forwarded_command'] == [*driver.DOCKER, *record['command'][1:]]
             and observation['inspection']['State']['Running'] is True
             and observation['feature_code_sha'] == own['feature_code_sha'],
             'same actual pair container inspections and offline socket observations')
        driver.check_inspection(observation['inspection'], observation)

def pairs(args):
    _, own = admitted(args); work = Path(args.work); base = load(work / 'bootstrap-owner.json')
    need(base['status'] == 'PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP' and base['identity'] == own,
         'fresh same-job signed original341 environment')
    actor = Actors(work / 'pairs-actors', 1470)
    report = dict(status='FAIL', identity=own, manifest_sha256=args.manifest_sha256, image=base['image'],
        installed='NOT RUN', hardware='NOT RUN', performance='NOT MEASURED', release='NOT_ADMITTED')
    try:
        detail = json.loads(actor.docker('image', 'inspect', base['image']))[0]
        need(require_image(detail, own) == base['image'], 'same fresh owned immutable image')
        cache = seed_source_cache(feature_root(), work); before = cache_snapshot(cache)
        save(work / 'source-cache-before.json', before)
        outputs = []; observations = fresh(work / 'build-observations')
        for number in (1, 2):
            output = work / ('attempt-' + str(number)); outputs.append(output)
            command = [sys.executable, '-I', '-B', str(HERE / 'execute_builder.py'), '--execute',
                '--feature-root', str(feature_root()), '--feature-code-sha', args.feature_code_sha,
                '--recipe', str(ROOT / 'packages/experiments/cachy-asahi-zlib-baseline'),
                '--output', str(output), '--lock', str(HERE / 'expected-packages.lock'),
                '--reviewed', str(HERE / 'recipe-inputs.json'), '--plan', str(HERE / 'source-plan.json'),
                '--plan-sha256', sha(read(HERE / 'source-plan.json')), '--catalog', str(HERE / 'source-inputs.json'),
                '--cache', str(cache), '--image', base['image'], '--observation', str(observations / (str(number) + '.json'))]
            actor.run(command, timeout=660)
            after = cache_snapshot(cache); save(work / ('source-cache-after-' + str(number) + '.json'), after)
            need(after == before, 'source cache bytes/modes changed during actual build')
        records = validate_pair_records(outputs, base['image'])
        validate_observations(work, records, own)
        command = [sys.executable, '-I', '-B', str(feature_root() / 'scripts/build/compare_v2.py'),
                   *map(str, outputs), '--require-bytes']
        raw = actor.run(command, timeout=90); result = json.loads(raw); save(work / 'comparison.json', result)
        need(result['status'] == 'contents-reproduced' and not result['errors'] and result['packages']
             and all(p['bytes_equal'] and p['buildinfo_equal'] and p['pkginfo_equal'] for p in result['packages'].values()),
             'actual archives and metadata must reproduce byte-for-byte')
        report.update(status='PASS_REAL_NATIVE_OFFLINE_BUILDER_PAIR_PENDING_CLEANUP',
            clean_environment_ids=[r['clean_environment_id'] for r in records],
            source_cache_unchanged=True, actual_comparison=result, qualification='BUILD_TOOL_COMPONENT_ONLY')
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=type(error).__name__ + ': ' + str(error)[:2048]); raise
    finally:
        save(work / 'pairs-owner.json', report)

def pair_cleanup(args, own):
    work = Path(args.work); actor = Actors(work / 'pair-cleanup-actors', 90)
    report = dict(status='FAIL', identity=own, removed=[], observed_absent=[])
    try:
        driver = module(HERE / 'execute_builder.py', '_actual_builder_inspection')
        observations = sorted((work / 'build-observations').glob('*.json'))
        need({p.name for p in observations} <= {'1.json', '2.json'}, 'only the two declared build attempts')
        for path in observations:
            observation = load(path); name = observation['name']
            need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name)
                 and observation['feature_code_sha'] == own['feature_code_sha']
                 and Path(observation['output']) in (work / 'attempt-1', work / 'attempt-2')
                 and observation['feature_root'] == str(feature_root()), 'finite same-run build observation')
            ids = actor.docker('ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$').split()
            need(len(ids) <= 1, 'unique owned builder name')
            if ids:
                rows = json.loads(actor.docker('inspect', ids[0])); need(len(rows) == 1, 'single owned builder')
                driver.check_inspection(rows[0], observation)
                actor.docker('rm', '-f', ids[0]); report['removed'].append(ids[0])
            need(not actor.docker('ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'),
                 'actual clean builder absence before image retirement')
            report['observed_absent'].append(name)
        report['status'] = 'PASS_ACTUAL_BUILD_CONSUMERS_ABSENT_BEFORE_IMAGE'
    finally:
        save(work / 'pair-cleanup-owner.json', report)

native_cleanup = cleanup
def cleanup(args):
    if not (Path(args.work) / 'feature-proof.json').exists():
        _, own = binding(args, feature_required=False)
        need(not (Path(args.work) / 'bootstrap').exists() and not (Path(args.work) / 'build-observations').exists(),
             'missing feature proof cannot hide admitted native work')
        save(Path(args.work) / 'cleanup-owner.json', dict(status='NO_NATIVE_ACTORS_ADMITTED', identity=own,
             native='NOT RUN', reason='feature-code proof never completed'))
        return
    return native_cleanup(args)

def retain(args):
    manifest, own = binding(args, feature_required=False)
    work = Path(args.work); public = fresh(args.public); copied = {}; total = 0
    def copy(path, name):
        nonlocal total
        raw = read(path); total += len(raw); need(total <= 128 * 1024**2, 'bounded public tool-component evidence')
        target = public / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        copied[name] = dict(bytes=len(raw), sha256=sha(raw))
    copy(args.proof, 'presecret-source-proof.json')
    for name in [*manifest['files'], MAP, *ALIASES]: copy(ROOT / name, 'source/' + name)
    feature_ok = False; feature_error = None
    try:
        binding(args); feature_ok = True
        for name in feature_files(feature_root()): copy(feature_root() / name, 'selected-feature-code/' + name)
        for name in held_helpers(feature_root()): copy(feature_root() / name, 'held-original-builder-code/' + name)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        feature_error = type(error).__name__ + ': ' + str(error)[:2048]
    for name in ('feature-proof.json', 'bootstrap-owner.json', 'pairs-owner.json', 'pair-cleanup-owner.json',
        'cleanup-owner.json', 'comparison.json', 'source-cache-origin.json', 'source-cache-before.json',
        'source-cache-after-1.json', 'source-cache-after-2.json'):
        if (work / name).is_file(): copy(work / name, name)
    bootstrap_names = ('inputs.lock.json', 'runner.json', 'bootstrap.json', 'bootstrap.log', 'packages.lock',
        'image-id', 'image-inspect.json', 'signatures.json', 'rootfs-inventory.json', 'rootfs-hooks.json',
        'package-audit.json', 'cache-checksums.json', 'acquisition.json', 'key-import.log',
        'retained-preparation.json', 'build-started.json', 'context/Dockerfile', 'context/disabled-hooks.txt', 'context/pacman.conf')
    for name in bootstrap_names:
        if (work / 'bootstrap' / name).is_file(): copy(work / 'bootstrap' / name, 'bootstrap/' + name)
    for directory in ('bootstrap-actors', 'pairs-actors', 'pair-cleanup-actors', 'cleanup-actors',
                      'build-observations', 'attempt-1', 'attempt-2'):
        if not (work / directory).is_dir(): continue
        for path in sorted((work / directory).rglob('*')):
            need(not path.is_symlink(), 'public evidence alias refused')
            if path.is_file(): copy(path, directory + '/' + path.relative_to(work / directory).as_posix())
    receipt = dict(status='FAIL_OR_PARTIAL_TOOL_COMPONENT', identity=own, manifest_sha256=args.manifest_sha256,
        files=copied, native_component='NOT QUALIFIED', installed='NOT RUN', hardware='NOT RUN',
        generic16k_execution='NOT RUN', performance='NOT MEASURED', release='NOT_ADMITTED')
    if feature_error: receipt['feature_proof_error'] = feature_error
    try:
        need(feature_ok, 'selected feature-code proof required for native qualification')
        base, pair, clean, consumers = (load(work / n) for n in
            ('bootstrap-owner.json', 'pairs-owner.json', 'cleanup-owner.json', 'pair-cleanup-owner.json'))
        need(base['identity'] == pair['identity'] == clean['identity'] == consumers['identity'] == own,
             'same context source/canonical code/run identity')
        need(base['status'] == 'PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP'
             and pair['status'] == 'PASS_REAL_NATIVE_OFFLINE_BUILDER_PAIR_PENDING_CLEANUP'
             and clean['status'] == 'PASS_ORDERED_OWNED_CONSUMER_THEN_IMAGE_ABSENCE'
             and consumers['status'] == 'PASS_ACTUAL_BUILD_CONSUMERS_ABSENT_BEFORE_IMAGE'
             and set(consumers['observed_absent']) == set(pair['clean_environment_ids'])
             and clean['removed_images'] == [base['image']] and clean['image_absence_verified'] is True,
             'actual pair plus ordered matching owned cleanup required')
        for phase in ('bootstrap', 'pairs', 'pair-cleanup', 'cleanup'):
            rows = load(work / (phase + '-actors/actors.json'))
            need(rows and all(r['status'] == 'PASS' and r['natural_exit'] and r['group_absent']
                 and r['leader_held_until_group_inspection'] for r in rows), 'complete naturally supervised actors')
        records = validate_pair_records([work / 'attempt-1', work / 'attempt-2'], base['image'])
        validate_observations(work, records, own)
        before = load(work / 'source-cache-before.json')
        need(before == load(work / 'source-cache-after-1.json') == load(work / 'source-cache-after-2.json')
             == cache_snapshot(work / 'source-cache'), 'retained cache preservation join')
        receipt.update(status='PASS_NATIVE_OFFLINE_BUILD_TOOL_COMPONENT_ONLY', native_component='PAIR_AND_OFFLINE_SOURCE_BRIDGE',
            source_cache_unchanged=True, qualification='NO_INSTALLATION_M2_PERFORMANCE_OR_RELEASE_ACCEPTANCE')
    except (Exception, KeyboardInterrupt) as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)[:2048]
    save(public / 'receipt.json', receipt)
    return 0 if receipt['status'] == 'PASS_NATIVE_OFFLINE_BUILD_TOOL_COMPONENT_ONLY' else 1

def main():
    parser = argparse.ArgumentParser(description='Exact-source native offline build tool component')
    parser.add_argument('mode', choices=('proof', 'feature-proof', 'bootstrap', 'pairs', 'cleanup', 'retain'))
    for name in ('source-root', 'proof', 'work', 'cache', 'public'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha', 'feature-code-sha', 'manifest-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--carrier', type=Path); parser.add_argument('--execute', action='store_true'); args = parser.parse_args()
    def cancel(*_): raise KeyboardInterrupt()
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, cancel)
    try:
        function = feature_proof if args.mode == 'feature-proof' else globals()[args.mode]
        return function(args) or 0
    except (Exception, KeyboardInterrupt) as error:
        print(type(error).__name__ + ': ' + str(error)[:2048], file=sys.stderr); return 1

if __name__ == '__main__':
    raise SystemExit(main())
