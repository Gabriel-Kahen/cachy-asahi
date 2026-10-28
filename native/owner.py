# SPDX-License-Identifier: MIT
"""Future source-bound native owner. No retained actor imports before admission."""
import argparse
import hashlib
import importlib.util
import io
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
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ALIASES, LABEL, LOCK_SHA, MAP, encoded, execution_selection, load, need, pin, read, save, verify_source

DOCKER = ('/usr/bin/docker', '--host=unix:///var/run/docker.sock')
CAPS = ('CHOWN', 'FOWNER', 'DAC_OVERRIDE', 'SETUID', 'SETGID')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def admission(root, args, env):
    # NULL package/source selectors and unresolved acquisitions fail before actors.
    policy = execution_selection(root)
    verify_source(root, args.map_sha256)
    need(args.execute and platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
         and os.getuid() == os.geteuid() != 0, 'explicit ordinary native ARM owner')
    need(re.fullmatch('[0-9a-f]{40}', args.source_sha or '') and re.fullmatch('[1-9][0-9]*', args.run_id or '')
         and type(args.ref) is str and args.ref.startswith('refs/heads/codex/'), 'Root actual source/ref/run binding required')
    need(env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') == args.source_sha
         and env.get('GITHUB_REF') == args.ref and env.get('GITHUB_RUN_ID') == args.run_id
         and env.get('GITHUB_RUN_ATTEMPT') == '1' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
         and env.get('GITHUB_WORKFLOW_REF') in {'Gabriel-Kahen/cachy-asahi/' + n + '@' + args.ref for n in ALIASES}
         and env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ARCH') == 'ARM64'
         and env.get('RUNNER_OS') == 'Linux', 'same-source first-attempt dedicated workflow')
    need(not any(k.startswith(('DOCKER_', 'LD_', 'GIT_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_')) for k in env), 'no credentials/loader/daemon overrides')
    temp = Path(env['RUNNER_TEMP']).absolute()
    need(args.work == temp / 'support-native-work' and args.cache == temp / 'alarm-cache'
         and args.carrier == temp / 'pgo-hosted-retained' and args.public == temp / 'support-native-public'
         and not temp.is_relative_to(root) and not root.is_relative_to(temp), 'fixed disjoint owned paths')
    need(not any(p.is_symlink() for p in (temp, *temp.parents)), 'ordinary runner paths')
    binding = dict(source_sha=args.source_sha, ref=args.ref, run_id=args.run_id, attempt=1)
    token = hashlib.sha256((args.source_sha + ':' + args.ref + ':' + args.run_id).encode()).hexdigest()[:24]
    return policy, binding, token


def git_proof(root, actor, binding):
    need((root / '.git').is_dir() and not (root / '.git').is_symlink(), 'ordinary publication Git directory')
    git = ['/usr/bin/git', '--no-replace-objects', '--git-dir=' + str(root / '.git'), '--work-tree=' + str(root),
           '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false']
    need(actor.run([*git, 'rev-parse', 'HEAD'], timeout=15) == binding['source_sha'], 'actual published source HEAD')
    joined = {}
    for row in actor.run([*git, 'ls-tree', '-rz', '--full-tree', binding['source_sha']], timeout=30).split('\0'):
        if not row:
            continue
        metadata, name = row.split('\t', 1)
        mode, kind, blob = metadata.split()
        raw = read(root / name)
        need(kind == 'blob' and mode == '100644' and blob == hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'whole source Git byte/mode join')
        joined[name] = dict(mode=mode, blob=blob, **pin(raw))
    manifest = load(root / MAP)
    need(set(joined) == set(manifest['files']) | {MAP, *ALIASES}, 'whole Git source namespace')
    return dict(binding=binding, files=joined)


def image_identity(row, binding, token):
    labels = row['Config']['Labels']
    need(row['Architecture'] == 'arm64' and row['Os'] == 'linux'
         and labels.get(LABEL) == token and labels.get(LABEL + '.source') == binding['source_sha']
         and labels.get(LABEL + '.run') == binding['run_id'] and re.fullmatch('sha256:[0-9a-f]{64}', row['Id']), 'exact owned native image')
    return row['Id']


def consumer_identity(row, role, binding, token, image, root, output, uid, gid):
    h, config = row['HostConfig'], row['Config']
    need(row['Name'] == '/support-' + role + '-' + token and row['Image'] == image
         and config['Labels'].get(LABEL) == token and config['Labels'].get(LABEL + '.source') == binding['source_sha']
         and config['Labels'].get(LABEL + '.run') == binding['run_id']
         and config['User'] == ('0:0' if role == 'lifecycle' else str(uid) + ':' + str(gid)), 'exact role/image/user')
    need(h['NetworkMode'] == 'none' and h['Privileged'] is False and h['ReadonlyRootfs'] is (role != 'lifecycle')
         and h['Memory'] == 2*1024**3 and h['NanoCpus'] == 2_000_000_000 and h['PidsLimit'] == 128
         and set(h['CapDrop']) == {'ALL'} and set(h.get('CapAdd') or []) == (set(CAPS) if role == 'lifecycle' else set())
         and h['SecurityOpt'] == ['no-new-privileges'] and not h.get('Devices') and not h.get('DeviceRequests')
         and not h.get('VolumesFrom') and not h.get('PortBindings'), 'real daemon resource/isolation contract')
    wanted = {('/source', str(root), False), ('/out', str(output / role), True)}
    if role == 'lifecycle':
        wanted.add(('/packages', str(output / 'build1'), False))
    binds = {(m['Destination'], m['Source'], m['RW']) for m in row['Mounts'] if m['Type'] == 'bind'}
    need(binds == wanted and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in row['Mounts'])
         and set(h['Tmpfs']) == {'/tmp'} and set(h['Tmpfs']['/tmp'].split(',')) == {'rw', 'nosuid', 'nodev', 'exec', 'size=1g'}, 'finite exact mounts')


def cache_file(cache, row):
    name = row['filename']
    need(type(name) is str and re.fullmatch('[A-Za-z0-9._+@:~-]{1,255}', name), 'fixed cache filename')
    path = cache / name
    need(type(row['size']) is int and 0 < row['size'] <= 1024**3
         and not any(p.is_symlink() for p in (path, *path.parents)), 'finite exact original cache input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['size'], 'ordinary exact-sized preseeded input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
             and checksum == row['sha256'], 'changed or mismatching preseeded input')
    finally:
        os.close(fd)
    return path


def capsule(public, destination, binding, map_sha):
    files = {}
    for path in sorted(public.rglob('*')):
        need(not path.is_symlink(), 'no link/special/private-key DATA export')
        if path.is_dir():
            continue
        name = str(path.relative_to(public))
        need(not any(part in ('private-keys-v1.d', 'openpgp-revocs.d', 'S.gpg-agent') for part in path.parts), 'private signing material excluded')
        files[name] = read(path, 8*1024**2)
    need(len(files) <= 511 and sum(map(len, files.values())) <= 32*1024**2, 'bounded complete public capsule')
    files['capsule.json'] = encoded(dict(schema=1, binding=binding, source_map_sha256=map_sha,
        files={n: pin(raw) for n, raw in sorted(files.items())}))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o644, 0
            archive.addfile(info, io.BytesIO(raw))
    raw = stream.getvalue()
    need(len(raw) <= 32*1024**2, 'capsule wire bound')
    destination.mkdir(mode=0o700)
    (destination / 'support-native-data.tar').write_bytes(raw)
    save(destination / 'capsule-receipt.json', dict(**pin(raw), binding=binding, source_map_sha256=map_sha,
        authentication='ROOT_ORIGINAL_CUSTODY_REQUIRED', acceptance=False))


def private_check_proof(root, args, public, actor, image, binding, token, policy):
    selected = policy['selected_package']
    recipe = selected['recipe_root']
    package_files = {name: row for name, row in selected['files'].items() if name.startswith(recipe + '/')}
    need(len(package_files) == 17, 'exact sealed17 guest check sources')
    guest = module(root / 'native/guest_vm.py', '_support_owned_core16k_guest')
    result = guest.run(root, args, public, actor, image, binding, token, policy, package_files=package_files)
    need(result['status'] == 'PASS_GUEST_EMU16K_EXACT_CHECK_FUNCTION'
         and result['execution'] == 'EMU16K_AARCH64' and result['exact_check'] is True
         and result['in_makepkg'] is False, 'real guest exact check must gate native nocheck pair')
    return result


def run(root, args):
    policy, binding, token = admission(root, args, os.environ)
    need(args.cache.is_dir() and args.cache.stat().st_uid == os.getuid() and args.cache.stat().st_mode & 0o777 == 0o700
         and args.carrier.is_dir() and not args.cache.is_symlink() and not args.carrier.is_symlink(), 'Root-preseeded private original inputs required')
    args.work.mkdir(mode=0o700)
    public = args.work / 'data'
    public.mkdir(mode=0o700)
    # First retained import occurs only after complete publication/selection/admission.
    pgo = module(root / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py', '_support_qualified_pgo102')
    pgo.DOCKER = DOCKER
    actor = pgo.Actors(args.work / 'actors', 14400)  # selected Core owner envelope; fit unmeasured
    images, containers = [], {}
    building = False
    report = dict(schema=1, status='FAIL', binding=binding, source_map_sha256=args.map_sha256,
        source_root=str(root), output_root=str(public), uid=os.getuid(), gid=os.getgid(),
        native_16K='NOT_QUALIFIED', guest_check_environment='EMU16K_AARCH64', native_pair_environment='NATIVE_ARM64_4K_DOCKER', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    previous_run = subprocess.run
    previous_env = {k: os.environ.get(k) for k in ('GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_NO_REPLACE_OBJECTS', 'GIT_OPTIONAL_LOCKS', 'GIT_NO_LAZY_FETCH', 'GIT_TERMINAL_PROMPT')}
    try:
        subprocess.run = pgo.owned_subprocess_run
        os.environ.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
        save(public / 'source-proof.json', git_proof(root, actor, binding))
        need(not actor.docker('ps', '-aq', '--filter', 'label=' + LABEL + '=' + token)
             and not actor.docker('image', 'ls', '-q', '--filter', 'label=' + LABEL + '=' + token), 'fresh owned daemon namespace')
        native = module(root / 'bootstrap/scripts/ci/native_arm.py', '_support_original341')
        helpers = root / 'bootstrap/scripts/ci/setup6-retained-helpers'
        sys.path.insert(0, str(helpers))
        seed = module(helpers / 'prepare.py', '_support_exact_retained_inputs')
        save(args.work / 'input-preparation.json', seed.prepare(args.carrier, args.cache, 'native248',
             root / 'bootstrap/scripts/ci/inputs.lock.json', min(actor.deadline, time.monotonic()+2250), args.carrier / '.git'))
        finite_inputs = module(root / 'native/inputs.py', '_support_original501_dispatch')
        parent_fetch = native.fetch
        native.fetch = finite_inputs.bind_fetch(load(root / 'bootstrap/scripts/ci/inputs.lock.json'), args.cache,
            lambda row, cache: cache_file(cache, row), parent_fetch)
        def native_run(argv, log=None, timeout=1800):
            nonlocal building
            command = list(map(str, argv))
            if command[0] == 'docker':
                command = [*DOCKER, *command[1:]]
                if command[len(DOCKER)] == 'build':
                    building = True
                    command[len(DOCKER)+1:len(DOCKER)+1] = ['--no-cache', '--tag', 'support-native-base:' + token,
                        '--label', LABEL + '=' + token, '--label', LABEL + '.source=' + binding['source_sha'],
                        '--label', LABEL + '.run=' + binding['run_id']]
                elif command[len(DOCKER)] == 'run':
                    command[len(DOCKER)+1:len(DOCKER)+1] = ['--name', 'support-probe-' + token,
                        '--label', LABEL + '=' + token, '--label', LABEL + '.source=' + binding['source_sha'], '--label', LABEL + '.run=' + binding['run_id'],
                        '--cpus=1', '--memory=128m', '--pids-limit=32']
            result = actor.run(command, log, min(timeout, 1800))
            return result if log is None else None
        native.run = native_run
        base = args.work / 'bootstrap'
        base.mkdir()
        shutil.copyfile(root / 'bootstrap/scripts/ci/inputs.lock.json', base / 'inputs.lock.json')
        original = load(base / 'inputs.lock.json')
        native.probe(base)
        need(native.audit(original, args.cache, base) == 248, 'all original248 signatures audited')
        image = native.build(original, args.cache, base, {})
        images.append(image)
        building = False
        need(read(base / 'packages.lock') == read(root / 'native/original341.lock'), 'actual exact341 base inventory')
        details = json.loads(actor.docker('image', 'inspect', image))[0]
        image_identity(details, binding, token)
        report['image'] = image
        proofdir = public / 'bootstrap'
        proofdir.mkdir()
        save(proofdir / 'image-inspect.json', details)
        for name in ('runner.json', 'packages.lock', 'signatures.json', 'bootstrap.json', 'cache-checksums.json', 'acquisition.json'):
            if (base / name).is_file():
                shutil.copyfile(base / name, proofdir / name)
        report['private_check'] = private_check_proof(root, args, public, actor, image, binding, token, policy)
        for role in ('build1', 'build2', 'lifecycle'):
            out = public / role
            out.mkdir(mode=0o700)
            command = ['create', '--name', 'support-' + role + '-' + token, '--pull=never', '--network=none', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=2g', '--cpus=2',
                '--user', '0:0' if role == 'lifecycle' else str(os.getuid()) + ':' + str(os.getgid()),
                '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=1g', '--label', LABEL + '=' + token,
                '--label', LABEL + '.source=' + binding['source_sha'], '--label', LABEL + '.run=' + binding['run_id'],
                '--mount', 'type=bind,src=' + str(root) + ',dst=/source,readonly',
                '--mount', 'type=bind,src=' + str(out) + ',dst=/out']
            if role == 'lifecycle':
                for capability in CAPS:
                    command += ['--cap-add', capability]
                command += ['--mount', 'type=bind,src=' + str(public / 'build1') + ',dst=/packages,readonly']
            else:
                command += ['--read-only']
            script = 'lifecycle.py' if role == 'lifecycle' else 'guest.py'
            command += ['--entrypoint=/usr/bin/python3', image, '-I', '-B', '/source/native/' + script,
                        '--output', '/out', '--source-map-sha256', args.map_sha256]
            if role == 'lifecycle':
                command += ['--source-sha', binding['source_sha']]
            ident = actor.docker(*command, timeout=60)
            need(re.fullmatch('[0-9a-f]{64}', ident), 'actual created container ID')
            containers[role] = ident
            before = json.loads(actor.docker('inspect', ident))[0]
            consumer_identity(before, role, binding, token, image, root, public, os.getuid(), os.getgid())
            save(out / 'inspect-before.json', before)
            actor.docker('start', '-a', ident, timeout=1200)
            after = json.loads(actor.docker('inspect', ident))[0]
            consumer_identity(after, role, binding, token, image, root, public, os.getuid(), os.getgid())
            save(out / 'inspect-after.json', after)
            need(after['State']['Running'] is False and after['State']['ExitCode'] == 0 and after['State']['Status'] == 'exited', 'natural successful native role completion')
        need(read(public / 'build1/package.pkg.tar') == read(public / 'build2/package.pkg.tar'), 'full independent native archive byte equality')
        report.update(status='PASS_FINITE_NATIVE_PAIR_AND_SIGNED_ALPM_LIFECYCLE', containers=containers,
                      pair=dict(archive_equal=True, independent_containers=len(set(containers.values())) == 3), makepkg_check=policy['makepkg_check'])
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        raise
    finally:
        pending = []
        handlers = {n: signal.signal(n, lambda number, frame: pending.append(number)) for n in (signal.SIGINT, signal.SIGTERM)}
        cleanup = dict(status='UNKNOWN_NOT_ACCEPTED', actors=[])
        try:
            need(getattr(actor, 'support_guest_outer_cleanup_safe', True), 'guest ownership unknown; retain backing and producer')
            retire = pgo.Actors(args.work / 'retirement-actors', 160)
            cleanup['actors'] = retire.rows
            ids = retire.docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL + '=' + token).split()
            need(len(ids) <= 5, 'finite exact owned native roles')
            for ident in ids:
                row = json.loads(retire.docker('inspect', ident))[0]
                need(row['Name'] in {'/support-' + role + '-' + token for role in ('probe', 'proof-export', 'build1', 'build2', 'lifecycle')}
                     and row['Config']['Labels'].get(LABEL + '.source') == binding['source_sha']
                     and row['Config']['Labels'].get(LABEL + '.run') == binding['run_id'], 'no foreign consumer cleanup')
                retire.docker('rm', '-f', ident, timeout=30)
            need(not retire.docker('ps', '-aq', '--filter', 'label=' + LABEL + '=' + token), 'owned container absence precedes image retirement')
            keyhome = args.work / 'bootstrap/gpg'
            if keyhome.is_dir():
                retire.run(['/usr/bin/gpgconf', '--homedir', str(keyhome), '--kill', 'gpg-agent'], timeout=20)
            for image in reversed(images):
                row = json.loads(retire.docker('image', 'inspect', image))[0]
                image_identity(row, binding, token)
                need(row.get('RepoTags') == ['support-native-base:' + token], 'no foreign image tags')
                retire.docker('image', 'rm', '--no-prune', image, timeout=40)
            remaining_containers = retire.docker('ps', '-aq', '--filter', 'label=' + LABEL + '=' + token)
            remaining_images = retire.docker('image', 'ls', '-q', '--filter', 'label=' + LABEL + '=' + token)
            need(not building and not remaining_containers and not remaining_images, 'no unresolved daemon build/image state')
            cleanup = dict(status='PASS_EXACT_OWNED_RESOURCES_RETIRED', containers_absent=True, images_absent=True,
                           daemon_build_complete=True, actors=retire.rows)
        except BaseException as error:
            cleanup['error'] = type(error).__name__ + ': ' + str(error)[:2048]
            report['status'] = 'FAIL_RETIREMENT_UNKNOWN'
        subprocess.run = previous_run
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        for n, handler in handlers.items():
            signal.signal(n, handler)
        if pending:
            report['status'] = 'FAIL_CANCELLATION_DURING_RETIREMENT'
        logs = public / 'actor-logs'
        logs.mkdir()
        for number, row in enumerate(actor.rows + cleanup.get('actors', [])):
            raw = read(row['log'], 8*1024**2)
            name = 'actor-logs/%04d.log' % number
            (public / name).write_bytes(raw)
            row.update(public_log=name, log_pin=pin(raw))
        report['actors'] = actor.rows
        save(public / 'cleanup.json', cleanup)
        save(public / 'report.json', report)
        capsule(public, args.public, binding, args.map_sha256)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('work', 'cache', 'carrier', 'public'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha', 'ref', 'run-id', 'map-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--preflight-only', action='store_true')
    args = parser.parse_args()
    def cancel(*_):
        raise KeyboardInterrupt('native support cancellation')
    for n in (signal.SIGINT, signal.SIGTERM):
        signal.signal(n, cancel)
    root = Path(__file__).resolve().parents[1]
    if args.preflight_only:
        admission(root, args, os.environ)
        print(json.dumps(dict(status='PASS_SOURCE_ADMISSION_ONLY', native='NOT RUN')))
    else:
        print(json.dumps(run(root, args)['status']))
