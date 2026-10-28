# SPDX-License-Identifier: MIT
"""Root-publication-gated original341 bootstrap and native C/C++ debugger consumer.

This file is delivered as source. No --execute call is authorized by construction.
"""
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
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import LABEL, binding, consumer_contract, input_contract, load, need, pin, read, save, source_bytes, verify_source

DOCKER = ('/usr/bin/docker', '--host=unix:///var/run/docker.sock')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def cache_file(cache, row):
    name = row['filename']
    need(re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}', name) and name not in ('.', '..'), 'cache filename')
    path = cache / name
    need(path.is_file() and not path.is_symlink() and path.stat().st_size == row['size'], 'missing exact preseeded cache input: ' + name)
    with path.open('rb') as stream:
        need(hashlib.file_digest(stream, 'sha256').hexdigest() == row['sha256'], 'cache bytes differ: ' + name)
    return path


def admission(root, args, env):
    verify_source(root, args.map_sha256); profile, original, expected = input_contract(root)
    own = binding(args.source_sha, args.ref, args.run_id, env)
    need(args.execute and platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
         and os.getuid() == os.geteuid() != 0 and env.get('GITHUB_ACTIONS') == 'true'
         and env.get('RUNNER_ARCH') == 'ARM64' and env.get('RUNNER_OS') == 'Linux', 'explicit disposable non-root native ARM owner required')
    need(not any(k.startswith(('DOCKER_', 'LD_', 'GIT_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_')) for k in env), 'loader/daemon/Git/private transport variables refused')
    temp = Path(env['RUNNER_TEMP']).absolute()
    need(args.work == temp / 'native-debugger-work' and args.cache == temp / 'alarm-cache'
         and args.carrier == temp / 'pgo-hosted-retained' and not temp.is_relative_to(root)
         and not root.is_relative_to(temp), 'fixed disjoint owned runner paths')
    need(not any(p.is_symlink() for p in (temp, *temp.parents, args.cache, args.carrier))
         and args.cache.is_dir() and args.cache.stat().st_uid == os.getuid()
         and args.cache.stat().st_mode & 0o777 == 0o700, 'ordinary existing private cache')
    return own, profile, original, expected


def image_identity(row, own):
    need(row['Architecture'] == 'arm64' and row['Os'] == 'linux'
         and row['Config']['Labels'].get(LABEL) == own['token']
         and row['Config']['Labels'].get(LABEL + '.source') == own['source'], 'owned native image labels')
    need(re.fullmatch('sha256:[0-9a-f]{64}', row['Id']), 'immutable image ID')
    return row['Id']


def consumer_identity(row, own, image, root, output):
    return consumer_contract(row, own, image, root, output, os.getuid(), os.getgid())


def run(root, args):
    own, profile, original, expected = admission(root, args, os.environ)
    need((root / '.git').is_dir() and not (root / '.git').is_symlink(), 'explicit ordinary publication Git directory')
    import provision
    proof = provision.prior_proof(root, args, own)
    transported = load(args.work / 'input-transport-owner.json')
    for phase in (transported,):
        need(phase['binding'] == own and phase['source_map_sha256'] == args.map_sha256, 'exact same-source prior DATA provisioning')
    need(transported['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY', 'completed hosted input provisioning required')
    provision.retired(transported['actors'], args.work)
    output = args.work / 'public'; output.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', binding=own, source_map_sha256=args.map_sha256,
                  input_inventory=pin(expected), source_root=str(root), output_root=str(output),
                  native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    pgo = module(root / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py', '_sealed_pgo102')
    pgo.DOCKER = DOCKER
    actor = pgo.Actors(args.work / 'actors', 4300)
    images = []; container = None; building = False; cleanup = dict(status='UNKNOWN')
    prior_run = subprocess.run
    git_environment = dict(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_NO_REPLACE_OBJECTS='1',
                           GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    try:
        subprocess.run = pgo.owned_subprocess_run
        os.environ.update(git_environment)
        git = ['/usr/bin/git', '--no-replace-objects', '--git-dir=' + str(root / '.git'),
               '--work-tree=' + str(root), '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false']
        head = actor.run([*git, 'rev-parse', 'HEAD'], timeout=15)
        need(head == own['source'], 'exact published source HEAD')
        tree = actor.run([*git, 'ls-tree', '-rz', '--full-tree', own['source']], timeout=30)
        joined = {}
        for row in tree.split('\0'):
            if not row:
                continue
            meta, name = row.split('\t', 1); mode, kind, digest = meta.split()
            body = source_bytes(root, name)
            need(kind == 'blob' and mode == ('100755' if (root / name).stat().st_mode & 0o111 else '100644')
                 and digest == hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest(), 'complete published Git byte/mode join')
            joined[name] = dict(mode=mode, blob=digest, **pin(body))
        need(set(joined) == set(load(root / 'native/source-map.json')['files']) | {'native/source-map.json'}, 'published closed Git namespace')
        save(output / 'source-proof.json', dict(binding=own, files=joined))
        need(not actor.docker('ps', '-aq', '--filter', 'label=' + LABEL + '=' + own['token'])
             and not actor.docker('image', 'ls', '-q', '--filter', 'label=' + LABEL + '=' + own['token']), 'fresh owned daemon namespace')
        native = module(root / 'bootstrap/scripts/ci/native_arm.py', '_sealed_original341')
        helpers = root / 'bootstrap/scripts/ci/setup6-retained-helpers'; sys.path.insert(0, str(helpers))
        seed = module(helpers / 'prepare.py', '_sealed_retained_input_preparation')
        save(args.work / 'input-data-preparation.json', seed.prepare(args.carrier, args.cache, 'native248',
            root / 'bootstrap/scripts/ci/inputs.lock.json', min(actor.deadline, time.monotonic()+2250), args.carrier / '.git'))
        # Only the original five pinned base rows may use the saved parent path.
        # All496 package/signature descriptors stay cache-only, with no fallback.
        from bootstrap_inputs import bind_fetch
        parent_fetch = native.fetch
        native.fetch = bind_fetch(original, [], args.cache,
                                  lambda row, selected_cache: cache_file(selected_cache, row), parent_fetch)
        def native_run(argv, log=None, timeout=1800):
            nonlocal building
            command = list(map(str, argv))
            if command[0] == 'docker':
                command = [*DOCKER, *command[1:]]
                if command[len(DOCKER)] == 'build':
                    building = True
                    command[len(DOCKER)+1:len(DOCKER)+1] = ['--no-cache', '--tag', 'native-debugger-base:' + own['token'],
                         '--label', LABEL + '=' + own['token'], '--label', LABEL + '.source=' + own['source']]
                elif command[len(DOCKER)] == 'run':
                    command[len(DOCKER)+1:len(DOCKER)+1] = ['--name', 'probe-' + own['token'],
                         '--label', LABEL + '=' + own['token'], '--label', LABEL + '.source=' + own['source'],
                         '--cpus=1', '--memory=128m', '--pids-limit=32']
            result = actor.run(command, log, min(timeout, 1800))
            return result if log is None else None
        native.run = native_run
        base = args.work / 'bootstrap'; base.mkdir()
        shutil.copyfile(root / 'bootstrap/scripts/ci/inputs.lock.json', base / 'inputs.lock.json')
        native.probe(base); need(native.audit(original, args.cache, base) == 248, 'original signed248 audit')
        image = native.build(original, args.cache, base, {}); images.append(image); building = False
        need(read(base / 'packages.lock') == read(root / 'native/original341.lock'), 'actual fresh original341 inventory')
        need(image_identity(json.loads(actor.docker('image', 'inspect', image))[0], own) == image, 'original341 owned image')
        report['bootstrap'] = dict(status='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP', image=image, packages=pin(read(base / 'packages.lock')))
        command = ['create', '--name', 'debugger-' + own['token'], '--pull=never', '--network=none',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=4g', '--cpus=2',
            '--user', str(os.getuid()) + ':' + str(os.getgid()), '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=2g',
            '--label', LABEL + '=' + own['token'], '--label', LABEL + '.source=' + own['source'],
            '--mount', 'type=bind,src=' + str(root) + ',dst=/source,readonly', '--mount', 'type=bind,src=' + str(output) + ',dst=/out',
            '--entrypoint=/usr/bin/python3', image, '-I', '-B', '/source/native/guest.py', '--output', '/out/journey', '--map-sha256', args.map_sha256]
        container = actor.docker(*command, timeout=60)
        need(re.fullmatch('[0-9a-f]{64}', container), 'exact created container ID')
        inspection = json.loads(actor.docker('inspect', container))[0]
        consumer_identity(inspection, own, image, root, output); save(output / 'consumer-inspect.json', inspection)
        actor.docker('start', '-a', container, timeout=1800)
        after = json.loads(actor.docker('inspect', container))[0]
        consumer_identity(after, own, image, root, output)
        save(output / 'consumer-after.json', after)
        need(after['State']['Running'] is False and after['State']['ExitCode'] == 0, 'actual completed native consumer')
        report['consumer'] = dict(image=image, container=container, state=after['State'])
        result = load(output / 'journey/result.json')
        need(result['status'] == 'PASS_NATIVE_DEBUGGER_COMPONENT_ONLY', 'all actual native developer components required')
        report['status'] = result['status']
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        raise
    finally:
        pending_cleanup = []
        cleanup_handlers = {number: signal.signal(number, lambda number, frame: pending_cleanup.append(number))
                            for number in (signal.SIGINT, signal.SIGTERM)}
        try:
            retire = pgo.Actors(args.work / 'retirement-actors', 160)
            rows = retire.docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL + '=' + own['token']).split()
            need(len(rows) <= 2, 'finite owned probe and consumer to retire')
            for ident in rows:
                row = json.loads(retire.docker('inspect', ident))[0]
                need(row['Config']['Labels'].get(LABEL + '.source') == own['source']
                     and row['Name'] in {'/debugger-' + own['token'], '/probe-' + own['token']}, 'exact owned cleanup probe/consumer')
                retire.docker('rm', '-f', ident, timeout=30)
            for directory in ('bootstrap',):
                keyhome = args.work / directory / 'gpg'
                if keyhome.is_dir():
                    retire.run(['/usr/bin/gpgconf', '--homedir', str(keyhome), '--kill', 'gpg-agent'], timeout=30)
            for image in reversed(images):
                row = json.loads(retire.docker('image', 'inspect', image))[0]; image_identity(row, own)
                need(all(tag in {'native-debugger-base:' + own['token']} for tag in row.get('RepoTags', [])), 'no foreign image tags')
                retire.docker('image', 'rm', '-f', image, timeout=30)
            need(not building and not retire.docker('ps', '-aq', '--filter', 'label=' + LABEL + '=' + own['token'])
                 and not retire.docker('image', 'ls', '-q', '--filter', 'label=' + LABEL + '=' + own['token']), 'daemon work/image/container absence required')
            cleanup = dict(status='PASS_EXACT_OWNED_RESOURCES_RETIRED', actors=retire.rows)
        except BaseException as error:
            cleanup = dict(status='UNKNOWN_NOT_ACCEPTED', error=type(error).__name__ + ': ' + str(error)[:2048])
            report['status'] = 'FAIL_RETIREMENT_UNKNOWN'
        subprocess.run = prior_run
        for name in git_environment:
            os.environ.pop(name, None)
        for number, handler in cleanup_handlers.items():
            signal.signal(number, handler)
        if pending_cleanup:
            report['status'] = 'FAIL_CANCELLATION_DURING_RETIREMENT'
            report['cancellation_during_cleanup'] = pending_cleanup
        save(output / 'cleanup.json', cleanup); report['actors'] = actor.rows
        save(output / 'receipt.json', report)
        report['provisioning'] = dict(proof=proof, transport=transported)
        proofs = output / 'bootstrap-proof'; proofs.mkdir()
        # Capture source-defined failure DATA before generic log mirroring.
        # Guard rejection must not replace the original bootstrap exception.
        try:
            from failure_retention import retain
            diagnostic = retain(root, args.work, args.cache, output, original, own, actor.rows)
        except Exception:
            diagnostic = dict(schema=1, status='FAIL_BOUNDED_BOOTSTRAP_FAILURE_DATA_GUARD', binding=own,
                guard_code='INTERNAL_RETENTION_FAILURE',
                files={name: dict(status='REFUSED', code='INTERNAL_RETENTION_FAILURE') for name in
                       ('acquisition.json', 'key-import.log', 'bootstrap.log', 'signatures.json')},
                blocked_actor_logs=[str(args.work / 'bootstrap' / name) for name in ('key-import.log', 'bootstrap.log')])
        diagnostic['source_map_sha256'] = args.map_sha256
        report['bootstrap_failure_data'] = diagnostic
        if diagnostic['status'] != 'PASS_BOUNDED_BOOTSTRAP_FAILURE_DATA' and report['status'] == 'PASS_NATIVE_DEBUGGER_COMPONENT_ONLY':
            report['status'] = 'FAIL_BOOTSTRAP_DIAGNOSTIC_RETENTION'
        save(output / 'bootstrap-failure-retention.json', diagnostic)
        retained_streams = {str(args.work / 'bootstrap' / name): row for name, row in diagnostic['files'].items()
                            if name in ('key-import.log', 'bootstrap.log') and row['status'] == 'RETAINED'}
        logs = output / 'actor-logs'; logs.mkdir()
        for number, row in enumerate(proof['actors'] + transported['actors'] + actor.rows + cleanup.get('actors', [])):
            path = Path(row['log'])
            if str(path) in diagnostic['blocked_actor_logs']:
                row['public_retention'] = 'REFUSED_BOOTSTRAP_FAILURE_DATA_GUARD'
                continue
            if str(path) in retained_streams:
                retained = retained_streams[str(path)]
                row['public_log'] = retained['public_path']
                row['log_pin'] = {key: retained[key] for key in ('bytes', 'sha256')}
                continue  # One exact guarded copy, without doubling the public byte budget.
            if path.is_file():
                data = read(path)
                target = logs / ('%04d.log' % number); target.write_bytes(data)
                row['public_log'] = str(target.relative_to(output)); row['log_pin'] = pin(data)
        for directory in ('bootstrap',):
            for name in ('packages.lock', 'signatures.json', 'bootstrap.json', 'cache-checksums.json', 'Dockerfile', 'runner.json'):
                if name == 'signatures.json':
                    continue  # Published only via the exact guarded retention path.
                path = args.work / directory / ('context/Dockerfile' if name == 'Dockerfile' else name)
                if path.is_file():
                    (proofs / (directory + '-' + name)).write_bytes(read(path))
        save(output / 'cleanup.json', cleanup); save(output / 'receipt.json', report)
        files = {}
        for path in sorted(output.rglob('*')):
            if path.is_symlink():
                target = os.readlink(path)
                files[str(path.relative_to(output))] = dict(kind='symlink', mode=stat.S_IMODE(path.lstat().st_mode), target=target, **pin(target.encode()))
            elif path.is_file() and path.name != 'artifacts.json':
                files[str(path.relative_to(output))] = dict(kind='file', mode=stat.S_IMODE(path.lstat().st_mode), **pin(read(path)))
        need(sum(r['bytes'] for r in files.values()) <= 32*1024**2, 'bounded public artifact namespace')
        save(output / 'artifacts.json', dict(schema=1, binding=own, source_map_sha256=args.map_sha256, files=files))
    need(report['bootstrap_failure_data']['status'] == 'PASS_BOUNDED_BOOTSTRAP_FAILURE_DATA', 'bootstrap failure DATA retention guard refused')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('work', 'cache', 'carrier'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha', 'ref', 'run-id', 'map-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    def cancel(number, frame):
        raise KeyboardInterrupt('native workflow cancellation')
    handlers = {number: signal.signal(number, cancel) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = run(Path(__file__).resolve().parents[1], args)
        print(json.dumps(dict(status=result['status'])))
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
