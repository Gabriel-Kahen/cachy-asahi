# SPDX-License-Identifier: MIT
"""Root-publication-gated original341 bootstrap, fixed8 overlay and native consumer.

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
from common import LABEL, binding, consumer_contract, input_contract, load, need, pin, read, save, source_bytes, uv_policy, verify_source

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
    need(args.work == temp / 'native-developer-work' and args.cache == temp / 'alarm-cache'
         and args.carrier == temp / 'pgo-hosted-retained' and not temp.is_relative_to(root)
         and not root.is_relative_to(temp), 'fixed disjoint owned runner paths')
    need(not any(p.is_symlink() for p in (temp, *temp.parents, args.cache, args.carrier))
         and args.cache.is_dir() and args.cache.stat().st_uid == os.getuid()
         and args.cache.stat().st_mode & 0o777 == 0o700, 'ordinary existing private cache')
    for row in profile['additions']['rows']:
        cache_file(args.cache, row)
        cache_file(args.cache, dict(filename=row['filename'] + '.sig', size=row['signature_size'], sha256=row['signature_sha256']))
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
    operation=getattr(args,'operation','source184')
    need(operation in ('source184','desktop-alpm-v1'),'explicit finite operation')
    need((root / '.git').is_dir() and not (root / '.git').is_symlink(), 'explicit ordinary publication Git directory')
    import provision
    proof = provision.prior_proof(root, args, own)
    transported = load(args.work / 'input-transport-owner.json')
    seeded = load(args.work / 'input-cache-owner.json')
    for phase in (transported, seeded):
        need(phase['binding'] == own and phase['source_map_sha256'] == args.map_sha256, 'exact same-source prior DATA provisioning')
    need(transported['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and seeded['status'] == 'PASS_EIGHT_INPUT_CACHE_DATA_ONLY', 'completed hosted input provisioning required')
    provision.transport_retired(transported, args.work, provision.carrier_profile(root), own, args.map_sha256)
    output = args.work / 'public'; output.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', binding=own, source_map_sha256=args.map_sha256,
                  input_inventory=pin(expected), source_root=str(root), output_root=str(output),
                  native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    if operation=='desktop-alpm-v1':report['operation']=operation
    pgo = module(root / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py', '_sealed_pgo102')
    pgo.DOCKER = DOCKER
    actor = pgo.Actors(args.work / 'actors', 4300)
    from image_lifecycle import reserve, register, verify_base, retire as retire_images
    from cleanup_control import build_operation, retire_created_containers
    ledger = None; container = None; created_base_id = None; namespace_fresh = False
    build_operations = []; probe_rows = []; cleanup = dict(status='UNKNOWN')
    prior_run = subprocess.run
    primary_error = None
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
        namespace_fresh = True
        ledger = reserve(actor, own)
        ledger['source_map_sha256'] = args.map_sha256
        native = module(root / 'bootstrap/scripts/ci/native_arm.py', '_sealed_original341')
        helpers = root / 'bootstrap/scripts/ci/setup6-retained-helpers'; sys.path.insert(0, str(helpers))
        seed = module(helpers / 'prepare.py', '_sealed_retained_input_preparation')
        save(args.work / 'input-data-preparation.json', seed.prepare(args.carrier, args.cache, 'native248',
            root / 'bootstrap/scripts/ci/inputs.lock.json', min(actor.deadline, time.monotonic()+2250), args.carrier / '.git'))
        # native248 seeds package pairs, not the original five base inputs.
        # Restore their pinned parent path only; package failures never fall back.
        from bootstrap_inputs import bind_fetch
        parent_fetch = native.fetch
        native.fetch = bind_fetch(original, profile['additions']['rows'], args.cache,
                                  lambda row, selected_cache: cache_file(selected_cache, row), parent_fetch)
        def native_run(argv, log=None, timeout=1800):
            nonlocal created_base_id
            command = list(map(str, argv))
            is_build = False; is_probe = False
            if command[0] == 'docker':
                command = [*DOCKER, *command[1:]]
                if command[len(DOCKER)] == 'build':
                    is_build = True
                    command[len(DOCKER)+1:len(DOCKER)+1] = ['--no-cache', '--tag', 'native-developer-base:' + own['token'],
                         '--label', LABEL + '=' + own['token'], '--label', LABEL + '.source=' + own['source']]
                elif command[len(DOCKER)] == 'run':
                    is_probe = True
                    command[len(DOCKER)+1:len(DOCKER)+1] = ['--name', 'probe-' + own['token'],
                         '--label', LABEL + '=' + own['token'], '--label', LABEL + '.source=' + own['source'],
                         '--cpus=1', '--memory=128m', '--pids-limit=32']
            before = len(actor.rows)
            try:
                result = actor.run(command, log, min(timeout, 1800))
            finally:
                if is_build:
                    build_operations.append(build_operation('base', command, actor.rows, before))
                if is_probe and len(actor.rows) == before + 1:
                    probe_rows.append(actor.rows[-1])
            if is_build:
                created_base_id = read(args.work / 'bootstrap/image-id').decode().strip()
                register(actor, ledger, 'base', created_base_id, build_operations[-1]['actor'])
            return result if log is None else None
        native.run = native_run
        base = args.work / 'bootstrap'; base.mkdir()
        shutil.copyfile(root / 'bootstrap/scripts/ci/inputs.lock.json', base / 'inputs.lock.json')
        native.probe(base); need(native.audit(original, args.cache, base) == 248, 'original signed248 audit')
        image = native.build(original, args.cache, base, {})
        need(image == created_base_id, 'registered exact base image ID')
        need(read(base / 'packages.lock') == read(root / 'native/original341.lock'), 'actual fresh original341 inventory')
        need(image_identity(json.loads(actor.docker('image', 'inspect', image))[0], own) == image, 'original341 owned image')
        report['bootstrap'] = dict(status='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP', image=image, packages=pin(read(base / 'packages.lock')))
        overlay = args.work / 'overlay'; overlay.mkdir()
        combined = dict(original, packages=original['packages'] + profile['additions']['rows'])
        need(native.audit(combined, args.cache, overlay) == 256, 'all exact supplemental signatures and metadata')
        context = overlay / 'context'; context.mkdir()
        deps = context / 'deps'; deps.mkdir()
        for row in profile['additions']['rows']:
            for item in (row, dict(filename=row['filename']+'.sig', size=row['signature_size'], sha256=row['signature_sha256'])):
                shutil.copyfile(cache_file(args.cache, item), deps / item['filename'])
                cache_file(deps, item)
        tool_policy = uv_policy(root)
        frontend = next(row for row in tool_policy['artifacts'] if row['role'] == 'frontend')
        source_bytes(root, frontend['path'])
        tools = context / 'tools'; tools.mkdir()
        with tarfile.open(root / frontend['path'], 'r:gz') as archive:
            item = archive.getmember(frontend['member']['name'])
            need(item.isfile() and item.size == frontend['member']['bytes'] and item.size <= 128*1024**2, 'bounded exact uv archive member')
            data = archive.extractfile(item).read(item.size + 1)
            need(pin(data) == {k: frontend['member'][k] for k in ('bytes', 'sha256')}, 'exact ARM uv executable payload')
            (tools / 'uv').write_bytes(data); (tools / 'uv').chmod(0o755)
        for name in ('LICENSE-MIT', 'LICENSE-APACHE'):
            (tools / name).write_bytes(read(root / 'uv-provenance/licenses' / name))
        hooks = load(overlay / 'rootfs-hooks.json')
        for value in load(overlay / 'package-audit.json').values():
            hooks += [Path(n).name for n in value['installed_paths'] if n.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) and n.endswith('.hook')]
        (context / 'disabled-hooks.txt').write_text(native.hook_masks(hooks))
        base_tag = verify_base(actor, ledger, phase='before_overlay')
        dockerfile = ('FROM ' + base_tag + '\nUSER root\nCOPY deps/ /tmp/developer-deps/\nCOPY tools/ /opt/native-developer-tools/\nCOPY disabled-hooks.txt /tmp/developer-hooks.txt\n'
           'RUN while IFS= read -r hook; do ln -sf /dev/null "/builder-disabled-hooks/$hook"; done < /tmp/developer-hooks.txt '
           '&& pacman -U --noconfirm --noscriptlet /tmp/developer-deps/*.pkg.tar.xz && ldconfig '
           '&& rm -rf /tmp/developer-deps /tmp/developer-hooks.txt /var/cache/pacman/pkg/* '
           '&& pacman -Q | LC_ALL=C sort > /builder-packages.lock\nUSER alarm\nWORKDIR /tmp\n')
        if operation=='desktop-alpm-v1':
            from desktop_alpm_v1 import prepare,dockerfile as release_dockerfile
            prepare(root,context,args.map_sha256);dockerfile=release_dockerfile(dockerfile,args.map_sha256)
        (context / 'Dockerfile').write_text(dockerfile)
        command = [*DOCKER, 'build', '--network=none', '--pull=false', '--no-cache', '--platform=linux/arm64',
            '--tag', 'native-developer-tools:' + own['token'], '--label', LABEL + '=' + own['token'],
            '--label', LABEL + '.source=' + own['source'], '--iidfile', str(overlay / 'image-id'), str(context)]
        before = len(actor.rows); overlay_error = None
        try:
            actor.run(command, timeout=600)
        except BaseException as error:
            overlay_error = error
            raise
        finally:
            build_operations.append(build_operation('tools', command, actor.rows, before))
            try:
                verify_base(actor, ledger, phase='after_overlay')
            except Exception:
                if overlay_error is None:
                    raise
        image = read(overlay / 'image-id').decode().strip()
        register(actor, ledger, 'tools', image, build_operations[-1]['actor'])
        image_identity(json.loads(actor.docker('image', 'inspect', image))[0], own)
        command = ['create', '--name', 'developer-' + own['token'], '--pull=never', '--network=none',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=4g', '--cpus=2',
            '--user', str(os.getuid()) + ':' + str(os.getgid()), '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=2g',
            '--label', LABEL + '=' + own['token'], '--label', LABEL + '.source=' + own['source'],
            '--mount', 'type=bind,src=' + str(root) + ',dst=/source,readonly', '--mount', 'type=bind,src=' + str(output) + ',dst=/out',
            '--entrypoint=/usr/bin/python3', image, '-I', '-B', ('/source/native/desktop_guest_v1.py' if operation=='desktop-alpm-v1' else '/source/native/guest.py'), '--output', '/out/journey', '--map-sha256', args.map_sha256]
        container = actor.docker(*command, timeout=60)
        need(re.fullmatch('[0-9a-f]{64}', container), 'exact created container ID')
        inspection = json.loads(actor.docker('inspect', container))[0]
        consumer_identity(inspection, own, image, root, output); save(output / 'consumer-inspect.json', inspection)
        from consumer_diagnostics import retain as retain_consumer
        consumer_index = len(actor.rows); consumer_error = None
        try:
            actor.docker('start', '-a', container, timeout=1800)
        except BaseException as error:
            consumer_error = error
            raise
        finally:
            report['consumer_diagnostic'] = retain_consumer(args.work, output, own, args.map_sha256,
                actor.rows, consumer_index, container, consumer_error)
            try:
                from build_summary import bind as bind_build_summary
                report['build_summary'] = bind_build_summary(output, own, args.map_sha256)
            except Exception:
                report['build_summary_retention'] = 'REFUSED_BOUNDED_BUILD_SUMMARY_DATA'
        need(report['consumer_diagnostic']['status'] == 'ORIGINAL_CONSUMER_ACTOR_DATA_ONLY',
             'original consumer diagnostic retention required')
        after = json.loads(actor.docker('inspect', container))[0]
        consumer_identity(after, own, image, root, output)
        save(output / 'consumer-after.json', after)
        need(after['State']['Running'] is False and after['State']['ExitCode'] == 0, 'actual completed native consumer')
        report['consumer'] = dict(image=image, container=container, state=after['State'])
        result = load(output / 'journey/result.json')
        need(result['status'] == ('PASS_DESKTOP_TOOLS_NATIVE_ALPM_COMPONENT' if operation=='desktop-alpm-v1' else 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY'), 'all actual native developer components required')
        report['status'] = result['status']
    except BaseException as error:
        primary_error = error
        if ledger is None:
            ledger = getattr(error, 'ledger', None)
        if ledger is not None:
            ledger['source_map_sha256'] = args.map_sha256
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        raise
    finally:
        pending_cleanup = []
        cleanup_handlers = {number: signal.signal(number, lambda number, frame: pending_cleanup.append(number))
                            for number in (signal.SIGINT, signal.SIGTERM)}
        retire = None
        cleanup = dict(status='UNKNOWN_NOT_ACCEPTED', actors=[], build_operations=build_operations,
                       container_retirement=[], daemon_absence=None, image_retirement=None)
        try:
            retire = pgo.Actors(args.work / 'retirement-actors', 160)
            need(namespace_fresh and ledger is not None and all(item['terminal'] for item in build_operations), 'unknown build/resource ownership; no cleanup mutation')
            retire_created_containers(retire, own, container, created_base_id, probe_rows, cleanup['container_retirement'])
            for directory in ('bootstrap', 'overlay'):
                keyhome = args.work / directory / 'gpg'
                if keyhome.is_dir():
                    retire.run(['/usr/bin/gpgconf', '--homedir', str(keyhome), '--kill', 'gpg-agent'], timeout=30)
            cleanup['image_retirement'] = retire_images(retire, ledger)
            containers_after = retire.docker('ps', '-aq', '--no-trunc', '--filter', 'label=' + LABEL + '=' + own['token'])
            container_query = retire.rows[-1]
            images_after = retire.docker('image', 'ls', '--no-trunc', '-q', '--filter', 'label=' + LABEL + '=' + own['token'])
            cleanup['daemon_absence'] = dict(containers=dict(output=containers_after, actor=container_query),
                                             images=dict(output=images_after, actor=retire.rows[-1]))
            need(not containers_after and not images_after, 'actual final owned daemon resources must be absent')
            need(cleanup['image_retirement']['status'] == 'PASS_EXACT_OWNED_IMAGE_ALIASES_RETIRED', 'owned image alias retirement unknown')
            cleanup['status'] = 'PASS_EXACT_OWNED_RESOURCES_RETIRED'
        except BaseException as error:
            cleanup.update(status='UNKNOWN_NOT_ACCEPTED', error=type(error).__name__ + ': ' + str(error)[:2048])
            report['status'] = 'FAIL_RETIREMENT_UNKNOWN'
        finally:
            cleanup['actors'] = [] if retire is None else retire.rows
            report['image_ledger'] = ledger
            if ledger is not None:
                ledger['source_map_sha256'] = args.map_sha256
            if cleanup['image_retirement'] is not None:
                cleanup['image_retirement'].update(binding=own, source_map_sha256=args.map_sha256)
            save(output / 'image-ledger.json', ledger)
            save(output / 'image-retirement.json', cleanup['image_retirement'])
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
        report['provisioning'] = dict(proof=proof, transport=transported, cache=seeded)
        try:
            provision.copy_transport_public(args.work, output, own, args.map_sha256)
        except Exception:
            report['status'] = 'FAIL_TRANSPORT_PUBLIC_RETENTION'
            report['transport_public_retention'] = 'REFUSED_BOUNDED_TRANSPORT_DATA'
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
        if diagnostic['status'] != 'PASS_BOUNDED_BOOTSTRAP_FAILURE_DATA' and report['status'] in ('PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY','PASS_DESKTOP_TOOLS_NATIVE_ALPM_COMPONENT'):
            report['status'] = 'FAIL_BOOTSTRAP_DIAGNOSTIC_RETENTION'
        save(output / 'bootstrap-failure-retention.json', diagnostic)
        retained_streams = {str(args.work / 'bootstrap' / name): row for name, row in diagnostic['files'].items()
                            if name in ('key-import.log', 'bootstrap.log') and row['status'] == 'RETAINED'}
        logs = output / 'actor-logs'; logs.mkdir()
        for number, row in enumerate(proof['actors'] + transported['actors'] + actor.rows + cleanup.get('actors', [])):
            path = Path(row['log'])
            if (report.get('consumer_diagnostic', {}).get('status') != 'ORIGINAL_CONSUMER_ACTOR_DATA_ONLY'
                    and row.get('argv') == [*DOCKER, 'start', '-a', container]):
                row['public_retention'] = 'REFUSED_CONSUMER_ACTOR_DATA_GUARD'
                continue
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
        for directory in ('bootstrap', 'overlay'):
            for name in ('packages.lock', 'signatures.json', 'bootstrap.json', 'cache-checksums.json', 'Dockerfile', 'runner.json'):
                if directory == 'bootstrap' and name == 'signatures.json':
                    continue  # The exact original is copied only through the guarded path above.
                path = args.work / directory / ('context/Dockerfile' if name == 'Dockerfile' else name)
                if path.is_file():
                    (proofs / (directory + '-' + name)).write_bytes(read(path))
        save(output / 'image-ledger.json', ledger)
        save(output / 'image-retirement.json', cleanup['image_retirement'])
        save(output / 'cleanup.json', cleanup); save(output / 'receipt.json', report)
        # Project only source-defined public evidence; never walk disposable guest trees.
        try:
            if operation=='desktop-alpm-v1':
                from desktop_projection_v1 import project
            else:
                from public_projection import project
            project(root, output, args.work / 'public-projection')
        except Exception as error:
            try:
                from privacy_diagnostics import validate_refusal
                detail = error.diagnostic()
                validate_refusal(detail)
                save(args.work / 'projection-refusal.json', dict(schema=1, binding=own,
                    source_map_sha256=args.map_sha256, diagnostic=detail))
            except Exception:
                pass  # Saving safe refusal DATA cannot replace the primary error.
            print('NATIVE_PUBLIC_PROJECTION_REFUSED ' + type(error).__name__, flush=True)
            if primary_error is None:
                raise
    need(report['bootstrap_failure_data']['status'] == 'PASS_BOUNDED_BOOTSTRAP_FAILURE_DATA', 'bootstrap failure DATA retention guard refused')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('work', 'cache', 'carrier'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha', 'ref', 'run-id', 'map-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--operation',choices=('source184','desktop-alpm-v1'),default='source184')
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
