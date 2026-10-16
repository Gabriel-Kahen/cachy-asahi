#!/usr/bin/env python3
"""Four accepted private inputs, no rebuild/install, one bounded graph trial."""
import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import subprocess
from types import SimpleNamespace
import uuid

spec = importlib.util.spec_from_file_location('graph_support', Path(__file__).with_name('support.py'))
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


def payload(report):
    return [{'path': '/' + name, 'type': 'file', 'mode': row['mode'], 'sha256': row['sha256']}
            for name, row in report['members'].items() if not name.startswith('.') and row['type'] == '0']


def prepare_inputs(archives, target, checks, full):
    pins = s.inputs()
    s.need(s.sha(full / 'audio-inputs.json') == pins['audio_policy_sha256'], 'audio-policy-differs')
    inspector = s.load('graph_audio_inspector', full / 'audio_inputs.py', pins['audio_inputs_helper_sha256'])
    policy = json.loads((full / 'audio-inputs.json').read_text())
    names = {r['filename'] for r in policy} | {r['filename'] + '.sig' for r in policy if 'signature_sha256' in r}
    s.need({p.name for p in archives.iterdir()} == names, 'retrieved-file-set-differs')
    selected_data = {r['graph_path'] for r in s.graphs()['cases']} | {r['path'] for r in s.graphs()['firs']}
    target.mkdir(mode=0o700); (target / 'lv2').mkdir(mode=0o700); (target / 'data').mkdir(mode=0o700)
    observations = []
    for row in pins['packages']:
        s.need(next(x for x in policy if x['name'] == row['name']) == row, 'accepted-policy-row-differs')
        archive = archives / row['filename']
        s.need(archive.is_file() and not archive.is_symlink() and archive.stat().st_size == row['size'] and
               s.sha(archive) == row['sha256'], 'accepted-package-bytes-differ')
        if 'signature_sha256' in row:
            signature = archives / (row['filename'] + '.sig')
            s.need(signature.is_file() and not signature.is_symlink() and
                   signature.stat().st_size == row['signature_size'] and s.sha(signature) == row['signature_sha256'],
                   'official-signature-pin-differs')
        inspector.inspect(row, checks.package(archive), SimpleNamespace(payload=payload))
        desired = {p['path'].lstrip('/'): p for p in row['payload'] if
                   (p['path'].lstrip('/') in selected_data if row['name'] == 'asahi-audio' else
                    p['path'].startswith('/usr/lib/lv2/'))}
        s.need(desired and (len(desired) == 20 if row['name'] == 'asahi-audio' else True), 'selected-payload-differs')
        copied = set()
        with tarfile_open(archive) as stream:
            for entry in stream:
                name = str(PurePosixPath(entry.name))
                if name not in desired: continue
                prefix = 'usr/share/asahi-audio/' if row['name'] == 'asahi-audio' else 'usr/lib/lv2/'
                relative = PurePosixPath(name.removeprefix(prefix))
                s.need(entry.isfile() and name not in copied and name.startswith(prefix) and
                       not relative.is_absolute() and not any(x in ('', '.', '..') for x in relative.parts) and
                       0 < entry.size <= 64 * 1024 * 1024, 'unsafe-selected-member')
                path = target / ('data' if row['name'] == 'asahi-audio' else 'lv2') / str(relative)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with path.open('xb') as out: shutil.copyfileobj(stream.extractfile(entry), out, 1024 * 1024)
                s.need(path.stat().st_size == entry.size and s.sha(path) == desired[name]['sha256'], 'selected-copy-differs')
                path.chmod(desired[name]['mode']); copied.add(name)
        s.need(copied == set(desired), 'selected-copy-incomplete')
        observations.append({'name': row['name'], 'version': row['version'], 'archive_bytes': row['size'],
                             'archive_sha256': row['sha256'], 'selected_files': len(copied)})
    s.need(sum(r['selected_files'] for r in observations) == 227, 'selected-total-differs')
    return observations


def tarfile_open(path):
    import tarfile
    return tarfile.open(path, 'r:xz')


def runtime_command(held, image, name, candidate, output, lock, product):
    argv = held.runtime_command(image, name, candidate, output, lock, product)
    mount = 'type=bind,src=' + str(held.HERE) + ',dst=/source,readonly'
    s.need(argv.count(mount) == 1, 'held-runtime-command-differs')
    argv[argv.index(mount)] = 'type=bind,src=' + str(s.HERE) + ',dst=/source,readonly'
    index = argv.index('--entrypoint=/usr/bin/python3')
    return argv[:index] + ['--mount', 'type=bind,src=' + str(held.HERE) + ',dst=/held,readonly',
                          '--mount', 'type=bind,src=' + str(candidate / 'data') + ',dst=/usr/share/asahi-audio,readonly'] + argv[index:]


def runtime_report(path, held, allow_failure=False):
    s.need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024, 'runtime-report-bounds')
    common = s.held('container'); value = common.json_document(path.read_bytes()); held.no_private_values(value)
    contract = s.load('graph_runtime_contract', s.HERE / 'container.py'); contract.common = lambda: common
    result = contract.validate_public(value)
    s.need(allow_failure or result['status'] == 'PASS', 'runtime-not-passed')
    return result


def run(args):
    held = s.held('run'); common = s.held('container'); api = held.pair_api(); image, lock = api.preflight(args)
    api.ordinary(s.HERE); archives = args.private.parent / 'incoming/audio-archives'; api.ordinary(archives)
    s.need(archives.is_dir() and archives.stat().st_uid == os.getuid() and not archives.stat().st_mode & 0o022,
           'owned-inputs-required')
    os.umask(0o077); args.private.mkdir(mode=0o700); args.output.mkdir(mode=0o700)
    result = {'status': 'FAIL', 'scope': 'PRIVATE-ASAHI-AUDIO-GRAPH-PROCESSING', 'native_rebuilds': 0,
              'package_pair_repeated': False, 'processing': 'PENDING', 'lsp_processing': 'PENDING',
              'installation': 'NOT RUN', 'target_audio': 'NOT RUN', 'hardware': 'NOT RUN',
              'selected_for_release': False, 'image_id': image, 'expected_packages_sha256': s.LOCK, 'cancelled': False}
    previous = {sig: signal.signal(sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())) for sig in (signal.SIGINT, signal.SIGTERM)}
    stage = 'accepted-inputs'; interrupted = []
    try:
        checks = api.module(args.product / 'scripts/checks/package_checks.py')
        result['accepted_inputs'] = prepare_inputs(archives, args.private / 'candidate', checks,
                                                  s.ROOT / 'scripts/ci/full-development-composition')
        stage = 'runtime'; raw = args.private / 'runtime'; raw.mkdir(mode=0o700)
        name = 'cachy-asahi-graph-processing-' + uuid.uuid4().hex[:16]
        s.save(args.private / 'runtime-container.json', {'name': name})
        try:
            api.command(runtime_command(held, image, name, args.private / 'candidate', raw, lock, args.product),
                        args.private / 'runtime.log', 900)
        except api.CommandFailure:
            try:
                failed = runtime_report(raw / 'observations.json', held, allow_failure=True)
                s.need(failed['status'] == 'FAIL', 'runtime-exit-status-differs')
                s.save(args.output / 'runtime.json', failed)
                result['runtime_failure'] = {key: failed[key] for key in ('stage', 'failure_class')}
            except (OSError, ValueError, KeyError, TypeError, common.Failure):
                result['runtime_failure'] = {'stage': 'controller', 'failure_class': 'unavailable-or-invalid-report'}
            raise
        runtime = runtime_report(raw / 'observations.json', held)
        runtime['controller_inputs'] = {p.relative_to(s.HERE).as_posix(): s.sha(p) for p in sorted(s.HERE.rglob('*')) if p.is_file() and p.suffix in ('.c', '.h', '.py', '.json')}
        s.save(args.output / 'runtime.json', runtime)
        result.update(status='PASS', graph_loadability='PASS', processing='PASS', lsp_processing='PASS',
                      positive_streams=16, failure_controls=8, graph_instances=16, process_calls=2048,
                      adapter_sha256=runtime['adapter']['sha256'])
    except (KeyboardInterrupt, OSError, ValueError, KeyError, TypeError, AssertionError, common.Failure, subprocess.SubprocessError) as error:
        result.update(failed_stage=stage, error_kind=type(error).__name__, cancelled=isinstance(error, KeyboardInterrupt))
        if isinstance(error, api.CommandFailure): result['child_exit_code'] = error.code
        if isinstance(error, common.Failure):
            contract = s.load('graph_failed_contract', s.HERE / 'container.py'); contract.common = lambda: common
            result['runtime_failure'] = {'stage': 'projection', 'failure_class': error.code if error.code in contract.failure_codes() else 'unavailable-or-invalid-report'}
    finally:
        for sig in previous: signal.signal(sig, lambda signum, _: interrupted.append(signum))
        try:
            try: result['cleanup'] = held.cleanup(args.private, [])
            except (OSError, ValueError, subprocess.SubprocessError): result['cleanup'] = {'status': 'FAIL', 'private_removed': False}
            if result['cleanup']['status'] != 'PASS': result['status'] = 'FAIL'
            if interrupted: result.update(status='FAIL', cancelled=True)
            s.save(args.output / 'result.json', result)
            if interrupted: result.update(status='FAIL', cancelled=True); s.save(args.output / 'result.json', result)
        finally:
            for sig, handler in previous.items(): signal.signal(sig, handler)
    if interrupted: result.update(status='FAIL', cancelled=True); s.save(args.output / 'result.json', result)
    return int(result['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'desktop', 'builder', 'private', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
