#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run ARM-C01 after the native integration job, using its still-local image."""
import argparse
import gzip
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

sys.dont_write_bytecode = True
import arm_c01 as arm

PURPOSE = 'ARM-C01-same-job-followup'
ORIGINALS = {'cachy-asahi-setup', 'cachy-asahi-fish-config', 'cachy-asahi-zsh-config', 'cachy-asahi-hyprland-settings'}
FILES = ('arm_c01.py', 'corpus.py', 'test_arm_c01.py', 'test_corpus.py', 'stage.py', 'test_stage.py')
HANDOFF = {'installed-image.json', 'installed-packages.lock', 'commit-receipt.json',
           'committed-image/result.json', 'committed-config.json', 'container-removal.json'}
EXPORTER = 'scripts/ci/integration_export.py'


def read_json(path, pin=None):
    arm.regular(path)
    data = path.read_bytes()
    if pin is not None:
        arm.need(arm.PIN.fullmatch(pin or '') and hashlib.sha256(data).hexdigest() == pin, 'JSON input pin differs')
    def unique(rows):
        result = {}
        for key, value in rows:
            arm.need(key not in result, 'duplicate JSON key refused')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def file_row(path):
    arm.regular(path, 8 * 1024**2)
    return {'sha256': arm.sha(path), 'mode': stat.S_IMODE(path.stat().st_mode)}


def freeze(root, output):
    """Local source operation only; no Docker, build, installation or Git."""
    arm.need(not output.exists() and not output.is_symlink(), 'new lock required')
    lock = {'schema_version': 1, 'purpose': PURPOSE, 'development_only': True, 'selected_for_release': False,
            'source_sha256': arm.SOURCE_SHA,
            'source_files': {name: file_row(root / 'scripts/experiments' / name) for name in FILES},
            'exporter': {'path': EXPORTER, **file_row(root / EXPORTER)}}
    arm.save(output, lock)
    return lock


def verify_handoff(directory, pins, image, commit, base, expected, expected_sha, base_sha):
    arm.need(set(pins) == HANDOFF, 'exact six-file installed handoff pin set required')
    for name, pin in pins.items():
        arm.regular(directory / name)
        arm.need(arm.PIN.fullmatch(pin or '') and arm.sha(directory / name) == pin, 'installed handoff file changed')
    metadata = read_json(directory / 'installed-image.json')
    receipt = read_json(directory / 'commit-receipt.json')
    fresh = read_json(directory / 'committed-image/result.json')
    config = read_json(directory / 'committed-config.json')
    cleanup = read_json(directory / 'container-removal.json')
    arm.need(all(isinstance(row, dict) for row in (metadata, receipt, fresh, config, cleanup)), 'object handoff receipts required')
    arm.need(metadata.get('image_id') == image and metadata.get('source_commit') == commit and
             metadata.get('lock_sha256') == expected_sha and metadata.get('hardware_validation') == 'NOT RUN', 'installed image binding differs')
    arm.need(pins['installed-packages.lock'] == expected_sha and metadata.get('commit_receipt_sha256') == pins['commit-receipt.json'], 'handoff lock/receipt pin differs')
    arm.need(receipt.get('status') == 'READY' and receipt.get('purpose') == 'sanitized-baseline-image-handoff'
             and receipt.get('source_commit') == commit and receipt.get('base_packages_sha256') == base_sha
             and receipt.get('installed_packages_sha256') == expected_sha and receipt.get('installed_package_count') == len(expected), 'READY handoff binding differs')
    versions = receipt.get('package_versions', {})
    arm.need(set(versions) == ORIGINALS and expected == {**base, **versions}, 'installed lock must equal base plus original four versions')
    checks = receipt.get('checks', [])
    arm.need(checks and all(row.get('status') == 'PASS' for row in checks) and
             {'successful-lifecycle-handoff', 'exact-base-plus-originals-inventory', 'original-payload-hash',
              'private-keyring-removed', 'image-tmp-view-empty'} <= {row.get('check') for row in checks}, 'complete passing handoff assertions required')
    arm.need(fresh.get('status') == 'PASS' and fresh.get('image_id') == image and fresh.get('source_commit') == commit
             and fresh.get('installed_packages_sha256') == expected_sha and fresh.get('hardware_validation') == 'NOT RUN', 'fresh committed-image verification required')
    baseline = fresh.get('baseline', [])
    arm.need(len(baseline) == 4 and {row.get('name'): row.get('version') for row in baseline} == versions and
             {row['name']: row['payload_sha256'] for row in baseline} == receipt.get('payload_sha256'), 'committed original payload/version binding differs')
    fields = {'User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Labels', 'Volumes', 'ExposedPorts',
              'StopSignal', 'Shell', 'Healthcheck', 'ArgsEscaped'}
    arm.need(isinstance(config.get('accepted_base_config'), dict) and isinstance(config.get('committed_config'), dict)
             and set(config['accepted_base_config']) == set(config['committed_config']) == fields,
             'complete committed configuration fields required')
    arm.need(re.fullmatch(r'sha256:[0-9a-f]{64}', metadata.get('base_image', '')) and
             config.get('status') == 'PASS' and config.get('image_id') == image and
             config.get('base_image') == metadata.get('base_image') == receipt.get('image_id') and
             config.get('accepted_base_config') == config.get('committed_config') and config.get('test_identity_in_image_env') is False,
             'accepted committed configuration required')
    arm.need(re.fullmatch(r'cachy-asahi-handoff-[0-9a-f]{32}', metadata.get('container', '')) and
             cleanup.get('status') == 'PASS' and cleanup.get('absence_verified') is True and
             cleanup.get('container') == metadata.get('container'), 'verified lifecycle container absence required')
    return {'kind': 'verified-original-installed-image', 'image_id': image, 'package_count': len(expected), 'handoff_sha256': pins}


def validate_inputs(args):
    """Read-only preflight usable in source audits; no outputs or commands."""
    root = args.source_root
    arm.need(root.is_absolute() and root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)), 'real absolute source root required')
    arm.need(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image or '') and re.fullmatch(r'[0-9a-f]{40}', args.source_commit or ''), 'immutable image/source commit required')
    arm.need(not os.environ.get('GITHUB_SHA') or os.environ['GITHUB_SHA'] == args.source_commit, 'workflow/source commit differs')
    lock = read_json(args.lock, args.lock_sha256)
    arm.need(isinstance(lock, dict) and set(lock) == {'schema_version', 'purpose', 'development_only', 'selected_for_release', 'source_sha256', 'source_files', 'exporter'}
             and lock['schema_version'] == 1 and lock['purpose'] == PURPOSE and lock['development_only'] is True
             and lock['selected_for_release'] is False and lock['source_sha256'] == arm.SOURCE_SHA, 'exact development experiment lock required')
    arm.need(set(lock['source_files']) == set(FILES) and lock['exporter']['path'] == EXPORTER, 'complete finite source/exporter freeze required')
    for name in FILES:
        arm.need(file_row(root / 'scripts/experiments' / name) == lock['source_files'][name], 'experiment source bytes/mode drift')
    arm.need(file_row(root / EXPORTER) == {key: lock['exporter'][key] for key in ('sha256', 'mode')}, 'reviewed exporter drift')
    arm.need(arm.sha(Path(__file__).resolve()) == lock['source_files']['stage.py']['sha256'] and
             arm.sha(Path(arm.__file__).resolve()) == lock['source_files']['arm_c01.py']['sha256'], 'executing adapter/core source differs')
    for path, pin in ((args.source, arm.SOURCE_SHA), (args.base_packages, args.base_packages_sha256),
                      (args.expected_packages, args.expected_packages_sha256)):
        arm.regular(path, 8 * 1024**2)
        arm.need(arm.PIN.fullmatch(pin or '') and arm.sha(path) == pin, 'retained source/inventory pin differs')
    base, expected = arm.inventory(args.base_packages.read_bytes()), arm.inventory(args.expected_packages.read_bytes())
    arm.need(len(base) == 341 and not set(base) & ORIGINALS, 'accepted 341-package base inventory required')
    if expected == base:
        arm.need(args.handoff_dir is None and args.handoff_pins is None and args.handoff_pins_sha256 is None, 'base-only mode cannot claim installed handoff')
        handoff = {'kind': 'accepted-base-image', 'image_id': args.image, 'package_count': len(base)}
    else:
        arm.need(len(expected) == 345 and args.handoff_dir and args.handoff_pins and args.handoff_pins_sha256, '345-package image needs verified handoff')
        pins = read_json(args.handoff_pins, args.handoff_pins_sha256)
        handoff = verify_handoff(args.handoff_dir, pins, args.image, args.source_commit, base, expected,
                                 args.expected_packages_sha256, args.base_packages_sha256)
    output = args.output
    arm.need(output.is_absolute() and not output.exists() and not output.is_symlink() and '..' not in output.parts
             and not any(c in str(output) for c in ',\n\r') and not any(p.is_symlink() for p in output.parents), 'new safe absolute stage output required')
    for directory in (root, args.handoff_dir, args.source.parent):
        if directory:
            arm.need(not output.is_relative_to(directory) and not directory.is_relative_to(output), 'input/source/output directories must be disjoint')
    return lock, handoff


def snapshot(args, lock, output):
    output.mkdir(mode=0o700)
    shutil.copyfile(args.source_root / EXPORTER, output / 'integration_export.py')
    arm.need(arm.sha(output / 'integration_export.py') == lock['exporter']['sha256'], 'snapshot exporter differs')
    for name, row in lock['source_files'].items():
        source = args.source_root / 'scripts/experiments' / name
        arm.need(file_row(source) == row, 'source changed before snapshot')
        shutil.copyfile(source, output / name); (output / name).chmod(row['mode'])
        arm.need(file_row(output / name) == row, 'snapshot source differs')
    for source, name, pin in ((args.source, 'zlib.tar.gz', arm.SOURCE_SHA),
                              (args.expected_packages, 'packages.lock', args.expected_packages_sha256)):
        shutil.copyfile(source, output / name)
        arm.need(arm.sha(output / name) == pin, 'snapshot input differs')


def cleanup_trial(trial, output, cancelled=None):
    """Fallback when cancellation killed the child launcher before its removal."""
    contract_path = trial / 'inputs/contract.json'
    if not contract_path.exists():
        return {'status': 'PASS', 'scope': 'launcher did not create a container contract'}
    contract = read_json(contract_path)
    arm.need(re.fullmatch(r'[0-9a-f]{32}', contract.get('nonce', '')), 'owned trial nonce required')
    name = 'cachy-asahi-arm-c01-' + contract['nonce']
    context = read_json(trial / '001-context.log')
    endpoint = context[0]['Endpoints']['docker']['Host']
    arm.need(endpoint in ('unix:///var/run/docker.sock', f'unix:///run/user/{os.getuid()}/docker.sock'), 'approved local cleanup endpoint required')
    output.mkdir()
    commands = arm.Commands(output, seconds=40)
    events = [] if cancelled is None else cancelled
    interrupted = []
    def command(label, argv, timeout):
        try:
            return commands.run(label, argv, timeout=timeout)
        except (arm.Cancelled, KeyboardInterrupt):
            # Commands has already terminated/reaped its tracked process group.
            # Its receipt cancellation must not abort the remaining teardown.
            events.append('container-cleanup'); interrupted.append(label)
            return None
    docker = ['docker', '--host=' + endpoint]
    query = docker + ['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']
    before = command('before', query, 10)
    if before is None:
        before = command('before-after-cancel', query, 5)
    if before is None:
        return {'status': 'FAIL', 'container': name, 'cancelled': True, 'absence_verified': False,
                'cleanup_uncertain': True, 'interrupted_commands': interrupted}
    arm.need(before.strip() in (b'', name.encode()), 'unexpected cleanup query result')
    if before.strip():
        command('remove', docker + ['rm', '-f', name], 15)
    after = command('after', query, 10)
    if after is None:
        after = command('after-cancel-recheck', query, 5)
    if after is None:
        return {'status': 'FAIL', 'container': name, 'cancelled': True, 'absence_verified': False,
                'cleanup_uncertain': True, 'interrupted_commands': interrupted}
    arm.need(after == b'', 'owned trial container still present')
    return {'status': 'FAIL' if interrupted else 'PASS', 'container': name, 'absence_verified': True,
            'cancelled': bool(interrupted), 'cleanup_uncertain': bool(interrupted), 'interrupted_commands': interrupted}


def project_evidence(trial, selected):
    """Project named text receipts only; no input cache, corpus bytes or binaries."""
    selected.mkdir()
    raw = trial / 'raw'
    chosen = {}
    for source, dest in ((trial / 'result.json', 'launcher-result.json'), (trial / '004-container.log', 'launcher-container.log'),
                         (raw / 'result.json', 'native-result.json'), (raw / 'environment.json', 'environment.json'),
                         (raw / 'corpus-manifest.json', 'corpus-manifest.json')):
        if source.exists():
            chosen[dest] = source
    commands = read_json(raw / 'commands.json') if (raw / 'commands.json').exists() else []
    projected = []
    for row in commands:
        copy = dict(row)
        if 'log' not in row:
            projected.append(copy); continue
        name = row['log']; arm.need(Path(name).name == name and name.endswith('.log'), 'flat declared native log required')
        # The pinned exporter rejects dependency-labelled paths. Keep the actual
        # bytes under an explicit public name and update the public receipt only.
        dest = name.replace('-dependencies.log', '-link-inputs.log')
        arm.need(dest not in chosen, 'public log projection collision')
        chosen[dest] = raw / name
        copy.update(log=dest, producer_log=name)
        projected.append(copy)
    for prefix in arm.build_names():
        for name in ('LICENSE.txt', 'Makefile.txt', 'zconf.h.txt', 'configure.log.txt'):
            source = raw / prefix / name
            if source.exists():
                chosen[prefix + '/' + name] = source
    arm.save(selected / 'commands.json', projected)
    total = 0
    for name, path in chosen.items():
        arm.regular(path); data = path.read_bytes(); total += len(data)
        arm.need(total <= 12 * 1024**2, 'public projection byte bound exceeded')
        if path.parent == raw and path.name.endswith('.log'):
            matching = [r for r in commands if r.get('log') == path.name]
            arm.need(len(matching) == 1 and hashlib.sha256(data).hexdigest() == matching[0].get('log_sha256'), 'native log projection hash differs')
        dest = selected / name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(data)
    arm.save(selected / 'projection.json', {'purpose': arm.EXPERIMENT + '-same-job-followup', 'raw_binary_and_corpus_exported': False,
                                          'files': {n: arm.sha(selected / n) for n in chosen}})


def export_public(snapshot_root, selected, output, pin):
    arm.need(arm.sha(snapshot_root / 'integration_export.py') == pin, 'exporter source drift')
    spec = importlib.util.spec_from_file_location('arm_c01_pinned_exporter', snapshot_root / 'integration_export.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.export_evidence(selected, output)


def export_artifacts(raw, output, verified):
    """Separate explicit development-output archive; never a root/image export."""
    # Recheck retained bytes and metadata immediately before selecting the finite
    # archive. A caller cannot transform the accepted receiver report into a new
    # allowlist or replace the driver between receipt verification and export.
    arm.need(arm.verify_result(raw, verified['contract']) == verified, 'verified export receipt differs')
    commands = read_json(raw / 'commands.json')
    by_name = {row['name']: row for row in commands}
    approved, drivers, outputs = {'strict-gzip.c': arm.STRICT_SHA}, [], []
    def command_reference(row):
        return {key: row[key] for key in ('name', 'argv', 'cwd', 'environment', 'exit_code',
                                          'log', 'log_sha256', 'log_bytes')}
    for build in verified['builds']:
        prefix = f"{build['variant']}-{build['attempt']}"
        for name, pin in build['artifacts'].items():
            arm.need(name in ('libz.a', 'example', 'minigzip'), 'unapproved compiled artifact')
            approved[prefix + '/' + name] = pin
        for name, pin in build['generated_configuration_sha256'].items():
            arm.need(name in ('Makefile', 'zconf.h', 'configure.log', 'LICENSE'), 'unapproved generated configuration')
            approved[prefix + '/' + name + '.txt'] = pin
        binary = prefix + '/strict-gzip'
        approved[binary] = build['strict_driver']['binary_sha256']
        drivers.append({'binary': binary, 'sha256': approved[binary], 'source': 'strict-gzip.c',
                        'source_sha256': arm.STRICT_SHA, 'archive': prefix + '/libz.a',
                        'cflags': arm.strict_flags(prefix)[0], 'ldflags': arm.strict_flags(prefix)[1],
                        'configured_flags': build['configured_flags'], 'elf': build['strict_driver']['elf'],
                        'compile': command_reference(by_name[prefix + '-strict-compile']),
                        'elf_command': command_reference(by_name[prefix + '-strict-elf'])})
    manifest = read_json(raw / 'corpus-manifest.json', verified.get('corpus_manifest_sha256'))
    names = {'empty.bin', 'onebyte.bin', 'repeated.txt', 'allbytes.bin', 'incompressible.bin',
             'heldout-source.bin', 'gzip-reference.gz', 'corrupt-crc.gz', 'truncated-trailer.gz'}
    arm.need(len(manifest.get('files', [])) == 9 and {row['path'] for row in manifest['files']} == names,
             'explicit public corpus allowlist required')
    for row in manifest['files']:
        arm.need(Path(row['path']).name == row['path'], 'flat approved corpus member required')
        approved['corpus/' + row['path']] = row['sha256']
    approved['corpus/manifest.json'] = verified['corpus_manifest_sha256']
    for plan in arm.command_plan(manifest):
        if not (plan['reject'] or plan['name'].endswith('-strict-valid')):
            continue
        command = by_name[plan['name']]
        name = Path(plan['target']).name
        approved[name] = command['stdout']['sha256']
        outputs.append({'member': name, 'role': 'strict-rejection-partial-output' if plan['reject'] else 'strict-valid-output',
                        'driver': str(Path(plan['argv'][0]).relative_to('/out')),
                        'input': 'corpus/' + Path(plan['source']).name,
                        'stdin': command['stdin'], 'stdout': command['stdout'],
                        'command': command_reference(command)})
    extras = arm.profile_adapter().artifact_files(arm, raw, verified['profile_verification']) if arm.profile_adapter() else {}
    arm.need(not set(extras) & set(approved), 'profile export collides with existing output')
    approved.update(extras)
    arm.need(len(approved) == 79 + len(extras) and len(drivers) == 4 and len(outputs) == 36, 'complete finite strict evidence archive required')
    output.mkdir(mode=0o700)
    bundle = output / f'development-{arm.EXPERIMENT}-outputs.tar.gz'
    total = 0
    with bundle.open('xb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|') as archive:
            for name, pin in sorted(approved.items()):
                path = raw / name; arm.regular(path, 32 * 1024**2 if name.endswith('.bin') else 8 * 1024**2); data = path.read_bytes()
                arm.need(hashlib.sha256(data).hexdigest() == pin, 'approved artifact changed before export')
                total += len(data); arm.need(total <= 64 * 1024**2, 'development artifact byte bound exceeded')
                entry = tarfile.TarInfo(name); entry.size = len(data)
                entry.mode = 0o755 if name.endswith(('/example', '/minigzip', '/strict-gzip')) else 0o644
                archive.addfile(entry, io.BytesIO(data))
                arm.need(stream.tell() <= 8 * 1024**2, 'compressed development artifact bound exceeded')
    arm.regular(bundle, 8 * 1024**2)
    receipt = {'purpose': arm.EXPERIMENT + '-same-job-followup', 'development_only': True, 'selected_for_release': False,
               'source_commit': verified['contract']['source_commit'], 'source_sha256': arm.SOURCE_SHA,
               'image_id': verified['contract']['image'], 'hardware_validation': 'NOT RUN',
               'performance_acceptance': 'NOT RUN', 'scope': 'verified zlib outputs, own MIT strict driver, strict output bytes and public corpus; no image/root/private-state export or execution replay',
               'files': approved, 'member_count': len(approved),
               'strict_driver_evidence': {'source': 'strict-gzip.c', 'source_sha256': arm.STRICT_SHA,
                                          'license': 'MIT', 'builds': drivers, 'outputs': outputs,
                                          'command_log_location': 'separate public evidence archive',
                                          'cross_decode_bytes': 'not retained; producer hash checks in public receipt'},
               'uncompressed_bytes': total, 'bundle_sha256': arm.sha(bundle), 'bundle_bytes': bundle.stat().st_size}
    arm.save(output / 'archive-manifest.json', receipt)
    return receipt


def publish_status(code, output, report, pin):
    """Seal controller status before this synchronous stage returns to its caller."""
    final = output / 'final-status'
    final.mkdir(exist_ok=True)
    arm.save(final / 'result.json', report)
    public = output / 'public-status'
    if public.exists():
        arm.need(public.is_dir() and not public.is_symlink() and shutil.rmtree.avoids_symlink_attacks,
                 'unsafe provisional status directory')
        # This provisional control bundle has not been handed to the caller.
        # Component receipt bundles are immutable; only this local status is resealed.
        shutil.rmtree(public)
    try:
        arm.need(export_public(code, final, public, pin)['evidence_export'] == 'PASS', 'final status export failed')
    except (OSError, ValueError, KeyError, TypeError):
        report.update(status='FAIL', evidence_export='FAIL', status_export='FAIL')
        arm.save(output / 'result.json', report)
        arm.save(final / 'result.json', report)
        raise


def run_stage(args):
    arm.need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
             os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid(), 'native ordinary nonroot stage controller required')
    arm.need(not any(os.environ.get(k) for k in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION')),
             'Docker overrides refused')
    lock, handoff = validate_inputs(args)
    out = args.output; out.mkdir(mode=0o700)
    code = out / 'source'
    launcher = out / 'launcher'; launcher.mkdir()
    trial = out / 'trial'
    report = {'schema_version': 1, 'purpose': PURPOSE, 'status': 'FAIL', 'source_commit': args.source_commit,
              'source_lock_sha256': args.lock_sha256, 'image_handoff': handoff, 'source_sha256': arm.SOURCE_SHA,
              'hardware_validation': 'NOT RUN', 'performance_acceptance': 'NOT RUN', 'selected_for_release': False}
    runner = arm.Commands(launcher, seconds=900)
    previous = {sig: signal.signal(sig, runner.cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
    cancelled = []
    verified = None
    try:
        snapshot(args, lock, code)
        argv = [sys.executable, '-B', str(code / 'arm_c01.py'), '--image', args.image, '--source', str(code / 'zlib.tar.gz'),
                '--source-commit', args.source_commit, '--expected-packages', str(code / 'packages.lock'),
                '--expected-packages-sha256', args.expected_packages_sha256, '--output', str(trial)]
        runner.run('trial', argv, timeout=880)
        receipt = read_json(trial / 'result.json')
        arm.need(receipt.get('status') == 'PASS' and receipt.get('image') == args.image and
                 receipt.get('controller_group_cleanup') == receipt.get('container_cleanup') == 'PASS', 'successful cleaned trial launcher required')
        contract = receipt['contract']
        arm.need(contract.get('source_commit') == args.source_commit and contract.get('packages_sha256') == args.expected_packages_sha256
                 and contract.get('runner_sha256') == lock['source_files']['arm_c01.py']['sha256']
                 and contract.get('corpus_sha256') == lock['source_files']['corpus.py']['sha256'], 'frozen trial contract differs')
        verified = arm.verify_result(trial / 'raw', contract, code / 'packages.lock', code / 'zlib.tar.gz')
        report['receiver_verification'] = verified.get('receiver_verification')
        for name in FILES:
            arm.need(file_row(code / name) == lock['source_files'][name], 'frozen trial source changed')
        report['status'] = 'PASS'
    except (arm.Cancelled, KeyboardInterrupt) as error:
        cancelled.append(type(error).__name__)
        report.update(status='FAIL', cancelled=True, error='native followup interrupted; review retained diagnostics')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        report['error'] = 'native followup failed; review sanitized retained diagnostics'
    finally:
        for sig in previous:
            signal.signal(sig, lambda signum, _: cancelled.append(signum))
        try:
            try:
                report['launcher_cleanup'] = 'PASS' if runner.stop() else 'FAIL'
            except (arm.Cancelled, KeyboardInterrupt):
                cancelled.append('launcher-cleanup')
                report['launcher_cleanup'] = 'FAIL'
            except (OSError, ValueError, subprocess.SubprocessError):
                report['launcher_cleanup'] = 'FAIL'
            try:
                report['container_cleanup'] = cleanup_trial(trial, out / 'cleanup', cancelled)
            except (arm.Cancelled, KeyboardInterrupt):
                cancelled.append('container-cleanup')
                report['container_cleanup'] = {'status': 'FAIL', 'cancelled': True, 'absence_verified': False,
                                               'cleanup_uncertain': True, 'error': 'owned container cleanup interrupted'}
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                report['container_cleanup'] = {'status': 'FAIL', 'absence_verified': False,
                                               'cleanup_uncertain': True, 'error': 'owned container cleanup could not be verified'}
            if report.get('launcher_cleanup') != 'PASS' or report['container_cleanup']['status'] != 'PASS' or cancelled:
                report['status'] = 'FAIL'
            arm.save(out / 'result.json', report)
            try:
                selected = out / 'selected'; project_evidence(trial, selected)
                exported = export_public(code, selected, out / 'public', lock['exporter']['sha256'])
                report['evidence_export'] = exported['evidence_export']
                if report['evidence_export'] != 'PASS':
                    report['status'] = 'FAIL'
                if report['status'] == 'PASS' and verified is not None:
                    report['development_artifacts'] = export_artifacts(trial / 'raw', out / 'public-artifacts', verified)
            except (OSError, ValueError, KeyError, TypeError):
                report.update(status='FAIL', evidence_export='FAIL', export_error='bounded public projection/export failed')
            if cancelled:
                report.update(status='FAIL', cancelled=True)
            arm.save(out / 'result.json', report)
            # Final controller status lives in its own manifest-bound bundle;
            # never rewrite already accepted/hash-bound component files.
            publish_status(code, out, report, lock['exporter']['sha256'])
            if cancelled:
                report.update(status='FAIL', cancelled=True)
                arm.save(out / 'result.json', report)
                publish_status(code, out, report, lock['exporter']['sha256'])
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    arm.late_cancellation(report, cancelled, out / 'result.json')
    if cancelled:
        publish_status(code, out, report, lock['exporter']['sha256'])
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--freeze', type=Path)
    parser.add_argument('--image'); parser.add_argument('--source-commit')
    for name in ('source', 'base-packages', 'expected-packages', 'handoff-dir', 'handoff-pins', 'lock', 'output'):
        parser.add_argument('--' + name, type=Path)
    for name in ('base-packages', 'expected-packages', 'handoff-pins', 'lock'):
        parser.add_argument('--' + name + '-sha256')
    args = parser.parse_args()
    try:
        if args.freeze:
            freeze(args.source_root, args.freeze); return 0
        arm.need(all(getattr(args, n) for n in ('source', 'base_packages', 'expected_packages', 'lock', 'output')), 'explicit retained inputs/new output required')
        return run_stage(args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('ARM-C01 followup refused; review pinned inputs and source contract', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
