#!/usr/bin/env python3
"""One finite native development job; local image consumers precede cleanup."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys

import packet
from common import command, digest, read_json, read_regular, require, save

ROOT = Path(__file__).resolve().parents[3]
STAGES = ('ksm', 'arm-c01-base', 'client', 'virtual')
PUBLIC_SELECTORS = {
    'ksm': {'adapter-status', 'recovery-status', 'public', 'public-material'},
    'arm-c01-base': {'adapter-status', 'recovery-status', 'public', 'owner/public', 'owner/public-status', 'owner/public-artifacts'},
    'client': {'adapter-status', 'owner-public'},
    'virtual': {'adapter-status', *('virtual-public/' + name for name in
                 ('result', 'events', 'minimal-frame', 'overlay-frame', 'qemu', 'tooling-launch',
                  'verify-launch', 'prepare-launch', 'runtime-launch', 'launcher'))},
}
CANCELLED = False
POLICY = None


def interrupt(*_):
    global CANCELLED
    CANCELLED = True
    raise KeyboardInterrupt()


def load_native(root):
    sys.path.insert(0, str(root / 'scripts/ci'))
    spec = importlib.util.spec_from_file_location('development_native_arm', root / 'scripts/ci/native_arm.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cancelled(controller=None):
    integration = sys.modules.get('integration')
    return CANCELLED or bool(controller and controller.cancelled) or bool(integration and integration.CANCEL_REQUESTED)


def run_client(controller, root, output, cache):
    from common import base_prerequisite
    report = {'status': 'NOT RUN', 'prerequisite': {}, 'public': []}
    output.mkdir(mode=0o700)
    public = output / 'adapter-status'; public.mkdir()
    try:
        prerequisite = base_prerequisite(controller)
        report['prerequisite'] = prerequisite
        report['status'] = 'FAIL'
        stage = root / 'scripts/client/stage.py'
        args = [sys.executable, '-B', str(stage), 'run', '--image', prerequisite['image_id'],
                '--bootstrap', str(controller.native_out / 'bootstrap.json'),
                '--bootstrap-sha256', digest(controller.native_out / 'bootstrap.json'),
                '--packages', prerequisite['packages_lock'], '--packages-sha256', prerequisite['packages_sha256'],
                '--source', str(root), '--stage-sha256', digest(stage), '--guard-sha256', digest(root / 'scripts/ci/source_suites.py'),
                '--output', str(output / 'owner-public')]
        code = command(args, output / 'private-driver.log', 420)
        owner = read_json(output / 'owner-public/receipt.json')
        require(code == 0 and owner.get('status') == 'PASS' and owner.get('native_client_tests') == 'PASS' and
                owner.get('container_cleanup') == owner.get('controller_tmp_removed') == 'PASS' and
                owner.get('image_id') == controller.image and owner.get('packages_sha256') == prerequisite['packages_sha256'],
                'native-client-acceptance-failed')
        report['status'] = 'PASS'
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['error_code'] = 'client-prerequisite-refused' if report['status'] == 'NOT RUN' else 'client-stage-failed'
        report['error_type'] = type(error).__name__
    finally:
        if cancelled(controller):
            report['status'] = 'FAIL'; report['error_code'] = 'cancelled'
        if (output / 'owner-public/receipt.json').is_file():
            report['public'].append(str((output / 'owner-public').absolute()))
        report['public'].append(str(public.absolute()))
        save(public / 'result.json', {key: value for key, value in report.items() if key != 'public'})
    return report


class Development:
    def __init__(self, root, output, cache, source_packet):
        self.root, self.output, self.cache, self.packet = root, output, cache, source_packet
        self.report = {'schema_version': 1, 'purpose': 'same-job-native-development', 'status': 'FAIL',
                       'development_only': True, 'selected_for_release': False, 'hardware_validation': 'NOT RUN',
                       'performance_acceptance': 'NOT RUN', 'production_trust': 'NOT RUN',
                       'source_commit': os.environ.get('GITHUB_SHA'), 'initial_integration': 'NOT RUN',
                       'publication': 'NOT RUN', 'stages': {name: {'status': 'NOT RUN', 'prerequisite': 'initial-build-not-completed'}
                                                     for name in STAGES}}
        self.public = []
        self.callback_entered = False
        (output / 'development-summary').mkdir()
        self.persist()

    def persist(self):
        try:
            save(self.output / 'result.json', self.report)
            save(self.output / 'development-summary/result.json', self.report)
        except BaseException:
            self.report.update(status='FAIL', error_code='durable-status-persistence-failed')
            print(json.dumps({'purpose': 'same-job-native-development', 'status': 'FAIL',
                              'error_code': 'durable-status-persistence-failed'}, sort_keys=True))
            raise

    def consume(self, controller):
        signal.setitimer(signal.ITIMER_REAL, 0)
        from base_stages import run_arm, run_ksm
        from virtual_stage import run_virtual
        self.callback_entered = True
        virtual_names = ('controller.py', 'audit_tooling.py', 'common.py', 'guest.py', 'prepare.py', 'run.py',
                         'gbm_probe.c', 'tooling.lock.json', 'tooling-audit.json')
        source_map = self.packet.get('source_files', {})
        if all('scripts/virtual/' + name in source_map for name in virtual_names):
            controller.virtual_packet_sha256 = {name: source_map['scripts/virtual/' + name]['sha256'] for name in virtual_names}
        # The initial image is still owned by Controller. It removes it only
        # after this callback returns, including after failed consumers.
        for name, action in (('ksm', run_ksm), ('arm-c01-base', run_arm), ('client', run_client), ('virtual', run_virtual)):
            if cancelled(controller):
                raise KeyboardInterrupt()
            output = self.output / name
            try:
                value = action(controller, self.root, output) if name == 'ksm' else action(controller, self.root, output, self.cache)
                require(value.get('status') in ('PASS', 'FAIL', 'NOT RUN', 'CAPTURED_REQUIRES_VISUAL_REVIEW'), 'invalid-stage-status')
                require(name == 'virtual' or value['status'] != 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'invalid-review-stage')
                if name == 'virtual' and value['status'] == 'PASS' and value.get('owner_status') == 'CAPTURED_REQUIRES_VISUAL_REVIEW':
                    value = dict(value, status='CAPTURED_REQUIRES_VISUAL_REVIEW', execution_status='PASS')
                for directory in value.get('public', []):
                    path = Path(directory).absolute()
                    require('..' not in path.parts and output.absolute() in path.parents and
                            path.relative_to(output.absolute()).as_posix() in PUBLIC_SELECTORS[name], 'stage-public-path-refused')
                    self.public.append(path)
                self.report['stages'][name] = {key: item for key, item in value.items() if key != 'public'}
            except KeyboardInterrupt:
                self.report['stages'][name] = {'status': 'FAIL', 'error_code': 'cancelled'}
                self.recover_public(name, output)
                raise
            except Exception as error:
                self.report['stages'][name] = {'status': 'FAIL', 'error_code': 'adapter-failed', 'error_type': type(error).__name__}
                self.recover_public(name, output)
            finally:
                self.persist()
        # Do not turn the original four-package summary into a new predicate.
        # Development failures stay authoritative in our separate aggregate.

    def recover_public(self, name, output):
        """Use adapter selectors, never a raw workspace walk after cancellation."""
        try:
            if name == 'virtual':
                from virtual_stage import public_paths
                paths = public_paths(output)
            elif name in ('ksm', 'arm-c01-base'):
                from base_stages import recovery_public
                paths = recovery_public(name, output)
            else:
                paths = [output / directory for directory in ('adapter-status', 'owner-public')
                         if (output / directory).is_dir()]
            for value in paths:
                path = Path(value).absolute()
                require('..' not in path.parts and output.absolute() in path.parents and
                        path.relative_to(output.absolute()).as_posix() in PUBLIC_SELECTORS[name], 'stage-public-path-refused')
                if path not in self.public:
                    self.public.append(path)
        except Exception:
            self.report['stages'][name]['failure_retention'] = 'FAIL'

    def run(self, native, argv):
        try:
            code = native.main(argv, integration_consumers=self.consume)
            self.report['initial_exit_code'] = code
        except KeyboardInterrupt:
            self.report['cancelled'] = True
        except Exception as error:
            self.report.update(error_code='initial-execution-failed', error_type=type(error).__name__)
        finally:
            try:
                initial = read_json(self.output / 'integration/result.json')
                self.report['initial_integration'] = 'PASS' if self.report.get('initial_exit_code') == 0 and initial.get('status') == 'PASS' else 'FAIL'
                self.report['initial_cleanup'] = initial.get('owned_image_cleanup', {'status': 'NOT RUN'})
            except (OSError, ValueError):
                self.report['initial_integration'] = 'FAIL'
            self.report['callback_entered'] = self.callback_entered
            self.report['cancelled'] = self.report.get('cancelled', False) or cancelled()
            self.persist()
        return self.report


def public_policy():
    global POLICY
    if POLICY is None:
        path = ROOT / 'scripts/ci/integration_export.py'
        require(digest(path) == '1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c', 'public-policy-source-drift')
        spec = importlib.util.spec_from_file_location('development_public_policy', path)
        POLICY = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(POLICY)
    return POLICY


def public_tree(root, opaque_approved=None):
    require('..' not in root.parts and root.is_dir() and not root.is_symlink() and
            all(stat.S_ISDIR(path.lstat().st_mode) for path in root.parents), 'public-directory-required')
    count, size = 0, 0
    policy = public_policy()
    opaque_approved = opaque_approved or {}
    for path in root.rglob('*'):
        info = path.lstat()
        require(not path.is_symlink(), 'public-symlink-refused')
        require(not any(policy.SENSITIVE_PATH.search(part) for part in path.relative_to(root).parts), 'public-sensitive-path-refused')
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'public-regular-file-required')
        count += 1; size += info.st_size
        require(count <= 4096 and size <= 16 * 1024**2, 'public-bundle-bound-exceeded')
        relative = path.relative_to(root).as_posix()
        source = False
        if root.name == 'public-material' and relative.startswith('source/'):
            name = relative.removeprefix('source/')
            source = name in packet.KSM_FILES
            require(source and digest(path) == read_json(ROOT / 'manifests/reviewed/ksmctl.json').get(name), 'public-gpl-source-binding-refused')
        binary = (root.name == 'public-material' and re.fullmatch(r'attempt-[12]/cachy-asahi-ksmctl-0\.1\.0-1-any\.pkg\.tar\.(xz|zst|gz)', relative)) or (
            root.name == 'public-artifacts' and relative == 'development-ARM-C01-outputs.tar.gz') or (
            root.name in ('minimal-frame', 'overlay-frame') and relative == root.name.removesuffix('-frame') + '.ppm')
        if relative in opaque_approved:
            row = opaque_approved[relative]
            require(row['bytes'] == info.st_size and row['sha256'] == digest(path), 'public-material-binding-refused')
            binary = True
        require(source or binary or path.suffix in policy.SUFFIXES, 'public-file-selector-refused')
        if source or path.suffix in policy.SUFFIXES or (relative in opaque_approved and path.suffix == '.conf'):
            text = read_regular(path, policy.FILE_LIMIT).decode('utf-8')
            require(not policy.PRIVATE_CONTENT.search(text) and
                    all(ord(char) >= 32 or char in '\n\r\t' for char in text), 'public-text-policy-refused')
        else:
            require(not re.search(rb'-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:[A-Z0-9 ]* )?PRIVATE KEY)-----',
                                  read_regular(path, 8 * 1024**2)), 'public-private-armor-refused')
    require(count > 0, 'empty-public-bundle')


def publish(development, bundle, emit=print):
    """Only existing producers' explicit public selectors reach workflow logs."""
    report = development.report
    roots = list(development.public)
    native = development.output / 'native'
    if native.is_dir():
        roots.append(native)
    initial = development.output / 'integration/public'
    if initial.is_dir():
        roots.extend(initial / name for name in ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites', 'summary')
                     if (initial / name).is_dir())
        try:
            initial_status = read_json(development.output / 'integration/result.json')
        except (OSError, ValueError):
            initial_status = {}
        for directory, stage in (('fixture-archives', 'fixtures'), ('signer-public-artifacts', 'signer'), ('repository-public-artifacts', 'repository')):
            path = initial / directory
            if path.exists() or initial_status.get('stages', {}).get(stage, {}).get('status') == 'PASS':
                roots.append(path)
    records = []
    for root in roots:
        try:
            # The original bootstrap exporter alone has the preexisting
            # context/GPG exclusion; new stages must supply explicit trees.
            if root != native:
                if root.parent == initial and root.name in ('fixture-archives', 'signer-public-artifacts', 'repository-public-artifacts'):
                    from initial_artifacts import receive
                    received = receive(ROOT, development.output / 'integration', root)
                    public_tree(root, {**received['opaque_approved'], **received['text_approved']})
                else:
                    public_tree(root)
            data = bundle(root)
            require(len(data) <= 8 * 1024**2, 'compressed-bundle-bound-exceeded')
            name = 'development-' + root.relative_to(development.output).as_posix().replace('/', '-')
            pin = hashlib.sha256(data).hexdigest()
            emit(f'CACHY_ASAHI_EVIDENCE_BEGIN {name} sha256={pin} bytes={len(data)}')
            emit(base64.encodebytes(data).decode(), end='')
            emit(f'CACHY_ASAHI_EVIDENCE_END {name}')
            records.append({'name': name, 'archive_root': root.name, 'sha256': pin, 'bytes': len(data), 'status': 'PASS'})
        except Exception as error:
            records.append({'name': 'development-' + root.relative_to(development.output).as_posix().replace('/', '-'),
                            'status': 'FAIL', 'error_code': 'bounded-publication-failed', 'error_type': type(error).__name__})
    report['bundles'] = records
    report['publication'] = 'PASS' if records and all(row['status'] == 'PASS' for row in records) else 'FAIL'
    stages = report['stages']
    required = (report.get('initial_integration') == 'PASS' and report.get('initial_cleanup', {}).get('status') == 'PASS'
                and not report.get('cancelled') and report['publication'] == 'PASS')
    required = required and all(stages[name]['status'] == 'PASS' for name in STAGES[:-1])
    virtual = stages['virtual']['status']
    report['status'] = ('CAPTURED_REQUIRES_VISUAL_REVIEW' if virtual == 'CAPTURED_REQUIRES_VISUAL_REVIEW' else 'PASS') if required and virtual in ('PASS', 'CAPTURED_REQUIRES_VISUAL_REVIEW') else 'FAIL'
    save(development.output / 'result.json', report)
    summary = development.output / 'development-summary'; summary.mkdir(exist_ok=True)
    save(summary / 'result.json', report)
    try:
        public_tree(summary)
        data = bundle(summary); pin = hashlib.sha256(data).hexdigest()
        emit(f'CACHY_ASAHI_EVIDENCE_BEGIN development-observed-summary sha256={pin} bytes={len(data)}')
        emit(base64.encodebytes(data).decode(), end='')
        emit('CACHY_ASAHI_EVIDENCE_END development-observed-summary')
    except Exception:
        report.update(status='FAIL', publication='FAIL', error_code='final-summary-publication-failed')
        save(development.output / 'result.json', report)
        save(summary / 'result.json', report)
    emit(json.dumps(report, sort_keys=True))
    return report['status'] in ('PASS', 'CAPTURED_REQUIRES_VISUAL_REVIEW')


def close_boundary(development, previous, timer):
    """Own pending delivery until cancellation has a durable terminal receipt."""
    global CANCELLED
    def remember(*_):
        global CANCELLED
        CANCELLED = True
    failed = False
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, set(previous))
    # Previous default handlers cannot resume before pending delivery is
    # observed and recorded. The closing handlers only remember signals.
    for sig in previous:
        try:
            signal.signal(sig, remember)
        except KeyboardInterrupt:
            CANCELLED = failed = True
        except Exception:
            failed = True
    try:
        signal.setitimer(signal.ITIMER_REAL, *timer)
    except KeyboardInterrupt:
        CANCELLED = failed = True
    except Exception:
        failed = True
    if signal.sigpending() & set(previous):
        CANCELLED = True
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    except KeyboardInterrupt:
        CANCELLED = failed = True
    except Exception:
        failed = True
    def record_failure():
        development.report.update(status='FAIL', cancelled=CANCELLED, error_code='terminal-finalization-failed')
        development.persist()
        print(json.dumps(development.report, sort_keys=True))
    if failed or CANCELLED:
        record_failure()
    for sig, handler in previous.items():
        try:
            signal.signal(sig, handler)
        except KeyboardInterrupt:
            CANCELLED = failed = True
        except Exception:
            failed = True
    if failed or CANCELLED:
        record_failure()
    return failed or CANCELLED


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inputs-sha256', 'recipes-sha256', 'integration-sha256', 'development-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--packet', type=Path, default=ROOT / 'scripts/ci/development/packet.lock.json')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args(argv)
    pins = {'scripts/ci/inputs.lock.json': args.inputs_sha256, 'scripts/ci/recipes.lock.json': args.recipes_sha256,
            'scripts/ci/integration.lock.json': args.integration_sha256}
    try:
        source_packet = packet.preflight(ROOT, args.packet, args.development_sha256, os.environ.get('GITHUB_SHA', ''))
        require(all(source_packet['metadata_pins'].get(name) == pin for name, pin in pins.items()), 'runtime-metadata-pins-drift')
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'purpose': 'same-job-native-development', 'status': 'FAIL', 'source_preflight': 'FAIL',
                          'execution': 'NOT RUN', 'error_code': 'reviewed-source-packet-refused'}, sort_keys=True))
        raise
    if args.check_only:
        print('development source packet verified; execution NOT RUN')
        return 0
    output, cache = args.output.absolute(), args.cache.absolute()
    require('..' not in output.parts and '..' not in cache.parts and not cache.is_symlink() and
            not any(p.is_symlink() for p in cache.parents), 'safe-output-cache-required')
    require(not output.exists() and not output.is_symlink() and not any(p.is_symlink() for p in output.parents), 'fresh-output-required')
    require(ROOT not in output.parents and ROOT not in cache.parents and output not in cache.parents and cache not in output.parents and output != cache,
            'disjoint-output-cache-required')
    output.mkdir(mode=0o700)
    cache.mkdir(mode=0o700, exist_ok=True)
    development = Development(ROOT, output, cache, source_packet)
    development.report['source_packet_sha256'] = args.development_sha256
    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    code = 1
    finalization_failed = False
    try:
        native = load_native(ROOT)
        native_args = ['integration', '--inputs-sha256', args.inputs_sha256, '--recipes-sha256', args.recipes_sha256,
                       '--integration-sha256', args.integration_sha256, '--integration-output', str(output / 'integration'),
                       '--cache', str(cache), '--output', str(output / 'native')]
        signal.setitimer(signal.ITIMER_REAL, 3000)
        development.run(native, native_args)
        signal.setitimer(signal.ITIMER_REAL, 0)
        from log_evidence import bundle
        try:
            code = 0 if publish(development, bundle) else 1
        except KeyboardInterrupt:
            development.report.update(status='FAIL', cancelled=True, publication='FAIL', error_code='publication-cancelled')
            with_signal = {sig: signal.signal(sig, signal.SIG_IGN) for sig in previous}
            try:
                development.persist()
                print(json.dumps(development.report, sort_keys=True))
            finally:
                for sig, handler in with_signal.items():
                    signal.signal(sig, handler)
            code = 1
    finally:
        finalization_failed = close_boundary(development, previous, previous_timer)
    return 1 if finalization_failed else code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, KeyboardInterrupt):
        print('FAIL: development boundary/source refusal', file=sys.stderr)
        sys.exit(1)
