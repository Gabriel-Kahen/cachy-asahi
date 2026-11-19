#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Call unchanged native_arm.py build mode inside the bounded job worker."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_runtime as jr
from packet import INPUTS_SHA, RECIPES_SHA, load, need, save
from base_broker import broker_class
from evidence import (BASE_PROBE_CALLS, BASE_PROBE_POLICY_CODES, BASE_PROBE_REFUSALS,
                      EPOCH, new_boundary, producer_boundary)

PHASES = {'preflight', 'base-probe', 'host-probe', 'acquisition', 'gpg-import',
          'gpg-verify', 'bootstrap', 'original-build', 'original-compare', 'complete'}
OUTCOMES = {'not-run', 'started', 'pass', 'command-failed', 'delegate-refused',
            'runner-failed', 'cancelled'}


ORIGINAL_RECIPES = {
    'cachy-asahi-hyprland-settings': 'packages/desktop/cachy-asahi-hyprland-settings',
    'cachy-asahi-fish-config': 'packages/shells/cachy-asahi-fish-config',
    'cachy-asahi-zsh-config': 'packages/shells/cachy-asahi-zsh-config',
    'cachy-asahi-setup': 'packages/settings/cachy-asahi-setup',
}


def cleanup_journal(path):
    """Observe metadata only; missing journal is not container absence."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return 'ABSENT'
    except OSError:
        return 'UNOBSERVED'
    return 'REGULAR' if stat.S_ISREG(mode) else 'OTHER'


def cleanup_diagnostic(phase='preflight', call='not-run', journal='UNOBSERVED', result=None, error=None):
    """Finite private projection; never publish raw cleanup error strings."""
    need(type(phase) is str and phase in PHASES | {'UNOBSERVED'} and type(call) is str and
         call in ('UNOBSERVED', 'not-run', 'started', 'returned', 'raised') and type(journal) is str and
         journal in ('UNOBSERVED', 'ABSENT', 'REGULAR', 'OTHER'), 'producer-cleanup-diagnostic')
    value = {'schema_version': 1, 'scope': 'producer-containers', 'phase': phase,
             'call': call, 'journal': journal, 'reason': 'none', 'boundary_error': 'none', 'observation_error': 'none',
             'status': 'UNOBSERVED', 'absence_verified': 'UNOBSERVED', 'cancelled': 'UNOBSERVED'}
    if error is not None:
        value['reason'] = ProducerCommands.refusal(error)
    elif call == 'returned':
        if type(result) is not dict:
            value['reason'] = 'malformed-result'
            return value
        status, absence, cancelled = (result.get(key) for key in ('status', 'absence_verified', 'cancelled'))
        value.update(status=status if type(status) is str and status in ('PASS', 'FAIL') else 'UNOBSERVED',
                     absence_verified=absence if type(absence) is bool else 'UNOBSERVED',
                     cancelled=cancelled if type(cancelled) is bool else 'UNOBSERVED')
        errors = result.get('errors', [])
        if type(errors) is not list:
            value['reason'] = 'malformed-result'
        elif errors:
            first = errors[0]
            value['reason'] = first if type(first) is str and first in BASE_PROBE_POLICY_CODES | {
                'docker-cleanup-cancellation-uncertain'} else 'unknown-error'
        elif cancelled is True:
            value['reason'] = 'cancelled'
        elif 'UNOBSERVED' in (value['status'], value['absence_verified'], value['cancelled']):
            value['reason'] = 'malformed-result'
        elif status == 'FAIL':
            value['reason'] = 'returned-failure'
    return value


def cleanup_refusal(error):
    try:
        code = ProducerCommands.refusal(error)
        return code if type(code) is str and code in BASE_PROBE_REFUSALS else 'unknown-error'
    except BaseException:
        return 'unknown-error'


def cleanup_observation(phase='preflight', call='not-run', journal='UNOBSERVED', result=None, error=None):
    """Diagnostic failure cannot skip cleanup or change its acceptance."""
    try:
        return cleanup_diagnostic(phase, call, journal, result, error)
    except BaseException as failure:
        return {'schema_version': 1, 'scope': 'producer-containers',
                'phase': phase if type(phase) is str and phase in PHASES else 'UNOBSERVED',
                'call': call if type(call) is str and call in ('not-run', 'started', 'returned', 'raised') else 'UNOBSERVED',
                'journal': journal if type(journal) is str and journal in (
                    'ABSENT', 'REGULAR', 'OTHER') else 'UNOBSERVED',
                'reason': 'none', 'boundary_error': 'none', 'observation_error': cleanup_refusal(failure),
                'status': 'UNOBSERVED', 'absence_verified': 'UNOBSERVED', 'cancelled': 'UNOBSERVED'}


def worker_boundary(receipt):
    value = producer_boundary(receipt.get('boundary'), worker=True) or new_boundary(worker=True)
    value.update(worker_status=receipt['status'], worker_cancelled=receipt['cancelled'])
    need(producer_boundary(value, worker=True) is not None, 'producer-boundary')
    receipt['boundary'] = value


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


class BoundedText:
    def __init__(self, target):
        self.target, self.count = target, 0

    def write(self, text):
        self.count += len(text.encode('utf-8'))
        need(self.count <= jr.MAX_OUTPUT, 'producer-driver-output-bound')
        return self.target.write(text)

    def flush(self):
        self.target.flush()


class BuilderCommands:
    SubprocessError, TimeoutExpired = subprocess.SubprocessError, subprocess.TimeoutExpired
    STDOUT, DEVNULL = subprocess.STDOUT, subprocess.DEVNULL

    def __init__(self, broker):
        self.broker = broker

    def check_output(self, command, text=False):
        need(text is True, 'original-builder-stream')
        return self.broker.capture(command)

    def run(self, command, stdout=None, stderr=None, timeout=None):
        if command[:3] == ['docker', 'rm', '-f']:
            need(len(command) == 4, 'original-builder-remove')
            receipt = self.broker.cleanup(remove_image=False)
            return subprocess.CompletedProcess(command, int(receipt['status'] != 'PASS'))
        result = self.broker.build(command, timeout)
        need(hasattr(stdout, 'write') and stderr == subprocess.STDOUT, 'original-builder-log')
        stdout.write(result.stdout)
        stdout.flush()
        return result


class ProducerCommands:
    SubprocessError, TimeoutExpired = subprocess.SubprocessError, subprocess.TimeoutExpired
    STDOUT, DEVNULL = subprocess.STDOUT, subprocess.DEVNULL

    def __init__(self, config, broker, runner, diagnostic=None, boundary=None):
        self.config, self.broker, self.runner = config, broker, runner
        self.root = Path(config['snapshot'])
        self.native_out = Path(config['jobroot']) / 'producer'
        self.actual_commands = []
        self.diagnostic = {'phase': 'preflight', 'outcome': 'not-run'}
        self.on_diagnostic = diagnostic
        self.boundary = new_boundary(worker=True)
        self.on_boundary = boundary
        self.compared = set()

    def observe(self, **changes):
        value = {**self.boundary, **changes}
        need(producer_boundary(value, worker=True) is not None, 'producer-boundary')
        self.boundary = value
        if self.on_boundary is not None:
            self.on_boundary(dict(value))

    def original_command(self, command):
        if type(command) is not list or not all(type(value) is str for value in command):
            return None
        for name, recipe in ORIGINAL_RECIPES.items():
            compare = [sys.executable, str(self.root / 'scripts/build/compare.py'),
                       str(self.native_out / (name + '-1')), str(self.native_out / (name + '-2')),
                       '--require-bytes']
            if command == compare:
                return name, 'compare'
            image = self.broker.image
            if type(image) is not str or re.fullmatch(r'sha256:[0-9a-f]{64}', image) is None:
                continue
            for attempt in (1, 2):
                build = [sys.executable, str(self.root / 'scripts/build/build.py'), str(self.root / recipe),
                         '--image', image, '--mode', 'native', '--source-date-epoch', str(EPOCH),
                         '--expected-packages', str(self.native_out / 'packages.lock'),
                         '--reviewed-inputs', str(self.native_out / (name + '-review.json')),
                         '--timeout', '300', '--output', str(self.native_out / (name + '-' + str(attempt)))]
                if command == build:
                    return name, 'build-' + str(attempt)
        return None

    def set_diagnostic(self, phase, outcome, *, call=None, refusal_code='none'):
        need(type(phase) is type(outcome) is str and phase in PHASES and outcome in OUTCOMES,
             'producer-diagnostic')
        value = {'phase': phase, 'outcome': outcome}
        if phase == 'base-probe':
            need(type(call) is str and call in BASE_PROBE_CALLS and type(refusal_code) is str and
                 refusal_code in BASE_PROBE_REFUSALS | {'none'} and
                 (outcome not in ('not-run', 'started', 'pass') or refusal_code == 'none'), 'producer-diagnostic')
            value.update(call=call, refusal_code=refusal_code)
        self.diagnostic = value
        if self.on_diagnostic is not None:
            self.on_diagnostic(dict(self.diagnostic))

    def progress(self, phase, outcome, error=None):
        options = {}
        if phase == 'base-probe':
            options = {'call': self.diagnostic['call'], 'refusal_code': self.refusal(error) if error is not None else 'none'}
        self.set_diagnostic(phase, outcome, **options)

    @staticmethod
    def refusal(error):
        if isinstance(error, jr.Cancelled):
            return 'cancelled'
        if isinstance(error, UnicodeError):
            return 'unicode-error'
        if isinstance(error, ValueError) and error.args and type(error.args[0]) is str and error.args[0] in BASE_PROBE_POLICY_CODES:
            return error.args[0]
        for kind, code in ((OSError, 'os-error'), (KeyError, 'key-error'), (TypeError, 'type-error'), (ValueError, 'value-error'),
                           (subprocess.SubprocessError, 'subprocess-error')):
            if isinstance(error, kind):
                return code
        return 'unknown-error'

    def base_probe_call(self, command):
        for args, call in ((['docker', 'info', '--format', '{{.Architecture}}'], 'docker-info'),
                           (['docker', 'version'], 'docker-version'),
                           (['docker', 'context', 'inspect'], 'docker-context')):
            if command == args:
                return call
        image = self.broker.image
        if type(image) is str:
            if command == ['docker', 'image', 'inspect', image]:
                return 'image-inspect'
            if command == ['docker', 'run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                           '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat',
                           image, '/builder-packages.lock']:
                return 'inventory-probe'
        return 'unclassified'

    @contextmanager
    def operation(self, phase, call=None):
        self.set_diagnostic(phase, 'started', call=call)
        try:
            yield
        except jr.Cancelled as error:
            self.progress(phase, 'cancelled', error)
            raise
        except Exception as error:
            outcome = self.diagnostic['outcome']
            self.progress(phase, 'delegate-refused' if outcome == 'started' else outcome, error)
            raise

    def call(self, function, *args, **kwargs):
        phase = self.diagnostic['phase']
        try:
            result = function(*args, **kwargs)
        except jr.Cancelled as error:
            self.progress(phase, 'cancelled', error)
            raise
        except Exception as error:
            self.progress(phase, 'runner-failed', error)
            raise
        if isinstance(result, subprocess.CompletedProcess) and result.returncode:
            self.progress(phase, 'command-failed')
        return result

    def run(self, command, stdout=None, stderr=None, timeout=60, text=False, capture_output=False):
        phase = 'preflight'
        if type(command) is list and command and all(type(v) is str for v in command):
            if command[0] == 'gpg':
                phase = 'gpg-import' if '--import' in command else 'gpg-verify'
            elif command[0] == 'docker':
                phase = 'bootstrap' if command[1:2] == ['build'] else 'base-probe'
            elif len(command) >= 2:
                phase = 'original-compare' if command[1].endswith('/compare.py') else 'original-build'
        with self.operation(phase, self.base_probe_call(command) if phase == 'base-probe' else None):
            original = self.original_command(command) if phase in ('original-build', 'original-compare') else None
            if original:
                self.observe(last_recipe=original[0], last_command=original[1],
                             last_command_zero='UNOBSERVED')
            result = self._run(command, stdout, stderr, timeout, text, capture_output)
            if original and type(result.returncode) is int:
                if original[1] == 'compare' and result.returncode == 0:
                    self.compared.add(original[0])
                self.observe(last_command_zero=result.returncode == 0,
                             comparisons_completed=len(self.compared))
            self.progress(phase, 'command-failed' if result.returncode else 'pass')
            return result

    def _run(self, command, stdout, stderr, timeout, text, capture_output):
        need(type(command) is list and command and all(type(v) is str for v in command), 'producer-command')
        if command[0] == 'gpg':
            base = ['gpg', '--batch', '--no-options', '--homedir', str(self.native_out / 'gpg'), '--no-auto-key-retrieve']
            need(command[:len(base)] == base and command[len(base):len(base)+1] in (['--import'], ['--status-fd']),
                 'producer-GPG-policy')
            # Verify commands use '--status-fd', '1'; all filenames are private pinned cache inputs.
            if command[len(base)] == '--import':
                need(len(command) == len(base) + 2, 'producer-GPG-import')
                paths = command[-1:]
            else:
                need(command[len(base):len(base)+3] == ['--status-fd', '1', '--verify'] and
                     len(command) == len(base) + 5, 'producer-GPG-verify')
                paths = command[-2:]
            for value in paths:
                path = Path(value)
                need(path.parent == Path(self.config['jobroot']) / 'cache' and path.is_file() and
                     not path.is_symlink(), 'producer-GPG-cache-path')
            actual = ['/usr/bin/gpg', '--no-autostart', *command[1:]]
            self.actual_commands.append(actual)
            save(Path(self.config['jobroot']) / 'producer-commands.json', {'commands': self.actual_commands})
            if capture_output:
                need(text is True and stdout is None and stderr is None, 'producer-GPG-streams')
            else:
                need(hasattr(stdout, 'write') and stderr == subprocess.STDOUT, 'producer-GPG-log')
            result = self.call(self.runner.run, actual, timeout=timeout, separate_stderr=True,
                               log='gpg-' + uuid.uuid4().hex + '.log')
            if capture_output:
                try:
                    output, errors = result.stdout.decode('utf-8'), result.stderr.decode('utf-8')
                except UnicodeError:
                    self.set_diagnostic(self.diagnostic['phase'], 'delegate-refused')
                    raise
                return subprocess.CompletedProcess(command, result.returncode, output, errors)
            data = result.stdout + result.stderr
            binary = getattr(stdout, 'buffer', None)
            if binary is not None:
                stdout.flush()
                binary.write(data)
                binary.flush()
            else:
                stdout.write(data.decode('utf-8', errors='backslashreplace'))
            stdout.flush()
            return result
        if command[0] == 'docker':
            result = self.call(self.broker.command, command, timeout)
        else:
            need(command[0] == sys.executable and len(command) >= 2 and
                 command[1] in (str(self.root / 'scripts/build/build.py'), str(self.root / 'scripts/build/compare.py')),
                 'producer-python-command')
            need(hasattr(stdout, 'write') and stderr == subprocess.STDOUT, 'producer-driver-log')
            builder = module('build', self.root / 'scripts/build/build.py')
            saved = sys.argv
            try:
                sys.argv = command[1:]
                target = BoundedText(stdout)
                with redirect_stdout(target), redirect_stderr(target):
                    if command[1].endswith('/build.py'):
                        out = Path(command[command.index('--output') + 1])
                        self.broker.expected_mounts = {'/inputs': str(out / 'inputs'), '/out': str(out / 'artifacts'),
                            '/builder-entry.sh': str(self.root / 'scripts/build/container-entry.sh'),
                            '/expected-packages.lock': str(out / 'expected-packages.lock')}
                        builder.subprocess = BuilderCommands(self.broker)
                        code = builder.main()
                    else:
                        comparator = module('compare', self.root / 'scripts/build/compare.py')
                        code = comparator.main()
                return subprocess.CompletedProcess(command, code)
            finally:
                sys.argv = saved
        if capture_output:
            need(text and stderr is None and stdout is None, 'producer-capture')
            return subprocess.CompletedProcess(command, result.returncode, result.stdout.decode(), '')
        need(hasattr(stdout, 'write') and stderr == subprocess.STDOUT, 'producer-log')
        stdout.write(result.stdout.decode())
        stdout.flush()
        return result

    def check_output(self, command, text=False, timeout=60):
        phase = 'host-probe' if command == ['lscpu'] else 'base-probe'
        with self.operation(phase, self.base_probe_call(command) if phase == 'base-probe' else None):
            result = self._check_output(command, text, timeout)
            self.progress(phase, 'pass')
            return result

    def _check_output(self, command, text, timeout):
        need(type(command) is list and command and all(type(v) is str for v in command), 'producer-command')
        need(text is True, 'producer-capture-text')
        if command[0] == 'docker':
            if command[:2] == ['docker', 'run']:
                result = self.call(self.broker.command, command, timeout)
                need(result.returncode == 0, 'producer-probe-failed')
                return result.stdout.decode().strip()
            return self.call(self.broker.capture, command)
        need(command == ['lscpu'], 'producer-host-command')
        result = self.call(self.runner.run, ['/usr/bin/lscpu'], timeout=timeout)
        need(result.returncode == 0, 'producer-host-probe')
        return result.stdout.decode().strip()


def execute(config, state):
    jobroot = Path(config['jobroot'])
    receipt = {'status': 'FAIL', 'cancelled': False, 'hardware': 'NOT RUN',
               'diagnostic': {'phase': 'preflight', 'outcome': 'not-run'},
               'boundary': new_boundary(worker=True), 'cleanup_diagnostic': cleanup_observation()}
    state.update(path=jobroot / 'producer-worker.json', receipt=receipt)

    def diagnostic(value):
        receipt['diagnostic'] = dict(value)
        save(state['path'], receipt)

    def boundary(value):
        receipt['boundary'] = dict(value)
        save(state['path'], receipt)

    cls = broker_class(Path(config['adapter']))
    jr.Cancelled = cls.runtime.Cancelled
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'LC_ALL', 'HOME', 'DOCKER_CONFIG')}
    runner = jr.Runner(config['producer_timeout'], env, jobroot / 'producer-tool-logs')
    cli = cls.runtime.Runner(config['producer_timeout'], {**env, 'DOCKER_BUILDKIT': '0'}, jobroot / 'producer-docker-logs')
    cleanup = cls.runtime.Runner(180, env, jobroot / 'producer-cleanup-logs')
    broker = cls(cli, cleanup, config['docker_binary'], config['docker_sha256'], config['endpoint'],
                 os.getuid(), os.getgid(), jobroot / 'base-image.json', config['nonce'], jobroot=jobroot,
                 context=jobroot / 'producer/context', iidfile=jobroot / 'producer/image-id')
    commands = ProducerCommands(config, broker, runner, diagnostic=diagnostic, boundary=boundary)
    try:
        with commands.operation('preflight'):
            commands.call(broker.initialize, expected_daemon=config['daemon'])
            commands.set_diagnostic('preflight', 'pass')
        native = module('native_arm', Path(config['snapshot']) / 'scripts/ci/native_arm.py')
        native.subprocess = commands
        original_acquire, original_build = native.acquire, native.build

        def acquire(*args, **kwargs):
            commands.set_diagnostic('acquisition', 'started')
            try:
                result = original_acquire(*args, **kwargs)
            except jr.Cancelled:
                commands.set_diagnostic('acquisition', 'cancelled')
                raise
            except Exception:
                commands.set_diagnostic('acquisition', 'command-failed')
                raise
            commands.set_diagnostic('acquisition', 'pass')
            return result

        def build(*args, **kwargs):
            commands.set_diagnostic('bootstrap', 'started')
            return original_build(*args, **kwargs)

        native.acquire, native.build = acquire, build
        code = native.main(['build', '--inputs', str(Path(config['snapshot']) / 'scripts/ci/inputs.lock.json'),
            '--inputs-sha256', INPUTS_SHA, '--recipes', str(Path(config['snapshot']) / 'scripts/ci/recipes.lock.json'),
            '--recipes-sha256', RECIPES_SHA, '--cache', str(jobroot / 'cache'), '--output', str(jobroot / 'producer')])
        if type(code) is int:
            commands.observe(native_delegate_zero=code == 0)
        need(type(code) is int and code == 0, 'original-producer-failed')
        commands.set_diagnostic('complete', 'pass')
        receipt.update(status='PASS', image_id=broker.image)
    except jr.Cancelled:
        receipt.update(status='FAIL', cancelled=True)
        raise
    finally:
        with jr.defer_signals() as events:
            phase, journal, observation_error = 'UNOBSERVED', 'UNOBSERVED', 'none'
            try:
                phase = commands.diagnostic['phase']
                journal = cleanup_journal(jobroot / 'base-image-containers.json')
            except BaseException as error:
                observation_error = cleanup_refusal(error)
            receipt['cleanup_diagnostic'] = cleanup_observation(phase, 'started', journal)
            try:
                receipt['cleanup'] = broker.cleanup(remove_image=False)
                result = receipt['cleanup']
                receipt['cleanup_diagnostic'] = cleanup_observation(phase, 'returned', journal, result)
                status = result.get('status') if type(result) is dict else None
                absence = result.get('absence_verified') if type(result) is dict else None
                cancelled = result.get('cancelled') if type(result) is dict else None
                commands.observe(worker_cleanup_status=status if status in ('PASS', 'FAIL') else 'UNOBSERVED',
                                 worker_cleanup_absence=absence if type(absence) is bool else 'UNOBSERVED',
                                 worker_cleanup_cancelled=cancelled if type(cancelled) is bool else 'UNOBSERVED')
                if receipt['cleanup'].get('status') != 'PASS':
                    receipt['status'] = 'FAIL'
                receipt['cancelled'] |= receipt['cleanup'].get('cancelled') is True
            except BaseException as error:
                if receipt['cleanup_diagnostic']['call'] == 'returned':
                    receipt['cleanup_diagnostic']['boundary_error'] = cleanup_refusal(error)
                else:
                    receipt['cleanup_diagnostic'] = cleanup_observation(phase, 'raised', journal, error=error)
                receipt['cleanup'] = {'status': 'FAIL', 'absence_verified': False}
                receipt['status'] = 'FAIL'
                receipt['cancelled'] |= isinstance(error, jr.Cancelled)
            if observation_error != 'none':
                receipt['cleanup_diagnostic']['observation_error'] = observation_error
            if events:
                receipt.update(status='FAIL', cancelled=True)
            worker_boundary(receipt)
            save(state['path'], receipt)
        if events:
            raise jr.Cancelled(events[0])
    return int(receipt['status'] != 'PASS')


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    state = {}
    try:
        with jr.cancellation_handlers():
            return execute(load(args.config, args.config_sha256), state)
    except (Exception, jr.Cancelled) as error:
        if state:
            state['receipt'].update(status='FAIL', cancelled=state['receipt']['cancelled'] or isinstance(error, jr.Cancelled))
            worker_boundary(state['receipt'])
            with jr.defer_signals():
                try:
                    save(state['path'], state['receipt'])
                except BaseException:
                    state['path'].unlink(missing_ok=True)
        print('fdk-producer-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
