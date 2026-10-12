#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Call unchanged native_arm.py build mode inside the bounded job worker."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_runtime as jr
from packet import INPUTS_SHA, RECIPES_SHA, load, need, save
from base_broker import broker_class


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

    def __init__(self, config, broker, runner):
        self.config, self.broker, self.runner = config, broker, runner
        self.root = Path(config['snapshot'])
        self.native_out = Path(config['jobroot']) / 'producer'
        self.actual_commands = []

    def run(self, command, stdout=None, stderr=None, timeout=60, text=False, capture_output=False):
        need(type(command) is list and all(type(v) is str for v in command), 'producer-command')
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
            result = self.runner.run(actual, timeout=timeout, separate_stderr=True,
                                     log='gpg-' + uuid.uuid4().hex + '.log')
            if capture_output:
                need(text is True and stdout is None and stderr is None, 'producer-GPG-streams')
                return subprocess.CompletedProcess(command, result.returncode,
                    result.stdout.decode('utf-8'), result.stderr.decode('utf-8'))
            need(hasattr(stdout, 'write') and stderr == subprocess.STDOUT, 'producer-GPG-log')
            stdout.write((result.stdout + result.stderr).decode('utf-8'))
            stdout.flush()
            return result
        if command[0] == 'docker':
            result = self.broker.command(command, timeout)
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
        need(text is True, 'producer-capture-text')
        if command[0] == 'docker':
            if command[:2] == ['docker', 'run']:
                result = self.broker.command(command, timeout)
                need(result.returncode == 0, 'producer-probe-failed')
                return result.stdout.decode().strip()
            return self.broker.capture(command)
        need(command == ['lscpu'], 'producer-host-command')
        result = self.runner.run(['/usr/bin/lscpu'], timeout=timeout)
        need(result.returncode == 0, 'producer-host-probe')
        return result.stdout.decode().strip()


def execute(config, state):
    cls = broker_class(Path(config['adapter']))
    jr.Cancelled = cls.runtime.Cancelled
    jobroot = Path(config['jobroot'])
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'LC_ALL', 'HOME', 'DOCKER_CONFIG')}
    runner = jr.Runner(config['producer_timeout'], env, jobroot / 'producer-tool-logs')
    cli = cls.runtime.Runner(config['producer_timeout'], {**env, 'DOCKER_BUILDKIT': '0'}, jobroot / 'producer-docker-logs')
    cleanup = cls.runtime.Runner(180, env, jobroot / 'producer-cleanup-logs')
    broker = cls(cli, cleanup, config['docker_binary'], config['docker_sha256'], config['endpoint'],
                 os.getuid(), os.getgid(), jobroot / 'base-image.json', config['nonce'], jobroot=jobroot,
                 context=jobroot / 'producer/context', iidfile=jobroot / 'producer/image-id')
    receipt = {'status': 'FAIL', 'cancelled': False, 'hardware': 'NOT RUN'}
    state.update(path=jobroot / 'producer-worker.json', receipt=receipt)
    try:
        broker.initialize(expected_daemon=config['daemon'])
        native = module('native_arm', Path(config['snapshot']) / 'scripts/ci/native_arm.py')
        native.subprocess = ProducerCommands(config, broker, runner)
        code = native.main(['build', '--inputs', str(Path(config['snapshot']) / 'scripts/ci/inputs.lock.json'),
            '--inputs-sha256', INPUTS_SHA, '--recipes', str(Path(config['snapshot']) / 'scripts/ci/recipes.lock.json'),
            '--recipes-sha256', RECIPES_SHA, '--cache', str(jobroot / 'cache'), '--output', str(jobroot / 'producer')])
        need(code == 0, 'original-producer-failed')
        receipt.update(status='PASS', image_id=broker.image)
    except jr.Cancelled:
        receipt.update(status='FAIL', cancelled=True)
        raise
    finally:
        with jr.defer_signals() as events:
            try:
                receipt['cleanup'] = broker.cleanup(remove_image=False)
                if receipt['cleanup'].get('status') != 'PASS':
                    receipt['status'] = 'FAIL'
                receipt['cancelled'] |= receipt['cleanup'].get('cancelled') is True
            except BaseException:
                receipt['cleanup'] = {'status': 'FAIL', 'absence_verified': False}
                receipt['status'] = 'FAIL'
            if events:
                receipt.update(status='FAIL', cancelled=True)
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
            with jr.defer_signals():
                try:
                    save(state['path'], state['receipt'])
                except BaseException:
                    state['path'].unlink(missing_ok=True)
        print('fdk-producer-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
