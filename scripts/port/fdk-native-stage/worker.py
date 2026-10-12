#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Bounded worker; reuse the frozen builder/checker without editing their sources."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import EPOCH, INVENTORY_SHA, compare_result, load, need, save, verify_attempt
from runtime import Cancelled, Runner, cancellation_handlers, defer_signals
from broker import Broker


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


class BuilderCommands:
    SubprocessError = subprocess.SubprocessError
    TimeoutExpired = subprocess.TimeoutExpired
    STDOUT = subprocess.STDOUT
    DEVNULL = subprocess.DEVNULL

    def __init__(self, broker):
        self.broker = broker

    def check_output(self, command, text=False):
        need(text is True, 'builder-capture-policy')
        return self.broker.capture(command)

    def run(self, command, stdout=None, stderr=None, timeout=None):
        if command[:3] == ['docker', 'rm', '-f']:
            need(len(command) == 4, 'builder-remove-policy')
            result = self.broker.cleanup()
            return subprocess.CompletedProcess(command, int(result['status'] != 'PASS'))
        result = self.broker.build(command, timeout)
        need(hasattr(stdout, 'write') and stderr == subprocess.STDOUT, 'builder-log-policy')
        stdout.write(result.stdout)
        stdout.flush()
        return result


def execute(config, state=None):
    root = Path(config['snapshot'])
    reviewed = load(root / 'scripts/port/fdk-native-stage/reviewed-inputs.json')
    action = config['action']
    builder = module('build', root / 'scripts/build/build.py')
    receipt = {'status': 'FAIL', 'action': action, 'hardware': 'NOT RUN'}
    if state is not None:
        state.update(receipt=receipt, path=Path(config['private']) / (action + '-receipt.json'))
    broker = None
    try:
        if action == 'compare':
            comparator = module('compare', root / 'scripts/build/compare.py')
            attempts = [Path(config['private']) / ('build-' + str(i)) for i in (1, 2)]
            rows = [verify_attempt(p, reviewed, config['image'], builder.package, builder.recipe, builder.bind_artifact) for p in attempts]
            result = comparator.compare(*attempts)
            save(Path(config['private']) / 'comparison-detail.json', result)
            receipt['comparison'] = compare_result(result, rows[0]['filename'], [r['container_name'] for r in rows])
            need(rows[0]['filename'] == rows[1]['filename'], 'comparison-artifact-name')
            receipt['attempts'] = rows
        else:
            need(action in ('build-1', 'build-2'), 'worker-action')
            work = Path(config['private'])
            runner = Runner(config['timeout'] + 30, dict(os.environ), work / (action + '-docker-logs'))
            cleanup = Runner(60, dict(os.environ), work / (action + '-cleanup-logs'))
            broker = Broker(runner, cleanup, config['docker_binary'], config['docker_sha256'],
                            config['endpoint'], config['image'], os.getuid(), os.getgid(),
                            work / 'containers.json', config['nonce'], expected_mounts={
                                '/inputs': str(work / action / 'inputs'), '/out': str(work / action / 'artifacts'),
                                '/builder-entry.sh': str(root / 'scripts/build/container-entry.sh'),
                                '/expected-packages.lock': str(work / action / 'expected-packages.lock')})
            broker.initialize(expected_daemon=config['daemon'])
            builder.subprocess = BuilderCommands(broker)
            sys.argv = ['build.py', str(work / 'recipe'), '--image', config['image'], '--output',
                        str(work / action), '--mode', 'native', '--source-date-epoch', str(EPOCH),
                        '--network', 'none', '--timeout', str(config['timeout']),
                        '--expected-packages', str(work / 'packages.lock'), '--reviewed-inputs',
                        str(root / 'scripts/port/fdk-native-stage/reviewed-inputs.json')]
            need(builder.main() == 0, 'builder-failed')
            receipt['artifact'] = verify_attempt(work / action, reviewed, config['image'], builder.package, builder.recipe, builder.bind_artifact)
        receipt['status'] = 'PASS'
    except Cancelled:
        receipt['cancelled'] = True
        raise
    finally:
        with defer_signals() as events:
            if broker is not None:
                try:
                    receipt['cleanup'] = broker.cleanup()
                    receipt['cancelled'] = receipt.get('cancelled', False) or receipt['cleanup'].get('cancelled') is True
                    if receipt['cleanup']['status'] != 'PASS':
                        receipt['status'] = 'FAIL'
                except Exception:
                    receipt['cleanup'] = {'status': 'FAIL', 'absence_verified': False}
                    receipt['status'] = 'FAIL'
            if events:
                receipt.update(status='FAIL', cancelled=True)
            save(Path(config['private']) / (action + '-receipt.json'), receipt)
        if events:
            receipt.update(status='FAIL', cancelled=True)
            with defer_signals():
                save(Path(config['private']) / (action + '-receipt.json'), receipt)
            raise Cancelled(events[0])
    return int(receipt['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    state = {}
    try:
        with cancellation_handlers():
            return execute(load(args.config, args.config_sha256, 65536), state)
    except (Exception, Cancelled) as error:
        if state:
            state['receipt'].update(status='FAIL', cancelled=state['receipt'].get('cancelled', False) or isinstance(error, Cancelled))
            with defer_signals():
                try:
                    save(state['path'], state['receipt'])
                except Exception:
                    state['path'].unlink(missing_ok=True)
        print('fdk-worker-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
