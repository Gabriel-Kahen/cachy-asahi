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
import json

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import EPOCH, INVENTORY_SHA, compare_result, load, need, save, verify_attempt
from runtime import Cancelled, Runner, cancellation_handlers, defer_signals
from broker import Broker
import worker_evidence as diagnostic
import inner_evidence


class ObservedBroker(Broker):
    """Pass-through observations of existing calls; no extra daemon operation."""
    def __init__(self, *args, observation, **kwargs):
        super().__init__(*args, **kwargs)
        self.observation, self.inspected = observation, None
        self.inner_state, self.inner_state_invalid, self.inner_inspection = None, False, None

    def _operation(self, argv, **kwargs):
        action = 'create' if argv[:1] == ['create'] else 'attach' if argv[:2] == ['start', '--attach'] else None
        if action:
            self.observation['current_predicate'] = 'CONTAINER_' + ('CREATE' if action == 'create' else 'ATTACH')
            self.observation['commands'][action] = diagnostic.no_exit('UNOBSERVED')
            self.observation['commands']['container'] = diagnostic.no_exit('UNOBSERVED')
        try:
            result = super()._operation(argv, **kwargs)
            if action:
                self.observation['commands'][action] = diagnostic.exit_record(result.returncode)
                if result.returncode: diagnostic.failure(self.observation, 'COMMAND_NONZERO')
                self.observation['current_predicate'] = 'BUILDER_CALL'
            if argv[:2] == ['container', 'inspect'] and len(argv) == 3:
                self.inspected = (argv[2], result.stdout)
            return result
        except BaseException as error:
            if action: diagnostic.failure(self.observation, diagnostic.error_reason(error, isinstance(error, Cancelled)))
            raise

    def _inspect(self, identifier, row, cleanup=False):
        previous = self.inner_state
        self.inner_state, self.inner_inspection = None, None
        self.inspected = None
        result = super()._inspect(identifier, row, cleanup=cleanup)
        # The original gate has validated these exact bytes against nonce/name/ID,
        # image, user, configuration, resources and mounts. Reuse, never query again.
        if self.inspected is not None and self.inspected[0] == identifier == result and \
                self.observation['commands']['attach']['kind'] != 'NOT_RUN':
            item = json.loads(self.inspected[1])[0]
            state = item.get('State', {})
            if type(state) is dict and state.get('Status') in ('exited', 'dead'):
                need(state.get('Running') is False and type(state.get('ExitCode')) is int and
                     0 <= state['ExitCode'] <= 255, 'worker-container-state')
                observed = diagnostic.exit_record(state['ExitCode'])
                need(self.observation['commands']['container'] in (diagnostic.no_exit('UNOBSERVED'), observed),
                     'worker-container-state-drift')
                self.observation['commands']['container'] = observed
                retained = {'container_id': item['Id'], 'container_name': row['name'], 'image': item['Image'],
                    'nonce': self.nonce, 'status': state['Status'], 'running': False, 'exit_code': state['ExitCode'],
                    'inspect_sha256': diagnostic.sha(self.inspected[1])}
                if previous is not None and previous != retained:
                    self.inner_state_invalid = True
                if not self.inner_state_invalid:
                    self.inner_state = retained
                    self.inner_inspection = self.inspected[1]
                else:
                    self.inner_state = None
        return result


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


def execute(config, state=None, config_sha=None):
    root = Path(config['snapshot'])
    action = config['action']
    observation = diagnostic.initial(config, config_sha)
    observation['inner'] = inner_evidence.unknown()
    receipt = {'status': 'FAIL', 'action': action, 'hardware': 'NOT RUN', 'cancelled': False,
               'diagnostics': observation, 'inner_context': None}
    if state is not None:
        state.update(receipt=receipt, path=Path(config['private']) / (action + '-receipt.json'))
    broker = None
    try:
        observation['current_predicate'] = 'REVIEWED_INPUTS'
        reviewed = load(root / 'scripts/port/fdk-native-stage/reviewed-inputs.json', diagnostic.RECIPE_SHA)
        observation['current_predicate'] = 'BUILDER_IMPORT'
        builder = module('build', root / 'scripts/build/build.py')
        if action == 'compare':
            observation['current_predicate'] = 'COMPARE_INPUTS'
            comparator = module('compare', root / 'scripts/build/compare.py')
            attempts = [Path(config['private']) / ('build-' + str(i)) for i in (1, 2)]
            rows = []
            for path in attempts:
                provenance, _ = diagnostic.capture(path / 'provenance.json', diagnostic.PROVENANCE_LIMIT)
                log_bytes, _ = diagnostic.capture(path / 'build.log', diagnostic.LOG_LIMIT)
                rows.append(verify_attempt(path, reviewed, config['image'], builder.package, builder.recipe,
                    builder.bind_artifact, record=diagnostic.decode(provenance), log_bytes=log_bytes))
            observation['current_predicate'] = 'COMPARE_CALL'
            result = comparator.compare(*attempts)
            save(Path(config['private']) / 'comparison-detail.json', result)
            observation['current_predicate'] = 'COMPARE_VERIFY'
            receipt['comparison'] = compare_result(result, rows[0]['filename'], [r['container_name'] for r in rows])
            need(rows[0]['filename'] == rows[1]['filename'], 'comparison-artifact-name')
            receipt['attempts'] = rows
        else:
            need(action in ('build-1', 'build-2'), 'worker-action')
            work = Path(config['private'])
            runner = Runner(config['timeout'] + 30, dict(os.environ), work / (action + '-docker-logs'))
            cleanup = Runner(60, dict(os.environ), work / (action + '-cleanup-logs'))
            observation['current_predicate'] = 'BROKER_INITIALIZE'
            broker = ObservedBroker(runner, cleanup, config['docker_binary'], config['docker_sha256'],
                            config['endpoint'], config['image'], os.getuid(), os.getgid(),
                            work / 'containers.json', config['nonce'], expected_mounts={
                                '/inputs': str(work / action / 'inputs'), '/out': str(work / action / 'artifacts'),
                                '/builder-entry.sh': str(root / 'scripts/build/container-entry.sh'),
                                '/expected-packages.lock': str(work / action / 'expected-packages.lock')}, observation=observation)
            broker.initialize(expected_daemon=config['daemon'])
            builder.subprocess = BuilderCommands(broker)
            sys.argv = ['build.py', str(work / 'recipe'), '--image', config['image'], '--output',
                        str(work / action), '--mode', 'native', '--source-date-epoch', str(EPOCH),
                        '--network', 'none', '--timeout', str(config['timeout']),
                        '--expected-packages', str(work / 'packages.lock'), '--reviewed-inputs',
                        str(root / 'scripts/port/fdk-native-stage/reviewed-inputs.json')]
            observation['current_predicate'] = 'BUILDER_CALL'
            observation['builder'].update(exit=diagnostic.no_exit('UNOBSERVED'), status='UNAVAILABLE')
            try:
                code = builder.main()
                observation['builder']['exit'] = diagnostic.exit_record(code)
                if code: diagnostic.failure(observation, 'COMMAND_NONZERO')
            except BaseException as error:
                diagnostic.failure(observation, diagnostic.error_reason(error, isinstance(error, Cancelled)))
                raise
            finally:
                # This records a captured failed provenance even if the builder raises.
                observation['current_predicate'] = 'BUILDER_PROVENANCE'
                provenance, log_bytes = diagnostic.observe_builder(observation, work / action, config, reviewed)
                try:
                    observation['inner'] = inner_evidence.capture_inner(work / action / 'artifacts',
                        work / action / 'inputs', reviewed, config, config_sha, getattr(broker, 'inner_state', None))
                except Exception:
                    observation['inner'] = inner_evidence.unknown('UNAVAILABLE')
                if observation['inner']['availability'] == 'BOUND':
                    try:
                        context = inner_evidence.binding_context(config, config_sha, reviewed, broker.inner_state)
                        need(provenance is not None, 'inner-provenance-required')
                        inner_evidence.check_context(context, observation['inner'], config, config_sha, reviewed,
                            commands=observation['commands'], provenance=provenance)
                        receipt['inner_context'] = context
                    except Exception:
                        observation['inner'] = inner_evidence.unknown('UNBOUND', observation['inner']['raw_sha256'])
            need(code == 0, 'builder-failed')
            need(observation['builder']['status'] == 'STATIC_PASS', 'builder-provenance-unverified')
            need(provenance is not None and log_bytes is not None, 'builder-captured-evidence-required')
            observation['current_predicate'] = 'ARTIFACT_VERIFY'
            receipt['artifact'] = verify_attempt(work / action, reviewed, config['image'], builder.package, builder.recipe,
                builder.bind_artifact, record=provenance, log_bytes=log_bytes)
        # Original artifact/comparison checks precede the modern observation requirement.
        observation['current_predicate'] = 'FINALIZATION'
        diagnostic.inner_complete(observation['inner'], action)
        receipt['status'] = 'PASS'
    except (Cancelled, KeyboardInterrupt):
        receipt['cancelled'] = True
        diagnostic.failure(observation, 'CANCELLED')
        raise
    except Exception as error:
        diagnostic.failure(observation, diagnostic.error_reason(error))
        raise
    finally:
        with defer_signals() as events:
            observation['current_predicate'] = 'CLEANUP'
            if broker is not None:
                try:
                    receipt['cleanup'] = broker.cleanup()
                    receipt['cancelled'] = receipt.get('cancelled', False) or receipt['cleanup'].get('cancelled') is True
                    if receipt['cleanup']['status'] != 'PASS':
                        receipt['status'] = 'FAIL'
                    clean = receipt['cleanup']
                    positive = clean.get('status') == 'PASS' and clean.get('absence_verified') is True and not clean.get('cancelled')
                    observation['cleanup'] = {'status': 'PASS' if positive else 'FAIL',
                        'absence': 'PASS' if positive else 'UNVERIFIED',
                        'reason': 'NONE' if positive else 'CANCELLED' if clean.get('cancelled') else 'UNVERIFIED'}
                    if not positive: receipt['status'] = 'FAIL'
                except BaseException as error:
                    receipt['cleanup'] = {'status': 'FAIL', 'absence_verified': False}
                    receipt['status'] = 'FAIL'
                    observation['cleanup'] = {'status': 'FAIL', 'absence': 'UNVERIFIED',
                        'reason': 'CANCELLED' if isinstance(error, (Cancelled, KeyboardInterrupt)) else
                                  'IO' if isinstance(error, OSError) else 'INVALID_DATA'}
                    receipt['cancelled'] |= isinstance(error, (Cancelled, KeyboardInterrupt))
            if events:
                receipt.update(status='FAIL', cancelled=True)
            if receipt['cancelled']:
                diagnostic.failure(observation, 'CANCELLED')
            elif observation['cleanup']['status'] == 'FAIL':
                diagnostic.failure(observation, 'INVALID_DATA')
            elif receipt['status'] == 'PASS':
                observation['current_predicate'] = 'COMPLETE'
            diagnostic.project(observation)
            save(Path(config['private']) / (action + '-receipt.json'), receipt)
        if events:
            receipt.update(status='FAIL', cancelled=True)
            diagnostic.failure(observation, 'CANCELLED', 'FINALIZATION')
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
            return execute(load(args.config, args.config_sha256, 65536), state, args.config_sha256)
    except (Exception, Cancelled, KeyboardInterrupt) as error:
        if state:
            cancelled = isinstance(error, (Cancelled, KeyboardInterrupt))
            state['receipt'].update(status='FAIL', cancelled=state['receipt'].get('cancelled', False) or cancelled)
            if 'diagnostics' in state['receipt']:
                diagnostic.failure(state['receipt']['diagnostics'], diagnostic.error_reason(error, cancelled), 'FINALIZATION')
            with defer_signals():
                try:
                    save(state['path'], state['receipt'])
                except Exception:
                    state['path'].unlink(missing_ok=True)
        print('fdk-worker-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
