#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit successor invocation; parent owns final image recovery/admission."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import SimpleNamespace

BASE = Path(__file__).resolve().parent

# Only exact source-issued validation reasons cross the private diagnostic boundary.
OUTPUT_REFUSALS = frozenset({
    'successor-bootstrap-binding',
    'successor-build-artifact-record',
    'successor-build-inventory',
    'successor-build-provenance',
    'successor-build-validation',
    'successor-builder-inventory',
    'successor-container-independence',
    'successor-container-journal',
    'successor-container-journal-binding',
    'successor-distinct-environments',
    'successor-native-result',
    'successor-native-result-binding',
    'successor-pair-comparison',
    'successor-pair-equality',
    'successor-pair-inputs',
    'successor-signature-result',
    'successor-signature-set',
    'successor-worker-count',
    'successor-worker-daemon',
    'successor-worker-receipt',
})


def initial_read(path, limit=8 * 1024**2):
    path = Path(path).absolute()
    if '..' in path.parts or any(not stat.S_ISDIR(p.lstat().st_mode) for p in path.parents):
        raise ValueError('successor-worker-parent')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= limit:
        raise ValueError('successor-worker-input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd); chunks = bytearray()
        while raw := os.read(fd, min(65536, limit + 1 - len(chunks))):
            chunks.extend(raw)
            if len(chunks) > limit: raise ValueError('successor-worker-input-bound')
        after, named = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(chunks) != before.st_size or any(getattr(before, k) != getattr(item, k)
                for item in (opened, after, named) for k in fields):
            raise ValueError('successor-worker-input-drift')
        return bytes(chunks)
    finally:
        os.close(fd)


def initial_decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result: raise ValueError('successor-worker-json-duplicate')
            result[key] = value
        return result
    def constant(value): raise ValueError('successor-worker-json-number')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    if type(value) is not dict: raise ValueError('successor-worker-config')
    return value


def contract_module(config):
    raw = initial_read(BASE / 'contract.py')
    pin = config.get('contract_sha256')
    if type(pin) is not str or re.fullmatch('[0-9a-f]{64}', pin) is None or hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('successor-worker-contract-pin')
    return source_module('contract', BASE / 'contract.py', raw)


def source_module(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


@contextmanager
def graph(config, deadline=None):
    """Execute packet-bound buffers; restore temporary project import bindings."""
    names = ('contract', 'job_runtime', 'packet', 'base_broker', 'evidence',
             'producer', 'package_checks', 'native_arm', 'build', 'compare')
    previous = {name: sys.modules.get(name) for name in names}
    paths = list(sys.path)
    try:
        c = contract_module(config)
        c.need(Path(config['source']) == BASE and Path(config['snapshot']) == BASE / 'native'
               and Path(config['adapter']) == BASE / 'providers/adapter', 'successor-worker-source')
        deadline = config['work_deadline'] if deadline is None else deadline
        _, packet = c.verify(BASE, config['packet_sha256'], deadline)
        buffers = {}
        for name, row in packet['files'].items():
            if name.endswith('.py'):
                c.live(deadline)
                path = BASE / name; raw = c.read(path, deadline=deadline)
                c.need(c.sha(raw) == row['sha256'], 'successor-worker-source-drift')
                buffers[path] = raw

        def load(name, path):
            path = Path(path)
            c.need(path in buffers, 'successor-worker-module-path')
            return source_module(name, path, buffers[path])

        for name in ('job_runtime', 'packet', 'base_broker', 'evidence', 'producer'):
            load(name, BASE / 'providers' / (name + '.py'))
        producer = sys.modules['producer']
        producer.module = load
        # The unchanged broker factory's loader executes the retained buffers.
        class CapturedLoader:
            def __init__(self, path): self.path = Path(path)
            def create_module(self, spec): return None
            def exec_module(self, value):
                c.need(self.path in buffers, 'successor-worker-adapter-path')
                exec(compile(buffers[self.path], str(self.path), 'exec'), value.__dict__)
        def spec(name, path):
            return importlib.util.spec_from_file_location(name, path, loader=CapturedLoader(path))
        sys.modules['base_broker'].importlib = SimpleNamespace(util=SimpleNamespace(
            spec_from_file_location=spec, module_from_spec=importlib.util.module_from_spec))
        load('package_checks', BASE / 'native/scripts/checks/package_checks.py')
        yield c, producer, load
    finally:
        sys.path[:] = paths
        for name, value in previous.items():
            if value is None: sys.modules.pop(name, None)
            else: sys.modules[name] = value


def environment(config):
    # Recovery runs in the parent, so reconstruct the same private tool environment.
    # This never changes the parent process's HOME or Docker configuration.
    root = Path(config['jobroot'])
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
            'HOME': os.environ['HOME'], 'DOCKER_CONFIG': str(root / 'docker-config')}


def owner(config, producer, deadline):
    """Clamp every newly constructed provider runner, including recovery resets."""
    producer.need(time.monotonic() < deadline, 'successor-deadline')
    cls = producer.broker_class(Path(config['adapter']))
    raw_runner = cls.runtime.Runner
    class BoundedRunner(raw_runner):
        def __init__(self, seconds, env, logs):
            super().__init__(seconds, env, logs)
            self.deadline = min(self.deadline, deadline)
        def run(self, *args, **kwargs):
            self.deadline = min(self.deadline, deadline)
            producer.need(time.monotonic() < self.deadline, 'successor-deadline')
            result = super().run(*args, **kwargs)
            producer.need(time.monotonic() < deadline, 'successor-deadline')
            return result
    cls.runtime.Runner = cls.accepted.Runner = BoundedRunner
    # Successor policy: actual HOME remains inherited; Docker's private config and
    # explicit GPG homedir isolate tool state. Reuse all original binary/socket/
    # config/UID predicates against the positively owned jobroot, including nested
    # recovery brokers. This does not claim the original private-HOME policy.
    original_local, inherited_home = cls.accepted.Broker._local, os.environ['HOME']
    def successor_local(self, runner):
        producer.need(runner.env.get('HOME') == inherited_home, 'successor-home-drift')
        return original_local(self, SimpleNamespace(env={**runner.env, 'HOME': config['jobroot']}))
    cls.accepted.Broker._local = successor_local
    class BoundedBroker(cls):
        def _operation(self, *args, **kwargs):
            if self.final_deadline is not None:
                self.final_deadline = min(self.final_deadline, deadline)
            self.runner.deadline = min(self.runner.deadline, deadline)
            self.cleanup_runner.deadline = min(self.cleanup_runner.deadline, deadline)
            producer.need(time.monotonic() < deadline, 'successor-deadline')
            result = super()._operation(*args, **kwargs)
            producer.need(time.monotonic() < deadline, 'successor-deadline')
            return result
        def _info(self, runner):
            runner.deadline = min(runner.deadline, deadline)
            producer.need(time.monotonic() < deadline, 'successor-deadline')
            return super()._info(runner)
    env = environment(config); root = Path(config['jobroot'])
    seconds = min(7200, deadline - time.monotonic())
    cli = BoundedRunner(seconds, {**env, 'DOCKER_BUILDKIT': '0'}, root / 'producer-docker-logs')
    cleanup_runner = BoundedRunner(min(180, seconds), env, root / 'producer-cleanup-logs')
    result = BoundedBroker(cli, cleanup_runner, config['docker_binary'], config['docker_sha256'],
        config['endpoint'], os.getuid(), os.getgid(), root / 'base-image.json', config['nonce'],
        jobroot=root, context=root / 'producer/context', iidfile=root / 'producer/image-id')
    # Only this freshly loaded private provider's cancellation type is unified.
    producer.jr.Cancelled = cls.runtime.Cancelled
    return result


def guarded_commands(producer, config, broker, runner, diagnostic, boundary, progress, recipe_order):
    class GuardedCommands(producer.ProducerCommands):
        def __init__(self):
            super().__init__(config, broker, runner, diagnostic, boundary)
            producer.need(len(recipe_order) == 4 and set(recipe_order) == set(producer.ORIGINAL_RECIPES),
                          'successor-recipe-order')
            self.expected = [(name, kind) for name in recipe_order
                             for kind in ('build-1', 'build-2', 'compare')]
            self.finished, self.started = [], []
            self.gpg_verified = 0
        def _run(self, command, *args):
            original = self.original_command(command)
            if len(command) > 1 and command[0] == sys.executable:
                producer.need(original is not None and len(self.started) == len(self.finished)
                              and len(self.started) < len(self.expected)
                              and original == self.expected[len(self.started)], 'successor-command-sequence')
                self.started.append(original); progress(self)
            result = super()._run(command, *args)
            if original is not None and type(result.returncode) is int and result.returncode == 0:
                self.finished.append(original)
            if command[0] == 'gpg' and '--verify' in command and type(result.returncode) is int and result.returncode == 0:
                self.gpg_verified += 1
            progress(self)
            return result
    return GuardedCommands()


def first_failure(receipt, error, producer):
    if receipt['first_failure'] is None:
        receipt['first_failure'] = (error.args[0] if type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in OUTPUT_REFUSALS
            else producer.cleanup_refusal(error))
    receipt['status'] = 'FAIL'
    receipt['cancelled'] |= isinstance(error, (producer.jr.Cancelled, KeyboardInterrupt))


def run(config):
    root = Path(config['jobroot'])
    receipt = {'schema_version': 1, 'baseline_id': config['baseline_id'],
        'source_commit': config['source_commit'], 'packet_sha256': config['packet_sha256'],
        'status': 'FAIL', 'cancelled': False, 'first_failure': None,
        'diagnostic': {'phase': 'preflight', 'outcome': 'not-run'},
        'native_code': None, 'build_invocations': 0, 'builds_completed': 0, 'comparisons_completed': 0,
        'signatures_verified': 0, 'image_id': None, 'daemon': None,
        'cleanup': 'PARENT RECOVERY REQUIRED', 'hardware': 'NOT RUN'}
    with graph(config) as (c, producer, load):
        c.live(config['work_deadline'])
        c.need(config['baseline_id'] == c.ID and not (root / 'native-worker.json').exists(), 'successor-worker-fresh')
        save = producer.save
        def persist(): save(root / 'native-worker.json', receipt)
        def diagnostic(value): receipt['diagnostic'] = value; persist()
        def boundary(value): pass  # Historical boundary schema is not successor admission.
        def progress(commands):
            receipt.update(build_invocations=sum(k != 'compare' for _, k in commands.started),
                builds_completed=sum(k != 'compare' for _, k in commands.finished),
                comparisons_completed=sum(k == 'compare' for _, k in commands.finished),
                signatures_verified=commands.gpg_verified)
            persist()
        persist()
        try:
            broker = owner(config, producer, config['work_deadline'])
            with broker.runtime.cancellation_handlers():
                receipt['daemon'] = broker.initialize(config.get('daemon'))
                tool = producer.jr.Runner(min(7200, config['work_deadline']-time.monotonic()),
                                          environment(config), root / 'producer-tool-logs')
                tool.deadline = min(tool.deadline, config['work_deadline'])
                reviews = c.decode(c.pinned(BASE / 'native/scripts/ci/recipes.lock.json', c.RECIPES))
                commands = guarded_commands(producer, config, broker, tool, diagnostic, boundary, progress,
                                            [Path(path).name for path in reviews])
                native = load('native_arm', Path(config['snapshot']) / 'scripts/ci/native_arm.py')
                native.subprocess = commands
                original_fetch, original_acquire = native.fetch, native.acquire
                def deny_network(*args, **kwargs): raise ValueError('successor-offline-cache-required')
                native.urllib = SimpleNamespace(request=SimpleNamespace(
                    Request=native.urllib.request.Request, urlopen=deny_network), error=native.urllib.error)
                def fetch(item, cache):
                    c.live(config['work_deadline'])
                    path = Path(cache) / native.input_name(item['filename'])
                    info = path.lstat()
                    c.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                           and info.st_uid == os.getuid() and info.st_size == item['size'], 'successor-offline-cache-required')
                    result = original_fetch(item, cache)
                    c.live(config['work_deadline'])
                    return result
                def acquire(*args, **kwargs):
                    commands.set_diagnostic('acquisition', 'started')
                    result = original_acquire(*args, **kwargs)
                    commands.set_diagnostic('acquisition', 'pass')
                    return result
                native.fetch, native.acquire = fetch, acquire
                code = native.main(['build', '--inputs', str(BASE / 'locks/inputs-successor.lock.json'),
                    '--inputs-sha256', c.INPUTS, '--recipes', str(BASE / 'native/scripts/ci/recipes.lock.json'),
                    '--recipes-sha256', c.RECIPES, '--cache', str(root / 'cache'), '--output', str(root / 'producer')])
                c.live(config['work_deadline'])
                receipt['native_code'] = code if type(code) is int else None
                progress(commands)
                c.need(type(code) is int and code == 0 and commands.finished == commands.expected
                       and commands.gpg_verified == 249, 'successor-native-result')
                receipt['image_id'] = broker.image
                commands.set_diagnostic('complete', 'started')
                _validate_outputs(receipt, config, c, load)
                receipt.update(status='PASS', diagnostic={'phase': 'complete', 'outcome': 'pass'})
        except BaseException as error:
            first_failure(receipt, error, producer)
        finally:
            persist()
    return int(receipt['status'] != 'PASS')


def cleanup(config, cleanup_deadline):
    """Recover only nonce/daemon/source-bound provider journals; never global prune."""
    result = {'status': 'FAIL', 'absence_verified': False, 'owned_image_absence': False,
              'cancelled': False, 'errors': []}
    recovery_end = min(cleanup_deadline, time.monotonic() + 180)
    with graph(config, recovery_end) as (c, producer, load):
        try:
            c.live(cleanup_deadline)
            c.need(cleanup_deadline <= config['cleanup_deadline'], 'successor-cleanup-deadline')
            broker = owner(config, producer, recovery_end)
            broker.initialize(config.get('daemon'))
            raw = broker.cleanup(remove_image=True)
            c.need(type(raw) is dict and raw.get('status') in ('PASS', 'FAIL')
                and all(type(raw.get(k)) is bool for k in ('absence_verified', 'owned_image_absence', 'cancelled'))
                and type(raw.get('errors')) is list and len(raw['errors']) <= 32
                and all(type(value) is str for value in raw['errors'])
                and (raw['status'] != 'PASS' or (raw['absence_verified'] and raw['owned_image_absence']
                     and not raw['cancelled'] and not raw['errors'])), 'successor-cleanup-result')
            for key in ('status', 'absence_verified', 'owned_image_absence', 'cancelled'):
                result[key] = raw[key]
            result['errors'] = [value if type(value) is str and value in producer.BASE_PROBE_POLICY_CODES
                                else 'unknown-error' for value in raw['errors']][:32]
            c.live(recovery_end)
        except BaseException as error:
            result.update(status='FAIL', absence_verified=False, owned_image_absence=False)
            result['cancelled'] |= isinstance(error, (producer.jr.Cancelled, KeyboardInterrupt))
            result['errors'].append(producer.cleanup_refusal(error))
    return result


def validate_receipt(receipt, config):
    with graph(config) as (c, producer, load):
        expected = {'schema_version', 'baseline_id', 'source_commit', 'packet_sha256', 'status',
            'cancelled', 'first_failure', 'diagnostic', 'native_code', 'build_invocations',
            'builds_completed', 'comparisons_completed', 'signatures_verified', 'image_id',
            'daemon', 'cleanup', 'hardware'}
        c.need(type(receipt) is dict and set(receipt) == expected and type(receipt['schema_version']) is int
            and receipt['schema_version'] == 1 and receipt['baseline_id'] == c.ID
            and all(receipt[k] == config[k] for k in ('source_commit', 'packet_sha256'))
            and receipt['status'] == 'PASS' and receipt['cancelled'] is False
            and receipt['first_failure'] is None and receipt['diagnostic'] == {'phase': 'complete', 'outcome': 'pass'}
            and receipt['cleanup'] == 'PARENT RECOVERY REQUIRED' and receipt['hardware'] == 'NOT RUN', 'successor-worker-receipt')
        for name, value in (('native_code', 0), ('build_invocations', 8), ('builds_completed', 8),
                            ('comparisons_completed', 4), ('signatures_verified', 249)):
            c.need(type(receipt[name]) is int and receipt[name] == value, 'successor-worker-count')
        c.need(type(receipt['image_id']) is str and re.fullmatch('sha256:[0-9a-f]{64}', receipt['image_id'])
            and receipt['image_id'] != 'sha256:' + '0'*64 and type(receipt['daemon']) is dict
            and set(receipt['daemon']) == {'id', 'architecture'} and type(receipt['daemon']['id']) is str
            and re.fullmatch('[A-Za-z0-9:_-]{8,128}', receipt['daemon']['id'])
            and receipt['daemon']['architecture'] in ('aarch64', 'arm64'), 'successor-worker-daemon')
        _validate_outputs(receipt, config, c, load)
    return receipt


def _validate_outputs(receipt, config, c, load):
    """Bounded metadata recheck; no archive reads or new cryptographic actors."""
    root = Path(config['jobroot']); output = root / 'producer'
    c.live(config['work_deadline'])
    inputs = c.decode(c.pinned(BASE / 'locks/inputs-successor.lock.json', c.INPUTS))
    reviews = c.decode(c.pinned(BASE / 'native/scripts/ci/recipes.lock.json', c.RECIPES))
    result = c.decode(c.read(output / 'result.json', 1024**2))
    required = {'mode': 'build', 'status': 'native-builds-and-byte-comparison-pass', 'native_build': 'PASS',
        'hardware_validation': 'NOT RUN', 'reviewed_inputs_sha256': c.INPUTS,
        'reviewed_recipes_sha256': c.RECIPES, 'bootstrap_script_sha256': c.NATIVE}
    c.need(all(result.get(k) == value for k, value in required.items())
        and type(result.get('verified_signed_packages')) is int and result['verified_signed_packages'] == 248,
        'successor-native-result-binding')
    lock = c.read(output / 'packages.lock', 1024**2)
    c.need(c.sha(lock) == c.INVENTORY and len(lock.splitlines()) == 341, 'successor-builder-inventory')
    captured_inputs = c.read(output / 'inputs.lock.json', 2 * 1024**2)
    bootstrap = c.decode(c.read(output / 'bootstrap.json', 1024**2))
    c.need(c.decode(captured_inputs) == inputs and bootstrap.get('status') == 'image-provisioned'
        and bootstrap.get('image_id') == receipt['image_id']
        and bootstrap.get('packages_lock_sha256') == c.INVENTORY
        and bootstrap.get('inputs_sha256') == c.sha(captured_inputs)
        and c.read(output / 'image-id', 1024).decode().strip() == receipt['image_id'], 'successor-bootstrap-binding')
    signatures = c.decode(c.read(output / 'signatures.json', 4 * 1024**2))
    expected = [inputs['rootfs'], *inputs['packages']]
    c.need(len(signatures) == 249 and set(signatures) == {row['filename'] for row in expected},
           'successor-signature-set')
    native = load('native_arm', BASE / 'native/scripts/ci/native_arm.py')
    for item in expected:
        c.live(config['work_deadline'])
        row = signatures[item['filename']]
        command = ['gpg', '--batch', '--no-options', '--homedir', str(output / 'gpg'), '--no-auto-key-retrieve',
            '--status-fd', '1', '--verify', str(root / 'cache' / (item['filename'] + '.sig')),
            str(root / 'cache' / item['filename'])]
        c.need(type(row) is dict and set(row) == {'command', 'exit_code', 'status', 'diagnostic'}
            and row['command'] == command and type(row['exit_code']) is int and row['exit_code'] == 0
            and type(row['status']) is type(row['diagnostic']) is str, 'successor-signature-result')
        native.valid_signature(row['status'], inputs['signer_fingerprint'])
    entry = c.sha(c.read(BASE / 'native/scripts/build/container-entry.sh'))
    names = set(); image = receipt['image_id']
    for path, hashes in reviews.items():
        c.live(config['work_deadline'])
        name = Path(path).name
        pair = []
        for attempt in (1, 2):
            directory = output / (name + '-' + str(attempt))
            row = c.decode(c.read(directory / 'provenance.json', 1024**2))
            c.need(row.get('status') == 'built-package-static-pass' and row.get('mode') == 'native'
                and row.get('image') == row.get('image_id') == image
                and row.get('recipe_inputs') == hashes and row.get('expected_packages_sha256') == c.INVENTORY
                and row.get('entry_script_sha256') == entry and row.get('builder_host_arch') in ('aarch64', 'arm64')
                and type(row.get('exit_code')) is int and row['exit_code'] == 0
                and type(row.get('source_date_epoch')) is int and row['source_date_epoch'] == inputs['source_date_epoch'],
                'successor-build-provenance')
            identity = row.get('clean_environment_id')
            c.need(type(identity) is str and re.fullmatch('cachy-asahi-[0-9a-f]{16}', identity)
                and identity not in names, 'successor-distinct-environments')
            names.add(identity)
            c.need(c.sha(c.read(directory / 'expected-packages.lock', 1024**2)) == c.INVENTORY
                and c.sha(c.read(directory / 'artifacts/packages.lock', 1024**2)) == c.INVENTORY,
                'successor-build-inventory')
            validation = c.decode(c.read(directory / 'validation.json', 4 * 1024**2))
            c.need(validation.get('errors') == [] and type(validation.get('artifacts')) is list
                and len(validation['artifacts']) == 1, 'successor-build-validation')
            artifacts = row.get('artifacts')
            c.need(type(artifacts) is dict and len(artifacts) == 1 and all(type(k) is type(v) is str
                and re.fullmatch('[A-Za-z0-9@+_.-]+', k) and re.fullmatch('[0-9a-f]{64}', v)
                for k, v in artifacts.items()), 'successor-build-artifact-record')
            pair.append(row)
        equal_fields = ('image', 'image_id', 'mode', 'source_date_epoch', 'recipe_inputs', 'recipe_metadata',
                        'expected_packages_sha256', 'entry_script_sha256', 'artifacts')
        c.need(all(k in pair[0] and k in pair[1] and pair[0][k] == pair[1][k] for k in equal_fields),
               'successor-pair-inputs')
        comparison = c.decode(c.read(output / (name + '-compare.json'), 1024**2))
        c.need(comparison.get('status') == 'contents-reproduced' and comparison.get('errors') == []
            and comparison.get('hardware_status') == 'NOT RUN' and type(comparison.get('packages')) is dict
            and set(comparison['packages']) == set(pair[0]['artifacts']), 'successor-pair-comparison')
        for value in comparison['packages'].values():
            c.need(type(value) is dict and set(value) == {'installed_contents_equal', 'pkginfo_equal',
                'bytes_equal', 'buildinfo_equal'} and all(value[k] is True for k in value), 'successor-pair-equality')
    journal = c.decode(c.read(root / 'base-image-containers.json', 65536))
    identity = journal.get('identity')
    # Reuse the packet-bound adapter policy: it records the canonical socket URL.
    endpoint = sys.modules['producer'].broker_class(Path(config['adapter'])).accepted.validate_endpoint(
        config['endpoint'], os.getuid())
    c.need(type(identity) is dict and identity.get('image') == image and identity.get('nonce') == config['nonce']
        and identity.get('endpoint') == endpoint and identity.get('binary_sha256') == config['docker_sha256']
        and identity.get('daemon') == receipt['daemon'] and type(identity.get('uid')) is int
        and identity['uid'] == os.getuid() and type(identity.get('gid')) is int and identity['gid'] == os.getgid(),
        'successor-container-journal-binding')
    rows = journal.get('containers')
    c.need(type(rows) is list and len(rows) == 9 and all(type(row) is dict for row in rows),
           'successor-container-journal')
    ids = [row.get('id') for row in rows]
    c.need(all(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) for value in ids)
        and len(set(ids)) == 9 and all(row.get('create_attempted') is True for row in rows)
        and {row.get('name') for row in rows} == names | {'cachy-asahi-probe-' + config['nonce']},
        'successor-container-independence')
    c.live(config['work_deadline'])


def validate_outputs(receipt, config):
    with graph(config) as (c, producer, load):
        _validate_outputs(receipt, config, c, load)
    return True


def failure_observation(receipt):
    diagnostic = receipt.get('diagnostic') if type(receipt) is dict else None
    phases = {'preflight', 'base-probe', 'host-probe', 'acquisition', 'gpg-import', 'gpg-verify',
              'bootstrap', 'original-build', 'original-compare', 'complete'}
    outcomes = {'not-run', 'started', 'pass', 'command-failed', 'delegate-refused', 'runner-failed', 'cancelled'}
    if type(diagnostic) is not dict or diagnostic.get('phase') not in phases or diagnostic.get('outcome') not in outcomes:
        return {'availability': 'UNOBSERVED'}
    # Only finite phase/outcome observations cross this diagnostic boundary.
    codes = {'os-error', 'unicode-error', 'key-error', 'type-error', 'value-error',
             'subprocess-error', 'unknown-error', 'cancelled'} | OUTPUT_REFUSALS
    failure = receipt.get('first_failure')
    return {'availability': 'OBSERVED', 'phase': diagnostic['phase'], 'outcome': diagnostic['outcome'],
            'first_failure': failure if type(failure) is str and failure in codes else 'unknown-error',
            'cancelled': receipt.get('cancelled') is True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    try:
        raw = initial_read(args.config, 65536)
        if re.fullmatch('[0-9a-f]{64}', args.config_sha256) is None or hashlib.sha256(raw).hexdigest() != args.config_sha256:
            raise ValueError('successor-worker-config-pin')
        return run(initial_decode(raw))
    except BaseException:
        print('successor-worker-refused', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
