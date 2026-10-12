# SPDX-License-Identifier: MIT
"""Same-job pending capture and terminal-only external-authority handoff."""
from contextlib import contextmanager
from pathlib import Path
import re
import time

import capture
import launch
import producer

STAGES = ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites')
ORIGINALS = {'cachy-asahi-fish-config', 'cachy-asahi-zsh-config',
             'cachy-asahi-hyprland-settings', 'cachy-asahi-setup'}
REFS = {'aggregate', 'repository', 'repository_contract', 'reset', 'public_manifest', 'public_acceptance',
        'cleanup', 'bootstrap', 'packages', 'current_inputs', 'fixture_manifest', 'integration_lock',
        'recipes_lock', 'projection', 'projected_repository', 'runner'}
LEGACY_LOGS = {'gpg-untrusted-A-status': 'signature-untrusted-A-status',
               'gpg-tampered-package-status': 'signature-tampered-package-status',
               'gpg-tampered-database-status': 'signature-tampered-database-status',
               'gpg-revoked-A-status': 'signature-revoked-A-status',
               'revoke-A-signing-home': 'revoke-A-signing-context',
               'revoke-A-verification-home': 'revoke-A-verification-context'}


def pinned(raw, pin):
    capture.need(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) and capture.digest(raw) == pin, 'external-record-pin')
    return capture.decode(raw)


def identity(value):
    patterns = {'source_commit': '[0-9a-f]{40}', 'recipe_source_commit': '[0-9a-f]{40}',
                'run_id': '[1-9][0-9]{0,19}', 'run_attempt': '[1-9][0-9]{0,9}',
                'nonce': '[0-9a-f]{32}', 'image_id': 'sha256:[0-9a-f]{64}'}
    capture.need(type(value) is dict and set(value) == set(patterns), 'job-identity')
    for key, pattern in patterns.items():
        capture.need(type(value[key]) is str and re.fullmatch(pattern, value[key]), 'job-identity')
    return dict(value)


def command_contract(command, *, deadline, cancelled=None):
    """Resolve the manifest just created by the original producer, not a template."""
    capture.check(deadline, cancelled)
    mounts = [command[index + 1] for index, item in enumerate(command[:-1]) if item == '--mount']
    inputs = [value for value in mounts if value.endswith(',dst=/inputs,readonly')]
    capture.need(len(inputs) == 1 and inputs[0].startswith('type=bind,src=/'), 'input-mount')
    source = inputs[0][len('type=bind,src='):-len(',dst=/inputs,readonly')]
    raw = capture.read(Path(source) / 'manifest.json', 1024**2, deadline=deadline)
    capture.check(deadline, cancelled)
    capture.need(command.count('--inputs-sha256') == 1 and
                 capture.digest(raw) == command[command.index('--inputs-sha256') + 1], 'actual-manifest-pin')
    return capture.decode(raw)


class Pending:
    """Own observation refs. Never infer final PASS from the consumer callback."""
    def __init__(self, private_root, producer_raw, producer_pin, *, job_deadline, cancelled=None):
        self.root = Path(private_root).absolute()
        capture.need(capture.digest(producer_raw) == producer_pin, 'producer-source-pin')
        self.producer_raw, self.producer_pin = producer_raw, producer_pin
        self.deadline, self.cancelled = job_deadline, cancelled
        self.contract, self.checkpoints, self.receipt = None, None, None
        self.transport, self.original_command = None, None
    def resolve(self, command):
        capture.check(self.deadline, self.cancelled)
        capture.need(self.contract is None, 'multiple-repository-launches')
        self.contract = command_contract(command, deadline=self.deadline, cancelled=self.cancelled)
        self.original_command = list(command)
        if self.transport is not None:
            expected = launch.validate_command(command, self.contract)
            self.transport.bind(expected['name'], expected['image'])
        self.checkpoints = capture.Checkpoints(self.root, self.contract['nonce'], deadline=self.deadline, cancelled=self.cancelled)
        return self.contract
    def prepare(self, command):
        expected = launch.validate_command(command, self.contract)
        target = expected['binds']['/runner'] / 'producer.py'
        # The runner belongs to the original same-job controller. The only added
        # source is separately pinned; repository.py and /out stay unchanged.
        capture.write_atomic(target, self.producer_raw, deadline=self.deadline)
        capture.need(capture.digest(capture.read(target, deadline=self.deadline)) == self.producer_pin, 'prepared-producer-drift')
        return self.producer_pin
    def checkpoint(self, frame, deadline):
        capture.need(self.checkpoints is not None, 'checkpoint-before-contract')
        return self.checkpoints.receive(frame, deadline)
    @contextmanager
    def interpose(self, integration, transport):
        capture.need(self.transport is None, 'overlapping-transport-scope')
        self.transport = transport
        try:
            with launch.scoped_executor(integration, private_root=self.root, contract=self.resolve,
                    run=transport, deadline=self.deadline, checkpoint_handler=self.checkpoint,
                    producer_pin=self.producer_pin, prepare_runner=self.prepare):
                yield
        finally:
            self.transport = None
    def approve_create(self, command):
        """Approve only the literal transformation of the authenticated original."""
        capture.check(self.deadline, self.cancelled)
        capture.need(self.contract is not None and self.original_command is not None, 'create-before-contract')
        expected = launch.validate_command(self.original_command, self.contract)
        cidfile = self.root / ('launch-' + expected['nonce']) / 'cid'
        approved = ['docker', 'create', '-i', '--cidfile', str(cidfile)] + self.original_command[2:]
        index = approved.index('/runner/repository.py')
        position = index + 2
        capture.need(type(command) is list and len(command) == len(approved) + 3
                     and command[position] == '--handoff-deadline', 'create-command-shape')
        # The launcher clips its existing deadline. Accept only a finite cutoff
        # that is still live and never exceeds the enclosing job cutoff.
        try:
            end = float(command[position + 1])
        except (ValueError, TypeError):
            raise capture.Refused('create-deadline') from None
        capture.check(end, self.cancelled)
        canonical_end = repr(end) == command[position + 1] or end.is_integer() and str(int(end)) == command[position + 1]
        capture.need(end <= self.deadline and canonical_end, 'create-deadline')
        approved[index:index + 1] = ['-I', '/runner/producer.py', '--handoff-deadline', command[position + 1]]
        capture.need(command == approved, 'create-command-policy')
        return {'name': expected['name'], 'image_id': expected['image'], 'cidfile': str(cidfile)}
    def capture(self, controller, *, selections, output, deadline):
        capture.check(min(self.deadline, deadline), self.cancelled)
        capture.need(self.contract is not None and self.checkpoints is not None
                     and len(self.checkpoints.records) == 2 and not self.checkpoints.failed, 'pending-checkpoints')
        capture.need(controller.image == self.contract['image_id']
                     and controller.commit == self.contract['source_commit'], 'pending-controller-identity')
        source = self.root / ('launch-' + self.contract['nonce']) / 'receipt.json'
        launch_raw = capture.read(source, deadline=min(self.deadline, deadline))
        observed = capture.decode(launch_raw)
        capture.need(observed.get('status') == observed.get('cleanup') == 'PASS'
                     and observed.get('ownership_verified') is True and not observed.get('cancelled'), 'pending-launch')
        rows = observed.get('checkpoints', [])
        expected = [{'sequence': row['sequence'], 'phase': row['phase'], 'frame_sha256': row['sha256'],
                     'payload_sha256': row['payload_sha256']} for row in self.checkpoints.records]
        capture.need(rows == expected, 'pending-checkpoint-launch-binding')
        selections = dict(selections)
        capture.need('custody/launch.json' not in selections, 'reserved-capture-name')
        selections['custody/launch.json'] = source
        for sequence in (1, 2):
            name = f'custody/checkpoint-{sequence}.json'
            capture.need(name not in selections, 'reserved-capture-name')
            selections[name] = self.root / f'checkpoint-{sequence}.json'
        self.receipt = capture.capture_files(selections, output, deadline=min(self.deadline, deadline), cancelled=self.cancelled)
        self.receipt['identity'] = {'source_commit': controller.commit, 'image_id': controller.image,
                                    'nonce': self.contract['nonce']}
        return dict(self.receipt)


def validate_terminal(records, job, launch_record, checkpoints, *, native_exit):
    """Necessary terminal facts; full successor gate remains independently required."""
    job = identity(job)
    capture.need(type(native_exit) is int and native_exit == 0 and type(records) is dict
                 and set(records) == {'aggregate', 'public_acceptance', 'native_result'}, 'terminal-native-exit')
    summary, public, native = (records[key] for key in ('aggregate', 'public_acceptance', 'native_result'))
    capture.need(summary.get('schema_version') == 1 and summary.get('purpose') == 'frozen-development-only-native-integration'
                 and summary.get('status') == 'PASS' and summary.get('source_commit') == job['source_commit']
                 and summary.get('base_image') == job['image_id'] and summary.get('cancelled') is False
                 and summary.get('development_only') is True and summary.get('selected_for_release') is False
                 and summary.get('hardware_validation') == summary.get('production_trust') == 'NOT RUN'
                 and all(summary.get('stages', {}).get(name, {}).get('status') == 'PASS' for name in STAGES), 'terminal-aggregate')
    cleaned = summary.get('owned_image_cleanup', {})
    capture.need(cleaned.get('status') == 'PASS' and cleaned.get('absence_verified') is True
                 and cleaned.get('cleanup_uncertain') is False, 'terminal-derivative-cleanup')
    capture.need(native.get('status') == 'native-builds-and-virtual-integration-pass'
                 and native.get('mode') == 'integration' and native.get('native_build') == 'PASS'
                 and native.get('virtual_integration') == 'PASS', 'terminal-native-record')
    capture.need(public.get('purpose') == 'accepted-repository-public-artifacts' and public.get('status') == 'PASS'
                 and all(public.get(key) == job[key] for key in ('source_commit', 'run_id', 'nonce')), 'terminal-public-export')
    capture.need(launch_record.get('status') == launch_record.get('cleanup') == 'PASS'
                 and launch_record.get('nonce') == job['nonce'] and launch_record.get('image_id') == job['image_id']
                 and launch_record.get('container') == 'cachy-asahi-repository-' + job['nonce']
                 and type(launch_record.get('container_id')) is str
                 and re.fullmatch('[0-9a-f]{64}', launch_record['container_id'])
                 and launch_record.get('ownership_verified') is True
                 and all(launch_record.get(field) is True for field in
                         ('absence_verified', 'name_absence_verified', 'id_absence_verified'))
                 and not launch_record.get('cancelled') and not launch_record.get('ownership_uncertain'), 'terminal-full-cid')
    capture.need(type(checkpoints) is list and len(checkpoints) == 2, 'terminal-checkpoints')
    bound = []
    for index, row in enumerate(checkpoints, 1):
        capture.need(type(row) is dict and set(row) == {'sequence', 'phase', 'sha256', 'payload_sha256', 'durable_host_digest'}
                     and type(row['sequence']) is int and row['sequence'] == index
                     and row['phase'] == capture.PHASES[index - 1] and row['durable_host_digest'] is True
                     and all(type(row[key]) is str and re.fullmatch('[0-9a-f]{64}', row[key])
                             for key in ('sha256', 'payload_sha256')), 'terminal-checkpoints')
        bound.append({'sequence': index, 'phase': row['phase'], 'frame_sha256': row['sha256'],
                      'payload_sha256': row['payload_sha256']})
    capture.need(launch_record.get('checkpoints') == bound, 'terminal-checkpoint-launch-binding')
    return {'status': 'PASS-terminal-prerequisites', 'native_admission': 'NOT RUN', 'identity': job}


def seal_terminal(input_root, authority_raw, authority_pin, *, records, job, launch_record,
                  checkpoints, native_exit, phase_modules, repo_root, deadline, supervise, cancelled=None):
    """External authority stays external; invoke the phase-aware gate directly."""
    capture.check(deadline, cancelled)
    facts = validate_terminal(records, job, launch_record, checkpoints, native_exit=native_exit)
    authority = pinned(authority_raw, authority_pin)
    capture.need(authority.get('archive_role') == 'baseline' and authority.get('schema_version') == 2
                 and authority.get('purpose') == 'accepted-repository-client-inputs', 'baseline-phase-authority')
    capture.need(all(authority.get(key) == value for key, value in facts['identity'].items() if key != 'run_attempt'), 'authority-job-binding')
    capture.need(records['native_result'].get('integration_sha256') == authority.get('integration_lock_sha256'), 'terminal-native-lock-binding')
    refs, files = authority.get('refs'), authority.get('files')
    capture.need(type(refs) is dict and set(refs) == REFS and type(files) is dict, 'authority-refs')
    previous = '0' * 64
    for index, row in enumerate(checkpoints, 1):
        name = f'custody/checkpoint-{index}.json'
        raw = capture.read(Path(input_root) / name, deadline=deadline)
        capture.need(files.get(name) == {'sha256': capture.digest(raw), 'bytes': len(raw)}, 'authority-checkpoint-file')
        verified = producer.parse_frame(producer.FRAME_MARKER + raw, nonce=job['nonce'], sequence=index,
                                        previous_frame_sha256=previous)
        frame = verified['frame']
        capture.need(verified['frame_sha256'] == row['sha256']
                     and frame['payload_sha256'] == row['payload_sha256'], 'authority-checkpoint-chain')
        previous = row['sha256']
    launch_raw = capture.read(Path(input_root) / 'custody/launch.json', deadline=deadline)
    capture.need(files.get('custody/launch.json') == {'sha256': capture.digest(launch_raw), 'bytes': len(launch_raw)}
                 and capture.decode(launch_raw) == launch_record, 'authority-launch-file')
    for role in ('aggregate', 'public_acceptance'):
        data = capture.read(Path(input_root) / str(capture.relative(refs[role])), deadline=deadline)
        capture.need(files.get(refs[role]) == {'sha256': capture.digest(data), 'bytes': len(data)}
                     and capture.decode(data) == records[role], 'terminal-authority-ref-binding')
    cleanup = capture.decode(capture.read(Path(input_root) / str(capture.relative(refs['cleanup'])), deadline=deadline))
    capture.need(all(cleanup.get(key) == launch_record.get(key) for key in
                 ('container', 'container_id', 'absence_verified', 'name_absence_verified', 'id_absence_verified'))
                 and cleanup.get('status') == 'PASS', 'terminal-cleanup-ref-binding')
    capture.need(callable(supervise), 'bounded-actor-supervisor-required')
    accepted = supervise('phase-accept', lambda: phase_modules['gate'].accept(Path(input_root),
        authority_raw, authority_pin, repo_root=Path(repo_root)), deadline=min(deadline, time.monotonic() + 330))
    capture.check(deadline, cancelled)
    capture.need(accepted.get('status') == 'PASS-input-acceptance', 'phase-input-acceptance')
    return {'status': 'PASS-input-acceptance', 'authority_sha256': authority_pin,
            'run_attempt': facts['identity']['run_attempt'], 'native_end_to_end': 'NOT RUN', 'accepted': accepted}


def collect_baseline(collector, pins, controller, *, output, provenance_root,
                     provenance_raw, provenance_pin, deadline, supervise, cancelled=None):
    """Explicit actor interface; caller must provide reviewed authenticated modules."""
    capture.check(deadline, cancelled)
    request = pinned(provenance_raw, provenance_pin)
    capture.need(request.get('archive_role') == 'baseline' and request.get('image_id') == controller.image
                 and request.get('source_commit') == controller.commit, 'baseline-provenance-request')
    native = controller.native_out
    boot, packages, inputs = (capture.read(native / name, deadline=deadline) for name in
                             ('bootstrap.json', 'packages.lock', 'inputs.lock.json'))
    capture.need(callable(supervise), 'bounded-actor-supervisor-required')
    collected = supervise('collect-base', lambda: collector['base'].collect_base(controller.image,
        boot, capture.digest(boot), packages, capture.digest(packages),
        {name: pins[name] for name in ('common.py', 'base.py', 'worker.py')},
        Path(output), inputs_raw=inputs, inputs_pin=capture.digest(inputs)),
        deadline=min(deadline, time.monotonic() + 330))
    capture.check(deadline, cancelled)
    result_raw = capture.read(Path(output) / 'result.json', deadline=deadline)
    received = supervise('receive-base', lambda: collector['base'].receive_base(Path(output), result_raw,
                         capture.digest(result_raw)), deadline=deadline)
    capture.need(collected.get('status') == received.get('status') == 'PASS', 'real-base-receiver')
    base_raw = capture.read(Path(output) / 'observed/base.json', deadline=deadline)
    components = supervise('consume-provenance', lambda: collector['provenance'].consume(Path(provenance_root),
        provenance_raw, provenance_pin, base_raw, capture.digest(base_raw)), deadline=deadline)
    capture.check(deadline, cancelled)
    return {'status': 'PENDING', 'components': components, 'collector_result_sha256': capture.digest(result_raw),
            'native_admission': 'NOT RUN'}


def restage(phase_modules, collector, input_root, authority_raw, authority_pin, components_raw,
            components_pin, policy_raw, policy_pin, license_raw, license_pin, output, *,
            terminal, repo_root, deadline, supervise, cancelled=None):
    capture.check(deadline, cancelled)
    capture.need(terminal.get('status') == 'PASS-input-acceptance'
                 and terminal.get('authority_sha256') == authority_pin, 'terminal-before-restage')
    policy = pinned(policy_raw, policy_pin)
    capture.need(policy.get('review_status') == 'ACCEPTED'
                 and policy.get('supported_models') == [] and policy.get('platform_scope') == 'generic-builder-only'
                 and set(policy.get('selected_packages', [])) == ORIGINALS, 'reviewed-generic-policy')
    capture.need(callable(supervise), 'bounded-actor-supervisor-required')
    metadata = supervise('bind-metadata', lambda: collector['provenance'].bind_metadata(components_raw,
        components_pin, authority_raw, authority_pin, policy_raw, policy_pin, license_raw, license_pin), deadline=deadline)
    capture.check(deadline, cancelled)
    result = supervise('phase-restage', lambda: phase_modules['adapter'].execute(Path(input_root),
        authority_raw, authority_pin, metadata, capture.digest(metadata), Path(output), repo_root=Path(repo_root)),
        deadline=min(deadline, time.monotonic() + 420))
    capture.check(deadline, cancelled)
    return result


def authority_selections(controller, *, integration_lock_path, integration_lock_pin, deadline, cancelled=None):
    """Select original raw evidence and exact public maps without workspace walks."""
    raw = controller.work / 'repository-raw'
    def read(path):
        capture.check(deadline, cancelled)
        value = capture.read(path, deadline=deadline)
        capture.check(deadline, cancelled)
        return value
    original = capture.decode(read(raw / 'result.json'))
    capture.need(original.get('status') == 'PASS' and original.get('test_private_state_removed') is True
                 and type(original.get('commands')) is list and len(original.get('cases', [])) == 11
                 and all(type(row.get('argv')) is list for row in original['commands']), 'original-raw-receipt')
    selections = {'raw/result.json': raw / 'result.json'}
    evidence = original.get('evidence_sha256')
    capture.need(type(evidence) is dict and 0 < len(evidence) <= 2048, 'raw-evidence-map')
    for name, pin in evidence.items():
        capture.relative(name)
        source = raw / name
        capture.need(capture.digest(read(source)) == pin, 'raw-evidence-byte-pin')
        selections['raw/' + name] = source
    fixed = {
        'raw/container-cleanup.json': raw / 'container-cleanup.json',
        'raw/container-launcher.json': raw / 'container-launcher.json',
        'raw/contract.json': controller.work / 'repository-inputs/manifest.json',
        'projected/result.json': controller.public / 'repository/result.json',
        'projected/projection.json': controller.public / 'repository/repository-inventory-projection.json',
        'native/bootstrap.json': controller.native_out / 'bootstrap.json',
        'native/packages.lock': controller.native_out / 'packages.lock',
        'native/inputs.lock.json': controller.native_out / 'inputs.lock.json',
        'native/runner.json': controller.native_out / 'runner.json',
        'source/fixture-manifest.json': controller.generated / 'fixture-manifest.json',
        'source/recipes.lock.json': controller.source / 'scripts/ci/recipes.lock.json',
        'source/integration.lock.json': Path(integration_lock_path),
    }
    lock_raw = read(integration_lock_path)
    capture.need(capture.digest(lock_raw) == integration_lock_pin and capture.decode(lock_raw) == controller.lock,
                 'actual-original-lock-binding')
    selections.update(fixed)
    projected = capture.decode(read(fixed['projected/result.json']))
    for name, pin in projected['evidence_sha256'].items():
        capture.relative(name)
        source = controller.public / 'repository' / name
        # Projection leaves some original-only evidence pins. Material that is
        # present must match; absent original names stay in the private raw map.
        if source.exists():
            capture.need(capture.digest(read(source)) == pin, 'projected-evidence-pin')
            selections['projected/' + name] = source
    # Equal bytes do not make raw and public namespaces interchangeable. The
    # successor requires six legacy names and nine operation copies plus index.
    index_path = controller.public / 'repository/repository-operation-aliases.json'
    index = capture.decode(read(index_path))
    capture.need(set(index) == {'schema_version', 'purpose', 'generic_content_guard',
                               'original_bytes_preserved', 'files'}
                 and type(index['schema_version']) is int and index['schema_version'] == 1
                 and index['purpose'] == 'validated-repository-operation-aliases'
                 and index['generic_content_guard'] == 'UNCHANGED' and index['original_bytes_preserved'] is True
                 and type(index['files']) is dict and len(index['files']) == 9, 'operation-alias-index')
    aliases = {}
    for label, alias in LEGACY_LOGS.items():
        matches = [row for row in original['commands'] if row.get('label') == label]
        capture.need(len(matches) == 1, 'legacy-alias-command')
        name = matches[0]['log']
        aliases[name] = name.split('-', 1)[0] + '-' + alias + '.txt'
    for name, row in index['files'].items():
        capture.need(type(row) is dict and set(row) == {'public_path', 'original_sha256', 'public_sha256', 'bytes'}
                     and row['original_sha256'] == row['public_sha256'] == evidence.get(name)
                     and type(row['bytes']) is int, 'operation-alias-pin')
        capture.need(name not in aliases, 'operation-alias-overlap')
        aliases[name] = row['public_path']
    capture.need(len(set(aliases.values())) == 15, 'distinct-operation-aliases')
    for original_name, alias in aliases.items():
        capture.relative(alias)
        data = read(raw / original_name)
        source = controller.public / 'repository' / alias
        capture.need(capture.digest(data) == evidence.get(original_name) and read(source) == data,
                     'operation-alias-byte-binding')
        if original_name in index['files']:
            capture.need(index['files'][original_name]['bytes'] == len(data), 'operation-alias-size')
        selections['projected/' + alias] = source
    selections['projected/repository-operation-aliases.json'] = index_path
    manifest_path = controller.public / 'repository-public-artifacts/public-artifact-manifest.json'
    manifest = capture.decode(read(manifest_path))
    selections['public/manifest.json'] = manifest_path
    for name, row in manifest['files'].items():
        capture.relative(name)
        source = manifest_path.parent / name
        data = read(source)
        capture.need(row == {'sha256': capture.digest(data), 'bytes': len(data)}, 'public-export-byte-pin')
        selections['public/' + name] = source
    return selections


def baseline_provenance(controller, job, *, repository_url, deadline, cancelled=None):
    """Assemble actual eight-build inputs; collection and acceptance stay separate."""
    job = identity(job)
    capture.need(controller.image == job['image_id'] and controller.commit == job['source_commit']
                 and type(repository_url) is str and re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository_url),
                 'provenance-controller-identity')
    selections, files, data = {}, {}, {}
    def add(name, path, pin=None):
        capture.relative(name); capture.need(name not in files, 'duplicate-provenance-path')
        capture.check(deadline, cancelled)
        raw = capture.read(path, deadline=deadline)
        capture.need(pin is None or capture.digest(raw) == pin, 'provenance-source-pin')
        selections[name], data[name] = Path(path), raw
        files[name] = {'sha256': capture.digest(raw), 'bytes': len(raw)}
        capture.need(len(files) <= 1024 and sum(row['bytes'] for row in files.values()) <= 64 * 1024**2,
                     'provenance-map-bound')
        return raw
    fixture_ref = 'source/fixture-manifest.json'
    fixture = capture.decode(add(fixture_ref, controller.generated / 'fixture-manifest.json'))
    capture.need(fixture.get('source_commit') == job['recipe_source_commit']
                 and set(fixture.get('packages', {})) == ORIGINALS, 'provenance-fixture-origin')
    entry_ref, generator_ref = 'source/container-entry.sh', 'source/fixtures.py'
    for target, source in ((entry_ref, 'scripts/build/container-entry.sh'),
                           (generator_ref, 'scripts/integration/fixtures.py')):
        row = controller.lock['source_files'][source]
        add(target, controller.source / source, row['sha256'])
    inputs_raw = capture.read(controller.native_out / 'inputs.lock.json', deadline=deadline)
    lock_raw = capture.read(controller.native_out / 'packages.lock', deadline=deadline)
    bootstrap = capture.decode(capture.read(controller.native_out / 'bootstrap.json', deadline=deadline))
    capture.need(bootstrap.get('image_id') == job['image_id']
                 and bootstrap.get('inputs_sha256') == capture.digest(inputs_raw)
                 and bootstrap.get('packages_lock_sha256') == capture.digest(lock_raw), 'provenance-bootstrap-binding')
    inputs = capture.decode(inputs_raw)
    capture.need(type(inputs.get('snapshot_id')) is str and
                 re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}', inputs['snapshot_id']), 'actual-input-snapshot')
    packages = []; lock_ref = None
    for name in sorted(ORIGINALS):
        builds = []
        for number in (1, 2):
            prefix = f'builds/{name}-{number}'; source = controller.native_out / f'{name}-{number}'
            record = capture.decode(add(prefix + '/provenance.json', source / 'provenance.json'))
            capture.need(record.get('status') == 'built-package-static-pass' and record.get('mode') == 'native'
                         and record.get('image_id') == job['image_id'] and type(record.get('files')) is dict
                         and type(record.get('recipe_inputs')) is dict and type(record.get('artifacts')) is dict
                         and len(record['artifacts']) == 1, 'actual-baseline-build-receipt')
            for relative, pin in record['files'].items():
                add(prefix + '/' + str(capture.relative(relative)), source / relative, pin)
            for relative, pin in record['recipe_inputs'].items():
                add(prefix + '/inputs/' + str(capture.relative(relative)), source / 'inputs' / relative, pin)
            filename, pin = next(iter(record['artifacts'].items()))
            capture.need(Path(filename).name == filename, 'provenance-artifact-name')
            archive = prefix + '/artifacts/' + filename
            capture.need(archive in files and files[archive]['sha256'] == pin, 'provenance-artifact-map')
            expected = prefix + '/expected-packages.lock'
            capture.need(expected in data and data[expected] == lock_raw, 'actual-build-lock')
            lock_ref = lock_ref or expected
            builds.append((prefix, archive))
        compare, diff = f'compares/{name}.json', f'diffs/{name}.diff'
        add(compare, controller.native_out / (name + '-compare.json'))
        origin = fixture['packages'][name]
        add(diff, controller.generated / str(capture.relative(origin['diff'])), origin['diff_sha256'])
        capture.need(data[builds[0][1]] == data[builds[1][1]], 'baseline-artifact-pair')
        packages.append({'name': name, 'archive': builds[0][1], 'first': builds[0][0], 'second': builds[1][0],
                         'compare': compare, 'diff': diff})
    request = {'schema_version': 1, 'purpose': 'native-artifact-provenance-inputs',
               **{key: job[key] for key in ('source_commit', 'recipe_source_commit', 'image_id')},
               'repository_url': repository_url, 'archive_role': 'baseline', 'snapshot_id': inputs['snapshot_id'],
               'packages_lock': lock_ref, 'files': files, 'packages': packages, 'fixture_manifest': fixture_ref,
               'entry_script': entry_ref, 'generator_source': generator_ref}
    capture.check(deadline, cancelled)
    return {'status': 'PENDING', 'request': request, 'selections': selections, 'file_count': len(files),
            'native_admission': 'NOT RUN'}


def capture_file_map(root, receipt, *, deadline, cancelled=None):
    """Include capture.json explicitly; the gate requires the exact file tree."""
    capture.check(deadline, cancelled)
    files = dict(receipt['files'])
    raw = capture.read(Path(root) / 'capture.json', deadline=deadline)
    recorded = capture.decode(raw)
    capture.need(recorded.get('files') == files and recorded.get('status') == 'PENDING'
                 and 'capture.json' not in files, 'capture-index-binding')
    files['capture.json'] = {'sha256': capture.digest(raw), 'bytes': len(raw)}
    return files


def terminal_inputs(captured_root, receipt, controller, output, *, public_acceptance_path,
                    crypto_request_path, crypto_receipt_path, deadline, cancelled=None):
    """Join actual post-return records into a fresh exact authority input tree."""
    files = capture_file_map(captured_root, receipt, deadline=deadline, cancelled=cancelled)
    selections = {name: Path(captured_root) / name for name in files}
    additions = {'terminal/aggregate.json': controller.out / 'result.json',
                 'terminal/native-result.json': controller.native_out / 'result.json',
                 'terminal/public-acceptance.json': Path(public_acceptance_path),
                 'crypto/request.json': Path(crypto_request_path), 'crypto/receipt.json': Path(crypto_receipt_path)}
    for name, path in additions.items():
        capture.check(deadline, cancelled)
        capture.need(name not in selections, 'reserved-terminal-path')
        raw = capture.read(path, 8 * 1024**2, deadline=deadline)
        selections[name], files[name] = path, {'sha256': capture.digest(raw), 'bytes': len(raw)}
    capture.need(len(files) <= 1024, 'terminal-input-count')
    staged = stage_exact(selections, files, output, deadline=deadline, cancelled=cancelled)
    records = {role: capture.decode(capture.read(Path(output) / name, deadline=deadline)) for role, name in
               (('aggregate', 'terminal/aggregate.json'), ('public_acceptance', 'terminal/public-acceptance.json'),
                ('native_result', 'terminal/native-result.json'))}
    return {'status': 'PENDING', 'files': staged['files'], 'records': records, 'file_count': len(files),
            'native_admission': 'NOT RUN'}


def authority_candidate(input_root, files, job, *, records, launch_record, checkpoints,
                        native_exit, crypto_request_ref, crypto_receipt_ref, deadline, cancelled=None):
    """Complete schema2 draft for the external issuer, never an accepted grant."""
    facts = validate_terminal(records, job, launch_record, checkpoints, native_exit=native_exit)
    files = dict(files)
    capture.need(0 < len(files) <= 1024, 'authority-file-count')
    total = 0
    def get(name):
        capture.check(deadline, cancelled); capture.relative(name)
        row = files.get(name)
        capture.need(type(row) is dict and set(row) == {'sha256', 'bytes'} and type(row['bytes']) is int
                     and 0 <= row['bytes'] <= 8 * 1024**2, 'authority-file-row')
        raw = capture.read(Path(input_root) / name, 8 * 1024**2, deadline=deadline)
        capture.need(row == {'sha256': capture.digest(raw), 'bytes': len(raw)}, 'authority-file-binding')
        return raw
    for name in files:
        total += len(get(name))
        capture.need(total <= 64 * 1024**2, 'authority-total-bound')
    repository = capture.decode(get('raw/result.json'))
    capture.need(repository.get('status') == 'PASS' and repository.get('source_commit') == job['source_commit']
                 and all(type(row.get('argv')) is list for row in repository.get('commands', []))
                 and repository.get('commands'), 'authority-actual-raw-commands')
    reset = 'raw/' + str(capture.relative(repository['sync_cache_reset']['receipt']))
    refs = {'aggregate': 'terminal/aggregate.json', 'repository': 'raw/result.json',
            'repository_contract': 'raw/contract.json', 'reset': reset,
            'public_manifest': 'public/manifest.json', 'public_acceptance': 'terminal/public-acceptance.json',
            'cleanup': 'raw/container-cleanup.json', 'bootstrap': 'native/bootstrap.json',
            'packages': 'native/packages.lock', 'current_inputs': 'native/inputs.lock.json',
            'fixture_manifest': 'source/fixture-manifest.json', 'integration_lock': 'source/integration.lock.json',
            'recipes_lock': 'source/recipes.lock.json', 'projection': 'projected/projection.json',
            'projected_repository': 'projected/result.json', 'runner': 'native/runner.json'}
    capture.need(set(refs) == REFS and len(set(refs.values())) == 16, 'authority-complete-refs')
    for name in refs.values(): get(name)
    for role, name in (('aggregate', refs['aggregate']), ('public_acceptance', refs['public_acceptance']),
                       ('native_result', 'terminal/native-result.json')):
        capture.need(capture.decode(get(name)) == records[role], 'authority-terminal-record-binding')
    capture.need(capture.decode(get('custody/launch.json')) == launch_record, 'authority-launch-record-binding')
    previous = '0' * 64
    for index, row in enumerate(checkpoints, 1):
        parsed = producer.parse_frame(producer.FRAME_MARKER + get(f'custody/checkpoint-{index}.json'),
            nonce=job['nonce'], sequence=index, previous_frame_sha256=previous)
        capture.need(parsed['frame_sha256'] == row['sha256']
                     and parsed['frame']['payload_sha256'] == row['payload_sha256'], 'authority-durable-checkpoints')
        previous = row['sha256']
    contract = capture.decode(get(refs['repository_contract']))
    baseline = contract.get('baseline')
    capture.need(type(baseline) is list and len(baseline) == 4
                 and {row.get('name') for row in baseline} == ORIGINALS, 'authority-baseline-scope')
    archives = []
    for row in sorted(baseline, key=lambda row: row['name']):
        name = 'public/TEST-repositories/baseline-A/' + Path(row['archive']).name
        get(name)
        capture.need(files[name]['sha256'] == row['sha256'], 'authority-baseline-archive-binding')
        archives.append({'name': row['name'], 'path': name, 'version': row['version'], **files[name]})
    crypto = {'schema_version': 2, 'purpose': 'external-repository-cryptographic-phase-acceptance', 'status': 'PENDING'}
    for role, name in (('request', crypto_request_ref), ('receipt', crypto_receipt_ref)):
        raw = get(name); record = capture.decode(raw)
        capture.need(type(record.get('schema_version')) is int and record['schema_version'] == 2
                     and record.get('purpose') == 'repository-cryptographic-phases'
                     and all(record.get(key) == job[key] for key in ('source_commit', 'run_id', 'nonce', 'image_id')),
                     'authority-crypto-record-binding')
        if role == 'receipt': capture.need(record.get('status') == 'PASS', 'authority-crypto-receipt')
        crypto[role] = {'path': name, **files[name]}
    authority = {'schema_version': 2, 'purpose': 'accepted-repository-client-inputs', 'status': 'PENDING',
                 'development_only': True, 'selected_for_release': False,
                 **{key: job[key] for key in ('run_id', 'source_commit', 'recipe_source_commit', 'nonce', 'image_id')},
                 'repository_source_sha256': launch.ORIGINAL_PIN, 'archive_role': 'baseline',
                 'files': files, 'refs': refs, 'archives': archives, 'crypto': crypto}
    for field, role in (('bootstrap_sha256', 'bootstrap'), ('packages_sha256', 'packages'),
                        ('current_inputs_sha256', 'current_inputs'), ('integration_lock_sha256', 'integration_lock'),
                        ('recipes_lock_sha256', 'recipes_lock'), ('fixture_manifest_sha256', 'fixture_manifest')):
        authority[field] = files[refs[role]]['sha256']
    capture.need(records['native_result'].get('integration_sha256') == authority['integration_lock_sha256'],
                 'authority-native-lock-binding')
    return {'status': 'PENDING-external-authority', 'authority': authority, 'file_count': len(files),
            'total_bytes': total, 'run_attempt': facts['identity']['run_attempt'], 'native_admission': 'NOT RUN'}


def stage_exact(selections, files, output, *, deadline, cancelled=None):
    """Stage a separate exact tree for collectors, without an extra index file."""
    capture.need(type(selections) is dict and type(files) is dict and set(selections) == set(files), 'exact-stage-map')
    receipt = capture.capture_files(selections, output, deadline=deadline, cancelled=cancelled, index=False)
    capture.need(receipt['files'] == files, 'exact-stage-byte-binding')
    return receipt


def attest_crypto(collector, input_root, request_raw, request_pin, output, *, crypto_root,
                  deadline, supervise, cancelled=None):
    capture.check(deadline, cancelled)
    request = pinned(request_raw, request_pin)
    capture.need(request.get('schema_version') == 2 and request.get('purpose') == 'repository-cryptographic-phases'
                 and len(request.get('files', {})) == 128 and callable(supervise), 'crypto-finite-request')
    stage_exact({name: Path(input_root) / str(capture.relative(name)) for name in request['files']},
                request['files'], crypto_root, deadline=deadline, cancelled=cancelled)
    result = supervise('crypto-attest', lambda: collector['crypto'].attest(Path(crypto_root), request_raw,
        request_pin, Path(output)), deadline=deadline)
    capture.check(deadline, cancelled)
    capture.need(result.get('status') == 'PASS', 'crypto-attestation')
    return result


def crypto_request(input_root, files, repository_ref, job, *, public_prefix, deadline, cancelled=None):
    """Derive an unsigned request from actual argv/log bytes; no crypto authority."""
    identity(job)
    capture.relative(public_prefix); capture.relative(repository_ref)
    def get(name):
        capture.check(deadline, cancelled); capture.relative(name)
        raw = capture.read(Path(input_root) / name, deadline=deadline)
        capture.need(files.get(name) == {'sha256': capture.digest(raw), 'bytes': len(raw)}, 'crypto-source-byte-binding')
        return raw
    repository = capture.decode(get(repository_ref))
    capture.need(repository.get('status') == 'PASS' and type(repository.get('commands')) is list
                 and repository.get('source_commit') == job['source_commit'], 'crypto-original-receipt')
    prefix = public_prefix + '/'
    public = {name: row for name, row in files.items() if name.startswith(prefix) and
              (name[len(prefix):].startswith('TEST-repositories/') or name[len(prefix):].startswith('TEST-'))}
    capture.need(len(public) == 112, 'crypto-six-public-repositories')
    objects = []
    for label, role in (('baseline-A', 'signer-A'), ('updated-B', 'signer-B')):
        selected = [name for name in public if name.startswith(prefix + 'TEST-repositories/' + label + '/')
                    and (re.search(r'\.pkg\.tar\.(xz|gz|zst)$', name) or Path(name).name in
                         ('integration.db.tar.gz', 'integration.files.tar.gz'))]
        capture.need(len(selected) == 7, 'crypto-seven-objects-per-role')
        objects.extend({'path': name, 'signature': name + '.sig', 'signer': role} for name in selected)
    objects.append({'path': prefix + 'TEST-repository-aliases.json',
                    'signature': prefix + 'TEST-repository-aliases.json.sig', 'signer': 'signer-B'})
    objects.sort(key=lambda row: row['path'])
    signers = {}
    for role in ('signer-A', 'signer-B', 'verifier'):
        original = repository['public_TEST_identities'][role]
        certificate = prefix + 'TEST-' + role + '-public.asc'
        capture.need(capture.digest(get(certificate)) == original['public_sha256'], 'crypto-certificate-binding')
        signers[role] = {'fingerprint': original['fingerprint'], 'certificate': certificate}
    signers['signer-A']['revoked_certificate'] = prefix + 'TEST-signer-A-revoked-public.asc'
    raw_prefix = str(Path(repository_ref).parent)
    commands = repository['commands']; native, selected_files = [], dict(public)
    for obj in objects:
        for name in ('path', 'signature'): get(obj[name])
        role = obj['signer']; relative = obj['path'][len(prefix):]
        target = '/out/' + relative if relative == 'TEST-repository-aliases.json' else '/scratch/repos/' + relative.removeprefix('TEST-repositories/')
        label = ('verify-database-' + ('baseline-A' if role == 'signer-A' else 'updated-B')
                 if Path(target).name in ('integration.db.tar.gz', 'integration.files.tar.gz') else 'verify-' + role)
        home = '/test-home/' + role
        argv = ['gpg', '--batch', '--no-options', '--homedir', home, '--no-default-keyring', '--keyring',
                home + '/pubring.gpg', '--no-auto-key-retrieve', '--status-fd', '1', '--verify', target + '.sig', target]
        matches = [(index, row) for index, row in enumerate(commands) if row.get('label') == label and row.get('argv') == argv]
        capture.need(len(matches) == 1, 'crypto-actual-argv-required')
        index, row = matches[0]
        log = raw_prefix + '/' + row['log']
        capture.need(type(row['exit_code']) is int and row['exit_code'] == 0
                     and capture.digest(get(log)) == row['sha256'] == repository['evidence_sha256'][row['log']], 'crypto-native-positive-log')
        selected_files[log] = files[log]
        native.append({'path': obj['path'], 'status_log': log, 'exit_code': row['exit_code'], 'command_index': index,
                       'native_phase': 'pre-A-revocation' if role == 'signer-A' else 'unrevoked-B'})
    matches = [(index, row) for index, row in enumerate(commands) if row.get('label') == 'gpg-revoked-A-status']
    capture.need(len(matches) == 1, 'crypto-native-revocation-log')
    index, row = matches[0]; log = raw_prefix + '/' + row['log']
    capture.need(capture.digest(get(log)) == row['sha256'] == repository['evidence_sha256'][row['log']], 'crypto-revocation-byte-pin')
    selected_files[log] = files[log]
    return {'schema_version': 2, 'purpose': 'repository-cryptographic-phases',
            **{key: job[key] for key in ('source_commit', 'run_id', 'nonce', 'image_id')},
            'files': selected_files, 'signers': signers, 'signed_objects': objects,
            'native_verifications': native, 'native_revocation': {'status_log': log, 'exit_code': row['exit_code'], 'command_index': index},
            'public_prefix': public_prefix}


def run_existing(native, integration, argv, pending, transport, *, grant_raw, grant_pin,
                 consumer, job_deadline, cancelled=None):
    """One existing initial job, scoped hook and PENDING callback; no default actor."""
    capture.check(job_deadline, cancelled)
    grant = pinned(grant_raw, grant_pin)
    capture.need(grant.get('purpose') == 'reviewed-same-job-handoff-execution'
                 and grant.get('source_peer_preflight') == 'PASS'
                 and grant.get('development_only') is True and grant.get('added_seconds') == 1200,
                 'external-execution-grant')
    capture.need(callable(consumer) and type(argv) is list and argv and argv[0] == 'integration', 'initial-integration-interface')
    observed = {}
    def callback(controller):
        end = min(job_deadline, time.monotonic() + 1200)
        capture.check(end, cancelled)
        observed['controller'] = controller
        observed['consumer'] = consumer(controller, pending, deadline=end)
        capture.check(end, cancelled)
        capture.need(observed['consumer'].get('status') == 'PENDING', 'callback-cannot-grant-authority')
    with pending.interpose(integration, transport):
        capture.check(job_deadline, cancelled)
        exit_code = native.main(argv, integration_consumers=callback)
    capture.check(job_deadline, cancelled)
    return {'status': 'PENDING' if exit_code == 0 and observed else 'FAIL', 'initial_exit_code': exit_code,
            'callback_entered': bool(observed), 'observation': observed.get('consumer'),
            'native_admission': 'NOT RUN'}
