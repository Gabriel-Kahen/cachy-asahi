# SPDX-License-Identifier: MIT
"""Independent pure-data KSM command/receipt contracts; launches no commands.

An ownership assertion is not native evidence. These validators require a future
accepted same-job executor to bind the records to operations it actually ran.
"""
from pathlib import Path
import re
import time

HASH = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


class Deadline:
    """One aggregate clock; individual phase allowances cannot extend it."""
    def __init__(self, seconds=8460, *, clock=time.monotonic):
        need(type(seconds) is int and 1 <= seconds <= 8460, 'deadline-budget')
        self.clock, self.end, self.seen = clock, clock() + seconds, set()

    def phase(self, name, maximum, reserve=210):
        caps = {'producer': 6600, 'build-1': 360, 'build-2': 360, 'comparison': 120,
                'lifecycle': 600, 'cleanup': 180, 'public': 30}
        need(name in caps and name not in self.seen, 'phase-replay-refused')
        required_reserve = 0 if name == 'public' else 30 if name == 'cleanup' else 210
        need(type(maximum) is int and 0 < maximum <= caps[name] and
             type(reserve) is int and reserve >= required_reserve,
             'phase-budget')
        remaining = self.end - self.clock() - reserve
        need(remaining > 0, 'aggregate-deadline')
        self.seen.add(name)
        return min(maximum, remaining)


def producer_command(root, private, python='/usr/bin/python3', *, inputs_sha, recipes_sha):
    root, private = safe_paths(root, private)
    need(HASH.fullmatch(inputs_sha) and HASH.fullmatch(recipes_sha), 'producer-source-pins')
    return [python, '-B', str(root / 'scripts/ci/native_arm.py'), 'build', '--inputs',
            str(root / 'scripts/ci/inputs.lock.json'), '--inputs-sha256', inputs_sha, '--recipes',
            str(root / 'scripts/ci/recipes.lock.json'), '--recipes-sha256', recipes_sha,
            '--cache', str(private / 'cache'), '--output', str(private / 'producer')]


def safe_paths(root, private):
    paths = [Path(x) for x in (root, private)]
    need(all(x.is_absolute() and '..' not in x.parts and ',' not in str(x) and '\n' not in str(x)
             for x in paths), 'bounded-absolute-paths-required')
    need(not paths[1].is_relative_to(paths[0]) and paths[0] != paths[1], 'private-output-outside-checkout')
    return paths


def build_commands(root, private, image, *, python='/usr/bin/python3'):
    root, private = safe_paths(root, private)
    need(IMAGE.fullmatch(image), 'immutable-image-required')
    return [[python, '-B', str(root / 'scripts/build/build.py'),
             str(root / 'packages/tools/cachy-asahi-ksmctl'), '--image', image,
             '--mode', 'native', '--source-date-epoch', '1791748800', '--network', 'none',
             '--timeout', '300', '--expected-packages', str(private / 'producer/packages.lock'),
             '--reviewed-inputs', str(private / 'approved-inputs.json'),
             '--output', str(private / ('build-' + str(index)))] for index in (1, 2)]


def compare_command(root, private, python='/usr/bin/python3'):
    root, private = safe_paths(root, private)
    return [python, '-B', str(root / 'scripts/build/compare.py'), str(private / 'build-1'),
            str(private / 'build-2'), '--require-bytes']


def lifecycle_command(root, private, binding, pins, *, python='/usr/bin/python3'):
    root, private = safe_paths(root, private)
    fields = {'image', 'daemon-id', 'docker-endpoint', 'docker-sha256', 'docker-socket-device',
              'docker-socket-inode', 'source-commit', 'run-id', 'runner-sha256', 'bootstrap-sha256',
              'stage-sha256', 'worker-sha256', 'contract-source-sha256',
              'build-1-provenance-sha256', 'build-2-provenance-sha256'}
    need(set(binding) == fields and all(type(v) is str and 0 < len(v) <= 128 for v in binding.values()),
         'lifecycle-binding-schema')
    need(IMAGE.fullmatch(binding['image']) and re.fullmatch(r'[0-9a-f]{40}', binding['source-commit'])
         and re.fullmatch(r'[0-9]{1,20}', binding['run-id']) and
         binding['docker-endpoint'] in {'unix:///run/docker.sock', 'unix:///var/run/docker.sock'} and
         re.fullmatch(r'[A-Za-z0-9:-]{8,128}', binding['daemon-id']) and
         all(re.fullmatch(r'[0-9]{1,20}', binding[x]) for x in ('docker-socket-device', 'docker-socket-inode'))
         and all(HASH.fullmatch(binding[x]) for x in fields if x.endswith('sha256')), 'lifecycle-binding-values')
    for key, filename in [('stage-sha256', 'stage.py'), ('worker-sha256', 'worker.py'),
                          ('contract-source-sha256', 'contract.py')]:
        need(binding[key] == pins['scripts/port/ksm-lifecycle/' + filename], 'held-lifecycle-source-drift')
    locations = {'runner': 'producer/runner.json', 'bootstrap': 'producer/bootstrap.json',
                 'packages': 'producer/packages.lock', 'approved-inputs': 'approved-inputs.json',
                 'build-1': 'build-1', 'build-2': 'build-2', 'output': 'lifecycle'}
    args = {**binding, **{k: str(private / v) for k, v in locations.items()}, 'source': str(root),
            'current-inputs': str(root / 'scripts/ci/inputs.lock.json')}
    return [python, '-B', str(root / 'scripts/port/ksm-lifecycle/stage.py'),
            *[value for key in sorted(args) for value in ('--' + key, args[key])]]


def validate_comparison(record, filename):
    need(set(record) == {'status', 'errors', 'packages', 'hardware_status', 'independence_limit'}
         and record['status'] == 'contents-reproduced' and record['errors'] == [] and
         record['hardware_status'] == 'NOT RUN' and set(record['packages']) == {filename},
         'comparison-receipt-refused')
    comparison = record['packages'][filename]
    need(set(comparison) == {'installed_contents_equal', 'pkginfo_equal', 'bytes_equal', 'buildinfo_equal'}
         and all(value is True for value in comparison.values()), 'full-comparison-required')
    return {'status': 'PASS', 'archives_equal': True, 'metadata_equal': True,
            'payload_equal': True, 'buildinfo_equal': True}


def validate_ownership(record, *, nonce, commit, run_id, image, daemon):
    """Required proposed producer interface; current original CLI cannot emit it."""
    need(set(record) == {'schema_version', 'status', 'nonce', 'source_commit', 'run_id',
                        'image_id', 'daemon_id', 'owns_image', 'containers_absent', 'journal_sha256'},
         'producer-owned-receipt-required')
    need(type(record['schema_version']) is int and record['schema_version'] == 1 and record['status'] == 'PASS' and
         (record['nonce'], record['source_commit'], record['run_id'], record['image_id'], record['daemon_id']) ==
         (nonce, commit, run_id, image, daemon) and record['owns_image'] is True and
         record['containers_absent'] is True and HASH.fullmatch(record['journal_sha256']) and
         re.fullmatch(r'[0-9a-f]{32}', nonce) and re.fullmatch(r'[0-9a-f]{40}', commit) and
         re.fullmatch(r'[0-9]{1,20}', run_id) and IMAGE.fullmatch(image), 'same-job-ownership-refused')


def validate_lifecycle(record, binding, source_pins, package, *, controller_exit):
    need(type(controller_exit) is int and controller_exit == 0, 'clean-controller-exit-required')
    for field in ('source_commit', 'run_id', 'image_id', 'daemon_id', 'docker_endpoint'):
        need(record.get(field) == binding[field], 'lifecycle-job-binding-refused')
    need(record.get('status') == 'PASS' and not record.get('cancelled') and
         record.get('source_sha256') == source_pins and record.get('package') == package and
         record.get('hardware') == record.get('management') == 'NOT RUN' and
         record.get('published') is False and record.get('private_artifacts_retained') is False and
         record.get('controller_tmp_removed') == record.get('docker_boundary_closed') == 'PASS',
         'lifecycle-receipt-refused')
    phases = record.get('phases')
    need(type(phases) is list and len(phases) == 2 and
         [p.get('phase') for p in phases] == ['sign', 'lifecycle'] and
         all(p.get('status') == p.get('container_cleanup') == 'PASS' for p in phases),
         'lifecycle-phases-required')
    for phase in phases:
        state = phase.get('container_state')
        need(type(state) is dict and set(state) == {'status', 'exit_code', 'oom_killed'} and
             state['status'] == 'exited' and type(state['exit_code']) is int and
             state['exit_code'] == 0 and state['oom_killed'] is False, 'clean-worker-exit-required')
    return {'status': 'PASS', 'cleanup': 'PASS'}
