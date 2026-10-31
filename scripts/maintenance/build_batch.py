#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Admit and run finite pinned OCI rebuilds; no installation or publication."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import time

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/build/build.py').is_file())
MAX_JSON = 16 * 1024 * 1024
HEX = re.compile('[0-9a-f]{64}')
BUILD_FILES = ('scripts/build/build.py', 'scripts/build/compare.py',
               'scripts/build/container-entry.sh', 'scripts/checks/package_checks.py',
               'scripts/release/check_source_pins.py', 'scripts/release/release.py',
               'scripts/release/source_delivery.py')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def regular(path):
    path = Path(os.path.abspath(path))
    need(path == path.resolve() and path.is_file(), 'regular nonsymlink file required: ' + str(path))
    return path


def read(path):
    with regular(path).open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    need(len(raw) <= MAX_JSON, 'JSON/input byte limit')
    return raw


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key: ' + key)
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda x: need(False, 'nonfinite JSON number'))


def selected(path, checksum):
    raw = read(path)
    need(type(checksum) is str and HEX.fullmatch(checksum) and sha(raw) == checksum,
         'selected checksum mismatch: ' + str(path))
    return decode(raw)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names.split()), 'unexpected/missing fields: ' + names)


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'integer outside finite resource bound')
    return value


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def dependencies(planner):
    paths = [ROOT / p for p in BUILD_FILES] + [regular(planner), Path(__file__).resolve()]
    return {str(p): digest(p) for p in paths}


def admission(input_path, input_sha, config_path, config_sha, planner_path, planner_sha):
    """Pure admission: read inputs and invoke the selected offline planner only."""
    planner = regular(planner_path)
    need(digest(planner) == planner_sha, 'planner implementation checksum mismatch')
    before = dependencies(planner)
    source = selected(input_path, input_sha)
    config = selected(config_path, config_sha)
    fields(config, 'schema_version owner review max_parallel cpu_budget memory_gib_budget max_wall_seconds max_attempts tasks')
    need(config['schema_version'] == 1 and type(config['schema_version']) is int, 'unsupported config schema')
    for key in ('owner', 'review'):
        need(type(config[key]) is str and 0 < len(config[key]) <= 512 and config[key].isprintable(), 'explicit batch owner/review required')
    integer(config['max_parallel'], 1, 32)
    integer(config['cpu_budget'], 4, 128)
    integer(config['memory_gib_budget'], 4, 128)
    integer(config['max_wall_seconds'], 1, 86400)
    integer(config['max_attempts'], 1, 10)
    need(type(config['tasks']) is list and len(config['tasks']) <= 4096, 'finite task list required')
    result = subprocess.run([sys.executable, '-B', str(planner), '--input', str(regular(input_path)),
                             '--input-sha256', input_sha], capture_output=True, timeout=120)
    need(result.returncode == 0, 'planner refused: ' + result.stderr.decode(errors='replace')[:2000])
    need(len(result.stdout) <= MAX_JSON, 'planner report byte limit')
    plan = decode(result.stdout)
    need(plan['input']['sha256'] == input_sha, 'planner input binding mismatch')
    slots = plan['capacity']['native_aarch64_slots'] or 0
    limit = min(config['max_parallel'], config['cpu_budget'] // 4,
                config['memory_gib_budget'] // 4, slots)
    build = module('batch_reviewed_build', ROOT / 'scripts/build/build.py')
    by_package = {p['name']: p for p in plan['packages']}
    group_for = {p: g for g in plan['groups'] for p in g['packages']}
    source_rows = {p['id']: p for p in source['sources']}
    build_rows = {p['package']: p for p in source['build_dependencies']}
    input_edges = {p['name']: set() for p in source['packages']}
    for edge in plan['build_inputs']:
        input_edges[edge['package']].add(edge['provider'])
    for row in plan['baseline_inputs']:
        input_edges[row['name']].update(row['prerequisites'])
    tasks = {}
    for row in config['tasks']:
        fields(row, 'package owner recipe reviewed_inputs reviewed_inputs_sha256 expected_packages expected_packages_sha256 image mode source_date_epoch timeout prerequisite_artifacts image_dependency_review')
        name = row['package']
        need(type(name) is str and re.fullmatch('[a-zA-Z0-9@_+][a-zA-Z0-9@_.+-]{0,127}', name), 'invalid task package')
        need(name not in tasks and name in by_package, 'duplicate or unplanned task')
        package = by_package[name]
        need(package['disposition'] == 'build' and row['owner'] == package['owner'] and bool(row['owner']), 'task ownership/disposition mismatch')
        need(row['mode'] in ('native', 'emulated'), 'explicit native/emulated mode required')
        build.image_pin(row['image'])
        integer(row['source_date_epoch'], 0, 2**63 - 1)
        integer(row['timeout'], 1, 86400)
        recipe = Path(os.path.abspath(row['recipe']))
        need(recipe == recipe.resolve() and recipe.is_dir(), 'nonsymlink recipe directory required')
        report = build.recipe(recipe / 'PKGBUILD')
        need(not report['errors'], 'recipe review failed: ' + str(report['errors']))
        reviewed = selected(row['reviewed_inputs'], row['reviewed_inputs_sha256'])
        need(reviewed == report['input_sha256'], 'reviewed recipe input mismatch')
        need(report['metadata']['pkgname'] == [name], 'recipe package identity mismatch')
        metadata = build.normalize_metadata(report['metadata'])
        version = metadata['pkgver'][0] + '-' + metadata['pkgrel'][0]
        if metadata['epoch'][0] != '0':
            version = metadata['epoch'][0] + ':' + version
        need(version == package['version'], 'recipe version differs from planned rebuild')
        planned = next(p for p in source['packages'] if p['name'] == name)
        need(metadata['arch'] == [planned['arch']], 'recipe architecture differs from plan')
        for actual, expected_values in ((metadata['depends'], planned.get('depend', [])),
                (metadata['provides'], planned.get('provides', [])),
                (metadata['makedepends'], build_rows[name]['makedepend']),
                (metadata['checkdepends'], build_rows[name]['checkdepend'])):
            need(sorted(set(actual)) == sorted(set(expected_values)), 'recipe graph metadata differs from planner')
        source_id = build_rows[name]['source_id']
        need(source_id in source_rows and source_rows[source_id]['recipe_sha256'] == reviewed['PKGBUILD'], 'planner source recipe pin mismatch')
        pins = []
        for url, checksum in zip(metadata['source'], metadata['sha256sums']):
            url = url.split('::', 1)[-1]
            pins.append(dict(url=url, commit=url.rsplit('#commit=', 1)[-1]) if url.startswith('git+')
                        else dict(url=url, sha256=checksum))
        projected = [{k: v for k, v in p.items() if k in ('url', 'commit', 'sha256')}
                     for p in source_rows[source_id]['sources']]
        need(pins == projected, 'planner source descriptors differ from recipe pins')
        lock_raw = read(row['expected_packages'])
        need(sha(lock_raw) == row['expected_packages_sha256'], 'package lock checksum mismatch')
        lock = lock_raw.decode()
        need(lock.strip() and lock.endswith('\n') and lock == ''.join(sorted(lock.splitlines(keepends=True))), 'nonempty sorted newline-terminated package lock required')
        lock_rows = [line.split(' ') for line in lock.splitlines()]
        need(all(len(p) == 2 and all(p) for p in lock_rows) and len({p[0] for p in lock_rows}) == len(lock_rows), 'duplicate/malformed package lock rows')
        lock_map = dict(lock_rows)
        group = group_for[name]
        required = sorted(p for g in plan['groups'] if g['id'] in group['prerequisites'] for p in g['packages'])
        need(type(row['prerequisite_artifacts']) is dict and sorted(row['prerequisite_artifacts']) == required, 'exact prerequisite artifact pins required')
        for p, checksum in row['prerequisite_artifacts'].items():
            need(type(checksum) is str and HEX.fullmatch(checksum), 'invalid prerequisite artifact digest')
            need(lock_map.get(p) == by_package[p]['version'], 'prerequisite absent/wrong version in image package lock')
        need(type(row['image_dependency_review']) is str and 0 < len(row['image_dependency_review']) <= 512, 'explicit image dependency review required')
        # The unchanged baseline closure must also be present, not merely claimed available.
        baseline = {p['name']: p for p in source['packages']}
        closure, pending = set(), [name]
        while pending:
            p = pending.pop()
            if p not in closure:
                closure.add(p)
                pending.extend(input_edges[p] - closure)
        for p in plan['baseline_inputs']:
            if p['name'] in closure:
                need(lock_map.get(p['name']) == baseline[p['name']]['version'], 'baseline input absent/wrong version in image lock')
        for p in sorted(closure - {name}):
            need(lock_map.get(p) == baseline[p]['version'],
                 'dependency closure input absent/wrong version in image lock: ' + p)
        used_selections = [selection for selection in plan.get('provider_selections', [])
                           if selection['package'] in closure]
        for selection in used_selections:
            evidence = selection['evidence']
            need(row['image'] == evidence['image'],
                 'reachable provider witness image differs from task image: ' + selection['package'])
            need(row['expected_packages_sha256'] == evidence['inventory_sha256'],
                 'reachable provider witness inventory differs from task lock: ' + selection['package'])
        task = dict(row)
        if used_selections:
            task['provider_selections'] = used_selections
        task.update(recipe=str(recipe), reviewed_inputs=str(regular(row['reviewed_inputs'])),
                    expected_packages=str(regular(row['expected_packages'])), recipe_inputs=reviewed,
                    group=group['id'], prerequisites=required)
        tasks[name] = task
    ineligible = set()
    for group in plan['groups']:
        if (group['held'] or len(group['packages']) != 1 or len(group['units']) != 1 or
                any(by_package[p]['disposition'] != 'build' for p in group['packages']) or
                any(p in ineligible for p in group['prerequisites'])):
            ineligible.add(group['id'])
    expected = {p['name'] for p in plan['packages'] if group_for[p['name']]['id'] not in ineligible}
    need(expected <= set(tasks), 'task coverage must include every runnable planned build')
    groups = []
    held_ids = set()
    for group in plan['groups']:
        holds = list(group['holds']) + list(plan['global_holds'])
        if group['held']:
            holds.append('PLANNER_HELD')
        if len(group['packages']) != 1 or len(group['units']) != 1:
            holds.append('SINGLE_PACKAGE_BUILDER_ONLY')
        if any(p not in tasks for p in group['packages']):
            holds.append('NO_REVIEWED_EXECUTION_TASK')
        if any(p in held_ids for p in group['prerequisites']):
            holds.append('HELD_PREREQUISITE')
        if holds:
            held_ids.add(group['id'])
        groups.append(dict(group, held=bool(holds), holds=sorted(set(holds))))
    need(dependencies(planner) == before, 'implementation changed during admission')
    selected(input_path, input_sha)
    selected(config_path, config_sha)
    return dict(schema_version=1, status='ADMISSION_ONLY_NOT_BUILT', authenticated=False,
                input_sha256=input_sha, config_sha256=config_sha, planner_sha256=planner_sha,
                implementation=before, python=str(Path(sys.executable).resolve()),
                python_version=sys.version, owner=config['owner'], review=config['review'],
                max_parallel=limit, resources=dict(per_build_cpus=4, per_build_memory_gib=4,
                cpu_budget=config['cpu_budget'], memory_gib_budget=config['memory_gib_budget'],
                capacity=plan['capacity']), max_wall_seconds=config['max_wall_seconds'],
                max_attempts=config['max_attempts'], tasks=tasks, groups=groups,
                planned_packages=sorted(by_package), baseline_inputs=plan['baseline_inputs'], global_holds=plan['global_holds'],
                hardware_status='NOT RUN', dependency_bytes_delivery='OPERATOR_REVIEWED_PREEXISTING_IMAGES_ONLY',
                dependency_solution='NOT_ESTABLISHED', capacity_measurement='NOT_MEASURED')


def revalidate(admit, task):
    need(all(digest(regular(p)) == checksum for p, checksum in admit['implementation'].items()),
         'implementation drift before launch')
    need(sha(read(task['reviewed_inputs'])) == task['reviewed_inputs_sha256'], 'reviewed input drift before launch')
    need(sha(read(task['expected_packages'])) == task['expected_packages_sha256'], 'package lock drift before launch')
    build = module('batch_launch_build', ROOT / 'scripts/build/build.py')
    report = build.recipe(Path(task['recipe']) / 'PKGBUILD')
    need(not report['errors'] and report['input_sha256'] == task['recipe_inputs'], 'recipe drift before launch')


def snapshot(path):
    """Seal the exact retained tree; never accept extra or symlink evidence."""
    need(path.is_dir() and not path.is_symlink(), 'missing output directory')
    files = {}
    for item in sorted(path.rglob('*')):
        need(not item.is_symlink(), 'symlink output forbidden')
        if item.is_file():
            files[str(item.relative_to(path))] = digest(item)
        else:
            need(item.is_dir(), 'special output forbidden')
        need(len(files) <= 65536, 'output file count bound')
    return files


class Builder:
    kind = 'PINNED_OCI_BUILD_PY'

    def start(self, task, output, log, lock_fd):
        command = [sys.executable, '-B', str(ROOT / 'scripts/build/build.py'), task['recipe'],
                   '--image', task['image'], '--output', str(output), '--mode', task['mode'],
                   '--source-date-epoch', str(task['source_date_epoch']), '--network', 'none',
                   '--timeout', str(task['timeout']), '--expected-packages', task['expected_packages'],
                   '--reviewed-inputs', task['reviewed_inputs']]
        return subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True, pass_fds=(lock_fd,))

    def verify(self, task, output):
        snapshot(output)
        compare = module('batch_compare', ROOT / 'scripts/build/compare.py')
        record, reports = compare.verify(output)
        build = module('batch_result_build', ROOT / 'scripts/build/build.py')
        reviewed_metadata = build.recipe(Path(task['recipe']) / 'PKGBUILD')['metadata']
        expected = dict(recipe_metadata=reviewed_metadata, image=task['image'], mode=task['mode'], source_date_epoch=task['source_date_epoch'],
                        recipe_inputs=task['recipe_inputs'], expected_packages_sha256=task['expected_packages_sha256'],
                        entry_script_sha256=digest(ROOT / 'scripts/build/container-entry.sh'), network='none')
        need(all(record.get(k) == v for k, v in expected.items()), 'result does not match admitted build inputs')
        need(decode(read(output / 'validation.json')).get('errors') == [], 'recorded validation errors')
        need(len(reports) == 1, 'exactly one package result required')
        need((output / 'artifacts/packages.lock').read_bytes() == read(task['expected_packages']), 'result lock mismatch')
        return next(iter(record['artifacts'].values()))

    def cleanup(self, task, output):
        path = output / 'provenance.json'
        if not path.exists():
            return
        record = decode(read(path))
        name = record.get('clean_environment_id')
        if name is None:
            return
        need(type(name) is str and re.fullmatch('cachy-asahi-[0-9a-f]{16}', name), 'invalid owned container identity')
        command = record.get('command', [])
        mounts = {(str(output / 'inputs'), '/inputs', False),
                  (str(output / 'artifacts'), '/out', True),
                  (str(ROOT / 'scripts/build/container-entry.sh'), '/builder-entry.sh', False),
                  (str(output / 'expected-packages.lock'), '/expected-packages.lock', False)}
        expected_mounts = {'type=bind,src=' + source + ',dst=' + dest + ('' if rw else ',readonly')
                           for source, dest, rw in mounts}
        need(type(command) is list and len(command) >= 5 and
             command[:4] == ['docker', 'run', '--rm', '--name'] and command[4] == name and
             command[-2] == task['image'] and record.get('image') == task['image'] and
             {command[i + 1] for i, arg in enumerate(command[:-1]) if arg == '--mount'} == expected_mounts,
             'container ownership command/image/mount mismatch')
        def absent():
            result = subprocess.run(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$'],
                                    capture_output=True, timeout=30, text=True)
            need(result.returncode == 0 and not result.stdout.strip(), 'owned container absence not established')
        result = subprocess.run(['docker', 'container', 'inspect', name], capture_output=True, timeout=30, text=True)
        if result.returncode != 0:
            absent()
            return
        items = decode(result.stdout.encode())
        need(type(items) is list and len(items) == 1, 'owned container inspect identity missing')
        actual = items[0]
        actual_mounts = actual.get('Mounts', [])
        bind_mounts = {(p.get('Source'), p.get('Destination'), p.get('RW'))
                       for p in actual_mounts if p.get('Type') == 'bind'}
        other_mounts_safe = all(p.get('Type') == 'bind' or
                               (p.get('Type') == 'tmpfs' and p.get('Destination') == '/tmp' and p.get('RW') is True)
                               for p in actual_mounts)
        need(actual.get('Name') == '/' + name and actual.get('Config', {}).get('Image') == task['image'] and
             bind_mounts == mounts and other_mounts_safe,
             'live container ownership image/mount mismatch')
        removed = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30, text=True)
        if removed.returncode != 0:
            absent()


def atomic(path, value):
    raw = encoded(value)
    need(len(raw) <= MAX_JSON, 'checkpoint JSON byte limit')
    temporary = path.with_name('.' + path.name + '.tmp')
    need(not temporary.is_symlink(), 'symlink checkpoint temporary forbidden')
    with temporary.open('wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(admit, output, resume=False, retry=(), builder=None, stop=None):
    """Production CLI always supplies Builder; tests inject a disposable fake."""
    builder = builder or Builder()
    output = Path(os.path.abspath(output))
    need(output == output.resolve() and output.parent.is_dir(), 'nonsymlink output with existing parent required')
    protected = [Path(p) for p in admit['implementation']]
    protected += [Path(t[k]) for t in admit['tasks'].values() for k in ('recipe', 'reviewed_inputs', 'expected_packages')]
    need(not any(p == output or p.is_relative_to(output) or output.is_relative_to(p) for p in protected), 'output overlaps admitted input')
    need(set(retry) <= set(admit['tasks']) and (not retry or resume), 'retry requires named admitted tasks and resume')
    need(not any((p / '.build-batch-owner').exists() for p in output.parents), 'nested batch output ownership forbidden')
    if not resume:
        output.mkdir(mode=0o700, exist_ok=False)
    else:
        need(output.is_dir(), 'resume output missing')
    lock_path = output / '.lock'
    need(not lock_path.is_symlink(), 'symlink lock forbidden')
    with lock_path.open('a+b') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('batch output already owned by a live runner/builder') from None
        token = sha(encoded(admit))
        if resume:
            state = decode(read(output / 'state.json'))
            need(state['admission_sha256'] == token and state['kind'] == builder.kind,
                 'resume admission/evidence kind mismatch')
            need(read(output / '.build-batch-owner') == (token + '\n').encode(), 'batch owner marker mismatch')
            need(read(output / 'admission.json') == encoded(admit), 'retained admission mismatch')
            need(set(state['packages']) == set(admit['planned_packages']), 'checkpoint task mismatch')
        else:
            with (output / '.build-batch-owner').open('xb') as marker:
                marker.write((token + '\n').encode())
            atomic(output / 'admission.json', admit)
            state = dict(schema_version=1, admission_sha256=token, kind=builder.kind,
                         status='RUNNING', hardware_status='NOT RUN', packages={
                             name: dict(status='PENDING' if name in admit['tasks'] else 'HELD', attempts=[]) for name in admit['planned_packages']})
        packages = state['packages']
        for name, row in packages.items():
            need(row['status'] in ('PENDING', 'ACTIVE', 'HELD', 'BLOCKED', 'FAILED', 'INTERRUPTED', 'SUCCESS'), 'invalid checkpoint status')
            need(row['status'] != 'ACTIVE' or (row['attempts'] and row['attempts'][-1]['status'] == 'RUNNING'), 'active checkpoint lacks running attempt')
            need(name in admit['tasks'] or row['status'] == 'HELD', 'unconfigured task cannot pass')
            need(type(row['attempts']) is list and len(row['attempts']) <= admit['max_attempts'], 'invalid attempt count')
            for i, attempt in enumerate(row['attempts'], 1):
                need(attempt['output'] == f'{name}/attempt-{i:03d}/build', 'checkpoint output ownership mismatch')
            if row['attempts'] and row['attempts'][-1]['status'] == 'RUNNING':
                builder.cleanup(admit['tasks'][name], output / row['attempts'][-1]['output'])
                row['attempts'][-1]['status'] = 'INTERRUPTED'
                row['status'] = 'INTERRUPTED'
            if row['status'] == 'SUCCESS':
                attempt = row['attempts'][-1]
                path = output / attempt['output']
                need(snapshot(path) == attempt['files'], 'retained success tree changed; refuse stale success')
                revalidate(admit, admit['tasks'][name])
                need(builder.verify(admit['tasks'][name], path) == attempt['artifact_sha256'], 'retained artifact changed')
            if name in retry:
                need(row['status'] in ('FAILED', 'INTERRUPTED'), 'retry only failed/interrupted packages')
                need(len(row['attempts']) < admit['max_attempts'], 'attempt bound exhausted')
                row['status'] = 'PENDING'
            elif row['status'] == 'BLOCKED':
                row['status'] = 'PENDING'
        for group in admit['groups']:
            if group['held']:
                for name in group['packages']:
                    if name in packages:
                        packages[name]['status'] = 'HELD'
        active = {}
        cancelled = [False]
        previous = {}
        def cancel(signum, frame):
            cancelled[0] = True
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, cancel)
        deadline = time.monotonic() + admit['max_wall_seconds']
        atomic(output / 'state.json', state)
        try:
            while True:
                now = time.monotonic()
                stopping = cancelled[0] or (stop is not None and stop()) or now >= deadline
                for name, (process, log, started) in list(active.items()):
                    task, row = admit['tasks'][name], packages[name]
                    attempt = row['attempts'][-1]
                    path = output / attempt['output']
                    timed_out = now - started >= task['timeout'] + 30
                    if stopping or timed_out:
                        # Stop only our session, then remove only its recorded container.
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGTERM)
                            try:
                                process.wait(timeout=3)
                            except subprocess.TimeoutExpired:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait(timeout=3)
                        builder.cleanup(task, path)
                    code = process.poll()
                    if code is None:
                        continue
                    log.close()
                    attempt['exit_code'] = code
                    row['status'] = 'INTERRUPTED' if stopping else 'FAILED'
                    try:
                        need(code == 0 and not stopping and not timed_out, 'build interrupted, timed out or nonzero exit')
                        revalidate(admit, task)
                        attempt['artifact_sha256'] = builder.verify(task, path)
                        attempt['files'] = snapshot(path)
                        row['status'] = 'SUCCESS'
                    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                        attempt['error'] = str(error)
                        builder.cleanup(task, path)
                    attempt['status'] = row['status']
                    del active[name]
                    atomic(output / 'state.json', state)
                for name, task in sorted(admit['tasks'].items()):
                    row = packages[name]
                    if row['status'] != 'PENDING':
                        continue
                    statuses = [packages[p]['status'] for p in task['prerequisites'] if p in packages]
                    if any(s in ('FAILED', 'HELD', 'BLOCKED', 'INTERRUPTED') for s in statuses):
                        row['status'] = 'BLOCKED'
                        atomic(output / 'state.json', state)
                        continue
                    if stopping or len(active) >= admit['max_parallel'] or any(s != 'SUCCESS' for s in statuses):
                        continue
                    mismatch = [p for p, checksum in task['prerequisite_artifacts'].items()
                                if p not in packages or not packages[p]['attempts'] or
                                packages[p]['attempts'][-1].get('artifact_sha256') != checksum]
                    if mismatch:
                        row.update(status='BLOCKED', reason='prerequisite artifact differs from reviewed image input: ' + ','.join(mismatch))
                        atomic(output / 'state.json', state)
                        continue
                    need(len(row['attempts']) < admit['max_attempts'], 'attempt bound exhausted')
                    parent = output / name
                    if not parent.exists():
                        parent.mkdir()
                    need(parent.is_dir() and not parent.is_symlink(), 'invalid package output owner')
                    attempt_dir = parent / f'attempt-{len(row["attempts"]) + 1:03d}'
                    attempt_dir.mkdir()
                    path = attempt_dir / 'build'
                    attempt = dict(output=str(path.relative_to(output)), status='RUNNING')
                    row['attempts'].append(attempt)
                    # PENDING plus RUNNING attempt survives a crash before/after spawn.
                    atomic(output / 'state.json', state)
                    log = (attempt_dir / 'runner.log').open('xb')
                    try:
                        revalidate(admit, task)
                        frozen = dict(task)
                        frozen['recipe'] = str(attempt_dir / 'recipe')
                        shutil.copytree(task['recipe'], frozen['recipe'], symlinks=True)
                        for key in ('reviewed_inputs', 'expected_packages'):
                            target = attempt_dir / (key + '.reviewed')
                            target.write_bytes(read(task[key]))
                            frozen[key] = str(target)
                        revalidate(admit, frozen)
                        process = builder.start(frozen, path, log, lock.fileno())
                    except (OSError, ValueError) as error:
                        log.close()
                        row['status'] = attempt['status'] = 'FAILED'
                        attempt['error'] = str(error)
                        atomic(output / 'state.json', state)
                        continue
                    active[name] = (process, log, time.monotonic())
                    row['status'] = 'ACTIVE'
                if not active:
                    if stopping or not any(p['status'] == 'PENDING' for p in packages.values()) or admit['max_parallel'] == 0:
                        break
                    # A newly blocked prerequisite may occur later in sorted order.
                    continue
                time.sleep(0.03)
            state['status'] = ('NO_WORK' if not packages else 'COMPLETE' if all(p['status'] == 'SUCCESS' for p in packages.values())
                               else 'INTERRUPTED' if stopping else 'INCOMPLETE')
            atomic(output / 'state.json', state)
            return state
        finally:
            cleanup_errors = []
            try:
                for name, (process, log, started) in active.items():
                    attempt = packages[name]['attempts'][-1]
                    try:
                        if process.poll() is None:
                            try:
                                os.killpg(process.pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                            try:
                                process.wait(timeout=3)
                            except subprocess.TimeoutExpired:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait(timeout=3)
                        builder.cleanup(admit['tasks'][name], output / attempt['output'])
                        packages[name]['status'] = attempt['status'] = 'INTERRUPTED'
                    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
                        # Keep RUNNING attempt on cleanup failure so resume retries cleanup.
                        cleanup_errors.append(dict(package=name, error=str(error)))
                    finally:
                        log.close()
                if active:
                    state['status'] = 'INTERRUPTED'
                    state['cleanup_errors'] = cleanup_errors
                    atomic(output / 'state.json', state)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'execute'))
    for name in ('input', 'config', 'planner'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--admission-sha256')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--retry', action='append', default=[])
    args = parser.parse_args(argv)
    try:
        admit = admission(args.input, args.input_sha256, args.config, args.config_sha256,
                          args.planner, args.planner_sha256)
        need(len(encoded(admit)) <= MAX_JSON, 'admission JSON byte limit')
        if args.action == 'plan':
            need(not (args.resume or args.retry or args.output or args.admission_sha256), 'execution options require execute')
            sys.stdout.buffer.write(encoded(admit))
            return 0
        need(args.output is not None and args.admission_sha256 == sha(encoded(admit)), 'execute requires output and selected admission SHA-256')
        result = run(admit, args.output, args.resume, args.retry)
        print(json.dumps({'status': result['status'], 'output': str(args.output.resolve())}, sort_keys=True))
        return 0 if result['status'] in ('COMPLETE', 'NO_WORK') else 1
    except (OSError, ValueError, KeyError, TypeError, IndexError, argparse.ArgumentTypeError, subprocess.SubprocessError, RecursionError) as error:
        print('build batch: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
