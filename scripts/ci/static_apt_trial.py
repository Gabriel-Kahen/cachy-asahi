#!/usr/bin/env python3
"""Bind disposable static setup receipts; never install or dispatch workloads."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('archive_cache', Path(__file__).with_name('static_apt_cache.py'))
archive_cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive_cache)
FIELDS = ('source', 'repository', 'ref', 'run_id', 'run_attempt', 'image', 'os', 'arch', 'plan_digest', 'helper_digest', 'key')
PACKAGES = 'bash fish zsh vim build-essential clang lld gnupg libarchive-tools pacman-package-manager makepkg e2fsprogs network-manager pkg-config libgtk-3-dev'.split()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bind_key(state):
    key = 'static-apt-v1-{os}-{arch}-ubuntu24-{image}-{helper_digest}-{plan_digest}'.format(**state)
    if state['phase'] != 'normal':
        key = 'static-apt-trial-{}-{}-{}'.format(state['run_id'], state['run_attempt'], key)
    require(len(key) <= 512, 'cache key exceeds service limit')
    return key


def compare_identity(cold, warm):
    require(cold['phase'] == 'cold' and cold['cache_hit'] != 'true', 'predecessor was not cold')
    require(cold['verified_before_install'] == 0 and cold['archive_count'] > 0, 'empty/noncold predecessor')
    require(all(cold[name] == warm[name] for name in FIELDS), 'source/ref/image/package-plan/key mismatch')
    require(cold['runner_name'] != warm['runner_name'], 'samples require separate hosted runners')


def check_cache(state, directory, rows, hit):
    count = sum(archive_cache.checked_bytes(directory / name, row) is not None for name, row in rows.items())
    if state['phase'] == 'cold':
        require(hit != 'true' and not list(directory.glob('*.deb')), 'cold sample restored archives')
    if state['phase'] == 'warm':
        require(hit == 'true', 'warm sample requires an exact cache hit')
        require(count == len(rows) and count > 0, 'warm cache lacks complete verified archive set')
    return count


def compare_finished(cold, warm):
    compare_identity(cold, warm)
    require(warm['phase'] == 'warm' and warm['cache_hit'] == 'true', 'not an exact warm sample')
    require(warm['verified_before_install'] == warm['archive_count'] > 0, 'incomplete warm cache')
    require(cold['packages_readback'] == warm['packages_readback'], 'installed package readback mismatch')
    require(cold['packages_sha256'] == warm['packages_sha256'], 'package digest mismatch')


def main():
    mode = sys.argv[1]
    require(mode in ('begin', 'clock', 'identity', 'cache', 'finish', 'report'), 'invalid mode')
    root = Path(os.environ['RUNNER_TEMP'])
    path = root / 'static-apt-trial-state.json'
    if mode == 'begin':
        phase = os.environ['CAA_STATIC_PHASE']
        require(phase in ('normal', 'cold', 'warm'), 'invalid phase')
        require(phase == 'normal' or os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch', 'trial requires dispatch caller')
        source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        require(source == os.environ['GITHUB_SHA'], 'checkout differs from workflow source')
        state = dict(phase=phase, source=source, start_ns=time.monotonic_ns(),
                     cold=json.loads(os.environ.get('CAA_COLD_RECEIPT') or 'null'))
        require((phase == 'warm') == (state['cold'] is not None), 'warm requires exactly one cold receipt')
        for field, env in (('repository', 'GITHUB_REPOSITORY'), ('ref', 'GITHUB_REF'), ('run_id', 'GITHUB_RUN_ID'), ('run_attempt', 'GITHUB_RUN_ATTEMPT'), ('image', 'ImageVersion'), ('os', 'RUNNER_OS'), ('arch', 'RUNNER_ARCH'), ('runner_name', 'RUNNER_NAME')):
            state[field] = os.environ[env]
            require(bool(state[field]), 'missing ' + env)
    else:
        state = json.loads(path.read_text())
    if mode == 'clock':
        state[sys.argv[2]] = time.monotonic_ns()
    elif mode == 'identity':
        state['plan_digest'] = archive_cache.plan_key(archive_cache.read_plan(root / 'static-apt-uris'))
        state['helper_digest'] = hashlib.sha256(Path(__file__).with_name('static_apt_cache.py').read_bytes()).hexdigest()
        state['key'] = bind_key(state)
        if state['phase'] == 'warm':
            compare_identity(state['cold'], state)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('key=' + state['key'] + '\n')
        state['cache_start_ns'] = time.monotonic_ns()
    elif mode == 'cache':
        state['cache_end_ns'] = time.monotonic_ns()
        state['cache_hit'] = os.environ.get('CAA_CACHE_HIT', '')
        rows = archive_cache.read_plan(root / 'static-apt-uris')
        state['archive_count'] = len(rows)
        state['verified_before_install'] = check_cache(state, root / 'static-apt-cache', rows, state['cache_hit'])
    elif mode == 'finish':
        state['packages_readback'] = subprocess.check_output(['dpkg-query', '-W', *PACKAGES], text=True)
        state['packages_sha256'] = hashlib.sha256(state['packages_readback'].encode()).hexdigest()
        state['setup_ns'] = time.monotonic_ns() - state['start_ns']
        state['timing_ns'] = {name: state[name + '_end_ns'] - state[name + '_start_ns'] for name in ('plan', 'cache', 'install')}
        if state['phase'] == 'warm':
            compare_finished(state['cold'], state)
        receipt = {key: value for key, value in state.items() if key != 'cold'}
        text = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
        (root / 'static-apt-setup-receipt.json').write_text(text + '\n')
        print(text)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('receipt=' + text + '\n')
    elif mode == 'report':
        warm = json.loads((root / 'static-apt-setup-receipt.json').read_text())
        require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == warm['source'], 'source moved during suite')
        compare_finished(state['cold'], warm)
        cold = state['cold']
        result = dict(status='PASS_ONE_HOSTED_SETUP_PAIR_AND_FULL_STATIC_SUITE', source=warm['source'], key=warm['key'],
                      cold_setup_seconds=cold['setup_ns'] / 1e9, warm_setup_seconds=warm['setup_ns'] / 1e9,
                      setup_delta_seconds=(cold['setup_ns'] - warm['setup_ns']) / 1e9,
                      scope='setup only; cold post-job save and full job durations require GitHub step/job receipts; one pair is not a general speed claim')
        print(json.dumps(result, sort_keys=True))
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write('```json\n' + json.dumps(result, indent=2) + '\n```\n')
    path.write_text(json.dumps(state, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
