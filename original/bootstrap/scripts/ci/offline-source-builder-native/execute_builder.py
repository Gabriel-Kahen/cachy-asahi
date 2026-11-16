#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the selected real builder unchanged, observing its actual local Docker run."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import threading
import time
import tempfile

DOCKER = ('/usr/bin/docker', '--host=unix:///var/run/docker.sock')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def save(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def check_inspection(row, observation):
    """Check observed daemon state, never infer mount protection from CLI text."""
    output = Path(observation['output']); host = row['HostConfig']
    need(row['Name'] == '/' + observation['name'] and row['Image'] == observation['image']
         and row['Config']['User'] == observation['user'], 'actual build identity')
    need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True
         and host['AutoRemove'] is True and host['Privileged'] is False
         and host['PidsLimit'] == 512 and host['Memory'] == 4 * 1024**3
         and host['NanoCpus'] == 4_000_000_000 and set(host['CapDrop']) == {'ALL'}
         and not host.get('CapAdd') and host['SecurityOpt'] == ['no-new-privileges']
         and not host.get('Devices') and not host.get('DeviceRequests') and not host.get('VolumesFrom'),
         'actual unchanged builder isolation')
    expected = {('/inputs', str(output / 'inputs'), False, 'bind'),
                ('/out', str(output / 'artifacts'), True, 'bind'),
                ('/builder-entry.sh', str(Path(observation['feature_root']) / 'scripts/build/container-entry-v2.sh'), False, 'bind'),
                ('/expected-packages.lock', str(output / 'expected-packages.lock'), False, 'bind'),
                ('/offline-sources', str(output / 'source-material/srcdest'), False, 'bind')}
    actual = {(m['Destination'], m['Source'], m['RW'], m['Type']) for m in row['Mounts'] if m['Type'] == 'bind'}
    need(actual == expected and len(row['Mounts']) in (5, 6)
         and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in row['Mounts'])
         and set(host['Tmpfs']) == {'/tmp'}
         and set(host['Tmpfs']['/tmp'].split(',')) == {'rw', 'nosuid', 'nodev', 'exec', 'size=4g'},
         'actual exact readonly source mount; no source-cache bind')
    need('CACHY_ASAHI_OFFLINE_SOURCES=1' in row['Config']['Env'], 'actual offline-source entry contract')


def run_builder(args):
    sys.path.insert(0, str(args.feature_root / 'scripts/build'))
    spec = importlib.util.spec_from_file_location('selected_actual_build_v2', args.feature_root / 'scripts/build/build_v2.py')
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    original_run = subprocess.run; original_argv = sys.argv
    observation = None
    def observed_run(argv, *positional, **kwargs):
        nonlocal observation
        command = list(map(str, argv))
        if not command or command[0] != 'docker':
            return original_run(argv, *positional, **kwargs)
        forwarded = [*DOCKER, *command[1:]]  # Only select the already admitted local daemon.
        if command[1:2] != ['run']:
            return original_run(forwarded, *positional, **kwargs)
        need(observation is None and '--rm' in command and '--name' in command, 'one actual clean builder run')
        name = command[command.index('--name') + 1]
        need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'actual runner-owned fresh name')
        observation = dict(status='STARTED_NOT_YET_OBSERVED', name=name, command=command,
                           forwarded_command=forwarded, image=args.image, output=str(args.output),
                           feature_root=str(args.feature_root), feature_code_sha=args.feature_code_sha,
                           user=f'{os.getuid()}:{os.getgid()}')
        save(args.observation, observation)  # Cancellation can now identify this exact run.
        stop = threading.Event(); observed = []
        def inspect_running():
            deadline = time.monotonic() + 30
            while not stop.is_set() and time.monotonic() < deadline:
                try:
                    result = original_run([*DOCKER, 'inspect', name], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        rows = json.loads(result.stdout)
                        if len(rows) == 1 and rows[0]['State']['Running'] is True:
                            observed.append(rows[0]); return
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass
                stop.wait(.05)
        watcher = threading.Thread(target=inspect_running, daemon=True); watcher.start()
        try:
            completed = original_run(forwarded, *positional, **kwargs)
            return completed
        finally:
            stop.set(); watcher.join(timeout=6)
            observation['observer_joined'] = not watcher.is_alive()
            if observed:
                observation['inspection'] = observed[0]
                save(args.observation, observation)
                check_inspection(observed[0], observation)
                observation['status'] = 'PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED'
            save(args.observation, observation)
    try:
        subprocess.run = observed_run
        sys.argv = ['build_v2.py', str(args.recipe), '--image', args.image, '--output', str(args.output),
            '--mode', 'native', '--source-date-epoch', '1791748800', '--network', 'none', '--timeout', '600',
            '--expected-packages', str(args.lock), '--reviewed-inputs', str(args.reviewed),
            '--source-plan', str(args.plan), '--source-plan-sha256', args.plan_sha256,
            '--source-catalog', str(args.catalog), '--source-cache', str(args.cache)]
        code = builder.main()
        need(code == 0 and observation is not None and observation['observer_joined'] is True
             and observation['status'] == 'PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED',
             'actual build and mount observation must both complete')
        return 0
    finally:
        subprocess.run = original_run; sys.argv = original_argv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('feature-root', 'recipe', 'output', 'lock', 'reviewed', 'plan', 'catalog', 'cache', 'observation'):
        parser.add_argument('--' + key, type=Path, required=True)
    for key in ('image', 'plan-sha256', 'feature-code-sha'):
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--execute', action='store_true'); args = parser.parse_args()
    need(args.execute and platform.machine() in ('aarch64', 'arm64') and os.getuid() == os.geteuid() != 0
         and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ARCH') == 'ARM64',
         'explicit real hosted native ARM builder required')
    socket_events = []
    def deny_socket(event, values):
        if event.startswith('socket.'):
            socket_events.append(event)
            raise ValueError('Python network operations forbidden during offline build')
    sys.addaudithook(deny_socket)
    try:
        return run_builder(args)
    finally:
        if args.observation.is_file():
            row = json.loads(args.observation.read_text()); row['python_socket_events'] = socket_events
            save(args.observation, row)


if __name__ == '__main__':
    raise SystemExit(main())
