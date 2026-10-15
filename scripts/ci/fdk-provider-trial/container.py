#!/usr/bin/env python3
"""Actual package transactions and shipped PipeWire AAC plugin execution."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

OUT = Path('/out')
PLUGIN = '/usr/lib/spa-0.2/bluez5/libspa-codec-bluez5-aac.so'


def run(args, *, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    print('$', ' '.join(map(str, args)), '\n', result.stdout, result.stderr, flush=True)
    if check:
        result.check_returncode()
    return result


def inventory():
    return dict(line.split(' ', 1) for line in run(['pacman', '-Q']).stdout.splitlines())


def unprivileged():
    os.setgroups([]); os.setgid(65534); os.setuid(65534)


def smoke(label, owner):
    result = subprocess.run(['/tmp/pipewire-aac-smoke', PLUGIN], capture_output=True,
        text=True, timeout=30, preexec_fn=unprivileged)
    (OUT / (label + '-codec.log')).write_text(result.stdout + result.stderr)
    print(label, result.stdout, result.stderr, flush=True)
    result.check_returncode()
    paths = [line.removeprefix('FDK_LIBRARY=') for line in result.stdout.splitlines()
             if line.startswith('FDK_LIBRARY=')]
    assert len(paths) == 1 and paths[0].startswith('/usr/lib/libfdk-aac.so.2')
    loaded = Path(paths[0]).resolve(strict=True)
    assert loaded.parent == Path('/usr/lib')
    assert run(['pacman', '-Qqo', str(loaded)]).stdout.strip() == owner
    digest = hashlib.sha256(loaded.read_bytes()).hexdigest()
    print(label, 'loaded provider', owner, loaded, digest, flush=True)
    return {'owner': owner, 'path': str(loaded), 'sha256': digest}


def main():
    assert platform.machine() == 'aarch64' and os.geteuid() == 0 and Path('/.dockerenv').is_file()
    plan = json.loads(Path('/inputs/plan.json').read_text())
    for row in plan['packages']:
        path = Path('/inputs') / row['filename']
        assert path.stat().st_size == row['size']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256']
    base = dict(line.split(' ', 1) for line in Path('/inputs/base.lock').read_text().splitlines())
    assert inventory() == base
    # Mask existing and incoming hooks; package scriptlets are also disabled.
    hooks = Path('/trial-hooks'); hooks.mkdir()
    names = set(plan['hooks'])
    for directory in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'):
        names.update(p.name for p in Path(directory).glob('*.hook'))
    for name in names:
        (hooks / name).symlink_to('/dev/null')
    Path('/tmp/pacman.conf').write_text('[options]\nArchitecture = aarch64\n'
        'SigLevel = Never\nLocalFileSigLevel = Never\nHookDir = /trial-hooks\n')
    # Input packages were signature/hash verified on the host. The local candidate
    # is intentionally unsigned. This private config is not release trust setup.
    pacman = ['pacman', '--config', '/tmp/pacman.conf', '--noconfirm', '--noscriptlet']
    upstream = next(row for row in plan['packages'] if row['name'] == 'libfdk-aac')
    run(pacman + ['-U'] + ['/inputs/' + row['filename'] for row in plan['packages']])
    baseline = base | {row['name']: row['version'] for row in plan['packages']}
    assert inventory() == baseline
    run(['pacman', '-Dk'])
    run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I/runner/headers',
        '-I/usr/include/spa-0.2', '/runner/smoke.c', '-ldl', '-lm', '-o', '/tmp/pipewire-aac-smoke'])
    consumed = {'upstream-before': smoke('upstream-before', 'libfdk-aac')}
    plugin_hash = hashlib.sha256(Path(PLUGIN).read_bytes()).hexdigest()
    assert plugin_hash == '25ce30c727b37acea500aa49842f1a58e371fa70d5f0b50ae7526fb951855ab5'
    candidate = Path('/inputs') / plan['candidate']
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == plan['candidate_sha256']
    # 4 is ALPM_QUESTION_CONFLICT_PKG: allow the explicit conflict replacement.
    run(pacman + ['--ask', '4', '-U', str(candidate)])
    expected = dict(baseline); del expected['libfdk-aac']; expected['cachy-asahi-fdk-aac'] = '3.0.0-1'
    assert inventory() == expected
    run(['pacman', '-T', 'libfdk-aac', 'libfdk-aac.so=2-64', 'libfdk-xhe-aac.so=0-64'])
    run(['pacman', '-Dk'])
    run(['pacman', '-Qkk', 'cachy-asahi-fdk-aac'])
    for path in ('/usr/lib/libfdk-aac.so.2', '/usr/lib/libfdk-xhe-aac.so.0'):
        assert run(['pacman', '-Qqo', path]).stdout.strip() == 'cachy-asahi-fdk-aac'
    assert run(['pacman', '-Qqo', PLUGIN]).stdout.strip() == 'pipewire-audio'
    assert hashlib.sha256(Path(PLUGIN).read_bytes()).hexdigest() == plugin_hash
    consumed['candidate'] = smoke('candidate', 'cachy-asahi-fdk-aac')
    refused = run(pacman + ['-R', 'cachy-asahi-fdk-aac'], check=False)
    diagnostic = refused.stdout + refused.stderr
    assert refused.returncode == 1 and inventory() == expected
    assert "breaks dependency 'libfdk-aac" in diagnostic and 'required by pipewire-audio' in diagnostic
    run(pacman + ['--ask', '4', '-U', '/inputs/' + upstream['filename']])
    assert inventory() == baseline
    run(['pacman', '-T', 'libfdk-aac', 'libfdk-aac.so=2-64'])
    run(['pacman', '-Dk'])
    assert run(['pacman', '-Qqo', '/usr/lib/libfdk-aac.so.2']).stdout.strip() == 'libfdk-aac'
    assert not Path('/usr/lib/libfdk-xhe-aac.so.0').exists()
    assert hashlib.sha256(Path(PLUGIN).read_bytes()).hexdigest() == plugin_hash
    consumed['upstream-restored'] = smoke('upstream-restored', 'libfdk-aac')
    assert consumed['upstream-before'] == consumed['upstream-restored']
    (OUT / 'result.json').write_text(json.dumps({'status': 'PASS',
        'provider_transaction': 'PASS', 'dependent_removal_refused': True,
        'upstream_restored': True, 'shipped_pipewire_aac_codec': 'PASS',
        'plugin_sha256': plugin_hash, 'candidate_sha256': plan['candidate_sha256'],
        'consumed_providers': consumed,
        'bluetooth_transport': 'NOT RUN', 'pipewire_daemon_graph': 'NOT RUN',
        'hardware_validation': 'NOT RUN', 'target_lifecycle': 'NOT RUN'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
