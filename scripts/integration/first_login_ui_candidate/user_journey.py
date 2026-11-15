#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Installed and extracted payload checks as the private ordinary test user."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path('/work/lifecycle/user')


def source_visible(inputs=Path('/inputs'), checkout=Path('/home/gabe/Documents/ChatGPT'), mountinfo=Path('/proc/self/mountinfo')):
    # Docker commit retains an empty directory at a former mount destination;
    # contents or an actual source mount are forbidden, not that placeholder.
    return (checkout.exists() or (inputs.exists() and (not inputs.is_dir() or any(inputs.iterdir())))
            or any(line.split()[4] == str(inputs) for line in mountinfo.read_text().splitlines()))


def files(home):
    return {str(p.relative_to(home)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(home.rglob('*')) if p.is_file()}


def run():
    os.umask(0o077)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert int(status['CapEff'].strip(), 16) == 0 and int(status['CapBnd'].strip(), 16) == 0
    assert status['NoNewPrivs'].strip() == '1' and status['Seccomp'].strip() == '2'
    if source_visible():
        raise ValueError('checkout/source inputs unexpectedly visible')
    ROOT.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed_bridge', '/usr/lib/cachy-asahi/first-login-ui/bridge.py')
    bridge = importlib.util.module_from_spec(spec); spec.loader.exec_module(bridge)
    home = ROOT / 'installed home'; home.mkdir(mode=0o700)
    templates = Path('/opt/ui-integration/templates')
    client = bridge.Bridge(Path('/usr'), home=home, template_root=templates)
    assert client.run('inspect')[0]['status'] == 'ready-to-select'
    assert client.run('preview', ('fish', 'zsh'))[0]['status'] == 'activation-preview'
    assert list(home.iterdir()) == []
    (home / '.zshrc').write_text('# preserve disposable user edit\n')
    try: client.run('apply')
    except bridge.Error: pass
    else: raise AssertionError('stale installed preview accepted')
    assert list(home.iterdir()) == [home / '.zshrc']
    client.run('preview', ('fish', 'zsh'))
    assert client.run('apply')[0]['status'] == 'activation-applied'
    assert (home / '.zshrc').read_text().startswith('# preserve disposable user edit\n')
    expected = json.loads(Path('/work/public/payloads.json').read_text())
    for source in expected.values():
        for path, row in source.items():
            assert hashlib.sha256((Path('/') / path).read_bytes()).hexdigest() == row['sha256']
            assert hashlib.sha256((Path('/work/extracted') / path).read_bytes()).hexdigest() == row['sha256']
    gui_root = ROOT / 'gui'; gui_root.mkdir(mode=0o700)
    shutil.copytree('/work/extracted', gui_root / 'moved prefix')
    shutil.copytree(templates, gui_root / 'templates')
    (gui_root / 'private home').mkdir(mode=0o700)
    runtime = ROOT / 'runtime'; runtime.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT), 'XDG_RUNTIME_DIR': str(runtime),
        'XDG_CONFIG_HOME': str(ROOT / 'xdg-config'), 'XDG_CACHE_HOME': str(ROOT / 'cache'),
        'GDK_BACKEND': 'x11', 'GSK_RENDERER': 'cairo', 'GDK_DEBUG': 'no-portals',
        'GDK_DISABLE': 'gl,vulkan,dmabuf', 'GTK_A11Y': 'none', 'LC_ALL': 'C.UTF-8'}
    installed = subprocess.run(['dbus-run-session', '--', 'xvfb-run', '-a', '-e', str(ROOT/'installed-xvfb.log'),
        '-s', '-screen 0 1024x768x24 -nolisten tcp -extension GLX',
        '/usr/bin/python3', '-I', '/driver/installed_gui.py', str(ROOT/'installed GUI home')],
        cwd='/',env=env,capture_output=True,text=True,timeout=90)
    (ROOT/'installed-gui.stdout').write_text(installed.stdout)
    (ROOT/'installed-gui.stderr').write_text(installed.stderr)
    if installed.returncode:raise ValueError('actual installed /usr GUI controls failed')
    installed_gui=json.loads(installed.stdout)
    assert installed_gui['count']==4
    result = subprocess.run(['dbus-run-session', '--', 'xvfb-run', '-a', '-e', str(ROOT / 'xvfb.log'),
        '-s', '-screen 0 1024x768x24 -nolisten tcp -extension GLX',
        '/usr/bin/python3', '-I', '/driver/gui_controls.py', '--child', str(gui_root)],
        cwd='/', env=env, capture_output=True, text=True, timeout=120)
    (ROOT / 'gui.stdout').write_text(result.stdout); (ROOT / 'gui.stderr').write_text(result.stderr)
    if result.returncode: raise ValueError('actual installed/extracted GUI controls failed')
    gui = json.loads(result.stdout)
    assert gui['count'] == 11
    snapshot = {str(p.relative_to(ROOT)): files(p) for p in (home, ROOT/'installed GUI home',gui_root / 'private home', gui_root / 'recovery home')}
    (ROOT / 'expected-user-files.json').write_text(json.dumps(snapshot, sort_keys=True))
    (ROOT / 'result.json').write_text(json.dumps({'installed_cli': 'PASS inspect/read-only preview/stale refusal/explicit apply/edit preservation',
        'payload_join': 'PASS all24 installed/extracted ordinary file hashes', 'GUI': gui,
        'installed_GUI':installed_gui,
        'process_confinement': {name:status[name].strip() for name in ('CapEff','CapBnd','NoNewPrivs','Seccomp')},
        'source_hidden': True, 'native_ARM': 'NOT RUN', 'M2': 'NOT RUN'}, indent=2))


def verify_removal():
    expected = json.loads((ROOT / 'expected-user-files.json').read_text())
    observed = {name: files(ROOT / name) for name in expected}
    if observed != expected: raise ValueError('user configuration changed during package removal')
    (ROOT / 'removal.json').write_text(json.dumps({'status': 'PASS removal preserves exact private user configuration digests',
        'homes': len(expected), 'native_ARM': 'NOT RUN', 'M2': 'NOT RUN'}))


if __name__ == '__main__':
    if os.geteuid() != 1000 or not sys.flags.isolated or sys.flags.optimize:
        raise SystemExit('Private ordinary-user diagnostic only; isolated unoptimized Python required')
    {'run': run, 'verify-removal': verify_removal}[sys.argv[1]]()
