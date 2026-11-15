# SPDX-License-Identifier: MIT
"""Unchanged installed GTK journey, with candidate/provider and confinement proof."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

spec = importlib.util.spec_from_file_location('ui_user_contract', '/driver/borrowed/user_journey.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
ROOT = Path('/work/python-desktop/user')


def snapshot(home):
    result = {}
    for path in sorted(home.rglob('*')):
        item = path.lstat()
        row = {'mode': item.st_mode & 0o7777, 'uid': item.st_uid, 'gid': item.st_gid}
        if path.is_symlink(): row['link'] = str(path.readlink())
        elif path.is_file(): row['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        else: row['directory'] = True
        result[path.relative_to(home).as_posix()] = row
    return result


def run(version):
    if sys.version_info[:3] != tuple(map(int, version.split('.'))):
        raise ValueError('wrong desktop Python provider')
    record = json.loads(Path('/work/public/python-provider.json').read_text())
    expected = record['candidate'] if version == '3.14.8' else record['provider']
    library = Path('/usr/lib/libpython3.14.so.1.0')
    mapped = sorted({line.split()[-1] for line in Path('/proc/self/maps').read_text().splitlines() if 'libpython' in line})
    if mapped != [str(library)] or hashlib.sha256(library.read_bytes()).hexdigest() != expected['payload'][str(library).lstrip('/')]['sha256']:
        raise ValueError('wrong mapped desktop libpython')
    import gi
    gi.require_version('Gtk', '4.0')
    from gi.repository import Gtk, GLib, Gio
    from gi import _gi
    if (str(Path(_gi.__file__)) != record['gi_extension']['path'] or
            hashlib.sha256(Path(_gi.__file__).read_bytes()).hexdigest() != record['gi_extension']['sha256']):
        raise ValueError('PyGObject consumer changed')
    ROOT.mkdir(mode=0o700, exist_ok=True)
    home = ROOT / ('GUI home ' + version)
    sys.argv = ['/driver/borrowed/installed_gui.py', str(home)]
    # This runs the exact installed /usr window/Preview/Apply/idle-close driver.
    runpy.run_path('/driver/borrowed/installed_gui.py', run_name='__main__')
    result = {'python': sys.version, 'executable': sys.executable, 'mapped_library': mapped,
              'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
              'gi_extension': str(_gi.__file__), 'gi_sha256': record['gi_extension']['sha256'],
              'Gtk': [Gtk.get_major_version(), Gtk.get_minor_version(), Gtk.get_micro_version()],
              'GLib': [GLib.MAJOR_VERSION, GLib.MINOR_VERSION, GLib.MICRO_VERSION],
              'Gio': str(Gio.ApplicationFlags.NON_UNIQUE), 'home': str(home), 'home_state': snapshot(home),
              'process_confinement': {key: status[key].strip() for key in ('CapEff', 'CapBnd', 'NoNewPrivs', 'Seccomp')},
              'source_hidden': True, 'installed_driver_sha256': hashlib.sha256(Path('/driver/borrowed/installed_gui.py').read_bytes()).hexdigest()}
    (ROOT / ('result-' + version + '.json')).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


def verify():
    for path in ROOT.glob('result-*.json'):
        result = json.loads(path.read_text())
        if snapshot(Path(result['home'])) != result['home_state']:
            raise ValueError('caller home changed during provider restoration/package removal')
    (ROOT / 'homes-preserved.json').write_text(json.dumps({'status': 'PASS exact caller home bytes/modes/UID/GID/links',
                                                         'homes': len(list(ROOT.glob('result-*.json')))}))


def launch(version):
    ROOT.mkdir(mode=0o700, exist_ok=True)
    runtime = ROOT / ('runtime-' + version)
    runtime.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT), 'XDG_RUNTIME_DIR': str(runtime),
           'XDG_CONFIG_HOME': str(ROOT / 'xdg-config'), 'XDG_CACHE_HOME': str(ROOT / 'cache'),
           'GDK_BACKEND': 'x11', 'GSK_RENDERER': 'cairo', 'GDK_DEBUG': 'no-portals',
           'GDK_DISABLE': 'gl,vulkan,dmabuf', 'GTK_A11Y': 'none', 'LC_ALL': 'C.UTF-8'}
    child = subprocess.run(['dbus-run-session', '--', 'xvfb-run', '-a', '-e', str(ROOT / ('xvfb-' + version + '.log')),
            '-s', '-screen 0 1024x768x24 -nolisten tcp -extension GLX',
            '/usr/bin/python3', '-I', '-B', '/driver/user_probe.py', 'run', version],
            cwd='/', env=env, capture_output=True, text=True, timeout=120)
    (ROOT / ('gui-' + version + '.stdout')).write_text(child.stdout)
    (ROOT / ('gui-' + version + '.stderr')).write_text(child.stderr)
    if child.returncode or json.loads(child.stdout)['count'] != 4:
        raise ValueError('unchanged installed GUI driver failed for provider ' + version)


if __name__ == '__main__':
    os.umask(0o077)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if (os.geteuid() != 1000 or not sys.flags.isolated or sys.flags.optimize
            or any(int(status[key].strip(), 16) for key in ('CapEff', 'CapBnd'))
            or status['NoNewPrivs'].strip() != '1' or status['Seccomp'].strip() != '2'
            or contract.source_visible()):
        raise SystemExit('source-hidden ordinary zero-capability GTK process required')
    if sys.argv[1] == 'run': run(sys.argv[2])
    elif sys.argv[1] == 'launch': launch(sys.argv[2])
    elif sys.argv[1] == 'verify': verify()
    else: raise ValueError('unknown fixed user operation')
