#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actual private-display GTK buttons and real helpers, separate optional test."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import resource
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def child(root):
    import gi
    gi.require_version('Gtk', '4.0')
    from gi.repository import Gtk, GLib, Gio
    gui = load('gui', root / 'moved prefix/usr/lib/cachy-asahi/first-login-ui/gui.py')
    prefix = root / 'moved prefix/usr'
    home, templates = root / 'private home', root / 'templates'
    Gtk.init()
    app = Gtk.Application(application_id='io.github.GabrielKahen.FirstLoginUITest', flags=Gio.ApplicationFlags.NON_UNIQUE)
    app.register(None)
    Window = gui.window_class()
    checks = []

    def wait(window, predicate=lambda: True):
        end = time.monotonic() + 20
        while window.busy or not predicate():
            while GLib.MainContext.default().iteration(False): pass
            if time.monotonic() >= end:
                raise AssertionError('GUI action deadline')
            time.sleep(0.01)
        while GLib.MainContext.default().iteration(False): pass

    def click(window, button):
        assert button.get_sensitive(), button.get_label()
        button.emit('clicked'); wait(window)

    def make(home):
        window = Window(app, gui.bridge.Bridge(prefix, home=home, template_root=templates))
        window.present(); wait(window, window.get_mapped)
        return window

    window = make(home)
    assert list(home.iterdir()) == []
    checks.append('real mapped window inspects without writes')
    assert not window.apply.get_sensitive()
    checks.append('apply disabled before explicit preview')
    window.choices['fish'].set_active(True); window.choices['zsh'].set_active(True)
    click(window, window.preview)
    assert window.apply.get_sensitive() and list(home.iterdir()) == []
    checks.append('real preview button enables apply without writes')
    end = time.monotonic() + 0.2
    while time.monotonic() < end:
        while GLib.MainContext.default().iteration(False): pass
        time.sleep(0.01)
    if shutil.which('import'):
        subprocess.run(['import', '-window', 'root', str(root / 'preview.png')], check=True, timeout=10)
    (home / '.zshrc').write_text('# preserve GUI test edit\n')
    click(window, window.apply)
    assert (home / '.zshrc').read_text() == '# preserve GUI test edit\n'
    assert 'changed' in window.status.get_text() and not window.apply.get_sensitive()
    checks.append('real stale apply button refuses and preserves edit')
    click(window, window.refresh); click(window, window.preview); click(window, window.apply)
    assert (home / '.config/fish/config.fish').is_file()
    assert (home / '.zshrc').read_text().startswith('# preserve GUI test edit\n')
    checks.append('explicit fresh apply writes real Setup8 config and preserves edit')
    click(window, window.preview); window.choices['fish'].set_active(False)
    assert not window.apply.get_sensitive()
    checks.append('selection change invalidates actual apply button')
    window.destroy()

    recovery_home = root / 'recovery home'; recovery_home.mkdir(mode=0o700)
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader('test_setup', str(prefix / 'bin/cachy-asahi-setup'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    setup = importlib.util.module_from_spec(spec); loader.exec_module(setup)
    engine = setup.Setup(recovery_home, templates)
    original = engine.fs.atomic
    class Interrupted(BaseException): pass
    def interrupt(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == engine.targets['fish']: raise Interrupted()
        return result
    engine.fs.atomic = interrupt
    try: engine.run('activate', ('fish', 'zsh'), True)
    except Interrupted: pass
    finally: engine.close()
    window = make(recovery_home)
    assert window.recover_preview.get_sensitive() and not window.preview.get_sensitive()
    checks.append('real pending journal enables only recovery preview')
    before = {str(p): p.read_bytes() for p in recovery_home.rglob('*') if p.is_file()}
    click(window, window.recover_preview)
    assert window.recover_apply.get_sensitive()
    assert before == {str(p): p.read_bytes() for p in recovery_home.rglob('*') if p.is_file()}
    checks.append('real recovery preview button preserves pending inputs')
    click(window, window.recover_apply)
    assert (recovery_home / '.zshrc').is_file()
    assert not (recovery_home / '.local/state/cachy-asahi/setup/journal.json').exists()
    checks.append('real resume button completes original transaction')
    assert not window.recover_apply.get_sensitive() and not window.recover_preview.get_sensitive()
    checks.append('completed recovery cannot be resumed again without inspect')
    window.destroy()
    (prefix / 'bin/cachy-asahi-first-login').write_text('#!/usr/bin/python3 -I\nimport time\ntime.sleep(60)\n')
    window = Window(app, gui.bridge.Bridge(prefix, home=home, template_root=templates))
    window.present(); window.close()
    wait(window)
    assert window.worker is None and window.closing
    checks.append('closing a busy real window cancels and joins helper worker')
    print(json.dumps({'status': 'PASS actual private Xvfb GTK window/button checks',
        'checks': checks, 'count': len(checks), 'GUI': 'actual private Xvfb',
        'source': 'checkouts hidden, moved installed prefix', 'native_ARM': 'NOT RUN', 'M2': 'NOT RUN'}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.child:
        child(args.child); return 0
    missing = [p for p in ('bwrap', 'xvfb-run', 'Xvfb', 'dbus-run-session', 'fish', 'zsh') if not shutil.which(p)]
    if missing:
        print(json.dumps({'GUI': 'NOT RUN', 'missing': missing})); return 2
    support = load('support', HERE / 'test_support.py')
    delivery = load('delivery', HERE / 'test_delivery.py')
    fixture = support.Fixture()
    try:
        script = fixture.root / 'private-gui.py'; shutil.copyfile(__file__, script)
        runtime = fixture.root / 'runtime'; runtime.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(fixture.root), 'XDG_RUNTIME_DIR': str(runtime),
            'XDG_CONFIG_HOME': str(fixture.root / 'xdg-config'), 'XDG_CACHE_HOME': str(fixture.root / 'cache'),
            'GDK_BACKEND': 'x11', 'GSK_RENDERER': 'cairo', 'GDK_DEBUG': 'no-portals',
            'GDK_DISABLE': 'gl,vulkan,dmabuf', 'GTK_A11Y': 'none', 'LC_ALL': 'C.UTF-8'}
        command = delivery.sandbox(fixture.root, ['dbus-run-session', '--', 'xvfb-run', '-a', '-e', str(fixture.root / 'xvfb.log'),
            '-s', '-screen 0 1024x768x24 -nolisten tcp -extension GLX', '/usr/bin/python3', '-I', str(script), '--child', str(fixture.root)])
        def no_core(): resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = subprocess.run(command, env=env, cwd='/', capture_output=True, text=True, timeout=100, preexec_fn=no_core)
        if args.output:
            args.output.mkdir(mode=0o700)
            (args.output / 'gui.json').write_text(result.stdout)
            (args.output / 'gui.stderr').write_text(result.stderr)
            if (fixture.root / 'preview.png').exists():
                shutil.copyfile(fixture.root / 'preview.png', args.output / 'preview.png')
            if (fixture.root / 'xvfb.log').exists():
                shutil.copyfile(fixture.root / 'xvfb.log', args.output / 'xvfb.log')
        print(result.stdout, end=''); print(result.stderr, file=sys.stderr, end='')
        return result.returncode
    finally:
        fixture.close()


if __name__ == '__main__':
    raise SystemExit(main())
