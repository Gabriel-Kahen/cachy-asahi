#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actual installed /usr window and buttons in the caller's private display."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

if not sys.flags.isolated or sys.flags.optimize or os.geteuid() != 1000:
    raise SystemExit('Private ordinary-user GUI probe only')
os.umask(0o077)
import gi
gi.require_version('Gtk','4.0')
from gi.repository import Gtk, GLib, Gio

spec = importlib.util.spec_from_file_location('installed_gui', '/usr/lib/cachy-asahi/first-login-ui/gui.py')
gui = importlib.util.module_from_spec(spec); spec.loader.exec_module(gui)
home = Path(sys.argv[1]); home.mkdir(mode=0o700)
(home / '.zshrc').write_text('# preserve installed GUI edit\n')
before = (home / '.zshrc').read_bytes()
Gtk.init()
app = Gtk.Application(application_id='io.github.GabrielKahen.InstalledFirstLoginTest',flags=Gio.ApplicationFlags.NON_UNIQUE)
app.register(None)
window = gui.window_class()(app, gui.bridge.Bridge(Path('/usr'),home=home,
                                                template_root=Path('/opt/ui-integration/templates')))
window.present()

def wait(mapped=False):
    end=time.monotonic()+20
    while window.busy or (mapped and not window.get_mapped()):
        while GLib.MainContext.default().iteration(False): pass
        if time.monotonic()>=end: raise AssertionError('installed GUI deadline')
        time.sleep(0.01)
    while GLib.MainContext.default().iteration(False): pass

wait(True)
assert list(home.iterdir())==[home/'.zshrc'] and not window.apply.get_sensitive()
window.choices['fish'].set_active(True);window.choices['zsh'].set_active(True)
window.preview.emit('clicked');wait()
assert window.apply.get_sensitive() and list(home.iterdir())==[home/'.zshrc']
window.apply.emit('clicked');wait()
assert (home/'.config/fish/config.fish').is_file()
assert (home/'.zshrc').read_bytes().startswith(before)
window.close()
assert window.worker is None
print(json.dumps({'status':'PASS actual installed /usr GTK window/buttons',
    'checks':['mapped installed window/read-only inspect','preview button/read-only preview',
              'apply button/real installed backend/edit preservation','idle close/no worker'],
    'count':4,'native_ARM':'NOT RUN','M2':'NOT RUN'},indent=2))
