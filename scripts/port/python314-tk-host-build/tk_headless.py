#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Load the built extension and evaluate Tcl without creating a Tk window."""
import json
import os
import sys
import tkinter
import _tkinter

assert sys.flags.isolated
assert sys.version_info[:3] == (3, 14, 8)
assert not any(os.environ.get(name) for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS'))
interpreter = tkinter.Tcl()
assert interpreter.eval('expr {6 * 7}') == '42'
print(json.dumps({'status': 'PASS headless Tcl only', 'python': sys.version,
                  'extension': _tkinter.__file__, 'TCL_VERSION': _tkinter.TCL_VERSION,
                  'TK_VERSION': _tkinter.TK_VERSION,
                  'Tcl_patchlevel': interpreter.eval('info patchlevel'),
                  'Tk_loaded': bool(interpreter.eval('info commands tk')),
                  'GUI': 'NOT RUN', 'native_ARM': 'NOT RUN', 'M2': 'NOT RUN'}, sort_keys=True))
