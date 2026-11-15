#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real installed GTK4 window/buttons on a real private X11 display, UID1000."""
import ctypes, ctypes.util, hashlib, importlib.util, json, os, sys, time
from pathlib import Path

def main():
    assert __debug__ and sys.flags.isolated and os.geteuid() == 1000
    import gi
    gi.require_version('Gtk', '4.0')
    from gi.repository import Gtk, GLib, Gio, Gdk
    spec = importlib.util.spec_from_file_location('installed_ui', '/usr/lib/cachy-asahi/first-login-ui/gui.py')
    gui = importlib.util.module_from_spec(spec); spec.loader.exec_module(gui)
    home = Path('/home/builder/UI-profile'); home.mkdir(mode=0o700)
    seed = b'# real-seat UI existing user settings\n'; (home / '.zshrc').write_bytes(seed)
    def files():
        return {str(p.relative_to(home)): hashlib.sha256(p.read_bytes()).hexdigest() for p in home.rglob('*') if p.is_file()}
    Gtk.init(); app = Gtk.Application(application_id='io.github.GabrielKahen.RealSeatUITest', flags=Gio.ApplicationFlags.NON_UNIQUE); app.register(None)
    window = gui.window_class()(app, gui.bridge.Bridge(Path('/usr'), home=home, template_root=Path('/opt/ui-session/templates')))
    window.present()
    def wait():
        end = time.monotonic() + 20
        while window.busy or not window.get_mapped():
            while GLib.MainContext.default().iteration(False): pass
            if time.monotonic() > end: raise TimeoutError('real installed GTK window deadline')
            time.sleep(.01)
        for _ in range(20):
            while GLib.MainContext.default().iteration(False): pass
            time.sleep(.01)
    wait(); initial = files(); assert initial == {'.zshrc': hashlib.sha256(seed).hexdigest()} and not window.apply.get_sensitive()
    display = Gdk.Display.get_default(); renderer = window.get_renderer()
    assert display.__gtype__.name == 'GdkX11Display' and renderer.__gtype__.name == 'GskCairoRenderer'
    window.choices['fish'].set_active(True); window.choices['zsh'].set_active(True)
    window.preview.emit('clicked'); wait(); assert files() == initial and window.apply.get_sensitive()
    window.apply.emit('clicked'); wait()
    assert window.status.get_text().startswith('Settings applied.')
    assert (home / '.config/fish/config.fish').is_file() and (home / '.zshrc').read_bytes().startswith(seed)
    edit = b'\n# user edit after actual GTK apply\n'; (home / '.zshrc').write_bytes((home / '.zshrc').read_bytes() + edit)
    edited = files(); window.refresh.emit('clicked'); wait(); window.preview.emit('clicked'); wait()
    assert files() == edited and window.apply.get_sensitive()
    window.apply.emit('clicked'); wait(); assert files() == edited and (home / '.zshrc').read_bytes().endswith(edit)
    # Read actual X server pixels; no screenshot or user configuration is exported.
    class XImage(ctypes.Structure):
        _fields_ = [('width', ctypes.c_int), ('height', ctypes.c_int), ('xoffset', ctypes.c_int), ('format', ctypes.c_int), ('data', ctypes.c_void_p), ('byte_order', ctypes.c_int), ('bitmap_unit', ctypes.c_int), ('bitmap_bit_order', ctypes.c_int), ('bitmap_pad', ctypes.c_int), ('depth', ctypes.c_int), ('bytes_per_line', ctypes.c_int)]
    x = ctypes.CDLL(ctypes.util.find_library('X11'))
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]; x.XOpenDisplay.restype = ctypes.c_void_p
    x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]; x.XDefaultRootWindow.restype = ctypes.c_ulong
    x.XGetImage.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong, ctypes.c_int]; x.XGetImage.restype = ctypes.POINTER(XImage)
    x.XDestroyImage.argtypes = [ctypes.POINTER(XImage)]; x.XCloseDisplay.argtypes = [ctypes.c_void_p]
    d = x.XOpenDisplay(None); assert d
    image = None
    try:
        image = x.XGetImage(d, x.XDefaultRootWindow(d), 0, 0, 1024, 768, ctypes.c_ulong(-1).value, 2); assert image
        count = image.contents.bytes_per_line * image.contents.height; assert 0 < count <= 4 * 1024**2
        pixels = ctypes.string_at(image.contents.data, count); assert len(set(pixels)) > 16
        rendering = {'display_type': display.__gtype__.name, 'renderer_type': renderer.__gtype__.name, 'root_image_bytes': count, 'root_image_sha256': hashlib.sha256(pixels).hexdigest(), 'image_exported': False}
    finally:
        if image: x.XDestroyImage(image)
        x.XCloseDisplay(d)
    window.close(); assert window.worker is None
    report = {'status': 'PASS_REAL_INSTALLED_GTK_CONTROLS', 'uid': os.geteuid(), 'pid': os.getpid(), 'initial_inspect_read_only': True, 'preview_read_only': True, 'explicit_apply': True, 'repeat_apply_preserved_user_edit': True, 'rendering': rendering, 'user_files': files()}
    print(json.dumps(report, sort_keys=True))
if __name__ == '__main__': main()
