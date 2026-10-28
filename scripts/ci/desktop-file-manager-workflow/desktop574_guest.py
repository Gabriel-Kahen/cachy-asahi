# SPDX-License-Identifier: MIT
"""Guarded file-manager adapter, independent of managed/physical-input routes."""
import importlib.util
from pathlib import Path
HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def main():
    base = load('files_base_guest', 'base_guest.py')
    session = load('files_session', 'session.py')
    original_guard, original_emit = base.guard, base.emit
    completed = set()

    def guard(root):
        original_guard(root)
        base.need('cachy_asahi_file_manager=1' in Path('/proc/cmdline').read_text().split(),
                  'file-manager fixture marker required')

    def phase(stage, config, env, logs):
        if stage == 'minimal':
            directory = Path(env['XDG_CONFIG_HOME']) / 'Thunar'
            directory.mkdir(mode=0o700)
            (directory / 'user-sentinel').write_text('preserve user-owned configuration exactly\n')
        session.phase(stage, config, env, logs);completed.add(stage)

    def emit(event, **values):
        if event in ('session_pass', 'complete'):
            if event == 'session_pass':base.need(completed == {'minimal', 'overlay'}, 'both file-manager phases required')
            values.update(thunar='PASS', dbus_copy='PASS', gio_rename='PASS', text_launch='PASS')
        if event in ('session_pass', 'complete', 'failed'):
            values.update(rename_ui='NOT_RUN', editor_ui='NOT_RUN',
                          managed_session='UNSELECTED_NOT_RUN', physical_keyboard='NOT_RUN')
        original_emit(event, **values)

    session.base = base
    base.guard, base.emit, base.phase = guard, emit, phase
    return base.main()


if __name__ == '__main__':raise SystemExit(main())
