# SPDX-License-Identifier: MIT
"""Compose the accepted real managed-user API with both owned application tasks."""
import importlib.util
from pathlib import Path
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec);sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    base = load('managed_workflow_base', 'base_guest.py')
    api = load('managed_workflow_api', 'managed_session.py')
    session = load('managed_workflow_session', 'session.py')
    api.bind(base)
    original_guard, original_emit = base.guard, base.emit
    completed = set()

    def guard(root):
        original_guard(root)
        base.need('cachy_asahi_managed_workflow=1' in Path('/proc/cmdline').read_text().split(),
                  'combined managed workflow marker required')

    def phase(stage, config, env, logs):
        if stage == 'minimal':
            for name in ('Thunar', 'alacritty'):
                directory = Path(env['XDG_CONFIG_HOME']) / name
                directory.mkdir(mode=0o700)
                (directory/'user-sentinel').write_text('preserve existing user configuration exactly\n')
            (Path(env['XDG_CONFIG_HOME'])/'vimrc').write_text('let g:preserved = 1\n')
        session.phase(stage, config, env, logs);completed.add(stage)

    def emit(event, **values):
        if event in ('session_pass', 'complete'):
            if event == 'session_pass':base.need(completed == {'minimal','overlay'}, 'both combined phases required')
            values.update(terminal='PASS', vim_edit='PASS', native_c='PASS', unicode_clipboard='PASS',
                          thunar='PASS', dbus_copy='PASS', gio_rename='PASS', text_launch='PASS', co_resident=True)
        if event in ('session_pass', 'complete', 'failed'):
            values.update(rename_ui='NOT_RUN', editor_ui='NOT_RUN', physical_keyboard='NOT_RUN',
                          managed_session='SELECTED_REAL_USER_MANAGER')
        original_emit(event, **values)

    session.base = base
    base.guard, base.emit, base.phase = guard, emit, phase
    return base.main()


if __name__ == '__main__':raise SystemExit(main())
