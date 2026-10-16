# SPDX-License-Identifier: MIT
"""Separate terminal workflow adapter; managed/physical-input routes unselected."""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def main():
    base = load('terminal_base_guest', 'base_guest.py')
    session = load('terminal_session', 'session.py')
    original_guard, original_emit = base.guard, base.emit
    completed = set()

    def guard(root):
        original_guard(root)
        base.need('cachy_asahi_terminal_workflow=1' in Path('/proc/cmdline').read_text().split(),
                  'terminal workflow fixture marker required')

    def phase(stage, config, env, logs):
        if stage == 'minimal':
            directory = Path(env['XDG_CONFIG_HOME']) / 'alacritty'
            directory.mkdir(mode=0o700)
            (directory / 'alacritty.toml').write_text('# user-owned; preserve exactly\n')
            (Path(env['XDG_CONFIG_HOME']) / 'vimrc').write_text('let g:preserved = 1\n')
        session.phase(stage, config, env, logs);completed.add(stage)

    def emit(event, **values):
        if event in ('session_pass', 'complete'):
            if event == 'session_pass':base.need(completed == {'minimal', 'overlay'}, 'both terminal phases required')
            values.update(terminal='PASS', vim_edit='PASS', native_c='PASS', unicode_clipboard='PASS')
        if event in ('session_pass', 'complete', 'failed'):
            values.update(thunar='UNSELECTED_NOT_RUN', managed_session='UNSELECTED_NOT_RUN', physical_keyboard='NOT_RUN')
        original_emit(event, **values)

    session.base = base
    base.guard, base.emit, base.phase = guard, emit, phase
    return base.main()


if __name__ == '__main__':
    raise SystemExit(main())
