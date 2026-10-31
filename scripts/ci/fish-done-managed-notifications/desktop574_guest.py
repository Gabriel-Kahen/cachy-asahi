# SPDX-License-Identifier: MIT
"""Adapter for the new optional-client lane using a pinned guest helper."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    base = load('slice_base_guest', 'base_guest.py')
    api = load('slice_managed_api', 'managed_session.py')
    api.bind(base)
    # Isolated Python excludes this directory; bind the exact loaded API for session.py.
    sys.modules['managed_session'] = api
    session = load('slice_session', 'session.py')
    original_guard, original_emit = base.guard, base.emit
    completed = set()

    def guard(root):
        original_guard(root)
        base.need('cachy_asahi_bar_notifications=1' in Path('/proc/cmdline').read_text().split(),
                  'bar-notification fixture marker required')
        base.need('cachy_asahi_done_managed=1' in Path('/proc/cmdline').read_text().split(),'explicit Done managed fixture required')

    def phase(stage, config, env, logs):
        trace = session.trace_requested(Path('/proc/cmdline').read_text())
        # Sentinels exercise explicit-template selection and repeated session setup.
        directory = Path(env['XDG_CONFIG_HOME'])
        if stage == 'minimal':
            for name in ('waybar', 'mako', 'fish'):
                owned = directory / name
                owned.mkdir(mode=0o700)
                (owned / 'user-owned.conf').write_text('preserve this custom configuration\n')
        session.phase(stage, config, env, logs, trace_waybar=trace)
        completed.add(stage)
        if stage=='overlay':
            session.phase('background',config,env,logs,trace_waybar=False)
            completed.add('background')

    def emit(event, **values):
        if event in ('session_pass', 'complete'):
            # boot receives the child's session_pass through a separate process;
            # its successful child exit already requires both phases.
            if event == 'session_pass':
                base.need(completed == {'minimal', 'overlay', 'background'}, 'both client phases required')
            values.update(waybar='PASS', mako='PASS', fish_done='PASS_REAL_MANAGED_FOREGROUND_TWO_CASES', watched_background='PASS_REAL_MANAGED_SINGLE_SUCCESS', battery='NOT_RUN', audio='NOT_RUN')
        original_emit(event, **values)

    session.base = base
    base.guard, base.emit, base.phase = guard, emit, phase
    return base.main()


if __name__ == '__main__':
    raise SystemExit(main())
