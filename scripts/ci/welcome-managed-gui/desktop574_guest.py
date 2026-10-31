# SPDX-License-Identifier: MIT
"""Installed Welcome/Doctor GUI adapter on the accepted real managed-user API."""
import importlib.util
from pathlib import Path
import sys


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module


def main():
    base=load('welcome_gui_base','base_guest.py');api=load('welcome_gui_api','managed_session.py')
    session=load('welcome_gui_session','session.py');api.bind(base)
    original_guard,original_emit=base.guard,base.emit;completed=set()
    def guard(root):
        original_guard(root)
        base.need('cachy_asahi_welcome_gui=1' in Path('/proc/cmdline').read_text().split(),'Welcome GUI VM marker required')
    def phase(stage,config,env,logs):
        if stage=='minimal':
            for name in ('Thunar','alacritty'):
                directory=Path(env['XDG_CONFIG_HOME'])/name;directory.mkdir(mode=0o700)
                (directory/'user-sentinel').write_text('preserve user-owned configuration\n')
            (Path(env['XDG_CONFIG_HOME'])/'alacritty/alacritty.toml').write_text('# existing user configuration; preserve exactly\n')
        session.phase(stage,config,env,logs);completed.add(stage)
    def emit(event,**values):
        if event in ('session_pass','complete'):
            if event=='session_pass':base.need(completed=={'minimal','overlay'},'both Welcome GUI phases required')
            values.update(welcome_gui='PASS',doctor_report='PASS',guide_navigation='PASS',launch_actions='PASS')
        if event in ('session_pass','complete','failed'):
            values.update(physical_input='NOT_RUN',managed_session='SELECTED_REAL_USER_MANAGER',
                          terminal_action_exit='UNOBSERVED_NONCHILD',hardware='NOT_RUN')
        original_emit(event,**values)
    session.base=base;base.guard,base.emit,base.phase=guard,emit,phase;return base.main()


if __name__=='__main__':raise SystemExit(main())
