# SPDX-License-Identifier: MIT
"""Select the managed keyboard lane; fixture shell config contains no payload."""
import importlib.util
from pathlib import Path
import sys


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module


def main():
    base=load('keyboard_base','base_guest.py');api=load('keyboard_managed','managed_session.py')
    # This directory is already on sys.path in guest.py; isolated Python keeps the explicit entrypoint safe.
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    session=load('keyboard_session','session.py');api.bind(base)
    original_guard,original_emit=base.guard,base.emit;completed=set()
    def guard(root):
        original_guard(root)
        base.need('cachy_asahi_virtual_keyboard=1' in Path('/proc/cmdline').read_text().split(),'virtual keyboard marker required')
    def phase(stage,config,env,logs):
        if stage=='minimal':
            directory=Path(env['XDG_CONFIG_HOME'])/'alacritty';directory.mkdir(mode=0o700)
            (directory/'user-sentinel').write_text('preserve this declared fixture configuration\n')
            (directory/'alacritty.toml').write_text(session.T.ALACRITTY+'''[terminal.shell]
program = "/bin/bash"
args = ["--noprofile", "--norc"]
[env]
HISTFILE = "/dev/null"
''')
        session.phase(stage,config,env,logs);completed.add(stage)
    def emit(event,**values):
        if event in ('session_pass','complete'):
            if event=='session_pass':base.need(completed=={'minimal','overlay'},'both keyboard phases required')
            values.update(virtual_keyboard='PASS',editor_ui='PASS_QMP_TYPED_VIM',physical_input='NOT_RUN',
                          managed_session='SELECTED_REAL_USER_MANAGER',hardware='NOT_RUN')
        original_emit(event,**values)
    session.base=base;base.guard,base.emit,base.phase=guard,emit,phase;return base.main()


if __name__=='__main__':raise SystemExit(main())
