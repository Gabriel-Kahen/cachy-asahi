#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Installed highlighting behavior, using the existing owned PTY transport."""
import importlib.util
import json
import os
from pathlib import Path
import sys


def main(root):
    spec=importlib.util.spec_from_file_location('accepted_highlight_terminal','/highlighting-fixture/terminal.py')
    T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
    wrapper=Path('/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh');zsh='/usr/bin/zsh'
    assert os.getuid()>0 and root.is_dir() and not list(root.iterdir())
    home=T.home_at(root,'home');before=(home/'history').read_bytes()
    T.run(zsh,home,'source '+T.quote(wrapper)+'; (( ! ${+functions[_zsh_highlight]} )) || exit 11')
    T.run(zsh,home,'_zsh_highlight() { :; }; old=$functions[_zsh_highlight]; source '+T.quote(wrapper)+
          '; [[ $functions[_zsh_highlight] == $old ]] || exit 12',interactive=True)
    setup=home/'setup.zsh';setup.write_text('''PROMPT='TOOLS> '; RPROMPT=''; HISTFILE=$HOME/history; SAVEHIST=0
bindkey -e
fixture_custom() { BUFFER=custom-preserved; CURSOR=$#BUFFER; }
zle -N fixture-custom fixture_custom; bindkey '^X^U' fixture-custom
typeset -g old_binding=$(bindkey '^X^U')
source WRAPPER
(( ${+functions[_zsh_highlight]} )) || exit 21
typeset -g old_function=$functions[_zsh_highlight]
source WRAPPER
[[ $old_function == $functions[_zsh_highlight] && $(bindkey '^X^U') == $old_binding ]] || exit 22
ZSH_HIGHLIGHT_STYLES[unknown-token]=fg=red
fixture_snapshot() { print -rn -- "$BUFFER"$'\\0'"${(j:|:)region_highlight}" > "$HOME/snapshot"; }
zle -N fixture-snapshot fixture_snapshot; bindkey '^X^D' fixture-snapshot
print ready > "$HOME/ready"
'''.replace('WRAPPER',T.quote(wrapper)))
    terminal=T.Terminal(home,zsh);snapshots=[]
    try:
        terminal.send(('source '+T.quote(setup)+'\n').encode());terminal.wait(lambda:(home/'ready').exists() and b'TOOLS> ' in terminal.output)
        terminal.send(b'caa_tools_nonexistent_command_92');terminal.settle();terminal.send(b'\x18\x04');terminal.wait(lambda:(home/'snapshot').exists())
        row=(home/'snapshot').read_text().split('\0');assert len(row)==2 and row[0]=='caa_tools_nonexistent_command_92' and 'fg=red' in row[1],row
        snapshots.append(row);(home/'snapshot').unlink()
        terminal.send(b'\x18\x15');terminal.settle();terminal.send(b'\x18\x04');terminal.wait(lambda:(home/'snapshot').exists())
        row=(home/'snapshot').read_text().split('\0');assert row[0]=='custom-preserved',row;snapshots.append(row)
        terminal.send(b'\x15exit 0\n');terminal.process.wait(timeout=5);assert terminal.process.returncode==0
        assert (home/'history').read_bytes()==before and not (home/'startup-read').exists()
        print(json.dumps(dict(status='PASS_INSTALLED_ZLE',natural_exit=0,noninteractive_noop=True,preexisting_module_wins=True,
            repeated_source=True,custom_binding_preserved=True,unknown_token_highlight=True,snapshots=snapshots)))
    finally:terminal.close()


if __name__=='__main__':main(Path(sys.argv[1]))
