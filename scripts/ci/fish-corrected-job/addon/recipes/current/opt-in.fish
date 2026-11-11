# SPDX-License-Identifier: MIT
# Source explicitly after user key bindings. No global startup registration.
if not status is-interactive
    return 0
end

# Any existing module/helper wins, including an autoloadable user function.
set -l caa_function
for caa_function in __history_previous_command __history_previous_command_arguments _plugin-bang-bang_key_bindings _plugin-bang-bang_uninstall caa_history_bang caa_history_argument
    if functions --query $caa_function
        return 0
    end
end

set -l caa_mode
switch "$fish_key_bindings"
    case fish_default_key_bindings
        set caa_mode default
    case fish_vi_key_bindings fish_hybrid_key_bindings
        set caa_mode insert
    case '*'
        return 0
end

# Keep stock input semantics and every user-owned affected binding intact.
set -l caa_preset (bind --preset --silent --mode $caa_mode '')
if not contains -- "$caa_preset" "bind --preset '' self-insert" "bind --preset -M insert '' self-insert"
    return 0
end
if bind --user --silent --mode $caa_mode '' >/dev/null
    return 0
end
set -l caa_bindings (bind --user --mode $caa_mode)
set -l caa_key
for caa_key in '!' '$'
    if bind --user --silent --mode $caa_mode $caa_key >/dev/null
        return 0
    end
    if bind --preset --silent --mode $caa_mode $caa_key >/dev/null
        return 0
    end
    # Also retain longer user sequences beginning with either character.
    set -l caa_prefix (string escape --style=regex -- (string escape --no-quoted -- $caa_key))
    if string match --regex --quiet -- " $caa_prefix," $caa_bindings
        return 0
    end
end

set -l caa_dir (path dirname -- (status filename))
set -l caa_file
for caa_file in __history_previous_command.fish __history_previous_command_arguments.fish
    if not test -r "$caa_dir/$caa_file"
        return 1
    end
end
source "$caa_dir/__history_previous_command.fish"
source "$caa_dir/__history_previous_command_arguments.fish"

function caa_history_bang --description 'Expand the previous command; keep empty history literal'
    if test "$(commandline --current-token)" = '!'; and test (count $history) -eq 0
        commandline --insert '!'
    else
        __history_previous_command
    end
end

function caa_history_argument --description 'Expand the previous argument; keep empty history literal'
    if test "$(commandline --current-token)" = '!'; and test (count $history) -eq 0
        commandline --insert '$'
    else
        __history_previous_command_arguments
    end
end

bind --mode $caa_mode '!' caa_history_bang repaint
bind --mode $caa_mode '$' caa_history_argument repaint
