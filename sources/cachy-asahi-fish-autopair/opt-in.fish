# SPDX-License-Identifier: MIT
# Source explicitly after selecting bindings and defining user customizations.
# Keep every early return inside a temporary function, not the caller's scope.
if status is-interactive; and not functions --query _caa_autopair_enable
    function _caa_autopair_enable --argument-names caa_dir
        # A preexisting upstream namespace, including autoloadable functions, wins.
        if string match --quiet '_autopair*' (functions --all --names)
            return 0
        end
        if string match --quiet 'autopair*' (set --names)
            return 0
        end
        set -l caa_functions _autopair_backspace _autopair_insert_left _autopair_insert_right _autopair_insert_same _autopair_tab _autopair_fish_key_bindings _autopair_uninstall
        for caa_function in $caa_functions
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
        set -l caa_generic (bind --preset --silent --mode $caa_mode '')
        if not contains -- "$caa_generic" "bind --preset '' self-insert" "bind --preset -M insert '' self-insert"
            return 0
        end
        if bind --user --silent --mode $caa_mode '' >/dev/null
            return 0
        end

        set -l caa_keys '(' ')' '[' ']' '{' '}' '"' "'" backspace ctrl-h tab
        set -l caa_user (bind --user --mode $caa_mode)
        for caa_key in $caa_keys
            if bind --user --silent --mode $caa_mode $caa_key >/dev/null
                return 0
            end
            # Retain longer user sequences starting with any affected key as well.
            set -l caa_prefix (string escape --style=regex -- (string escape --no-quoted -- $caa_key))
            if test (count $caa_user) -gt 0; and string match --regex --quiet -- " $caa_prefix," $caa_user
                return 0
            end
            set -l caa_preset (bind --preset --silent --mode $caa_mode $caa_key)
            switch $caa_key
                case backspace ctrl-h
                    if not contains -- "$caa_preset" "bind --preset $caa_key backward-delete-char" "bind --preset -M insert $caa_key backward-delete-char"
                        return 0
                    end
                case tab
                    if not contains -- "$caa_preset" 'bind --preset tab complete' 'bind --preset -M insert tab complete'
                        return 0
                    end
                case ')'
                    if not contains -- "$caa_preset" 'bind --preset \) self-insert expand-abbr' 'bind --preset -M insert \) self-insert expand-abbr'
                        return 0
                    end
                case '*'
                    if test -n "$caa_preset"
                        return 0
                    end
            end
        end

        for caa_function in $caa_functions[1..5]
            test -r "$caa_dir/$caa_function.fish"; or return 1
        end
        for caa_function in $caa_functions[1..5]
            source "$caa_dir/$caa_function.fish"; or return 1
        end
        set --global autopair_left '(' '[' '{' '"' "'"
        set --global autopair_right ')' ']' '}' '"' "'"
        set --global autopair_pairs '()' '[]' '{}' '""' "''"
        bind --mode $caa_mode backspace _autopair_backspace
        bind --mode $caa_mode ctrl-h _autopair_backspace
        bind --mode $caa_mode tab _autopair_tab
        for caa_index in 1 2 3
            bind --mode $caa_mode $autopair_left[$caa_index] "_autopair_insert_left "(string escape -- $autopair_left[$caa_index])" "(string escape -- $autopair_right[$caa_index])
            bind --mode $caa_mode $autopair_right[$caa_index] "_autopair_insert_right "(string escape -- $autopair_right[$caa_index])
        end
        for caa_index in 4 5
            bind --mode $caa_mode $autopair_left[$caa_index] "_autopair_insert_same "(string escape -- $autopair_left[$caa_index])
        end
    end
    _caa_autopair_enable (path dirname -- (status filename))
    set -l caa_result $status
    functions --erase _caa_autopair_enable
    test $caa_result -eq 0
end
