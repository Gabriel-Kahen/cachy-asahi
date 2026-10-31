# SPDX-License-Identifier: MIT
# Explicit source only; keep every guard return out of the caller's scope.
if status is-interactive; and not functions --query _caa_done_enable
    function _caa_done_enable --argument-names directory
        if string match --quiet --regex '^(__done|caa_done_)' (functions --all --names)
            return 0
        end
        if string match --quiet '__done*' (set --names)
            return 0
        end
        if not set --query DBUS_SESSION_BUS_ADDRESS; or test -z "$DBUS_SESSION_BUS_ADDRESS"
            return 0
        end
        command --query notify-send; or return 0
        command --query timeout; or return 0
        test -r "$directory/done.fish"; or return 1
        source "$directory/done.fish"
    end
    _caa_done_enable (path dirname -- (status filename))
    set -l result $status
    functions --erase _caa_done_enable
    test $result -eq 0
end
