# SPDX-License-Identifier: MIT
# Original cachy-asahi opt-in helpers. No upstream CachyOS code is included.
# Source explicitly from your own Fish config after existing customizations.
if not status is-interactive
    return
end

if not functions -q caa_ll
    function caa_ll --description 'List all entries with details'
        command ls -alF -- $argv
    end
end

if not functions -q caa_mcd
    function caa_mcd --description 'Create one directory and enter it'
        if test (count $argv) -ne 1
            printf '%s\n' 'Usage: caa_mcd DIRECTORY' >&2
            return 2
        end
        # Resolve both operations here, even when CDPATH contains another match.
        set -l caa_target "$argv[1]"
        if test -n "$caa_target"; and not string match --quiet '/*' -- "$caa_target"
            set caa_target "./$caa_target"
        end
        command mkdir -p -- "$caa_target"; and cd -- "$caa_target"
    end
end
