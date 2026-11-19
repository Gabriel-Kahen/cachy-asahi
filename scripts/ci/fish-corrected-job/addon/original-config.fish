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
        command mkdir -p -- $argv[1]; and cd -- $argv[1]
    end
end
