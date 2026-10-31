# MIT License

# Copyright (c) 2016 Francisco Lourenço & Daniel Wehner

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Linux opt-in adaptation; see NOTICE and source-provenance.json.

function __done_humanize_duration -a milliseconds
    set -l seconds (math --scale=0 "$milliseconds/1000" % 60)
    set -l minutes (math --scale=0 "$milliseconds/60000" % 60)
    set -l hours (math --scale=0 "$milliseconds/3600000")

    if test "$hours" -gt 0
        printf '%s' $hours'h '
    end
    if test "$minutes" -gt 0
        printf '%s' $minutes'm '
    end
    if test "$seconds" -gt 0
        printf '%s' $seconds's'
    end
end

function __done_clock
    read -l uptime remainder </proc/uptime; or return 1
    math --scale=0 "$uptime * 1000"
end

function __done_notify --argument-names duration outcome kind detail
    set -l threshold 5000
    if set --query caa_done_min_duration
        string match --quiet --regex '^[0-9]{1,9}$' -- "$caa_done_min_duration"; or return 1
        set threshold $caa_done_min_duration
    end
    string match --quiet --regex '^[0-9]+$' -- "$duration"; or return 1
    test "$duration" -gt "$threshold"; or return 0
    for pattern in $caa_done_exclude
        if string match --quiet --regex -- "$pattern" "$detail"
            return 0
        end
    end
    set -l humanized (__done_humanize_duration $duration)
    if test -z "$humanized"
        set humanized "$duration ms"
    end
    set -l title "Done in $humanized"
    set -l urgency normal
    if test "$outcome" -ne 0
        set title "Failed ($outcome) after $humanized"
        set urgency critical
    end
    set -l message "$kind completed."
    if test "$caa_done_show_command" = 1
        set -l text (string sub --length 240 -- "$detail")
        set text (string replace --all '&' '&amp;' -- "$text")
        set text (string replace --all '<' '&lt;' -- "$text")
        set text (string replace --all '>' '&gt;' -- "$text")
        set message "$kind: $text"
    end
    # No eval, shell interpolation of command text, sound or desktop probing.
    command timeout --foreground --signal=TERM --kill-after=1s 2s notify-send \
        --hint=int:transient:1 --urgency=$urgency --icon=utilities-terminal \
        --app-name=fish --expire-time=3000 -- "$title" "$message" >/dev/null 2>&1
end

function __done_ended --on-event fish_postexec
    set -l outcome $status
    # Watch registration and cancellation are management operations, not work.
    if string match --quiet --regex '^caa_done_(watch|disable)( |$)' -- "$argv[1]"
        return 0
    end
    __done_notify "$CMD_DURATION" "$outcome" 'Foreground command' "$argv[1]"
end

function caa_done_watch --argument-names pid
    test (count $argv) -eq 1; or return 2
    string match --quiet --regex '^[1-9][0-9]*$' -- "$pid"; or return 2
    # Require a live child job of this Fish, never attach to another process.
    set -l children (jobs --pid $pid 2>/dev/null)
    test (count $children) -eq 1; and test "$children[1]" = "$pid"; or return 1
    set -l handler __done_job_$pid
    functions --query $handler; and return 0
    set -l started (__done_clock); or return 1
    set -l detail (jobs --command $pid 2>/dev/null | string collect)
    function $handler --on-process-exit $pid --inherit-variable started --inherit-variable detail --inherit-variable handler
        set -l elapsed (math (__done_clock) - $started)
        # A single-process job uses PROCESS_EXIT: event name, pid, exit status.
        set -l outcome $argv[3]
        functions --erase $handler
        __done_notify "$elapsed" "$outcome" 'Watched job' "$detail"
    end
end

function caa_done_disable
    # This namespace was checked unused before activation; user options remain.
    set -l handlers (string match '__done_job_*' (functions --all --names))
    if test (count $handlers) -gt 0
        functions --erase $handlers
    end
    functions --erase __done_clock __done_notify __done_ended __done_humanize_duration caa_done_watch caa_done_disable
end
