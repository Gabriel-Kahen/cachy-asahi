# First-login terminal journey

This opt-in host check exercises **real controlling PTYs** with the delivered
FirstLogin0.1.0-2 and Setup8 payloads, actual Fish/Zsh, and exact selected template
bytes. It complements the frozen scripted-interactive/no-PTY installed journey.
It changes only newly owned temporary state and evidence. No package, account,
service or desktop is installed or changed. Native ARM, M2, graphical login,
physical interruption and release acceptance remain **NOT RUN**.

`journey.py` verifies and extracts only the launcher, first-login Python module
and separately delivered Setup8 executable from two exact local package archives.
It copies the two exact original project templates and the unchanged onboarding
module used for cancellation-safe spawn/cleanup. The latter's whole hash is
verified **before compiling its bytes**; no copied operator or native role is
loaded. The finite staged closure runs outside every checkout, with `/home`
hidden, a read-only system root and staged inputs, new HOME/XDG/workspace, and
unprivileged bubblewrap user/PID/network namespaces. There is no fallback if
that host namespace or a real PTY is unavailable. This host context supplies no
normal native Docker image-build capability evidence.

The binary/mode pins for Fish, Zsh, Python, bsdtar, bubblewrap, ls, mkdir and
basename are recorded and rechecked inside and after the journey. Root ownership
and nonwritable modes are checked before launch. Host system executable hardlinks
are valid; mutable input payloads must be single-link regular files. In the host
user namespace, unmapped system root appears as overflow UID65534; the result
records that observation and the actual UID map. Dynamic libraries, shell global
startup files and the complete host root are not a reproducible image closure.
The check records the actual system versions rather than admitting other versions
as equivalent.

The selected archives are:

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst` | 19471 | `d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839` |
| `cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz` | 33900 | `8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47` |

The FirstLogin archive is unsigned host assembly. Setup8 is the retained prior
native component input; reusing its bytes grants no new native credit. Source
and payload pins are explicit in `journey.py` and each run's `input_profile`.
The Fish/Zsh templates are their exact selected project source bytes, SHA256
`223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c` and
`7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f`.
They are not substituted from the unrelated new settings/lock/enrollment archives.

From the checkout root, with the already present host dependencies, use a fresh
absolute evidence directory:

```sh
python3 -I -B scripts/integration/first_login_pty/journey.py \
  --first-login-archive /absolute/cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst \
  --setup-archive /absolute/cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz \
  --output /absolute/owned-parent/fresh-evidence \
  --run-temporary-pty-journey
```

The seven literal sessions perform:

1. Start a real Fish reader; establish a visible test prompt, prove stdin/stdout/
   stderr are terminal descriptors and the typed child is the terminal foreground
   group, then type FirstLogin activation and exit with terminal EOF.
2. Start Fish through the managed configuration. Type `caa_ll` and `caa_mcd` with
   a space-containing directory and observe real listing/directory effects. Type
   a user variable and prompt edit into the config. Interrupt a live foreground
   Python child with terminal Ctrl-C, verify its retirement and a usable prompt,
   then exit with EOF.
3. Start Zsh through the managed configuration, verify its delivered opt-in prompt,
   interactive/completion state and actual command output. Type a user variable
   and prompt edit. Repeat the foreground Ctrl-C/continued-prompt/EOF journey.
4. Observe the user's Fish prompt at startup, type repeated FirstLogin activation,
   exercise the helpers/user variable and verify exact config-byte preservation.
5. Observe the user's Zsh prompt and variable, then type Setup8 deactivation.
6. Start Fish through the remaining user config; preserve the user prompt/variable
   and prove both project helpers are absent.
7. Start Zsh through the remaining user config; preserve the user prompt/variable
   and prove the managed loaded flag is absent. Both final sessions exit by EOF.

Fresh inspect and activation preview must preserve the entire observed user tree,
including directories and ownership/modes. Typed edits and config bytes must
survive repeat, deactivation and subsequent shell startup. Deterministic test
prompts coordinate the journey after initial product/user prompt observations;
this is not a graphical terminal-emulator or theme-rendering test.

`terminal.py` is a finite driver for these sessions, not a replacement supervisor
framework. It uses `openpty`, a new session/controlling terminal, fixed24x100 size,
explicit environment and bounded input. Shells are actual readers, not `shell -c`.
Output markers must begin a terminal line; reprinted command text cannot satisfy
the observation. It records raw bytes and literal inputs (hex), actions, prompt
observations, foreground identities and cleanup. Each session has a25-second /
128KiB cap; the outer isolated journey is bounded to180 seconds. The few capture
commands have10-second /64KiB caps. Missing PTY, timeout, excess output, unexpected
exit or missing natural EOF fails.

Every successful shell must exit naturally with code0 after EOF, be reaped, and
leave no session member in two observations. On failure/cancellation the driver
uses the exact owned session ID and pidfds/start-time checks; it retires children
while their shell can reap them, then reaps the shell, closes its PTY descriptors
and records diagnostics. It never signals a foreign session. Deferred cleanup
retains cancellation evidence. Positive scratch is removed only after collecting
its evidence; failed/uncertain scratch is retained by exact path for inspection.
Existing evidence names are never reused.

Run the focused controls with those same two real archives; `--evidence` is an
optional fresh directory retaining the positive case:

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/first_login_pty/test_pty.py \
  --first-login-archive /absolute/cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst \
  --setup-archive /absolute/cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz \
  --evidence /absolute/owned-parent/fresh-control-evidence -v
```

The thirteen controls include the complete delivered journey plus actual timeout,
output overflow, false command-text marker, fragmented observation/EOF, absent
PTY/no fallback, missing EOF, unexpected exit, SIGTERM cleanup/handler restoration,
foreign-session preservation, changed cancellation helper, wrong archive and
changed template. Missing prerequisites fail; no skips or substitute executable
fixtures establish the positive case.

Actual local result: thirteen pass, zero skips, Python3.14.7, Fish4.9.3,
Zsh5.9.2, x86_64/4KiB, UID/GID1000. Seven real PTY sessions passed, two live
foreground Ctrl-C cases retired, seven EOF0 exits and `REAPED_EMPTY_TWICE` in all
sessions. `validation.json` pins the retained final result, raw transcripts and
source bytes. Frozen packages, installed helper, old integration journeys and
native families remain unchanged. No native admission or once-role was invoked.
