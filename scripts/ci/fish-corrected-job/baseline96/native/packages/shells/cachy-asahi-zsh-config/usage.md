# cachy-asahi Zsh configuration

This original configuration enables built-in completion for an interactive Zsh
session. It skips insecure completion directories, writes no completion dump,
and preserves an already initialized completion setup. It sets no aliases,
editor, history file, login shell, services or power defaults.

Installing the package does not activate it. For one session, run in Zsh:

```zsh
source /usr/share/cachy-asahi/zsh/config.zsh
```

To opt in persistently, add this guarded line to your existing `~/.zshrc` (or
`$ZDOTDIR/.zshrc` when using ZDOTDIR) with your editor:

```zsh
[[ ! -r /usr/share/cachy-asahi/zsh/config.zsh ]] || source /usr/share/cachy-asahi/zsh/config.zsh
```

Place it after your existing completion/theme initialization. Do not replace
your configuration file. To disable the completion setup, set
`CACHY_ASAHI_ZSH_COMPLETION=0` before the source line. A plain prompt can be
enabled separately by setting `CACHY_ASAHI_ZSH_PROMPT=1` before that line.
Without this setting, your current prompt is preserved. A second source in the
same session is a no-op; start a fresh session after changing the settings.

To deactivate, remove the source line and optional settings with your editor,
then start a new Zsh session. Package removal deletes only package-owned files;
the guarded source line safely does nothing when the package is absent. Running
shells retain state until restarted. No user files are installed or removed.

Original project material is licensed under MIT; read the installed LICENSE
and NOTICE. Native builds, package lifecycle and hardware validation remain
pending before release.
