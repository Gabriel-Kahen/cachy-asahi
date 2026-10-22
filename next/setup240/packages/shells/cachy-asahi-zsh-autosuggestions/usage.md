# Opt-in Zsh autosuggestions

Installing this package places six regular files under `/usr/share`. It does
not activate the plugin, select a login shell or edit any startup/history file.
Zsh 4.3.11 or later is required. The upstream module is unchanged at revision
`85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5` (VERSION v0.7.1).

For one interactive session, run:

```zsh
source /usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh
```

For persistent opt-in, add this guarded line yourself to your existing `.zshrc`,
after your chosen completion/widget setup:

```zsh
[[ -r /usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh ]] && source /usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh
```

Noninteractive sourcing is a no-op. Repeated sourcing is a no-op, and an already
loaded autosuggestions module wins. The wrapper sets no history options,
aliases, keybindings, prompt or plugin configuration. Upstream installs its ZLE
wrappers and a precmd hook after explicit opt-in; it preserves existing widget
behavior and keybindings rather than promising that ZLE definitions never
change. It will use the history already available to that shell to suggest a
suffix. Type a prefix; at the end of the line, right arrow (`forward-char`) or
End accepts the suggestion into the editable buffer. Acceptance does not run it.

You can configure upstream variables before sourcing, such as
`ZSH_AUTOSUGGEST_STRATEGY=(history)` or `ZSH_AUTOSUGGEST_IGNORE_WIDGETS`.
Asynchronous suggestions are enabled by upstream on newer Zsh versions; to
choose synchronous behavior, `unset ZSH_AUTOSUGGEST_USE_ASYNC` after sourcing.
Preserve your existing plugin ordering. Modules loaded or widgets replaced
later can require the upstream rebinding behavior; other plugins and all
terminal bindings are not universally certified by this package's fixtures.
No startup network or package acquisition occurs.

To stop suggestions in the current process, use the upstream ZLE
`autosuggest-disable` widget (bind it yourself if desired). For complete removal
from the running shell, remove your source line and start a new session.
Removing the package only removes its six owned `/usr/share` files; it does not
remove your line, home files, command history or unrelated plugin packages.
The guarded source line becomes a no-op after removal and works again after
reinstallation. Loaded functions/widgets remain in old running processes until
you restart them. Interrupted use does not run installation/removal hooks.

Host fixture checks are separate from native ARM packaging, actual package
manager install/upgrade/remove/reinstall and both M2 Air sizes. This data-only
module introduces no compiled binary; base Zsh and terminal/platform 16K and
hardware acceptance remain separate requirements.
