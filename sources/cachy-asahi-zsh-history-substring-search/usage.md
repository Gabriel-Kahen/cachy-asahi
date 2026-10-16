# Opt-in history substring search

Requires Zsh 5.9 or newer. Nothing is loaded automatically and the package
does not create or edit startup files, keybindings or history files.

Source the wrapper explicitly from an interactive Zsh:

```zsh
source /usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh
```

If you use syntax highlighting, load it **before** substring search. The
upstream runtime supplies a fallback `_zsh_highlight` when none exists; the
separate highlighting wrapper treats existing functions as user-owned and
will preserve that fallback rather than replacing it. Recommended order:

```zsh
# Your existing autosuggestions/configuration first, if used.
[[ ! -r /usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh ]] ||
  source /usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh
[[ ! -r /usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh ]] ||
  source /usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh
```

The wrapper leaves every keybinding in place. Choose your own keys after
inspecting their existing meaning; for example these are **manual changes**
to the Emacs keymap, not package defaults:

```zsh
bindkey -M emacs '^P'
bindkey -M emacs '^N'
# If you choose to replace those bindings:
bindkey -M emacs '^P' history-substring-search-up
bindkey -M emacs '^N' history-substring-search-down
```

Type a literal substring, then invoke your chosen up/down widget to traverse
matching in-memory history. An empty buffer uses ordinary history movement;
multiline buffers retain upstream cursor behavior. Existing upstream
`HISTORY_SUBSTRING_SEARCH_*` settings are respected; see the pinned upstream README
for case sensitivity, prefix/fuzzy search, uniqueness and highlighting:
https://github.com/zsh-users/zsh-history-substring-search/blob/a0bdb0d47dbaba31dba2db7af8c48a5d9c74049a/README.md

Existing public/private substring functions, widgets or internal parameters
take precedence: the wrapper returns without replacing them. Repeated source
is a no-op. Noninteractive shells return before loading modules or changing
functions/options. The wrapper requires the modern `add-zle-hook-widget` path
so upstream's older all-widget rebinding fallback is not selected.

To stop using it, remove your own explicit source and binding lines and start
a fresh shell. Uninstalling package files does not unwind widgets in already
running shells. Guarded source lines tolerate an absent package; persistent
configuration and any restoration of user-chosen bindings remain your choice.
No package hook, service, global Zsh startup, alias, login-shell or platform
setting is installed or modified.
