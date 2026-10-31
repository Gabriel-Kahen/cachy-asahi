# Optional Fish autopair

This package provides five unchanged MIT editing helpers from
[jorgebucaran/autopair.fish](https://github.com/jorgebucaran/autopair.fish/tree/4d1752ff5b39819ab58d7337c69220342e9de0e2)
and an independent opt-in wrapper. The integration version is 0.1.0, not an
upstream release tag. Fish 4.9.3 or newer is required. Only host x86_64 Fish
4.9.3 has been executed here; the held 574-package ARM inputs also pin 4.9.3-1.

To enable, put this user-owned block in your existing config.fish **after**
selecting your default, vi or hybrid bindings and defining custom bindings:

```fish
if test -r /usr/share/cachy-asahi/fish-autopair/opt-in.fish
    source /usr/share/cachy-asahi/fish-autopair/opt-in.fish
end
```

The wrapper acts only interactively. It pairs `()`, `[]`, `{}`, `""`, `''`,
places the cursor inside, skips matching closers, and deletes an adjacent pair
with Backspace or Ctrl-H. Tab uses the upstream completion helper. Activation
binds default mode for default bindings, or insert mode for vi/hybrid; vi normal
mode remains intact. It does not select or reset your keymap. The upstream
startup file, variable-change rebinder and uninstall event are never sourced.
Changing keymaps later requires a fresh shell and sourcing after the change.

Any existing upstream function (including an autoloadable helper), autopair
variable or temporary wrapper name wins. Existing user generic bindings,
affected keys, or longer sequences beginning with an affected key prevent the
entire module from activating. Altered preset generic/Backspace/Ctrl-H/Tab/`)`
bindings or a preset binding for another affected character also prevent it.
Only the known stock `)` binding is accepted; while enabled its abbreviation
expansion action is replaced by upstream closer handling. Other keybindings
and functions remain intact. Prefix checks are deliberately conservative:
a key-like sequence in binding command text can also make activation yield.
Repeated sourcing is a no-op and returns normally to the calling configuration
or function; it does not register further hooks.

Escaping retains upstream behavior: a backslash followed by a quote stays
literal, but a backslash followed by `(` currently produces `\()` with the
cursor before `)`. The module is an editor aid, not a parser or an execution
filter. Typed command substitutions remain text until you submit the command.

All installed files are ordinary mode-0644 files under /usr/share. Installation
does not edit startup files, history, universal variables, prompts or login
shells, and performs no downloads. Removal deletes package files; the guarded
user block does nothing in a fresh shell. Running shells retain loaded functions
and bindings until restart. Reinstall restores the same opt-in path. Actual
package-manager installation/removal, native ARM builds, generic 16K operation,
both physical M2 Air targets and performance measurements are NOT RUN.
