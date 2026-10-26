# Optional Fish history expansion

This package supplies the two unchanged MIT-licensed plugin-bang-bang helpers
at revision ec991b80ba7d4dda7a962167b036efc5c2d79419 and an original opt-in wrapper.
Fish 4.0 or newer is required; actual host tests use Fish 4.9.3 on x86_64.
No Oh My Fish, Fisher, first-login download or global startup hook is installed.

After setting your chosen Fish bindings and sourcing any original project
helpers, add this user-owned block to your existing config.fish:

```fish
if test -r /usr/share/cachy-asahi/fish/config.fish
    source /usr/share/cachy-asahi/fish/config.fish
end
# Place after your fish_user_key_bindings/custom binding calls.
if test -r /usr/share/cachy-asahi/fish-bang-bang/opt-in.fish
    source /usr/share/cachy-asahi/fish-bang-bang/opt-in.fish
end
```

The first block is optional and belongs to the separate original Fish helper
package. This module works without it. Activation runs only in an interactive
shell using stock default, vi or hybrid key bindings. It adds user bindings for
`!` and `$` only in default editing mode or vi/hybrid insert mode. Vi normal
mode is preserved. It never resets the binding set or changes fish_key_bindings.

Type `!!` to insert the previous command, or `!$` to ask Fish's native token
history search for the previous argument. Expansion edits the command buffer;
press Enter separately to execute it. Empty history keeps `!!`/`!$` literal.
Quoted tokens retain upstream behavior; this is not Bash's complete history
language. History persistence, filtering, file paths, universal variables,
prompts, aliases and the original caa_ll/caa_mcd helpers are not changed.

If any upstream helper or bang-bang hook already exists, it wins and this
wrapper returns without loading. A custom generic binding, either affected
character, a longer user sequence starting with that character, or a preset
affected-character binding likewise prevents activation. Other bindings remain
intact. Bind listings are checked conservatively; a matching key-like sequence
inside command text may also cause activation to yield. Repeated sourcing is
harmless. To select another binding set, restart the shell and source this
wrapper after selecting that set; no variable-change rebinder is registered.

Package installation owns only its seven /usr/share files. It does not edit
your configuration or change your login shell. Removal deletes package files;
the guarded source block remains user-owned and does nothing in fresh shells.
Already-running shells keep loaded functions/bindings until restart. Reinstall
restores the same opt-in path. The upstream auto-binding and uninstall hooks
are retained in the complete source record but are never installed or sourced.
Actual package-manager lifecycle and both M2 Air targets remain untested.


Pkgrel2 contains every guard return inside an immediately erased private
_caa_bang_enable function. Repeated, skipped and noninteractive sourcing now
continues the caller's remaining commands, including when composing this module
with autopair and Done. A preexisting private helper wins without replacement.
All original helper/module/binding precedence and the two upstream helpers stay
unchanged. No startup files or key choices are added. New combined host evidence
is distinct from previously held pkgrel1/native587 results; pkgrel2 native/16K/M2
acceptance remains NOT_RUN until a new actual.
