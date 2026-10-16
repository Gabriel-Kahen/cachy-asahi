# Opt-in Zsh syntax highlighting

This data-only package installs seventeen regular0644 files under /usr/share.
It edits no startup file, chooses no shell and loads no module during package
installation/removal. It packages unchanged upstream revision
`e6683f20e5c38d3e5447f45845d04ddda75d0f23`, version0.8.1-dev,
under BSD-3-Clause. Zsh4.3.11+ is required; the initial terminal fixtures use
modern Zsh and do not certify every older supported version.

For the current interactive shell:

```zsh
source /usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh
```

For persistent opt-in, add this line yourself at the END of your existing
.zshrc, after completion, key bindings, widget definitions and autosuggestions:

```zsh
[[ -r /usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh ]] && source /usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh
```

Upstream requires highlighting last. Preserve your existing plugin order;
do not add a second source line when a plugin manager already loads this or
another syntax-highlighting implementation. The wrapper skips when the
upstream _zsh_highlight function already exists, including an existing user
module. It is not a detector for every unrelated highlighting implementation.
Repeated sourcing and noninteractive sourcing are no-ops.

Set upstream choices before opt-in, for example:

```zsh
typeset -ga ZSH_HIGHLIGHT_HIGHLIGHTERS=(main brackets)
typeset -gA ZSH_HIGHLIGHT_STYLES
ZSH_HIGHLIGHT_STYLES[unknown-token]='fg=red'
```

All seven upstream highlighters are available. The wrapper sets no colours,
highlighter list, prompt, aliases, history options or keybindings. Upstream
registers ZLE hooks on modern Zsh and wraps widgets on older versions; actual
widget definitions may therefore change while existing editing behaviour and
bindings remain usable. Later plugin/widget replacement can need a changed
source order. No plugin download or startup network activity occurs.

Remove your own source line and start a fresh shell to stop highlighting.
Package removal removes only its seventeen /usr/share files, leaving .zshrc,
history and other modules untouched. The guarded source line becomes a no-op
when the package is absent and loads again after reinstall. Already loaded
functions/hooks remain in old shells until those processes exit; there is no
partial unload/reset action or installation/removal hook. No user lifecycle
journal is needed because this package does not edit user files.

Terminal fixtures demonstrate fixed typing/editing/highlight/coexistence cases
using an isolated HOME. They do not establish universal terminal accessibility,
all plugin ordering, native ARM package lifecycle or M2 hardware acceptance.
No package build, installation or hardware test has been performed for this
candidate. See README.md/INSTALL.md for the unmodified upstream documentation;
this package's explicit opt-in procedure above controls its integration.
