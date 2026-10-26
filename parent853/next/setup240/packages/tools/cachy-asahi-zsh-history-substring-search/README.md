# Pinned opt-in Zsh history substring search

Project integration package version 0.1.0; upstream is identified by full
commit `a0bdb0d47dbaba31dba2db7af8c48a5d9c74049a`, not an invented release tag.
The complete necessary runtime is vendored byte-for-byte under BSD-3-Clause.
Its source hash is
`0b864862a3b48992d7316cc7e585a1315fa389d730c17bf16e2f2bd5918089f3`.
The complete embedded runtime license is retained, with the
official archive URL/hash and selected file hashes in source-provenance.json.
The independent MIT wrapper, recipe and fixture code remain separately licensed.

This supplies the individually licensed substring-search function required by
the shell-function inventory. It adds no global shell configuration or automatic
binding. The wrapper preserves preexisting module namespaces and uses Zsh 5.9+
hook support, avoiding upstream's legacy all-widget wrapping path. See usage.md
for explicit loading, highlighting order, manual key choices and removal.

Runtime dependency: `zsh>=5.9`; build/check dependency: Python 3. Standard
makepkg/base-devel supplies Bash and install. No network, source generation or
compilation occurs during package construction. check() performs shell syntax
checks and bounded real ZLE/PTY fixtures in private HOME/history directories;
package() installs seven regular 0644 files beneath /usr/share only. It never
installs an rc, hook, service, executable, symlink or package-manager scriptlet.

Worker evidence is host x86_64 Zsh 5.9.2 execution and pure private package
staging. PTY fixtures cover literal substring traversal, forward movement,
multiline history and current-buffer cursor movement, unmatched input, quoted
glob/dollar text without command execution, custom Up/Down bindings and widgets,
existing substring namespaces, repeat sourcing and noninteractive no-op. An
optional host fixture also sources the staged pinned syntax-highlighting package
first and checks coexistence. Source/module and private history bytes are
checked; all normal fixture shells exit naturally with status 0.

No system install, native ARM build pair, package-manager lifecycle, 16-KiB,
M2 hardware, performance or release admission is established by those checks.
Shared manifests remain coordinator-owned; this is a proposed development
package, not registration or target acceptance.
