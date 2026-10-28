# cachy-asahi-support 0.1.0-1

`cachy-asahi-support create` bundles explicitly reviewed, SHA-256-selected JSON
reports offline. `verify` checks a separately retained archive hash and can
extract privately. `--version` identifies this package. See `support-bundle.md`
for the exact input formats, privacy projection, options and limitations.

The installed launcher resolves its own prefix, checks three pinned runtime
files and runs the unchanged support command. Its private tree recreates only
the relative paths required by the existing offline Doctor/session APIs. It
does not import another installed project package, an artifact packet, the
source checkout, current directory or PYTHONPATH. The isolated Python shebang
also suppresses user-site imports and bytecode writes. Standard-library Python
3.11 or later is the sole runtime dependency; no optional dependencies, GPG,
pacman, service/session tools or network clients are needed by this command.

Package-owned paths are exactly the command under `/usr/bin`, three modules
under `/usr/lib/cachy-asahi/support`, documentation under
`/usr/share/doc/cachy-asahi-support`, and NOTICE/LICENSE under
`/usr/share/licenses/cachy-asahi-support`. Package removal deletes only these
files. There are no install scripts, ALPM hooks, services, autostarts, backup
entries, configuration writes, privilege helpers or system/boot changes.
User-created support directories and reports remain user-owned and untouched.
Running the command requires an explicit output destination and never uploads.

The local PKGBUILD has pinned flat source files and declares `arch=('any')`.
This architecture declaration does not establish a native ARM build. `check()`
validates metadata/pins and runs focused source/staging/CLI tests. Tests call
only this package's reviewed pure `package()` function into fresh private
temporary pkgdirs; they never run makepkg, ALPM, install onto the host, GPG or
any live collector. When available, bubblewrap additionally hides the source
checkout and unshares networking during the staged-command test; absent
bubblewrap is explicitly skipped and cannot count as hidden-source evidence.

Review and stage in a disposable, ordinary-user build environment. Actual
makepkg/native build pairs, package archives/BUILDINFO, ALPM lifecycle, native
16K and M2 checks are separate work. The accompanying native request starts
with NULL actual bindings. No build or installation success is inferred from
pure package() staging or host CLI checks.
