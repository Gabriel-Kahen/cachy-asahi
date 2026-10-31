# Unselected GNU libc provider experiment

This is a new project-owned GNU 2.43 recipe for a disposable generic aarch64
system provider. It has not been built or installed. It does not change any
selected inventory, platform policy, existing private candidate, or release gate.

The source, detached signature, publisher keyring, two patches, licenses,
toolchain baseline, and complete GNU tests come from the accepted private source
packet for run 38915137670, Source d1055cf95f7d236fc55396db36b432df5191ff2a.
Use the three exact `public_inputs` in `source-lock.json`; do not substitute an
upstream Git snapshot, reduced source tree, or held binary payload. The private
build's success establishes no build or runtime result for this changed recipe.

The recipe installs the loader/DSOs in `/usr/lib`, headers in `/usr/include`,
gettext catalogs in `/usr/share/locale`, compiled C.utf8 in `/usr/lib/locale`,
and GNU's `gai.conf` in `/etc`. `/usr/share/locale` is 17 ASCII bytes; its NUL
terminator preserves the 18-byte `_nl_default_dirname` ABI OBJECT. The normal
`/lib` alias belongs to `filesystem`. `--disable-multi-arch` remains mandatory
to preserve the accepted baseline symbol types and bindings. No performance
claim follows from that choice.

Authenticated held glibc has no explicit Provides, Conflicts, or Replaces. The
candidate deliberately provides only `glibc=2.43` and conflicts with `glibc`.
Its own identity is `cachy-asahi-glibc-gnu-provider 2.43.caa1-1`; it does not
provide the held `2.43+r22+g8362e8ce10b2-2` version or claim its downstream or
security patches. Dependencies retain `linux-api-headers>=4.10`, `filesystem`,
and `tzdata`. The held 574 lock's 13 versioned glibc dependencies all require
`glibc>=2.27`; actual dependency resolution remains a lifecycle gate.

`stage.py` operates only on the staged package tree. It removes GNU's three
timezone commands already owned by held `tzdata`, the example `var/db/Makefile`,
and any generated loader cache. It rejects extra system configuration, root
loader aliases, escaping links, special files, private paths, incorrectly
aligned loadable ELF files, or a changed locale OBJECT size. These checks do not
replace GNU `check`, GNU `check-abi`, or the eleven-library held-ABI comparison.

There is no install scriptlet or package hook. GNU's `gai.conf` is a backed-up
configuration file; `rpc` is ordinary package content. This bounded experiment
ships C.utf8 and GNU locale sources/tools, but does not recreate ALARM's
`locale-gen`, `/etc/locale.gen`, `memusage`, or optional GD `memusagestat`.
Replacing the held package can remove those package-owned commands and leave a
modified `/etc/locale.gen.pacsave`. Broader locale generation, migration, and
cache-hook behavior must be designed and tested before general system use.
Do not copy the held install scriptlet: it calls the absent `locale-gen`.

Retained GNU signature evidence reports current KEYEXPIRED/EXPKEYSIG. It uses
the GNU HTTPS publisher keyring without independent pretrusted fingerprint
authority. This source proposal preserves that limitation. It does not resolve
the historical held binary's missing matching BUILDINFO recipe. Native pair,
installed provider lifecycle, generic 16K provider execution, exact M2 machine
tests, security/maintenance review, and release admission are all unfinished.
