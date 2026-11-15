# External XS consumer for the Perl 5.42.3-1.3 candidate

This is an original, small ExtUtils::MakeMaker consumer, not another Perl package
recipe. Source is under `scripts/port/perl5423-xs-consumer/`. It has not been
compiled, loaded, installed, or run with Perl, including `perl -c`. No actor,
daemon, download, native job, or operational Reader was invoked. Native artifact
selectors in the templates remain NULL. Root owns any coordinated host/native
trial under the one-heavy-actor policy.

The XS module copies Perl scalars and arrays through the C API and roundtrips a
native signed IV. Its test covers undef, integers, empty strings, embedded NULs,
UTF8 flags, mixed arrays, and signed 64-bit extrema. The extension also returns
its actual compile-time Perl/API versions and IV size. Compile guards require
5.42.3 headers and eight-byte IVs. These assertions are source only until a real
consumer is built and loaded.

## Admission and DATA preflight

`preflight.py` only reads pinned inputs and prints a future environment/command
plan. It never starts Perl, make, a compiler, installer, or shell command. Hash
bindings do not create authority: Root must derive and review the inputs from
the accepted exact archive and independently admit the root/toolchain.

Fill copies of `admission.TEMPLATE.json` and `inputs.TEMPLATE.json` later with:

* The exact `perl-5.42.3-1.3-{aarch64,x86_64}.pkg.tar.zst` path/size/SHA, accepted
  PKGINFO/BUILDINFO sidecars, and the actual toolchain inventory lock.
* An existing caller-owned disposable installed/extracted **prefix**, with its
  path, UID, device and inode. `/`, aliases, and group/world-writable prefixes
  refuse. The fixture does not install into or alter the root. An installed
  system root can be supplied as a privately owned disposable prefix; the host
  `/usr` is never selected implicitly.
* A Root-derived complete file map for `usr/bin/perl` and every regular file in
  `usr/lib/perl5/5.42/core_perl` and `usr/share/perl5/core_perl`, including all
  CORE headers, libperl, Config and MakeMaker. Each row has bytes, SHA and mode.
  Extra modules, aliases, missing headers and changed bytes refuse.
* Canonical absolute compiler, linker-**driver**, and make paths, their actual
  byte/hash pins, and a pinned package inventory. Normally the linker driver is
  the admitted compiler driver, not bare `ld`. There is no PATH-based compiler
  or interpreter selection. Paths must be shell-safe and contain no spaces.
* For native aarch64, the actual Source/run/job artifact identifiers. Host
  x86_64 is an explicit separate scope with native selectors NULL; it grants no
  native credit. No artifact or toolchain is selected automatically.

The candidate identity is pinned to commit
`c8e9baea97f83f652763e701143d6dec5b679f31`, PKGBUILD SHA
`cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068`,
and upstream source SHA
`16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725`.
Package/build metadata must identify release 1.3; runtime `v5.42.3` alone cannot
distinguish it from older packaging.

Root later stages exactly these five reviewed files into a fresh caller-owned
0700 work directory: `Makefile.PL`, `Consumer.xs`, `provenance.pl`,
`lib/CachyAsahi/Perl5423/Consumer.pm`, and `t/roundtrip.t`. Prior build outputs,
source changes, or an overlapping candidate/work root refuse. The DATA-only
planning command is:

```sh
python3 -I -B scripts/port/perl5423-xs-consumer/preflight.py \
  --admission /ROOT/REVIEWED_ADMISSION.json --admission-sha256 REVIEWED_SHA256 \
  --inputs /ROOT/REVIEWED_INPUT_MAP.json --inputs-sha256 REVIEWED_SHA256 \
  --work /ROOT/OWNED_FRESH_FIXTURE_STAGE
```

The printed plan requires replacing the entire environment with the returned
map. It fixes candidate library search, interpreter/core paths and tool drivers,
then proposes Makefile.PL, make, make test, and standalone provenance commands.
**This task does not execute that plan.** Root must coordinate the actual trial.

## Substitution checks and future evidence

The fixture resets `@INC` to the admitted candidate trees, allowing only the
fixture's exact blib module/object during the runtime test. MakeMaker receives
explicit PERL/FULLPERL, PERL_LIB/PERL_ARCHLIB/PERL_INC, CC/LD/MAKE, and absolute
MYEXTLIB. Its returned values must agree. The pinned MakeMaker source audit
matters: `MM_Unix::init_main` derives PERL_INC from PERL_ARCHLIB, so setting only
PERL_INC would allow accidental baseline headers.

The future configure/runtime receipts report the actual executable, version,
Config and MakeMaker, loaded module/DSO paths, root/input/archive bindings,
toolchain hashes, selected header/library pins, compiled API values, and loaded
extension hash. `/proc/self/maps` must identify the admitted CORE libperl. A GCC
dependency file must identify the candidate EXTERN.h/perl.h/XSUB.h/config.h/
patchlevel.h used by the real compilation. Ambient Perl overrides refuse.

Five actor-fenced Python DATA controls pass on Python 3.12.13/3.14.6, covering the
plan and rejection of NULL native selectors, wrong release/recipe, changed or
aliased headers, extra modules, substituted tools, changed input maps and stale
work outputs. Perl/C/XS syntax and runtime remain unverified because no Perl or
compiler actor was allowed. Root must retain actual logs, generated Makefile,
dependency file, extension and receipts from a later admitted smoke.

A later passing result would establish only this tiny external XS build/load
against the exact admitted candidate/root/toolchain. It would not establish the
external XS ecosystem's ABI compatibility, installed-system lifecycle, native
16K/M2 behavior, performance, or release acceptance.
