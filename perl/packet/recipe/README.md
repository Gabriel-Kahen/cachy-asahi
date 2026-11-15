# Perl 5.42.3-1.3 configure-time candidate

This unselected, **unbuilt** successor addresses one observed source of the
1.2 clean-pair difference: upstream configure-time strings. Existing
`perl5423-source-candidate` 1.2, its builder and all historical evidence remain
unchanged. There is no new archive or reproducibility acceptance yet. Root owns
review, resource/capacity admission and any actual clean repeat builds.

The source remains official Perl/perl5
`bc3dab4d4f66de5ea67dda34e5feb5230a54c603`, with the same two pinned upstream regex
fixes, notices, providers, dependencies, compiler/runtime flags and complete
upstream `test_harness` target. The 29 relative command aliases and POD retention
behavior are unchanged. `source-lock.json` records source/notices/patch pins and
the new metadata policy; `.SRCINFO` pins every actual recipe source input.

## Supported upstream mechanism

Pinned `Configure` assigns `cf_time` unconditionally from `date` at line3920,
after command-line definitions are applied. Consequently, `-Dcf_time` alone
does not preserve an override. Near the end, lines24819–24830 load `config.over`
before emitting `config.sh`. `INSTALL` lines1497–1508 explicitly documents this
supported override file, and the existing `-des` accepts its default “yes.”
`config_h.SH` and `utils/perlbug.PL` consume the resulting metadata.

The 1.3 recipe requires the already declared `SOURCE_DATE_EPOCH=1785628800` and
converts that epoch with real GNU `date`, in the existing C locale/UTC timezone.
It writes only this source-local assignment:

```sh
cf_time='Sun Aug  2 00:00:00 UTC 2026'
```

Missing/different epochs, date conversion errors or unexpected date output fail
before writing the override or invoking Configure. Existing custom/nonregular
or symlinked `config.over` paths are refused; an exact generated body is accepted
on retries without rewriting it. New-file creation uses shell noclobber.
The recipe checks the effective `config.sh` assignment before `make`, and the
source-built `check_config.pl` additionally requires `$Config{cf_time}` to equal
the canonical value. No upstream source patch, host-clock change, date wrapper,
compiler/runtime flag change, test exclusion or archive normalization is used.

This targets the previously observed time-bearing `perlbug`/`perlthanks`,
`CORE/config.h` and `Config_heavy.pl` content and corresponding `.MTREE` records.
It does not establish that another differing input cannot appear in new builds.

## Completed focused checks

```sh
python3 -I -B -Werror::ResourceWarning \
  packages/port/perl5423-repro-candidate/test_recipe.py
python3 -I -B -Werror::ResourceWarning \
  packages/port/perl5423-repro-candidate/test_configure_time.py \
  --source /absolute/path/to/retained/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603.tar.gz
```

All 13 inherited recipe/staging controls and eight timestamp-focused controls
pass under Python3.12.13 and3.14.7. The focused controls execute the actual pinned
upstream `myread` generation and late-override shell fragments. Separate,
explicitly modeled Configure/make callbacks test refusal/order behavior and
prove that the complete Configure argument vector remains identical to1.2.
They invoke no compiler, full Configure or make.

Actual `makepkg --verifysource` passes all11 source checksums in a network-none,
read-only-root private bubblewrap environment. Actual `prepare()` applies the
unchanged regex patches with zero fuzz to exact retained source members; its
resulting `regexec.c` and `regexp.h` hashes match the prior audited results.
Normal upstream hunk offsets are retained in the log. Bash and Perl syntax
checks pass. These results are source preparation/metadata evidence only.

`validation.json` pins the source inspection, source-only preparation, controls,
unchanged parent/helper material and private logs. No full Configure, compilation,
upstream harness, package assembly, staging of a genuine1.3 payload, ALPM
transaction or new clean pair has run. The existing1.2 builder intentionally
continues to use its frozen1.2 namespace and supplies no1.3 build path; Root must arrange an
explicit1.3 build contract and apply the existing capacity/resource guard before
admission. No build is admitted from a free-space observation alone.

Native ARM/16K, both M2 Air sizes, external XS/target ABI, performance,
historical ALARM correspondence, legal/policy, production trust and release
acceptance remain unqualified. Source preparation and modeled controls do not
prove archive reproducibility or hardware behavior.
