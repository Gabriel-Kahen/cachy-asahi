# Inspect literal versioned dependencies

The historical `scripts/checks/package_checks.py` fallback rejects every `<` or `>` character as shell syntax, including quoted `depends=('python>=3.12')`. This affects the build-tools package and current SourceTools `python>=3.14` recipe unless they supply reviewed `.SRCINFO`. Its many pinned historical/current consumers remain unchanged.

`scripts/checks/package_checks_v2.py` is an explicit versioned successor. It preserves the recipe/archive/platform checks and adds a closed literal dependency-word parser. [Arch's PKGBUILD manual](https://man.archlinux.org/man/PKGBUILD.5.en) documents comparisons `>=`, `<=`, `=`, `>` and `<`; provisions permit exact `=` versions only. Runtime/build/check/optional dependencies, conflicts and replacements, including the existing `_aarch64` fields, use this grammar. Optional descriptions follow `: `, separately from a numeric version epoch.

```sh
python3 -I -B scripts/checks/package_checks_v2.py recipe /absolute/recipe/PKGBUILD
```

The new single-recipe command inspects tool recipes directly, without the older bulk command's desktop/shell/settings discovery restriction. The existing `recipes` and `artifacts` commands retain their behavior. JSON results preserve complete recipe input hashes and the existing independent-review requirements.

Comparison signs must be inside one completely quoted dependency word. Bare package names and literal `name=version` words remain supported. Names use Arch's ASCII package-name characters and cannot start with a dot/hyphen. Versions use a conservative ASCII literal subset: letters/digits, `_+.~`, optional numeric epoch and optional numeric package release/subrelease. Empty/multiple/invalid comparisons, unquoted redirection, concatenated shell words and assignment tails refuse. Other version forms require reviewed `.SRCINFO`.

The old `$`, backtick, semicolon and backslash refusal remains in every field, even inside quotes. Comparison signs remain forbidden outside the dependency grammar, including source/license fields and optional-dependency descriptions. Nothing sources Bash, substitutes variables, evaluates expressions, solves dependencies or compares version ordering. This remains static DATA inspection, not a shell sandbox or a proof that arbitrary PKGBUILD bodies match their metadata.

Every original checker function other than `literal_metadata()` and the CLI dispatcher remains byte-for-byte held; `relation_literals()` is the only new function. Protected platform names/paths and all original archive/recipe constants remain unchanged. The build-tools package successor installs this explicitly pinned owner as its private `package_checks.py`; SourceTools0.2 and historical packaged checkers remain unchanged.

The eleven new controls reproduce both real recipes, cover every comparison and supported relation field, quote/shell refusals, optional description/epoch separation, protected platform relations, full recipe inspection without `.SRCINFO`, the real CLI dispatcher and the inverse of unchanged functions/constants. No PKGBUILD, source, native build, package manager, subprocess or network actor executes in these parser controls. Native ARM/ALPM/M2/performance/release acceptance remains untested.
