# Literal PKGBUILD and .SRCINFO consistency

This opt-in Python >=3.12 command uses only the standard library. It reads two ordinary single-link files (at most1MiB each), compares their explicitly modeled literal declarations, and prints a JSON report with both complete input hashes. It does not source Bash, import recipe code, invoke makepkg, fetch inputs, inspect installed packages or change files.

```sh
python3 -I -B scripts/checks/recipe_metadata_consistency.py /absolute/recipe/PKGBUILD
# An independently retained metadata file can be selected explicitly:
python3 -I -B scripts/checks/recipe_metadata_consistency.py /absolute/recipe/PKGBUILD --srcinfo /absolute/retained/.SRCINFO
```

Exit0/status `MATCH_MODELED_LITERAL_DECLARATIONS` means only the compared declarations agree. Exit1/`MISMATCH` lists stale fields. Exit2/`UNSUPPORTED` identifies forms outside the static subset; `INPUT_ERROR` identifies missing, aliased, unstable, nonordinary, oversized or invalid-text inputs. Unsupported cases never become agreement. This command does not alter either existing package checker, any installed tool, or source preflight routing.

The model compares one package's name/base, version/release, numeric epoch (default0, maximum20 digits), architecture, dependency/make/check/optional dependency/provides/conflicts/replaces declarations, and source/checksum groups. Architecture-qualified groups must name a declared architecture. Relations and architectures compare as sets; source and checksum order is significant. MD5, SHA1/224/256/384/512 and BLAKE2 declarations are supported. Hex case normalizes; literal SKIP agrees only as a declaration and gives no source-integrity assurance. Each declared checksum group must have the same length as its source group. Versions and relations are compared as declarations, without ALPM version ordering or dependency resolution.

PKGBUILD supports separate unquoted/simple quoted words and literal arrays, including comments and multiline arrays. Single quotes preserve literal dollar signs; double-quoted expansions, backticks, escapes, compound words, amended/duplicate assignments, top-level commands/conditionals, dynamic pkgver functions and split packages return UNSUPPORTED. Common prepare/build/check/package function bodies must use an indented layout and a column-zero closing brace; those bodies are explicitly opaque and never executed. This is a declaration checker, not a Bash parser, sandbox, recipe-safety check or prediction of runtime metadata. A script can mutate metadata during execution; no executed or generated metadata is accepted by this report.

Fields outside the model (for example description, license, options, install hooks or PGP keys) are listed in `ignored_fields`. Agreement gives those fields no validation or trust credit. Full shell/recipe review, source signatures/content, build provenance, native ARM/ALPM, hardware, and release acceptance remain separate. Dynamic recipes should be independently reviewed; do not replace dynamic expressions or regenerate metadata merely to turn this report green.

The focused DATA controls cover matching literal declarations, stale versions/epochs/releases/dependencies/provides/hash/source order/architecture, qualified groups, unsupported expansions/split packages, bounded input refusal, actual CLI exit statuses, unexecuted hostile shell text, and read-only comparison of the current build-tools recipe. The dedicated5-minute hosted workflow runs them on Python3.12 and3.14 with pinned checkout/setup actions and read-only contents permission. No native workflow is selected.
