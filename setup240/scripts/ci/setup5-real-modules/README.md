# Setup5 with the six real shell products

Host-only integration using the accepted `cachy-asahi-setup 0.1.0-5` packaged
CLI bytes and the existing `shell-modules-coexistence` behavior cases. This
adapter stages actual `package()` functions into its private output tree. It
never installs packages or changes the caller's home, startup files or desktop
notification service. No product code is patched.

The accepted input is Root ref
`79d8d2f53510e4f3a04f39c1b1e24c999aa32e44`, with the complete 149-file,
1,305,823-byte input closure and exact index, archive pair and executable pins.
Its native run `38934198468` is input provenance; running this driver provides
host evidence only. The package archives are read in memory and only the
verified `usr/bin/cachy-asahi-setup` member is written to private output.

Six explicit selections are activated in each private behavior home:
Fish bang-bang, autopair and Done; Zsh autosuggestions, syntax highlighting and
history substring search. The full CLI-generated `config.fish` or `.zshrc`,
including an existing user prefix, is sourced. Preview is read-only, repeated
apply is byte/metadata unchanged, and normal removal restores exact user
configuration bytes and modes while preserving unrelated fixture files.
Separate edited Fish/Zsh owned blocks cause activation and removal to exit 2
and retain edits; removing the unedited components leaves those two records.

The inherited request-order cases are retained, but Setup5 normalizes the
actual generated order to bang-bang/autopair/Done and
suggestions/highlighting/substring. The receipt records both; these cases do
not establish alternate generated source orders.

The only private behavior-driver patch replaces exactly one
`unset ZSH_AUTOSUGGEST_USE_ASYNC` with
`(( ${+ZSH_AUTOSUGGEST_USE_ASYNC} )) || exit 25`. This exercises normal async
suggestions and asserts the setting in the real interactive shell. Original
and adapted driver hashes are recorded. The original driver is retained.
The existing Done fixture is adapted at two exact AST constants so its
configuration preservation assertion compares against the captured complete
generated file. Its binding check uses the existing coexistence subset check,
which permits added module bindings while requiring every prior binding.
All behavior assertions and ordinary exit checks remain in the reused cases.

The four private PTYs check typed Fish expansion, brackets/quotes, Done's
private recorder invocation, Zsh async suggestions/acceptance, highlighting,
substring traversal and literal data. They also check custom keys, hooks,
functions/widgets, repeated sourcing and caller continuation. Two noninteractive
cases require silent module no-op behavior and caller continuation. The Done
recorder has a private PATH and nonexistent session bus; no real notification
is sent. Shells use no-config startup and explicitly source the complete
Setup5-generated file after establishing the existing custom behavior.
Each behavior case has a 30-second watchdog and inherited bounded PTY teardown.

Run with existing Fish, Zsh, Bash, GNU install/timeout and Python 3; no downloads:

```sh
python -B scripts/ci/setup5-real-modules/run.py \
  --source /absolute/repository \
  --accepted-inputs /absolute/accepted-setup5-inputs/payload \
  --output /absolute/fresh-private-output
```

The output must not exist. Ancestor aliases and source drift are refused.
All 86 dependency files (82 product files, four existing driver files), plus
this adapter's three files, are pinned. Local package source checksum arrays
are validated when freezing. Receipts include all source hashes, staged
payload bytes/modes/hashes, product versions, interpreter identities, actual
host architecture/page size, lifecycle and behavior outcomes. The accepted
setup package CLI is unmodified; the staged module products are the exact
pinned source recipes, not newly built native archives.

Inert controls use only a chosen temporary directory and never launch shells:

```sh
SETUP5_SOURCE=/absolute/repository \
SETUP5_ACCEPTED_INPUTS=/absolute/accepted-setup5-inputs/payload \
SETUP5_CONTROL_ROOT=/absolute/existing-private-control-directory \
  python -B scripts/ci/setup5-real-modules/test_source.py -v
```

Passing host results do not establish native ARM/16K/M2 runtime, desktop
notifications, target installation, release admission or performance gains.
Setup3 and existing 587/600 selections are outside this driver's scope.
