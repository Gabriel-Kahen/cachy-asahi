# Current Fish first-login host rehearsal

The maintained rehearsal now explicitly selects Fish0.1.0-2 alongside
FirstLogin0.1.0-2, Setup8 0.3.0-1 and Zsh0.1.0-1. This is current host-candidate
software evidence. Historical Fish0.1.0-1 native/host evidence and copied frozen
Source helpers remain unchanged and do not qualify this candidate.

PR462 head `471d87523500a474d1c686217719195e43122b93` failed its
[static job](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/43774386306/job/132997215104)
at “Check first-login recovery and installed delivery” with
`Selected finite recipe identity/version differs: fish`. The exact local CLI
reproduced this stale0.1.0-1 selector before assembly. Updating only that selector
then exposed a second stale pin: the guest helper's historical template profile
correctly refused the new Fish bytes. Both failures and cleanup results remain
retained privately; neither was skipped or converted into success.

The helper now has a first-class finite `paths['template_profile']` interface.
Missing selection retains `fish0.1.0-1-zsh0.1.0-1`; the current rehearsal explicitly
passes `fish0.1.0-2-zsh0.1.0-1`. Each profile requires exact known body hashes and
bytes. Unknown profiles or mismatched declared hashes refuse before any user
command. Reports include the selected profile, template hashes and current helper
source hash. The27-command workflow, ownership/preservation checks and callback
execution boundary remain intact; template globals are not rewritten by tests.

| Template | SHA-256 |
| --- | --- |
| Historical Fish0.1.0-1 | `223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c` |
| Current Fish0.1.0-2 | `d26d8826c8a7e096a55d0a4b3eee8e67013d6c9b201971e89ca32e273c0847aa` |
| Unchanged Zsh0.1.0-1 | `7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f` |

The explicit build-and-rehearse regression test passed in16.356s. The existing CI
CLI was also run successfully against committed implementation
`db2a2c561e61fb96295ee7e7ca9b53660b8f1fed`:

```sh
python3 -I -B scripts/integration/first_login_rehearsal.py \
  --output /absolute/new/private/output \
  --build-and-rehearse --installed-guest-controls
```

All four local recipes' source checks and unsigned host assembly passed. The
extracted-package journey completed41 commands/10 real scripted interactive
Fish/Zsh startups. The separately invoked guest controls passed all4 tests; its
positive workflow completed27 commands/10 scripted interactive startups, real
Setup8 exit75/journal recovery, user-edit preservation and deactivation. Unknown
profile, wrong hash, changed template, root identity and HOME alias refusals remain
covered. The callback ran as the already ordinary host user; root-to-alarm
switching, PTY, GUI and physical interruption were not exercised. Temporary build
and user state retired. The current helper hash is
`ea924ca25fcd861316437a6ed46a29cbf79c8c43c4cab973834da0c3560460b5`.

The committed-source result is9474 bytes, SHA-256
`5d68c4539aac60b5c1c1398e1881bddfc690b86e323789b8230894cd68ffa2f2`.
The unchanged frozen FirstLogin/Enrollment Source family also passed its16
actor-fenced DATA controls. That check is not a native trial or Reader acceptance.

The rehearsal intentionally retains its existing `--nodeps --nocheck --nosign`
host-assembly contract and fixed source epoch. Dependency resolution, recipe
check() execution, ALPM installation, new native ARM build pairs, M2 hardware,
physical power-loss recovery and release acceptance remain NOT RUN. No Fish
runtime/recipe, shared manifest/workflow, new FirstLogin03 source or historical
validation record was changed by this correction.
