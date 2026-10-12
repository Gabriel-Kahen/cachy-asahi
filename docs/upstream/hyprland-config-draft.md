# Draft: legacy CachyOS Hyprland settings fail the v0.56.2 verifier

Status: **reviewable draft; NOT SUBMITTED**. Source pins and parser results were checked October 11, 2026. This is an x86_64 configuration-verifier finding. No CachyOS package installation, compositor session, ARM build or M2 validation was performed.

**Routing decision:** do not open a duplicate issue now. [PKGBUILDS PR #1972](https://github.com/CachyOS/CachyOS-PKGBUILDS/pull/1972) is open and already removes this archived settings recipe. Its reviewed head is `185c9cd1f6d50291f513312224b881a60ddf526b`; API `merged_at` is null. The asset repository is archived. The coordinator can use the report below as supporting evidence in that existing review after obtaining submission authorization. Recheck PR status before any action. A hypothetical issue title, if maintainers later request a separate report, is: **`cachyos-hyprland-settings 1.4.4 ships config rejected by Hyprland 0.56.2`**. No maintainer contact has occurred.

## Proposed report body

The pinned `cachyos-hyprland-settings` recipe packages settings 1.4.4 and depends on `hyprland` without a version bound. With the existing Hyprland v0.56.2 verifier, that settings bundle produces parser errors for `dwindle:pseudotile`, the standalone `togglesplit` dispatcher and legacy window/layer rules. This provides a reproducible compatibility reason for retiring the archived profile in #1972. It does not report an Apple GPU defect or establish a compositor regression.

### Exact inputs

| Input | Pin and checksum |
| --- | --- |
| [CachyOS PKGBUILD](https://github.com/CachyOS/CachyOS-PKGBUILDS/blob/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-hyprland-settings/PKGBUILD) | Project commit `c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`; `1.4.4-1`; file SHA-256 `efb477c4f2ba94d8681e9555ee0507ce2fe60e156ac85b437dcf90dfe3ab4bff` |
| [Settings assets](https://github.com/CachyOS/cachyos-hyprland-settings/tree/449635e3718f4f178503682b29b159b0a758e5e7) | Tag `1.4.4` resolves to `449635e3718f4f178503682b29b159b0a758e5e7` |
| [Tag archive](https://codeload.github.com/CachyOS/cachyos-hyprland-settings/tar.gz/refs/tags/1.4.4) | SHA-256 `6329177a462392ae018e81572359aaf4c530e4ff4136ef6f170ab33eb043893b`; SHA-512 `64a04b9f0adbc37bd7f6f19a9bd099fc0a30bad3b7e42207653f83cc3ecac9086ee9c3209e8be69d84eeac6a7f3f5611ae85183bd83e39feaa80af046fb4bf86` matches recipe |
| [Hyprland release](https://github.com/hyprwm/Hyprland/releases/tag/v0.56.2) | Existing binary reports v0.56.2, clean commit `efb50993780079460b0cbed1363e2166a2de1d9f`; x86_64 |
| [Hyprland API example](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/example/hyprland.lua) | SHA-256 `e35a9ed7463d5f7430db7e817024bfd1594738645d5a18b2173ff4107b242d14` |

The recipe reference identifies source packaging, not an installed CachyOS repository version. The inspected asset tag is newer than the repository's latest GitHub **release object**, 1.4.1; the tag and release list are different records. These source bytes were independently re-downloaded and hashed; no asset was installed or redistributed as an adapted package.

The original files under `etc/skel/.config/hypr/` have these SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `hyprland.conf` | `218d297aedc21cdb57d3583d219285c82be94a0467eb2169b2da65eb558a6189` |
| `config/keybinds.conf` | `1121a766cb5ec625a1dd89b33074084b2c5f3020a755dbb6e0a293c7e3b8b6a6` |
| `config/variables.conf` | `18697e39df43ab0065d8ad6eec868289b9dcde15e62cbcc6bb235a98344fbd3f` |
| `config/windowrules.conf` | `b4384f14f6e643b0e6fd9e533434bcc6d412dd589952abeb0446e62df9271a4b` |

### Minimal reproduction

Use an **already installed** matching Hyprland binary and Python 3; no package installation or session launch is needed. `Hyprland --help` describes `--verify-config` as parsing without running Hyprland. Run this Python block as an ordinary user. It keeps all configuration and XDG paths in a temporary directory, prints the observed version and result, and asserts the currently observed failure. Shell stdout can be saved as the reproduction log.

```sh
python3 - <<'PY'
import os, subprocess, tempfile
from pathlib import Path
print(subprocess.check_output(['Hyprland', '--version'], text=True))
config = '''dwindle {
    pseudotile = true
}
bindd = SUPER, J, Toggle split, togglesplit,
windowrule = float,class:^(org.gnome.Calculator)$
'''
with tempfile.TemporaryDirectory(prefix='hyprland-config-repro-') as tmp:
    base = Path(tmp)
    home = base / 'home'
    home.mkdir()
    path = base / 'minimal.conf'
    path.write_text(config)
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
               XDG_CACHE_HOME=str(home / '.cache'), XDG_STATE_HOME=str(home / '.local/state'),
               LC_ALL='C')
    result = subprocess.run(['Hyprland', '--verify-config', '--config', str(path)],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout)
    print('exit_code:', result.returncode)
    assert result.returncode == 1, 'capture changed behavior; do not claim this result'
PY
```

Expected: settings advertised for the current supported compositor parse without unknown options, dispatchers or rule fields. Actual: exit 1, with these diagnostics from the five-line reduction:

```text
line 2: config option <dwindle:pseudotile> does not exist.
line 4: Invalid dispatcher, requested "togglesplit" does not exist
line 5: invalid field float: missing a value
```

The full pinned bundle also fails (exit 1), including original `config/keybinds.conf:17`, `config/variables.conf:63`, and `config/windowrules.conf:8`. Full results are retained in [full-bundle-verifier.txt](full-bundle-verifier.txt); the minimal log is [minimal-verifier.txt](minimal-verifier.txt).

For that full-bundle check, only regular files inside the archive's `etc/skel/.config/hypr/` subtree were copied into a temporary directory. Every file was checked against the desktop inventory's original hash. Active `source = ~/.config/hypr/...` directives were rewritten to absolute paths in that copied tree using `(?m)^(\s*source\s*=\s*)~\/\.config\/hypr\/([^\r\n]+)$`; commented imports were left commented. This changes import paths, not options/rules/dispatchers or line count. It avoids importing real user configuration. Other executable strings/autostart definitions were not rewritten or activated. The rewrite list and post-rewrite hashes are in [reproduction-observation.json](reproduction-observation.json); temporary paths in logs are sanitized to `TEMP_REPRO`. The post-rewrite hashes identify the actually executed temporary files; their random paths make those hashes differ on reruns, and sanitized path displays cannot recreate those exact bytes. Log hashes identify the retained sanitized outputs. The five-line reproduction has no imports and does not depend on that rewrite.

### Bounded correction if the profile is retained

Preferred package-maintenance disposition is the already proposed retirement in #1972, plus a clear supported-profile/migration note. Existing user copies are not automatically migrated by deleting a package recipe. Do not impose permanent compositor holds or an untested downgrade to keep the old dotfiles working.

If maintainers elect to retain a profile instead, migrate it against a declared compositor API and verify the entire copied import tree in CI. A narrow illustration for just the three failing constructs is:

```lua
hl.config({general = {layout = "dwindle"}, dwindle = {preserve_split = true}})
hl.bind("SUPER + J", hl.dsp.layout("togglesplit"))
hl.window_rule({match = {class = "^(org.gnome.Calculator)$"}, float = true})
```

This omits removed `dwindle:pseudotile`, uses the injected `hl` API and the supported layout-message dispatcher, and replaces a legacy comma rule with a Lua rule. The pinned upstream example supplies these API forms; [Dwindle documentation](https://wiki.hypr.land/0.55.0/Configuring/Layouts/Dwindle-Layout/) explains the split message and `preserve_split`. The v0.55.0 release explicitly records removal of the old pseudotile option. [Release notes](https://github.com/hyprwm/Hyprland/releases/tag/v0.55.0)

The illustration **passes the same v0.56.2 x86 verifier** (exit 0, `config ok`): [bounded-correction-verifier.txt](bounded-correction-verifier.txt). This is not a complete asset migration or applied patch. Key dispatch, rule behavior, session startup, installation/upgrades and any M2 behavior remain NOT RUN. Validate the complete chosen profile and real session before declaring compatibility. Source licensing/notices must be resolved separately before downstream redistribution.

### Limits and related work

See [upstream history](history.md) for current related report/PR status and duplicate checks. The older windowrule rename PR addresses the 0.48-era syntax transition, not this verified 0.56.2 result. The new-version issue tracks the 1.4.4 tag update; it does not establish its compatibility with the later API. This report supplies concrete parser evidence only. It does not ask Hyprland upstream to restore a deliberately removed option or claim a regression between two tested compositor versions.

## Internal provenance for reviewers

The earlier desktop worker log is [upstream-config-verifier.txt](../../packages/desktop/evidence/upstream-config-verifier.txt), SHA-256 `2f1bb25271f5394ad8be2cc6bdb683fe278dff80b792460215e4355792e5935c`. This task independently reproduced it with the same pinned archive/host parser. The complete host/library version string, commands, sanitized log hashes, source rewrites and configuration hashes are stored in `reproduction-observation.json`.

Two draft API guesses were tested and rejected before the bounded illustration above: `require("hyprland")` fails module lookup, and `hl.dsp.layout.msg(...)` fails because `layout` is a function. Their failed logs remain in `proposed-verifier.txt` and `proposed-global-verifier.txt`; they are not proposed corrections. The reviewed illustration follows the actual pinned example's `hl.dsp.layout(...)`. No code or recipe was modified by this documentation task. The body above is ready for coordinator review; external submission is NOT RUN.
