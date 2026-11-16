#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Installed first-login guest workflow using only an owner-held command callback.

No subprocess/supervisor, package installation, network or native acceptance.
The caller owns deadlines, ordinary-user workspace creation and final cleanup.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

# Exact selected original 0.1.0-1 package templates; no synthetic replacement.
TEMPLATE_CONTENT = {
    'fish/config.fish': b"# SPDX-License-Identifier: MIT\n# Original cachy-asahi opt-in helpers. No upstream CachyOS code is included.\n# Source explicitly from your own Fish config after existing customizations.\nif not status is-interactive\n    return\nend\n\nif not functions -q caa_ll\n    function caa_ll --description 'List all entries with details'\n        command ls -alF -- $argv\n    end\nend\n\nif not functions -q caa_mcd\n    function caa_mcd --description 'Create one directory and enter it'\n        if test (count $argv) -ne 1\n            printf '%s\\n' 'Usage: caa_mcd DIRECTORY' >&2\n            return 2\n        end\n        command mkdir -p -- $argv[1]; and cd -- $argv[1]\n    end\nend\n",
    'zsh/config.zsh': b"# SPDX-License-Identifier: MIT\n# Original cachy-asahi configuration; see LICENSE and NOTICE.\n# Enable explicitly from an interactive user's configuration.\n[[ -o interactive ]] || return 0\n[[ ${_CACHY_ASAHI_ZSH_LOADED:-0} == 1 ]] && return 0\n\n# Reuse a user's completion setup. Skip insecure directories and do not write\n# a completion dump; Zsh performs its own permission audit.\nif [[ ${CACHY_ASAHI_ZSH_COMPLETION:-1} == 1 ]] && (( ! ${+_comps} )); then\n  autoload -Uz compinit\n  compinit -i -D || return 1\nfi\n\n# A plain prompt is separately opt-in so an existing theme keeps ownership.\nif [[ ${CACHY_ASAHI_ZSH_PROMPT:-0} == 1 ]]; then\n  PROMPT='%n@%m %~ %# '\nfi\n\ntypeset -g _CACHY_ASAHI_ZSH_LOADED=1\n",
}


# Historical default is retained. Current rehearsal explicitly opts into Fish02.
DEFAULT_TEMPLATE_PROFILE = 'fish0.1.0-1-zsh0.1.0-1'
CURRENT_TEMPLATE_PROFILE = 'fish0.1.0-2-zsh0.1.0-1'
TEMPLATE_PROFILES = {
    DEFAULT_TEMPLATE_PROFILE: TEMPLATE_CONTENT,
    CURRENT_TEMPLATE_PROFILE: {**TEMPLATE_CONTENT, 'fish/config.fish': b'# SPDX-License-Identifier: MIT\n# Original cachy-asahi opt-in helpers. No upstream CachyOS code is included.\n# Source explicitly from your own Fish config after existing customizations.\nif not status is-interactive\n    return\nend\n\nif not functions -q caa_ll\n    function caa_ll --description \'List all entries with details\'\n        command ls -alF -- $argv\n    end\nend\n\nif not functions -q caa_mcd\n    function caa_mcd --description \'Create one directory and enter it\'\n        if test (count $argv) -ne 1\n            printf \'%s\\n\' \'Usage: caa_mcd DIRECTORY\' >&2\n            return 2\n        end\n        # Resolve both operations here, even when CDPATH contains another match.\n        set -l caa_target "$argv[1]"\n        if test -n "$caa_target"; and not string match --quiet \'/*\' -- "$caa_target"\n            set caa_target "./$caa_target"\n        end\n        command mkdir -p -- "$caa_target"; and cd -- "$caa_target"\n    end\nend\n'},
}
TEMPLATE_HASHES = {
    DEFAULT_TEMPLATE_PROFILE: {'fish/config.fish': '223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c',
                              'zsh/config.zsh': '7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f'},
    CURRENT_TEMPLATE_PROFILE: {'fish/config.fish': 'd26d8826c8a7e096a55d0a4b3eee8e67013d6c9b201971e89ca32e273c0847aa',
                              'zsh/config.zsh': '7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f'},
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def path_pins(paths):
    pins = {}
    for name in ('first_login', 'setup', 'fish', 'zsh', 'python3'):
        path = Path(paths[name])
        require(path.is_absolute() and path.is_file() and os.access(path, os.X_OK), 'selected executable unavailable: ' + name)
        target = path.resolve()
        row = target.stat()
        pins[name] = {'path': str(path), 'resolved_path': str(target), 'sha256': digest(target.read_bytes()),
                      'bytes': row.st_size, 'mode': stat.S_IMODE(row.st_mode)}
    return pins


def snapshot(home, uid, gid):
    result, total = {}, 0
    for path in sorted(home.rglob('*')):
        row = path.lstat()
        require(row.st_uid == uid and row.st_gid == gid and not row.st_mode & 0o022,
                'unexpected user-state ownership or writable mode')
        item = {'uid': row.st_uid, 'gid': row.st_gid, 'mode': stat.S_IMODE(row.st_mode)}
        if stat.S_ISREG(row.st_mode):
            require(row.st_nlink == 1 and row.st_size <= 2 * 1024**2, 'unsafe/oversized private user file')
            raw = path.read_bytes(); total += len(raw)
            item.update(kind='file', sha256=digest(raw))
        else:
            require(stat.S_ISDIR(row.st_mode), 'non-directory/non-regular private user state refused')
            item['kind'] = 'directory'
        result[str(path.relative_to(home))] = item
        require(len(result) <= 512 and total <= 8 * 1024**2, 'private user-state observation bound')
    return result


def template_profile(paths):
    selected = paths.get('template_profile', DEFAULT_TEMPLATE_PROFILE)
    require(type(selected) is str and selected in TEMPLATE_PROFILES, 'unknown finite template profile')
    content, expected = TEMPLATE_PROFILES[selected], TEMPLATE_HASHES[selected]
    require(set(content) == set(expected) and all(digest(raw) == expected[name] for name, raw in content.items()),
            'finite template profile source hash differs')
    require(paths['template_sha256'] == expected, 'selected template hash profile differs')
    return selected, content


def templates(paths):
    root = Path(paths['template_root'])
    owner = paths.get('template_owner', 0)
    expected = paths['template_sha256']
    require(root.is_absolute() and root.resolve() == root and root.is_dir(), 'canonical template directory required')
    _, content = template_profile(paths)
    result = {}
    for relative, original in content.items():
        path = root / relative
        for parent in (root, path.parent):
            row = parent.lstat()
            require(stat.S_ISDIR(row.st_mode) and row.st_uid == owner and not row.st_mode & 0o022,
                    'unsafe template directory')
        row = path.lstat()
        require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_uid == owner and not row.st_mode & 0o022,
                'unsafe template file')
        raw = path.read_bytes()
        require(raw == original and digest(raw) == expected[relative], 'selected actual template bytes differ')
        result[relative] = {'sha256': digest(raw), 'bytes': len(raw), 'owner': owner}
    return result


def run(paths, home, run, uid, gid, label='first-login'):
    """run(step, argv, expected=0, cwd=Path)->bytes is supplied by the actor.

    All commands explicitly enter the selected ordinary account. The callback
    owns execution, deadlines/output bounds and process cleanup. No PTY exists.
    """
    report = {'schema_version': 1, 'status': 'FAIL', 'ordered_steps': [],
              'shell_scope': 'actual scripted interactive Fish/Zsh startup; no PTY or terminal emulator',
              'pty': 'NOT RUN', 'graphical_login': 'NOT RUN', 'hardware': 'NOT RUN',
              'recovery_scope': 'delivered Setup8 process exits75 after its first durable Fish write; real journal replay, not power-loss recovery'}
    try:
        require(type(uid) is int and type(gid) is int and uid > 0 and gid > 0, 'ordinary non-root UID/GID required')
        selected, _ = template_profile(paths)
        report.update(template_profile=selected, template_sha256=dict(TEMPLATE_HASHES[selected]))
        require(re.fullmatch('[a-z0-9][a-z0-9-]{0,47}', label), 'bounded command label required')
        user = paths.get('user', 'alarm')
        require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', user), 'explicit ordinary account required')
        home = Path(home)
        require(home.is_absolute() and home.resolve() == home, 'canonical private HOME required')
        row = home.lstat()
        require(stat.S_ISDIR(row.st_mode) and row.st_uid == uid and row.st_gid == gid
                and stat.S_IMODE(row.st_mode) == 0o700 and not any(home.iterdir()), 'fresh owned 0700 HOME required')
        workspace = Path(paths.get('workspace', home))
        require(workspace.is_absolute() and workspace.resolve() == workspace and workspace.is_dir(), 'owned private workspace required')
        row = workspace.stat()
        require(row.st_uid == uid and row.st_gid == gid and not row.st_mode & 0o077, 'private workspace ownership/mode differs')
        report.update(uid=uid, gid=gid, user=user, home=str(home), path_pins=path_pins(paths), template_pins=templates(paths))
        env = {'HOME': str(home), 'XDG_CONFIG_HOME': str(home / '.config'), 'XDG_STATE_HOME': str(home / '.local/state'),
               'XDG_CACHE_HOME': str(home / '.cache'), 'XDG_DATA_HOME': str(home / '.local/share'),
               'ZDOTDIR': str(home), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TERM': 'dumb'}
        prefix = ['/usr/bin/runuser', '-u', user, '--', '/usr/bin/env', '-i',
                  *(key + '=' + value for key, value in env.items())]
        def call(step, argv, expected=0, marker=None):
            name = label + '-' + step
            report['ordered_steps'].append(name)
            data = run(name, [*prefix, *map(str, argv)], expected=expected, cwd=workspace)
            require(isinstance(data, bytes), 'held callback must return bytes')
            require(marker is None or marker.encode() in data, 'expected real shell behavior missing: ' + step)
            return data
        first, setup, python = (str(paths[name]) for name in ('first_login', 'setup', 'python3'))
        root_options = ['--home', str(home), '--template-root', str(paths['template_root'])]
        def first_call(step, operation, *options, expected=0):
            return json.loads(call(step, [first, operation, *options, '--setup-helper', setup, *root_options], expected))
        def remove(step, apply=False):
            return json.loads(call(step, [setup, 'remove', '--components', 'fish', 'zsh', *root_options,
                                          *(['--apply'] if apply else [])]))
        def shells(phase, active, edited=False):
            if active:
                fish = "functions -q caa_ll caa_mcd; or exit 21; caa_ll; caa_mcd '" + phase + " space'; or exit 22; test (basename $PWD) = '" + phase + " space'; or exit 23; printf '%s\\n' CAA_FISH_ACTIVE"
                zsh = '[[ -o interactive && $_CACHY_ASAHI_ZSH_LOADED == 1 && ${+_comps} == 1 && -n $_comps[cd] ]] || exit 24; print -r -- CAA_ZSH_ACTIVE'
            else:
                fish = "functions -q caa_ll; and exit 25; functions -q caa_mcd; and exit 26; printf '%s\\n' CAA_FISH_REMOVED"
                zsh = '(( ${+_CACHY_ASAHI_ZSH_LOADED} == 0 )) || exit 27; print -r -- CAA_ZSH_REMOVED'
            if edited:
                fish += "; test \"$CAA_USER_KEPT\" = yes; or exit 28"
                zsh += '; [[ $CAA_USER_KEPT == yes ]] || exit 29'
            call(phase + '-fish', [paths['fish'], '--private', '--interactive', '--command', fish],
                 marker='CAA_FISH_ACTIVE' if active else 'CAA_FISH_REMOVED')
            call(phase + '-zsh', [paths['zsh'], '-d', '-i', '-c', zsh],
                 marker='CAA_ZSH_ACTIVE' if active else 'CAA_ZSH_REMOVED')
        identity = json.loads(call('identity', [python, '-I', '-c',
            'import json,os;print(json.dumps({"uid":os.geteuid(),"gid":os.getegid()}))']))
        require(identity == {'uid': uid, 'gid': gid}, 'callback ordinary-user identity differs')
        call('fish-version', [paths['fish'], '--version'])
        call('zsh-version', [paths['zsh'], '--version'])
        before = snapshot(home, uid, gid)
        observed = first_call('inspect', 'inspect')
        available = {item['component']: item['available'] for item in observed['components']}
        require(available['fish'] and available['zsh'], 'actual selected components unavailable')
        require(snapshot(home, uid, gid) == before, 'inspect changed private HOME')
        first_call('preview', 'activate', '--components', 'fish', 'zsh')
        require(snapshot(home, uid, gid) == before, 'preview changed private HOME')
        first_call('apply', 'activate', '--components', 'fish', 'zsh', '--apply')
        call('workspace-marker', [python, '-I', '-c',
             'from pathlib import Path;Path("journey-sentinel").write_text("owned user workspace\\n")'])
        shells('first', True)
        fish_config, zsh_config = home / '.config/fish/config.fish', home / '.zshrc'
        edits = '\nset -g CAA_USER_KEPT yes\n', '\ntypeset -g CAA_USER_KEPT=yes\n'
        call('user-edits', [python, '-I', '-c',
             'from pathlib import Path;import sys\nfor name,edit in zip(sys.argv[1:3],sys.argv[3:]):\n with Path(name).open("a") as output:output.write(edit)',
             fish_config, zsh_config, *edits])
        edited = {str(path): path.read_bytes() for path in (fish_config, zsh_config)}
        first_call('repeat-after-edit', 'activate', '--components', 'fish', 'zsh', '--apply')
        require(all(Path(path).read_bytes() == raw for path, raw in edited.items()), 'repeat changed user edits')
        shells('edited', True, True)
        unchanged = snapshot(home, uid, gid)
        remove('deactivate-preview')
        require(snapshot(home, uid, gid) == unchanged, 'deactivation preview changed HOME')
        remove('deactivate', True)
        user_only = {str(path.relative_to(home)): path.read_bytes() for path in (fish_config, zsh_config)}
        require(all(b'CAA_USER_KEPT' in raw for raw in user_only.values()), 'deactivation lost user edits')
        shells('removed', False, True)
        crash = '''import os,runpy,sys
Setup=runpy.run_path(sys.argv[1],run_name='setup_engine')['Setup']
engine=Setup(sys.argv[2],sys.argv[3]);atomic=engine.fs.atomic
def stop(path,*args,**kwargs):
 result=atomic(path,*args,**kwargs)
 if path==engine.targets['fish']:os._exit(75)
 return result
engine.fs.atomic=stop
engine.run('activate',('fish','zsh'),True)
raise SystemExit(76)
'''
        call('interrupted-setup', [python, '-I', '-c', crash, setup, home, paths['template_root']], expected=75)
        pending = snapshot(home, uid, gid)
        first_call('pending-inspect', 'inspect', expected=2)
        first_call('pending-new-selection-refused', 'activate', '--components', 'fish', '--apply', expected=2)
        first_call('recover-preview', 'recover', expected=2)
        require(snapshot(home, uid, gid) == pending, 'pending inspection/refusal/preview changed HOME')
        recovered = first_call('recover', 'recover', '--apply')
        require(recovered['setup_result']['recovered_transaction'], 'original journal was not recovered')
        require(not (home / '.local/state/cachy-asahi/setup/journal.json').exists(), 'recovery journal remains')
        shells('recovered', True, True)
        remove('final-deactivate', True)
        shells('final', False, True)
        require(all((home / name).read_bytes() == raw for name, raw in user_only.items()), 'final deactivation changed preserved user bytes')
        require(path_pins(paths) == report['path_pins'] and templates(paths) == report['template_pins'], 'installed paths/templates changed during journey')
        report.update(status='PASS', command_count=len(report['ordered_steps']), shell_startups=10,
                      user_edit_preservation={name: digest(raw) for name, raw in user_only.items()},
                      final_user_state=snapshot(home, uid, gid), template_and_program_preservation=True,
                      recovery_confirmed=True, final_components_deactivated=True)
        return report
    except BaseException as error:
        report.update(error=str(error) or type(error).__name__, command_count=len(report['ordered_steps']))
        error.first_login_result = report
        raise
