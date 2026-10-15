#!/usr/bin/env python3
"""Finite offline development-package transactions, inside disposable Docker only."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess


def run(*argv):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, timeout=45)


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(root):
    return {str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mode, path.stat().st_uid,
            path.stat().st_gid, path.stat().st_mtime_ns) for path in root.rglob('*') if path.is_file()}


def main():
    require(os.getuid() == 0 and Path('/.dockerenv').is_file() and os.uname().machine == 'aarch64', 'disposable ARM Docker required')
    rows = json.loads(Path('/inputs/packages.json').read_text())
    names = [row['name'] for row in rows]
    require(names == ['cachy-asahi-zsh-autosuggestions', 'cachy-asahi-fish-bang-bang', 'cachy-asahi-topmem'], 'fixed package subset required')
    base = Path('/inputs/packages.lock').read_text()
    require(run('pacman', '-Q') and ''.join(sorted(run('pacman', '-Q').splitlines(True))) == base, 'base inventory differs')
    alarm = pwd.getpwnam('alarm')
    homes = []
    for kind in ('fresh', 'existing'):
        home = Path('/tmp') / kind
        home.mkdir(mode=0o700)
        (home / '.config/fish').mkdir(parents=True)
        # Fish may create this file even with --no-config; establish the fixture first.
        (home / '.config/fish/config.fish').write_text('# preserved Fish configuration\n')
        (home / '.config/fish/config.fish').chmod(0o600)
        if kind == 'existing':
            (home / '.local/share/fish').mkdir(parents=True)
            for name, data in (('.zshrc', b'# user-owned\n'), ('.zsh_history', b'echo sentinel\n'),
                               ('.local/share/fish/fish_history', b'- cmd: echo sentinel\n  when: 1\n')):
                path = home / name
                path.write_bytes(data)
                path.chmod(0o600)
        for path in (home, *home.rglob('*')):
            os.chown(path, alarm.pw_uid, alarm.pw_gid)
        homes.append((home, fingerprint(home)))
    Path('/tmp/pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Never\nLocalFileSigLevel = Never\nHookDir = /builder-disabled-hooks\n')
    # These unsigned packages are local development fixtures; release trust is a separate track.
    pacman = ('pacman', '--config', '/tmp/pacman.conf', '--noconfirm', '--noscriptlet')

    def preserved():
        for home, before in homes:
            require(fingerprint(home) == before, 'user configuration/history changed')

    def shell(home, executable, code):
        return run('runuser', '-u', 'alarm', '--', 'env', '-i', 'PATH=/usr/bin:/bin', 'TERM=dumb',
                   'HOME=' + str(home), 'ZDOTDIR=' + str(home), 'XDG_CONFIG_HOME=' + str(home / '.config'),
                   'XDG_DATA_HOME=' + str(home / '.local/share'), 'XDG_CACHE_HOME=/tmp/probe-cache',
                   executable, *(('-dfi', '-c') if executable == 'zsh' else ('--no-config', '--private', '--interactive', '-c')), code)

    def installed(index):
        expected = {}
        for row in rows:
            item = row['versions'][index]
            require(run('pacman', '-Q', row['name']).strip() == row['name'] + ' ' + item['version'], 'installed version differs')
            run('pacman', '-Qkk', row['name'])
            for relative, desired in item['payload'].items():
                path = Path('/') / relative
                actual = path.lstat()
                require(stat.S_ISREG(actual.st_mode) and stat.S_IMODE(actual.st_mode) == desired['mode'] and
                        actual.st_uid == actual.st_gid == 0 and
                        hashlib.sha256(path.read_bytes()).hexdigest() == desired['sha256'], 'installed payload differs: ' + relative)
                expected[relative] = True
                require(run('pacman', '-Qoq', str(path)).strip() == row['name'], 'file ownership differs')
        for home, _ in homes:
            shell(home, 'zsh', 'source /usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh; source /usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh; (( ${+functions[_zsh_autosuggest_start]} ))')
            shell(home, 'fish', 'fish_default_key_bindings; set -g fish_key_bindings fish_default_key_bindings; source /usr/share/cachy-asahi/fish-bang-bang/opt-in.fish; source /usr/share/cachy-asahi/fish-bang-bang/opt-in.fish; functions --query caa_history_bang caa_history_argument')
            try:
                result = run('runuser', '-u', 'alarm', '--', '/usr/bin/python3', '-I', '-B',
                             '/interactive.py', '--home', str(home))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                output = error.output or ''
                if isinstance(output, bytes):
                    output = output.decode(errors='replace')
                print('interactive failure ' + home.name + ': ' + output[-8192:], flush=True)
                raise
            report = json.loads(result)
            require(report['status'] == 'TOOLS_INTERACTIVE_PASS' and report['user_files_preserved'] is True,
                    'interactive/controlled-process probe failed')
            print('interactive ' + home.name + ': ' + result.strip(), flush=True)
        preserved()

    def absent():
        inventory = ''.join(sorted(run('pacman', '-Q').splitlines(True)))
        require(inventory == base, 'base inventory not restored')
        for row in rows:
            for relative in row['versions'][0]['payload']:
                require(not (Path('/') / relative).exists(), 'package file remained after removal')
        for home, _ in homes:
            shell(home, 'zsh', '[[ ! -r /usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh ]] || source /usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh; (( ! ${+functions[_zsh_autosuggest_start]} ))')
            shell(home, 'fish', 'if test -r /usr/share/cachy-asahi/fish-bang-bang/opt-in.fish; source /usr/share/cachy-asahi/fish-bang-bang/opt-in.fish; end; not functions --query caa_history_bang')
        preserved()

    for label, index in (('install', 0), ('changed-version-upgrade', 1), ('reinstall', 1)):
        run(*pacman, '-U', *('/inputs/' + row['versions'][index]['archive'] for row in rows))
        installed(index)
        print(label + ': PASS', flush=True)
        if index == 1:
            run(*pacman, '-R', *names)
            absent()
            print('remove: PASS', flush=True)
    print('TOOLS_LIFECYCLE_PASS', flush=True)


if __name__ == '__main__':
    main()
