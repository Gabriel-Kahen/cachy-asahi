#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in extracted-package shell journey; only new temporary user state changes.

Consumes four explicitly pinned local archives. No package installation, network,
account, service, graphical session or hardware operation is performed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('first_login_commands', ROOT / 'scripts/integration/onboarding.py')
commands = importlib.util.module_from_spec(spec)
spec.loader.exec_module(commands)
Failure = commands.Failure
PACKAGE_NAMES = {'first_login': 'cachy-asahi-first-login', 'setup': 'cachy-asahi-setup',
                 'fish': 'cachy-asahi-fish-config', 'zsh': 'cachy-asahi-zsh-config'}
MEMBERS = {
    'first_login': ('usr/bin/cachy-asahi-first-login', 'usr/lib/cachy-asahi/first-login/first_login.py',
                    'usr/share/doc/cachy-asahi-first-login/README.md',
                    'usr/share/doc/cachy-asahi-first-login/source-provenance.json',
                    'usr/share/licenses/cachy-asahi-first-login/LICENSE',
                    'usr/share/licenses/cachy-asahi-first-login/NOTICE'),
    'setup': ('usr/bin/cachy-asahi-setup',),
    'fish': ('usr/share/cachy-asahi/fish/config.fish',),
    'zsh': ('usr/share/cachy-asahi/zsh/config.zsh',),
}


def require(value, message):
    if not value:
        raise Failure(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def selection(path, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected or ''), 'Reviewed selection SHA-256 required')
    require(path.stat().st_size <= 16384 and sha(path) == expected, 'Selection size/pin differs')
    value = json.loads(path.read_text())
    require(isinstance(value, dict) and set(value) == set(PACKAGE_NAMES), 'Exactly four package inputs required')
    for name, row in value.items():
        require(isinstance(row, dict) and set(row) == {'path', 'sha256'}, 'Invalid package input fields')
        source = Path(row['path'])
        require(source.is_absolute() and source.is_file() and not source.is_symlink(), 'Regular absolute archive path required')
        require(0 < source.stat().st_size <= 8 * 1024 * 1024, 'Archive size outside finite input budget')
        require(re.fullmatch('[0-9a-f]{64}', row['sha256']) and sha(source) == row['sha256'], 'Archive pin differs')
    return value


class Runner(commands.Commands):
    """Retain the existing bounded process/PTY implementation and actual exit codes."""
    def run(self, label, argv, expected_code=0, **kwargs):
        try:
            result = super().run(label, [str(value) for value in argv], **kwargs)
        except Failure:
            record = self.records[-1]
            if expected_code == 0 or record['error'] is not None or record['returncode'] != expected_code:
                raise
            result = (self.out / record['stdout_file']).read_text(errors='replace')
        record = self.records[-1]
        record['expected_returncode'] = expected_code
        record['success'] = record['error'] is None and record['returncode'] == expected_code
        commands.save(self.out / (self.phase + '-commands.json'), self.records)
        require(record['success'], 'Unexpected command exit: ' + label)
        return result


def extract(inputs, prefix, runner):
    retained = {}
    for name, row in inputs.items():
        archive = Path(row['path'])
        listing = runner.run(name + '-list', ['/usr/bin/bsdtar', '-tf', archive]).splitlines()
        require(len(listing) <= 100 and len(listing) == len(set(listing)), 'Archive member count/duplicates refused')
        metadata = runner.run(name + '-metadata', ['/usr/bin/bsdtar', '-xOf', archive, '.PKGINFO'])
        require('pkgname = ' + PACKAGE_NAMES[name] + '\n' in metadata and 'arch = any\n' in metadata,
                'Selected archive package identity/architecture differs')
        retained[name] = {'archive_sha256': row['sha256'], 'members': {}}
        for index, member in enumerate(MEMBERS[name]):
            require(member in listing, 'Selected runtime payload missing: ' + member)
            runner.run(f'{name}-member{index}', ['/usr/bin/bsdtar', '-xOf', archive, member])
            record = runner.records[-1]
            raw = (runner.out / record['stdout_file']).read_bytes()
            require(0 < len(raw) <= 1024 * 1024, 'Runtime member outside finite payload budget')
            target = prefix / member
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o755 if member.startswith('usr/bin/') else 0o644)
            retained[name]['members'][member] = hashlib.sha256(raw).hexdigest()
        require(sha(archive) == row['sha256'], 'Archive changed during retained-member reads')
    return retained


def snapshot(home):
    return {str(path.relative_to(home)): (sha(path), stat.S_IMODE(path.stat().st_mode))
            for path in home.rglob('*') if path.is_file()}


def journey(prefix, home, runner):
    first = prefix / 'usr/bin/cachy-asahi-first-login'
    setup = prefix / 'usr/bin/cachy-asahi-setup'
    templates = prefix / 'usr/share/cachy-asahi'
    roots = ['--setup-helper', str(setup), '--home', str(home), '--template-root', str(templates)]
    setup_roots = ['--home', str(home), '--template-root', str(templates)]
    def first_call(label, operation, *options, code=0):
        return json.loads(runner.run(label, [first, operation, *options, *roots], expected_code=code))
    def setup_call(label, operation, apply=False):
        return json.loads(runner.run(label, [setup, operation, '--components', 'fish', 'zsh', *setup_roots,
                                             *(['--apply'] if apply else [])]))
    def shells(label, active, edited=False):
        if active:
            fish = "functions -q caa_ll caa_mcd; or exit 21; caa_ll; caa_mcd '" + label + " space'; or exit 22; test (basename $PWD) = '" + label + " space'; or exit 23; printf '%s\\n' CAA_FISH_ACTIVE"
            zsh = '[[ -o interactive && $_CACHY_ASAHI_ZSH_LOADED == 1 && ${+_comps} == 1 && -n $_comps[cd] ]] || exit 24; print -r -- CAA_ZSH_ACTIVE'
        else:
            fish = "functions -q caa_ll; and exit 25; functions -q caa_mcd; and exit 26; printf '%s\\n' CAA_FISH_REMOVED"
            zsh = '(( ${+_CACHY_ASAHI_ZSH_LOADED} == 0 )) || exit 27; print -r -- CAA_ZSH_REMOVED'
        if edited:
            fish += "; test \"$CAA_USER_KEPT\" = yes; or exit 28"
            zsh += '; [[ $CAA_USER_KEPT == yes ]] || exit 29'
        runner.run(label + '-fish', ['/usr/bin/fish', '--private', '--interactive', '--command', fish],
                   terminal=True, expected='CAA_FISH_ACTIVE' if active else 'CAA_FISH_REMOVED')
        runner.run(label + '-zsh', ['/usr/bin/zsh', '-d', '-i', '-c', zsh],
                   terminal=True, expected='CAA_ZSH_ACTIVE' if active else 'CAA_ZSH_REMOVED')
    runner.run('fish-version', ['/usr/bin/fish', '--version'])
    runner.run('zsh-version', ['/usr/bin/zsh', '--version'])
    before = snapshot(home)
    observed = first_call('inspect', 'inspect')
    available = {row['component']: row['available'] for row in observed['components']}
    require(available['fish'] and available['zsh'], 'Actual selected programs/templates unavailable')
    require(snapshot(home) == before, 'Inspect modified fresh home')
    first_call('preview', 'activate', '--components', 'fish', 'zsh')
    require(snapshot(home) == before, 'Preview modified fresh home')
    first_call('apply', 'activate', '--components', 'fish', 'zsh', '--apply')
    (runner.cwd / 'journey-sentinel').write_text('owned workspace\n')
    shells('first', True)
    fish_config, zsh_config = home / '.config/fish/config.fish', home / '.zshrc'
    for path, edit in ((fish_config, '\nset -g CAA_USER_KEPT yes\n'),
                       (zsh_config, '\ntypeset -g CAA_USER_KEPT=yes\n')):
        with path.open('a') as output:
            output.write(edit)
    edited = {str(path): path.read_bytes() for path in (fish_config, zsh_config)}
    first_call('repeat-after-edit', 'activate', '--components', 'fish', 'zsh', '--apply')
    require(all(Path(path).read_bytes() == data for path, data in edited.items()), 'Repeat changed user edits')
    shells('edited', True, True)
    unchanged = snapshot(home)
    setup_call('deactivate-preview', 'remove')
    require(snapshot(home) == unchanged, 'Removal preview modified home')
    setup_call('deactivate', 'remove', True)
    require(all(b'CAA_USER_KEPT' in path.read_bytes() for path in (fish_config, zsh_config)), 'Removal lost edits')
    shells('removed', False, True)
    # Stop the actual delivered Setup8 process immediately after its first durable
    # Fish write. This deterministic injected crash leaves the real journal intact.
    crash = """import os,runpy,sys
Setup=runpy.run_path(sys.argv[1],run_name='setup_engine')['Setup']
engine=Setup(sys.argv[2],sys.argv[3]); atomic=engine.fs.atomic
def stop(path,*args,**kwargs):
    result=atomic(path,*args,**kwargs)
    if path==engine.targets['fish']: os._exit(75)
    return result
engine.fs.atomic=stop
engine.run('activate',('fish','zsh'),True)
raise SystemExit(76)
"""
    runner.run('interrupted-setup', ['/usr/bin/python3', '-I', '-c', crash, setup, home, templates], expected_code=75)
    pending = snapshot(home)
    first_call('pending-inspect', 'inspect', code=2)
    first_call('pending-new-selection-refused', 'activate', '--components', 'fish', '--apply', code=2)
    first_call('recover-preview', 'recover', code=2)
    require(snapshot(home) == pending, 'Pending inspect/refusal/recovery preview changed home')
    recovered = first_call('recover', 'recover', '--apply')
    require(recovered['setup_result']['recovered_transaction'], 'Expected journal was not recovered')
    require(not (home / '.local/state/cachy-asahi/setup/journal.json').exists(), 'Recovery journal remains')
    shells('recovered', True, True)
    setup_call('final-deactivate', 'remove', True)
    shells('final', False, True)
    return {'fresh_inspect_preview_read_only': True, 'actual_shell_startups': 10,
            'repeat_and_deactivation_preserve_user_edits': True,
            'recovery': 'actual delivered Setup8 process exits75 after first durable Fish write; real journal resumes',
            'final_user_config_sha256': {str(path.relative_to(home)): sha(path) for path in (fish_config, zsh_config)}}


def execute(inputs, output):
    require(os.geteuid() != 0, 'Run as an ordinary user without sudo')
    for program in ('/usr/bin/fish', '/usr/bin/zsh', '/usr/bin/bsdtar', '/usr/bin/python3'):
        require(Path(program).is_file() and os.access(program, os.X_OK), 'Required actual program unavailable: ' + program)
    output.mkdir(mode=0o700, exist_ok=False)
    report = {'status': 'FAIL', 'scope': 'extracted unsigned host packages and actual shell software only',
              'native_arm': 'NOT RUN', 'hardware': 'NOT RUN', 'graphical_login': 'NOT RUN', 'package_installation': 'NOT RUN',
              'host_architecture': platform.machine(), 'host_page_size': os.sysconf('SC_PAGE_SIZE'),
              'entry_sha256': sha(__file__), 'command_runner_sha256': sha(commands.__file__),
              'program_sha256': {name: sha('/usr/bin/' + name) for name in ('fish', 'zsh', 'python3', 'bsdtar')}}
    try:
        with tempfile.TemporaryDirectory(prefix='private-journey-', dir=output) as temporary:
            scratch = Path(temporary)
            home, workspace, prefix = scratch / 'home', scratch / 'workspace', scratch / 'prefix'
            for path in (home, workspace, prefix):
                path.mkdir(mode=0o700)
            env = {'HOME': str(home), 'XDG_CONFIG_HOME': str(home / '.config'),
                   'XDG_STATE_HOME': str(home / '.local/state'), 'XDG_CACHE_HOME': str(home / '.cache'),
                   'XDG_DATA_HOME': str(home / '.local/share'), 'ZDOTDIR': str(home),
                   'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TERM': 'dumb'}
            runner = Runner(output, env, workspace, timeout=20, phase='first-login')
            report['packages'] = extract(inputs, prefix, runner)
            report['journey'] = journey(prefix, home, runner)
            report['commands'] = len(runner.records)
        report.update(status='PASS', temporary_state_removed=True)
    except Exception as error:
        report['error'] = str(error) if isinstance(error, Failure) else type(error).__name__
        raise
    finally:
        commands.save(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run-temporary-journey', action='store_true', help='explicitly run selected extracted payloads in private temporary user state')
    args = parser.parse_args()
    try:
        require(args.run_temporary_journey, 'Execution requires --run-temporary-journey')
        require(args.output.is_absolute(), 'New absolute evidence directory required')
        report = execute(selection(args.inputs, args.inputs_sha256), args.output)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
