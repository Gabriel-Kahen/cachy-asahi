#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare selected per-user configurations after an accepted package transaction.

Development entry point: no package, account, boot, service or session operations.
The installed setup helper remains the authority for configuration ownership.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

COMPONENTS = ('fish', 'zsh', 'hyprland')
PROGRAMS = {'fish': '/usr/bin/fish', 'zsh': '/usr/bin/zsh', 'hyprland': '/usr/bin/Hyprland'}
PATH_OPTIONS = ('home', 'template_root', 'config_home', 'zdotdir', 'state_dir')


class Error(Exception):
    pass


def freeze_paths(args):
    """Keep later recovery commands on the same roots even in another shell."""
    selected = argparse.Namespace(**vars(args))
    explicit_home = args.home is not None
    selected.home = args.home or Path.home()
    for option, variable, default in (('config_home', 'XDG_CONFIG_HOME', '.config'),
                                      ('zdotdir', 'ZDOTDIR', '.')):
        value = getattr(args, option)
        inherited = os.environ.get(variable) if not explicit_home else None
        setattr(selected, option, value or (Path(inherited) if inherited else selected.home / default))
    inherited_state = os.environ.get('XDG_STATE_HOME') if not explicit_home else None
    selected.state_dir = args.state_dir or (Path(inherited_state) / 'cachy-asahi/setup'
                                          if inherited_state else selected.home / '.local/state/cachy-asahi/setup')
    selected.template_root = args.template_root or Path('/usr/share/cachy-asahi')
    return selected


def helper_command(args, operation, components=(), apply=False):
    command = [str(args.setup_helper), operation]
    if components:
        command += ['--components', *components]
    for option in PATH_OPTIONS:
        value = getattr(args, option)
        if value is not None:
            command += ['--' + option.replace('_', '-'), str(value)]
    if apply:
        command.append('--apply')
    return command


def invoke(command):
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False, cwd='/',
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8',
                 'PYTHONNOUSERSITE': '1', 'PYTHONSAFEPATH': '1'})
    except OSError:
        raise Error('Setup helper unavailable; install the reviewed setup package or select its executable explicitly.') from None
    try:
        data = json.loads(process.stdout)
    except ValueError:
        raise Error('Setup helper returned no valid JSON report; no configuration contents printed.') from None
    if not isinstance(data, dict) or process.returncode not in (0, 1, 2):
        raise Error('Setup helper failed; inspect it separately with the same path options.')
    return data, process.returncode


def followup(args, operation, components=(), apply=False):
    command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), operation,
               '--setup-helper', str(args.setup_helper)]
    if components:
        command += ['--components', *components]
    for option in PATH_OPTIONS:
        value = getattr(args, option)
        if value is not None:
            command += ['--' + option.replace('_', '-'), str(value)]
    if apply:
        command.append('--apply')
    return shlex.join(command)


def status(args, components, run):
    data, code = run(helper_command(args, 'status', components))
    if (data.get('schema_version') != 1 or data.get('operation') != 'status'
            or data.get('mode') != 'read-only' or data.get('exit_code') != code
            or not isinstance(data.get('state'), dict) or not isinstance(data.get('pending'), dict)
            or data.get('state', {}).get('status') not in ('missing', 'valid', 'unknown')
            or data.get('pending', {}).get('status') not in
            ('none', 'resumable', 'blocked', 'unknown', 'migration-owned')):
        raise Error('Setup status interface is unavailable or incompatible; inspect the helper separately.')
    actions = data.get('actions')
    if (not isinstance(actions, list) or len(actions) != len(components)
            or any(not isinstance(row, dict) for row in actions)
            or {row.get('component') for row in actions} != set(components)):
        raise Error('Setup status omitted selected components; no activation attempted.')
    return data, code


def operation(args, name, components, apply, run):
    data, code = run(helper_command(args, name, components, apply))
    if (data.get('operation') != name or data.get('mode') != ('applied' if apply else 'preview')
            or not isinstance(data.get('actions'), list)):
        raise Error('Setup operation returned an incompatible report; inspect the helper separately.')
    return data, code


def execute(args, run=invoke, executable=os.access):
    args = freeze_paths(args)
    if args.apply and args.operation == 'inspect':
        raise Error('Inspect is read-only; choose activate or recover with --apply.')
    if args.operation == 'activate' and not args.components:
        raise Error('Choose explicit components from inspect before activation.')
    if args.operation != 'activate' and args.components:
        raise Error('Component selection belongs to activate; recovery replays the original transaction.')
    components = tuple(dict.fromkeys(args.components or COMPONENTS))
    observed, code = status(args, components, run)
    pending = observed['pending']['status']
    report = {'schema_version': 1, 'operation': args.operation, 'mode': 'read-only',
              'setup_status': observed, 'components': [], 'next': [],
              'scope': 'user configuration only; first graphical login and hardware NOT RUN'}
    for row in observed['actions']:
        program = PROGRAMS[row['component']]
        template = row.get('template')
        program_available = executable(program, os.X_OK)
        available = template in ('available', 'changed') and program_available
        report['components'].append({'component': row['component'], 'available': available,
                                     'template': template, 'program': program,
                                     'program_available': program_available})
    if pending != 'none':
        report['status'] = 'recovery-required'
        if pending == 'migration-owned':
            report['next'] = ['Use cachy-asahi-config-migrate with the original migration manifest and path options; setup cannot resume a migration-owned transaction.']
            return report, 2
        if pending != 'resumable' or observed['state']['status'] == 'unknown':
            report['next'] = observed.get('guidance', [])
            return report, 1
        report['next'] = [followup(args, 'recover'), followup(args, 'recover', apply=True)]
        if args.operation != 'recover':
            return report, 2
    if args.operation == 'recover':
        if code == 1:
            report['status'] = 'blocked'
            return report, 1
        recovered, recovery_code = operation(args, 'recover', (), args.apply, run)
        report.update(status='recovery-applied' if args.apply else 'recovery-preview',
                      mode=recovered['mode'], setup_result=recovered)
        if args.apply and not recovery_code:
            report['next'] = [followup(args, 'inspect')]
        return report, recovery_code
    if args.operation == 'inspect':
        report['status'] = 'attention-required' if code else 'ready-to-select'
        available = [row['component'] for row in report['components'] if row['available']]
        if available and code != 1:
            report['next'] = [followup(args, 'activate', available)]
        return report, code
    if code == 1 or any(not row['available'] for row in report['components']):
        report.update(status='blocked', next=['Resolve missing programs/templates or unsafe state before activation.'])
        return report, 1
    preview, preview_code = operation(args, 'activate', components, False, run)
    report['mode'] = preview['mode']
    report['setup_result'] = preview
    if preview_code or preview.get('pending_transaction') or preview.get('preserved_conflicts'):
        report['status'] = 'blocked'
        report['next'] = ['Preserve existing configuration; resolve the helper report before retrying.']
        return report, preview_code or 2
    if not args.apply:
        report.update(status='activation-preview', next=[followup(args, 'activate', components, apply=True)])
        return report, 0
    applied, apply_code = operation(args, 'activate', components, True, run)
    report.update(status='activation-applied' if not apply_code else 'attention-required',
                  mode=applied['mode'], setup_result=applied)
    report['next'] = ['Start fresh shells for selected shell components.']
    if 'hyprland' in components:
        report['next'] += ['Validate the copied configuration and select it through the retained, tested base session launcher. Keep the prior session available.']
    report['next'] += applied.get('guidance', [])
    return report, apply_code


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument('operation', nargs='?', default='inspect', choices=('inspect', 'activate', 'recover'))
    value.add_argument('--components', nargs='+', choices=COMPONENTS)
    value.add_argument('--apply', action='store_true', help='explicitly apply the selected user-configuration operation')
    value.add_argument('--setup-helper', type=Path, default=Path('/usr/bin/cachy-asahi-setup'))
    for option in PATH_OPTIONS:
        value.add_argument('--' + option.replace('_', '-'), type=Path)
    return value


def main():
    args = parser().parse_args()
    try:
        if os.geteuid() == 0:
            raise Error('Run first login as the intended non-root user, without sudo.')
        if not args.setup_helper.is_absolute():
            raise Error('Select the setup helper by absolute path.')
        report, code = execute(args)
        print(json.dumps(report, indent=2, sort_keys=True))
        return code
    except (Error, OSError, ValueError, KeyError, TypeError) as error:
        message = str(error) if isinstance(error, Error) else 'Setup report/path is invalid; inspect the helper separately.'
        print(json.dumps({'status': 'error', 'error': message}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
