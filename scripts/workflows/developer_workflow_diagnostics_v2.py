#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Versioned diagnostics for the unchanged, whole-pinned developer workflow."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sys


_PATH = Path(__file__).with_name('developer_workflow.py')
_RAW = _PATH.read_bytes()
if hashlib.sha256(_RAW).hexdigest() != '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba':
    raise ValueError('reviewed original developer workflow pin differs')
_BASE = importlib.util.module_from_spec(importlib.util.spec_from_file_location('_diagnostic_workflow_v1', _PATH))
# A private module namespace keeps frozen consumers on their original v1 class.
exec(compile(_RAW, str(_PATH), 'exec'), _BASE.__dict__)


class _ObservedCore:
    """Forward custody unchanged; observe the effective cap supplied by v1."""
    def __init__(self, core):
        self.core, self.cap_seconds = core, None

    def __getattr__(self, name):
        return getattr(self.core, name)

    def supervise(self, child, **kwargs):
        self.cap_seconds = kwargs['cap']
        return self.core.supervise(child, **kwargs)


class Commands(_BASE.Commands):
    def run(self, *args, **kwargs):
        core, count = self.core, len(self.records)
        observed = _ObservedCore(core)
        self.core = observed
        try:
            return super().run(*args, **kwargs)
        except _BASE.Failure as error:
            # Prelaunch refusals already explain their cause and have no receipt.
            if len(self.records) != count + 1 or self.records[-1]['success']:
                raise
            row = self.records[-1]
            diagnostic = dict(step=row['step'], expected=row['expected'],
                              cap_seconds=observed.cap_seconds,
                              cancelled=list(self.cancelled), launch_error=row.get('launch_error'),
                              supervision=row['supervision'], log=row['log'], log_pin=row['log_pin'])
            try:
                with (self.output / row['log']).open('rb') as stream:
                    raw = stream.read(self.max_output + 1)
                if _BASE.pin(raw) != row['log_pin']:
                    raise ValueError('saved command log differs from receipt')
                tail = raw[-2048:]
                diagnostic.update(output_omitted_bytes=len(raw) - len(tail),
                                  output_tail=tail.decode('utf-8', errors='backslashreplace'))
            except (OSError, ValueError) as context_error:
                diagnostic['log_context_error'] = str(context_error)
            raise _BASE.Failure('command failed or retirement unknown: '
                                + json.dumps(diagnostic, sort_keys=True, ensure_ascii=True)) from error
        finally:
            self.core = core


class _CompileCommands:
    def __init__(self, commands):
        self.commands = commands
        self.output = commands.output

    def run(self, step, argv, cwd, expected):
        compiler = Path(argv[0])
        resolved = compiler.resolve(strict=True)
        raw = self.commands.run(step, argv, cwd, expected)
        if compiler.resolve(strict=True) != resolved:
            raise _BASE.Failure('compiler invocation changed during compilation')
        if expected == 'nonzero' and b'INTENTIONAL_DEVELOPER_WORKFLOW_FAILURE' not in raw:
            raise _BASE.Failure('compile failure lacks deliberate diagnostic')
        return raw


class IncrementalBuild(_BASE.IncrementalBuild):
    def __init__(self, commands):
        super().__init__(_CompileCommands(commands))


# Only the privately loaded journey uses the stricter compile-failure control.
_BASE.IncrementalBuild = IncrementalBuild


def run(output, tool_path=os.defpath, timeout=15, total=180):
    if (not all(type(x) in (int, float) and math.isfinite(x) for x in (timeout, total))
            or not 2 <= timeout <= 60 or not timeout <= total <= 600):
        raise ValueError('require 2 <= command timeout <= 60, timeout <= total <= 600')
    if not tool_path or any(not p or not Path(p).is_absolute() for p in tool_path.split(os.pathsep)):
        raise ValueError('tool search path must contain only nonempty absolute directories')
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('output aliases refused')
    output.mkdir(mode=0o700, exist_ok=False)
    home = output / 'home'
    home.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', architecture=platform.machine(),
                  kernel=platform.release(), page_size=os.sysconf('SC_PAGE_SIZE'),
                  uid=os.getuid(), python=dict(version=sys.version, path=sys.executable,
                                              file=_BASE.file_pin(sys.executable)),
                  evidence_scope='LOCAL_USERSPACE_COMPONENT_ONLY',
                  native_ARM='NOT_QUALIFIED', native_16K='NOT_QUALIFIED', installed='NOT_RUN',
                  physical_M2='NOT_RUN', independent_user='NOT_RUN', package_rebuild='NOT_RUN',
                  performance='NOT_MEASURED', release='NOT_ADMITTED', tools={},
                  sources={'runner': _BASE.pin(_RAW), 'diagnostics_runner': _BASE.file_pin(__file__),
                           'owned_process': _BASE.file_pin(_BASE.ROOT / 'scripts/virtual/owned_process.py'),
                           'fixtures': {n: _BASE.pin(v) for n, v in _BASE.fixture_files().items()},
                           'project_fixtures': {n: _BASE.pin(v) for n, v in _BASE.project_fixture_files().items()}})
    result = output / 'result.json'
    _BASE.save(result, report)
    commands = None
    try:
        commands = Commands(output, home, tool_path, timeout, total)
        tools = {}
        for name in (*_BASE.REQUIRED, *_BASE.OPTIONAL):
            found = shutil.which(name, path=tool_path)
            if found is None:
                report['tools'][name] = dict(
                    status='MISSING_REQUIRED' if name in _BASE.REQUIRED else 'MISSING_OPTIONAL')
                continue
            resolved = str(Path(found).resolve(strict=True))
            # Clang selects its driver mode from the invocation name.
            tools[name] = found if name in ('cc', 'c++') else resolved
            version = commands.run('version-' + name.replace('+', 'p'), [tools[name], '--version'], output)
            if str(Path(tools[name]).resolve(strict=True)) != resolved:
                raise _BASE.Failure('tool invocation changed during version probe: ' + name)
            report['tools'][name] = dict(status='PRESENT', path=found, resolved=resolved,
                                         file=_BASE.file_pin(resolved), version=version.decode(errors='replace').splitlines(),
                                         workflow='VERSION_ONLY_WORKFLOW_NOT_RUN')
        missing = [name for name in _BASE.REQUIRED if name not in tools]
        if missing:
            report.update(status='MISSING_TOOLS', missing_required=missing)
        else:
            report['journey'] = _BASE.journey(commands, tools, output)
            report['base_command_count'] = len(commands.records)
            for name in _BASE.REQUIRED:
                report['tools'][name]['workflow'] = 'EXECUTED'
            report['project_workflows'] = {}
            _BASE.project_workflows(commands, tools, output, report['project_workflows'])
            for backend, project in report['project_workflows'].items():
                if project['status'] == 'PASS_REAL_PROJECT_WORKFLOW':
                    report['tools'][backend]['workflow'] = 'EXECUTED_REAL_PROJECT'
            for name in ('cc', 'c++'):
                tool = report['tools'][name]
                if (str(Path(tools[name]).resolve(strict=True)) != tool['resolved']
                        or _BASE.file_pin(tool['resolved']) != tool['file']):
                    raise _BASE.Failure('compiler binding changed during workflow: ' + name)
            report['status'] = 'PASS_LOCAL_DEVELOPER_COMPONENT'
    except (OSError, ValueError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['commands'] = [] if commands is None else commands.records
        _BASE.save(result, report)
    return report


def print_failure(report):
    details = {k: report[k] for k in ('status', 'error', 'missing_required') if k in report}
    summary = json.dumps(details, ensure_ascii=True)
    if len(summary) >= 16 * 1024:
        details['error'] = details['error'][:1024]
        details['error_truncated'] = True
        summary = json.dumps(details, ensure_ascii=True)
    print(summary, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new private directory, retained in full')
    parser.add_argument('--tool-path', default=os.defpath, help='absolute tool directories, separated by colon')
    parser.add_argument('--command-timeout', type=float, default=15)
    parser.add_argument('--total-timeout', type=float, default=180)
    args = parser.parse_args()
    try:
        report = run(args.output, args.tool_path, args.command_timeout, args.total_timeout)
    except (OSError, ValueError) as error:
        print_failure(dict(status='FAIL', error=str(error)))
        return 2
    print(json.dumps({k: report[k] for k in ('status', 'architecture', 'page_size')}))
    if report['status'] == 'PASS_LOCAL_DEVELOPER_COMPONENT':
        return 0
    print_failure(report)
    return 2


def __getattr__(name):
    return getattr(_BASE, name)


if __name__ == '__main__':
    raise SystemExit(main())
