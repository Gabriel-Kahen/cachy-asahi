#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Debug original C/C++ children with existing GDB; finite local evidence only."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/workflows/fixtures/debugger'
WORKFLOW_PIN = '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba'
FLAGS = ('-Wall', '-Wextra', '-Werror', '-g', '-O0', '-fno-omit-frame-pointer')
NAMES = ('hello.c', 'hello.cpp', 'LICENSE')
REQUIRED = ('cc', 'c++', 'gdb')


def load_workflow():
    path = ROOT / 'scripts/workflows/developer_workflow.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != WORKFLOW_PIN:
        raise ValueError('reviewed developer workflow helper pin differs')
    spec = importlib.util.spec_from_file_location('_debugger_workflow', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


W = load_workflow()
Failure, pin, file_pin, save = W.Failure, W.pin, W.file_pin, W.save


def ordinary_pin(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise Failure('ordinary file required: ' + str(path))
    return file_pin(path)


def fixture_files():
    files = {}
    for name in NAMES:
        path = FIXTURES / name
        if path.lstat().st_size > 128 * 1024:
            raise Failure('fixture exceeds source cap')
        ordinary_pin(path)
        files[name] = path.read_bytes()
    return files


def gdb_quote(path):
    value = str(path)
    if any(c in value for c in ('\n', '\r', '\0')):
        raise ValueError('GDB paths must not contain newline, CR or NUL')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def debugger_script(source, binary):
    lines = source.read_text().splitlines()
    stops = [n for n, line in enumerate(lines, 1) if '/* WORKFLOW_BREAKPOINT */' in line]
    if len(stops) != 1:
        raise Failure('exactly one fixed source breakpoint required')
    return ('set pagination off\nset confirm off\nset startup-with-shell off\n'
            'set disable-randomization off\nset print frame-arguments all\n'
            'file ' + gdb_quote(binary) + '\n'
            'break ' + gdb_quote(source) + ':' + str(stops[0]) + '\n'
            'run\nprintf "DEBUGGER_LOCAL:%d\\n", known_local\n'
            'backtrace 4\ncontinue\nprintf "DEBUGGER_EXIT:%d\\n", $_exitcode\n'
            'echo DEBUGGER_DONE\\n\n').encode(), stops[0]


def validate_debugger(raw, source, line, expected, version):
    text = raw.decode('utf-8', errors='replace')
    location = re.escape(str(source)) + ':' + str(line)
    # Count and order assertions: an exit-0 GDB invocation alone is insufficient.
    patterns = [r'(?m)^Breakpoint 1, workflow_step \(seed=10\) at ' + location + r'\r?$',
                r'(?m)^DEBUGGER_LOCAL:' + str(expected) + r'\r?$',
                r'(?m)^#0\s+workflow_step \(seed=10\) at ' + location + r'\r?$',
                r'(?m)^#1\s+(?:0x[0-9a-f]+ in )?main \(\) at ' + re.escape(str(source)) + r':\d+\r?$',
                r'(?m)^Debugger version ' + version + ': ' + str(expected) + r'\r?$',
                r'(?m)^\[Inferior \d+ \(process \d+\) exited normally\]\r?$',
                r'(?m)^DEBUGGER_EXIT:0\r?$', r'(?m)^DEBUGGER_DONE\r?$']
    end = 0
    for pattern in patterns:
        matches = list(re.finditer(pattern, text))
        if len(matches) != 1 or matches[0].start() < end:
            raise Failure('missing, duplicate or out-of-order debugger observation: ' + pattern)
        end = matches[0].end()
    return dict(source_breakpoint=dict(path=str(source), line=line), known_local=expected,
                stack=['workflow_step(seed=10)', 'main()'], continued=True, normal_exit=0)


class Project:
    def __init__(self, language, commands, tools, output):
        if language not in ('c', 'cpp'):
            raise ValueError('only original C and C++ fixtures are supported')
        self.language, self.commands, self.tools = language, commands, tools
        self.compiler = tools['cc' if language == 'c' else 'c++']
        self.root = output / (language + '-project'); self.root.mkdir(mode=0o700)
        files = fixture_files()
        self.source = self.root / ('hello.' + language)
        self.source.write_bytes(files[self.source.name])
        (self.root / 'LICENSE').write_bytes(files['LICENSE'])
        self.binary = self.root / 'hello'
        self.verified = None
        self.value = dict(status='RUNNING', language=language, records=[])

    def inputs(self):
        return dict(source=ordinary_pin(self.source), compiler=file_pin(self.compiler),
                    debugger=file_pin(self.tools['gdb']), flags=list(FLAGS))

    def products(self):
        return ordinary_pin(self.binary) if self.binary.exists() else None

    def record(self, step, outcome, **extra):
        snapshot = 'source-%s-%02d.%s' % (self.language, len(self.value['records']), self.language)
        raw = self.source.read_bytes()
        (self.commands.output / snapshot).write_bytes(raw)
        self.value['records'].append(dict(step=step, outcome=outcome, inputs=self.inputs(),
                                         binary=self.products(), source_snapshot=snapshot,
                                         source_snapshot_pin=pin(raw), **extra))
        save(self.commands.output / ('project-' + self.language + '.json'), self.value)

    def build(self, step, expected=0):
        self.verified = None
        inputs, before = self.inputs(), self.products()
        try:
            # Successful rebuilds must create a new product, never inherit an old
            # executable from a no-op compiler. The deliberate failure retains
            # its stale product so refusal is observable against real bytes.
            if expected == 0:
                self.binary.unlink(missing_ok=True)
            raw = self.commands.run(self.language + '-' + step,
                                    [self.compiler, *FLAGS, str(self.source), '-o', str(self.binary)],
                                    self.root, expected)
            if inputs != self.inputs():
                raise Failure('build inputs changed during compilation')
            if expected == 'nonzero':
                if b'INTENTIONAL_DEBUGGER_COMPILE_FAILURE' not in raw:
                    raise Failure('nonzero compile lacks deliberate failure diagnostic')
                self.record(step, 'EXPECTED_COMPILE_FAILURE', previous_binary=before)
                return
            binary = self.products()
            if binary is None:
                raise Failure('compiler returned success without a binary')
            self.verified = dict(inputs=inputs, binary=binary)
            self.record(step, 'BUILT', previous_binary=before)
        except BaseException:
            self.verified = None
            raise

    def require_usable(self):
        if self.verified is None or self.verified != dict(inputs=self.inputs(), binary=self.products()):
            self.verified = None
            raise Failure('unbuilt, changed or failed source/tool/binary; debugger launch refused')

    def refuse_stale(self, step):
        before = len(self.commands.records)
        try:
            self.debug(step, 17, 'one')
        except Failure:
            if len(self.commands.records) != before:
                raise Failure('stale debugger refusal launched a command')
            self.record(step, 'STALE_DEBUGGER_REFUSED', attempted_launches=0)
        else:
            raise Failure('stale binary was eligible for debugging')

    def debug(self, step, expected, version):
        self.require_usable()
        receipt, self.verified = self.verified, None
        raw_script, line = debugger_script(self.source, self.binary)
        script = self.commands.output / (self.language + '-' + step + '.gdb')
        script.write_bytes(raw_script)
        raw = self.commands.run(self.language + '-' + step,
                                [self.tools['gdb'], '-nx', '-nh', '--quiet', '--batch',
                                 '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                                 '-x', str(script)], self.root)
        observed = validate_debugger(raw, self.source, line, expected, version)
        if (receipt != dict(inputs=self.inputs(), binary=self.products())
                or ordinary_pin(script) != pin(raw_script)):
            raise Failure('debug inputs, binary or command file changed during execution')
        self.record(step, 'PASS_SOURCE_LOCAL_STACK_CONTINUE_EXIT', observed=observed,
                    debugger_commands=dict(path=str(script), file=pin(raw_script)), binding=receipt)
        self.verified = receipt

    def journey(self):
        self.build('initial-build'); first = dict(inputs=self.inputs(), binary=self.products())
        self.debug('initial-debug', 17, 'one')
        initial = self.source.read_bytes()
        edited = initial.replace(b'seed + 7', b'seed + 11').replace(b'version one', b'version two').replace(b'== 17', b'== 21')
        if initial == edited:
            raise Failure('edit failed to change fixture')
        self.source.write_bytes(edited)
        self.refuse_stale('edited-before-build')
        self.build('edited-build'); changed = dict(inputs=self.inputs(), binary=self.products())
        if first['inputs']['source'] == changed['inputs']['source'] or first['binary'] == changed['binary']:
            raise Failure('source edit did not change both source and binary identity')
        self.debug('edited-debug', 21, 'two')
        self.source.write_bytes(edited + b'\n#error INTENTIONAL_DEBUGGER_COMPILE_FAILURE\n')
        self.build('broken-build', 'nonzero')
        self.refuse_stale('compile-failure-refusal')
        self.source.write_bytes(edited)
        self.refuse_stale('restored-before-rebuild')
        self.build('recovery-build'); self.debug('recovery-debug', 21, 'two')
        self.value.update(status='PASS_REAL_GDB_WORKFLOW', initial=first, edited=changed,
                          compile_failure='REAL_NONZERO_STALE_DEBUGGER_REFUSED', recovery='PASS_REBUILT')
        save(self.commands.output / ('project-' + self.language + '.json'), self.value)


def run(output, tool_path=os.defpath, timeout=20, total=180):
    if (not all(type(n) in (int, float) and math.isfinite(n) for n in (timeout, total))
            or not 2 <= timeout <= 60 or not timeout <= total <= 600):
        raise ValueError('require 2 <= command timeout <= 60 and timeout <= total <= 600')
    if not tool_path or any(not p or not Path(p).is_absolute() for p in tool_path.split(os.pathsep)):
        raise ValueError('absolute nonempty tool directories required')
    output = Path(output).absolute()
    gdb_quote(output)
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('output aliases refused')
    output.mkdir(mode=0o700, exist_ok=False)
    home = output / 'home'; home.mkdir(mode=0o700)
    temporary = output / 'tmp'; temporary.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', architecture=platform.machine(), kernel=platform.release(),
                  page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(),
                  python=dict(path=sys.executable, version=sys.version, file=file_pin(sys.executable)),
                  scope='LOCAL_TRUSTED_DEBUGGER_FIXTURE', tools={}, projects={},
                  native_ARM='NOT_RUN', native_16K='NOT_RUN', Asahi_installed='NOT_RUN',
                  physical_M2='NOT_RUN', independent_user='NOT_RUN', performance='NOT_MEASURED',
                  release='NOT_ADMITTED', sources=dict(runner=file_pin(__file__), helper=file_pin(W.__file__),
                  owned_process=file_pin(ROOT / 'scripts/virtual/owned_process.py'),
                  fixtures={name: pin(raw) for name, raw in fixture_files().items()}))
    save(output / 'result.json', report)
    commands = None
    try:
        commands = W.Commands(output, home, tool_path, timeout, total)
        commands.env.update(TMPDIR=str(temporary), DEBUGINFOD_URLS='')
        tools = {}
        for name in REQUIRED:
            found = shutil.which(name, path=tool_path)
            if found is None:
                report['tools'][name] = dict(status='MISSING', workflow='NOT_RUN')
                continue
            resolved = str(Path(found).resolve()); tools[name] = resolved
            raw = commands.run('version-' + name.replace('+', 'p'), [resolved, '--version'], output)
            report['tools'][name] = dict(status='PRESENT', path=found, resolved=resolved,
                                        file=file_pin(resolved), version=raw.decode(errors='replace').splitlines())
        missing = sorted(set(REQUIRED) - tools.keys())
        if missing:
            report.update(status='MISSING_TOOLS', missing=missing,
                          projects={n: dict(status='NOT_RUN', missing=missing) for n in ('c', 'cpp')})
        else:
            for language in ('c', 'cpp'):
                project = Project(language, commands, tools, output)
                report['projects'][language] = project.value
                try:
                    project.journey()
                except BaseException:
                    project.value['status'] = 'FAIL'
                    save(output / ('project-' + language + '.json'), project.value)
                    raise
            report['status'] = 'PASS_LOCAL_DEBUGGER_COMPONENT'
    except (OSError, ValueError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['commands'] = [] if commands is None else commands.records
        save(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tool-path', default=os.defpath)
    parser.add_argument('--command-timeout', type=float, default=20)
    parser.add_argument('--total-timeout', type=float, default=180)
    args = parser.parse_args()
    try:
        report = run(args.output, args.tool_path, args.command_timeout, args.total_timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(dict(status=report['status'], projects={n: r['status'] for n, r in report['projects'].items()},
                         missing=report.get('missing', []), error=report.get('error'))))
    return 0 if report['status'] == 'PASS_LOCAL_DEBUGGER_COMPONENT' else 2


if __name__ == '__main__':
    raise SystemExit(main())
