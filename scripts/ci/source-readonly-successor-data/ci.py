#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Focused read-only Source binding DATA checks; no previous suites or actors."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE_PIN = dict(bytes=17681, sha256='9c0cedcdb18e10f9305ab8ed854075efb67a478b9a97f03cb368258866e51488')
BASE_PATH = ROOT / 'scripts/ci/native-successor-data/ci.py'
raw = BASE_PATH.read_bytes()
if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != BASE_PIN:
    raise ValueError('whole immutable DATA preparation/result helper required')
spec = importlib.util.spec_from_file_location('readonly_existing_ci_helpers', BASE_PATH)
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
SUITES = {'llhttp': 7, 'fish': 9, 'libgit2': 8}


def locks():
    fs = B.filesystem()
    return (fs.decode((HERE / 'llhttp-inputs.lock.json').read_bytes()),
            fs.decode((HERE / 'fish-lib-inputs.lock.json').read_bytes()))


def bindings():
    llhttp, other = locks()
    return dict(llhttp=llhttp['suite'], fish=other['fish']['suite'], libgit2=other['libgit2']['suite'])


def prepare(inputs, output):
    """Reuse verified public inputs and pure staging; never run the older suites."""
    prior = B.prepare(inputs, output); fs = B.filesystem(); llhttp, other = locks()
    for group in (llhttp['constructors'], other['fish']['constructor_operands'], other['libgit2']['constructor_operands']):
        for name, expected in group.items(): B.checked_file(ROOT / name, expected, fs)
    for name, row in bindings().items():
        B.checked_file(ROOT / row['path'], row['whole_test_pin'], fs)
        B.native_members((ROOT / row['path']).read_bytes(), row)
        B.need(row['registered_count'] == SUITES[name], 'exact focused author control count')
    family = ROOT / 'scripts/ci/llhttp-reference-native-source'
    B.load(family / 'successor_v4/prepare.py', 'readonly_source85').construct(output / 'llhttp76', output / 'llhttp85')
    source85 = B.identity(fs.snapshot(output / 'llhttp85'), fs)
    B.need(source85 == llhttp['source85_expected'], 'exact genuine reconstructed Source85')
    B.load(family / 'successor_v5/prepare.py', 'readonly_source93').construct(output / 'llhttp85', output / 'llhttp93')
    source93 = B.identity(fs.snapshot(output / 'llhttp93'), fs)
    B.need(source93 == llhttp['source93_expected'], 'exact Source93 tuple from public reference metadata')
    areas = dict(fish48=output / 'fish48', source50=output / 'fish50'); chain = {}
    family = ROOT / 'scripts/ci/fish-config02-native-source'
    for step in other['fish']['construction']:
        label = step['output']
        if label not in areas:
            areas[label] = output / ('fish-' + label)
            B.load(family / ('successor_' + step['version']) / 'prepare.py', 'readonly_fish_' + label).construct(
                areas[step['input']], areas[label])
        chain[label] = B.identity(fs.snapshot(areas[label]), fs)
        B.need(chain[label] == other['fish']['expected_chain'][label], 'exact Fish chain tuple: ' + label)
    B.load(family / 'successor_v8/prepare.py', 'readonly_fish62').construct(areas['source60'], output / 'fish-source62')
    chain['source62'] = B.identity(fs.snapshot(output / 'fish-source62'), fs)
    B.need(chain['source62'] == other['fish']['expected_chain']['source62'], 'exact Fish62 tuple')
    return dict(existing_public_sources=prior['published_sources'], source85=source85, source93=source93,
                source93_reference=llhttp['source93_reference'], source93_fresh_checkout=False, fish=chain,
                recipes=prior['recipes'], constructor_actual_selectors='NULL; unchanged author validators required',
                old_suites_replayed=False, Root_authority=None, native='NOT RUN')


def worker(name, inputs, output, receipt):
    B.limits(); attempts = B.install_fence(); fs = B.filesystem()
    row = bindings()[name]; script = ROOT / row['path']
    B.checked_file(script, row['whole_test_pin'], fs); B.native_members(script.read_bytes(), row)
    lib = fs.decode((ROOT / 'scripts/ci/native-successor-data/libgit2-inputs.lock.json').read_bytes())
    os.environ.update(LLHTTP_V5_PARENT=str(output / 'llhttp85'), LIBGIT2_CONSUMER_ROOT=str(ROOT),
                      LIBGIT2_DATA_RECIPE_ROOT=str(output / 'recipes'),
                      LIBGIT2_DATA_ARCHIVE=str(inputs / lib['upstream_archives']['libgit2']['filename']),
                      LLHTTP_DATA_ARCHIVE=str(inputs / lib['upstream_archives']['llhttp']['filename']))
    temp = output / ('tmp-' + name); temp.mkdir(mode=0o700); original_temp = tempfile.mkdtemp
    def portable_temp(suffix=None, prefix=None, dir=None):
        return original_temp(suffix, prefix, B.temporary_parent(dir, temp))
    tempfile.mkdtemp = portable_temp
    results = []; original_main = unittest.main
    def observed_main(*args, **kwargs):
        kwargs['exit'] = False; value = original_main(*args, **kwargs); results.append(value.result); return value
    unittest.main = observed_main; sys.argv = [str(script)]
    if row['blocked_methods']: sys.argv += ['Controls.' + method for method in row['registered_methods']]
    if name == 'fish':
        os.environ['TMPDIR'] = '/tmp'; sys.argv += ['--base', str(output / 'fish-source60')]
    # Preserve Fish's original write fence: retain the result FD before its hook.
    import runpy
    with receipt.open('xb') as stream:
        runpy.run_path(str(script), run_name='__main__')
        B.need(len(results) == 1, 'one unchanged author CLI result')
        report = dict(status='PASS_FOCUSED_SOURCE_DATA_ONLY', suite=name,
                      **B.require_result(results[0], attempts, SUITES[name]), Root_authority=None, native='NOT RUN')
        stream.write(B.encode(report))


def run(inputs, output):
    fs = B.filesystem(); inputs, output = fs.absolute(inputs), fs.absolute(output)
    B.need(not output.is_relative_to(ROOT) and output != inputs and not output.is_relative_to(inputs)
           and not inputs.is_relative_to(output), 'fresh output outside code and input domains')
    parent = fs.directory(output.parent)
    try:
        info = os.fstat(parent); B.need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'owned output parent')
        os.mkdir(output.name, 0o700, dir_fd=parent)
    finally: os.close(parent)
    report = dict(status='FAIL', tests=0, suites=[], errors=[], blocked_actual92=1, old_suites_replayed=False,
                  Root_authority=None, native='NOT RUN', VM=None, M2=None)
    command = [sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(HERE / 'ci.py')]
    env = dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), LC_ALL='C', TZ='UTC', TMPDIR=str(output))
    try:
        log = output / 'prepare.rawlog'
        with log.open('xb') as stream:
            done = subprocess.run(command + ['--prepare', '--inputs', str(inputs), '--output', str(output)],
                                  env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
        B.need(done.returncode == 0 and log.stat().st_size < 4 * 1024**2, 'DATA preparation failed; see rawlog')
        report['inputs'] = fs.decode((output / 'inputs.DATA.json').read_bytes())
        for name, count in SUITES.items():
            log, receipt = output / (name + '.rawlog'), output / (name + '.DATA.json')
            with log.open('xb') as stream:
                done = subprocess.run(command + ['--worker', name, '--receipt', str(receipt), '--inputs', str(inputs),
                                                '--output', str(output)], env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
            B.need(done.returncode == 0 and log.stat().st_size < 4 * 1024**2, 'focused suite failed: ' + name)
            row = fs.decode(receipt.read_bytes()); B.need(row['tests'] == count and row['skips'] == row['actor_attempts'] == 0, 'exact worker receipt')
            report['suites'].append(row); report['tests'] += count
        B.need(report['tests'] == 24, 'all focused24 controls without skipped cases')
        report['status'] = 'PASS_FOCUSED_SOURCE_DATA_ONLY'
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
        for log in sorted(output.glob('*.rawlog')):
            print(log.name + ':\n' + log.read_bytes()[-8192:].decode('utf-8', 'replace'), file=sys.stderr)
    (output / 'result.DATA.json').write_bytes(B.encode(report)); print(json.dumps(report, sort_keys=True))
    return report['status'] == 'PASS_FOCUSED_SOURCE_DATA_ONLY'


if __name__ == '__main__':
    B.need(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, 'use unoptimized Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', choices=SUITES); parser.add_argument('--receipt', type=Path); parser.add_argument('--prepare', action='store_true')
    args = parser.parse_args()
    if args.prepare:
        B.limits(); attempts = B.install_fence(); result = prepare(args.inputs, args.output)
        B.need(not attempts, 'preparation actor attempted'); (args.output / 'inputs.DATA.json').write_bytes(B.encode(result))
    elif args.worker: worker(args.worker, args.inputs, args.output, args.receipt)
    else: sys.exit(0 if run(args.inputs, args.output) else 1)
