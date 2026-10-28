#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run existing builders with the fixed, build-only audio recipe/payload scope."""
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'scripts/checks'))
import package_checks as checks

RECIPES_SHA = '1b1b966ab8e537f98f3e962555385f6764bb5a64511198757c762a5f9a7704c6'
POLICY = Path(__file__).with_name('recipes.json')
if checks.digest(POLICY) != RECIPES_SHA: raise ValueError('fixed audio recipes changed')
RECIPES = json.loads(POLICY.read_text())


def need(value, message):
    if not value: raise ValueError(message)


def recipe(path):
    report = checks.recipe(path)
    row = next((r for r in RECIPES if r['input_sha256'] == report['input_sha256']), None)
    need(row is not None and report['metadata'] == row['metadata'], 'fixed reviewed audio recipe required')
    allowed = {'protected platform package name: speakersafetyd'} if row['name'] == 'speakersafetyd' else set()
    report['errors'] = [e for e in report['errors'] if e not in allowed]
    report['status'] = 'fail' if report['errors'] else 'static-pass'
    return report


def package(path):
    report = checks.package(path)
    metadata = report['metadata']['.PKGINFO']
    row = next((r for r in RECIPES if metadata.get('pkgname') == [r['name']]), None)
    need(row is not None, 'fixed audio package required')
    need(not existing_build.bind_artifact(row['metadata'], report, row['input_sha256']['PKGBUILD']), 'audio metadata/source binding differs')
    members = report['members']
    files = {n:r for n,r in members.items() if r['type'] != '5' and n not in {'.PKGINFO','.BUILDINFO','.MTREE'}}
    need(set(files) == set(row['payload']), 'unexpected audio payload')
    ancestors = {str(p) for n in files for p in Path(n).parents if str(p) != '.'}
    need(all(n in ancestors for n,r in members.items() if r['type'] == '5'), 'unexpected audio directory')
    for name, expected in row['payload'].items():
        actual = files[name]
        need(actual['type'] == '0' and actual['mode'] == expected['mode'], 'audio payload type/mode differs')
        if expected['ELF']:
            need(name in report['elf'] and not report['elf'][name]['errors'], 'AArch64/structural ELF check failed')
        else:
            need(actual['sha256'] == expected['sha256'], 'reviewed audio data differs')
    allowed = set()
    if row['name'] == 'speakersafetyd':
        allowed = {'protected platform package name: speakersafetyd'}
        allowed |= {'protected platform path: '+n for n in set(files)|ancestors}
    report['errors'] = [e for e in report['errors'] if e not in allowed]
    report['status'] = 'fail' if report['errors'] else 'artifact-static-pass'
    return report


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


existing_build = module('audio_existing_build', 'scripts/build/build.py')

def main():
    need(len(sys.argv) > 1 and sys.argv[1] in ('build','compare'), 'build or compare required')
    operation = sys.argv.pop(1)
    selected = existing_build if operation == 'build' else module('audio_existing_compare','scripts/build/compare.py')
    selected.package = package
    if operation == 'build': selected.recipe = recipe
    return selected.main()


if __name__ == '__main__': sys.exit(main())
