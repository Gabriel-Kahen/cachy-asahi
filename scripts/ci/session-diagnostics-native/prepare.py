#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Build a small complete source context, including the registered workflow alias."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('diagnostics_constructor_contract', HERE / 'contract.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def row(path):
    C.safe(path)
    C.need(path.is_file() and path.stat().st_size <= 16 * 1024**2, 'bounded ordinary source required')
    return dict(bytes=path.stat().st_size, sha256=C.digest(path))


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def prepare(source, output, recipe, package_source=None):
    for path in (source, output, recipe):
        C.safe(path)
    C.need(not output.exists() and not source.is_relative_to(output) and not recipe.is_relative_to(output),
           'fresh separate output context required')
    C.need(package_source is None or re.fullmatch('[0-9a-f]{40}', package_source), 'published package source must be exact SHA')
    infrastructure = json.loads((HERE / 'infrastructure-pins.json').read_bytes())
    for name, pin in infrastructure.items():
        C.need(row(source / name) == pin, 'original infrastructure drift: ' + name)
    C.verify_package(recipe)
    if package_source:
        for name, pin in C.frozen_files().items():
            raw = subprocess.check_output(['git', '-C', str(source), 'show',
                   package_source + ':packages/tools/' + C.NAMES[0] + '/' + name], timeout=20)
            C.need(dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) == pin, 'published package source differs: ' + name)
    output.mkdir(mode=0o700)
    for name in infrastructure:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    shutil.copytree(recipe, output / 'packages/tools' / C.NAMES[0])
    target = output / C.LANE
    target.mkdir(parents=True)
    for path in sorted(HERE.iterdir()):
        if path.is_file() and path.name not in ('input-policy.json', 'source-pins.json', 'source-manifest.json'):
            shutil.copyfile(path, target / path.name)
    policy = dict(schema_version=1, candidate_source=package_source, actual_source=None, actual_ref=None, actual_run=None,
                  scope='ONE_FROZEN_SESSION_DIAGNOSTICS_PACKAGE', native='NOT_RUN',
                  candidate_files=C.frozen_files(), dispatcher_workflow_id=381664314)
    save(target / 'input-policy.json', policy)
    workflow_text = (HERE / 'workflow.yml.in').read_text()
    C.need(workflow_text.count('@JOB_SHA256@') == 1 and '@MANIFEST_SHA256@' not in workflow_text,
           'acyclic workflow bootstrap must pin entry script only')
    workflow_text = workflow_text.replace('@JOB_SHA256@', row(target / 'job.py')['sha256'])
    # Both final workflow bytes exist before either source binding is computed.
    for name in (C.ACTOR, C.ALIAS):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(workflow_text)
    pins = {p.relative_to(output).as_posix(): row(p)['sha256'] for p in sorted(output.rglob('*')) if p.is_file()}
    save(target / 'source-pins.json', pins)
    manifest = dict(schema_version=1, scope='ONE_FROZEN_SESSION_DIAGNOSTICS_NATIVE_CONTEXT', native_runtime='NOT_RUN',
                    self_excluded=C.LANE + '/source-manifest.json',
                    files={p.relative_to(output).as_posix(): row(p) for p in sorted(output.rglob('*')) if p.is_file()})
    C.need(len(manifest['files']) <= 128, 'finite source closure required')
    save(target / 'source-manifest.json', manifest)
    authorization = dict(files={p.relative_to(output).as_posix(): row(p) for p in sorted(output.rglob('*')) if p.is_file()})
    save(output.parent / (output.name + '-authorization.json'), authorization)
    return dict(status='CLOSED_SOURCE_ONLY', files=len(authorization['files']),
                bytes=sum(r['bytes'] for r in authorization['files'].values()), workflows_identical=True,
                dispatcher_workflow_id=381664314, candidate_source=package_source,
                actual_source=None, actual_ref=None, actual_run=None, native='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'recipe'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--package-source')
    args = parser.parse_args()
    print(json.dumps(prepare(args.source.absolute(), args.output.absolute(), args.recipe.absolute(), args.package_source), sort_keys=True))
