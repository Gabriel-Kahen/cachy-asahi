#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze an already assembled finite source tree; no actor or acquisition."""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import closed as C


def construct(template, output):
    template, output = C.safe(template), C.safe(output)
    C.need(not output.exists() and output.parent.is_dir() and
           not output.is_relative_to(template) and not template.is_relative_to(output),
           'fresh disjoint closed source output required')
    files = C.files(template)
    for name in (*C.WORKFLOWS, C.MANIFEST):
        files.pop(name, None)
    output.mkdir(mode=0o755)
    for name in sorted(files):
        path = output/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(C.read(template/name))
    source_only = dict(actual_source=None, actual_ref=None, actual_run=None,
        native_build='NOT_RUN', installed_delivery='NOT_RUN', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    C.save(output/'source-only.json', source_only)
    data = json.loads(C.read(output/C.DATA/'context.json'))
    association = dict(actual=None, authority='RETAINED_SOURCE_AND_ARCHIVE_DATA_ONLY', files={})
    for name, row in data['files'].items():
        grant = 'MIT'
        package = 'fish-done-fixture'
        if name == 'done.pkg.tar.xz':
            package = 'cachy-asahi-fish-done0.1.0-2; retained native pair38921031485'
        elif name.endswith('.tar.gz'):
            package = name.removesuffix('.tar.gz')
        association['files'][name] = dict(pin=row, source_association=name, license=grant,
                                         package=package, actual_authority=False)
    association['files']['context.json'] = dict(pin=C.pin(C.read(output/C.DATA/'context.json')),
        source_association='reserved-process24-file successor constructor', license='MIT', actual_authority=False)
    C.save(output/C.SLICE/'data-association.json', association)
    manifest = dict(schema_version=1, actual_source=None, actual_ref=None, actual_run=None,
        context_sha256=C.digest(output/C.DATA/'context.json'), retained574='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad',
        infrastructure_source='Setup8 real-shell ready-context-v2 accepted original574/retirement helpers',
        scope='GENERIC_NATIVE_CPU_SWAY_PRIVATE_MAKO_ONLY', files=C.files(output))
    C.save(output/C.MANIFEST, manifest)
    rendered = C.read(output/C.TEMPLATE).decode().replace('@MANIFEST_SHA256@', C.digest(output/C.MANIFEST)).replace(
        '@JOB_SHA256@', manifest['files'][C.SLICE+'/job.py']['sha256'])
    for name in C.WORKFLOWS:
        path = output/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered)
    C.verify(output)
    return dict(status='PASS_CLOSED_PUBLISHABLE_SOURCE', files=len(C.files(output)),
        manifest_sha256=C.digest(output/C.MANIFEST), context_sha256=manifest['context_sha256'],
        native_build='NOT_RUN', installed_delivery='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.template.absolute(), args.output.absolute()), indent=2))
