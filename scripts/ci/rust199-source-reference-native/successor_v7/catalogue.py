#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Derive exact preservation DATA from Root-supplied sealed factual audit inputs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
path = HERE.parent / 'filesystem.py'
if hashlib.sha256(path.read_bytes()).hexdigest() != '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':
    raise ValueError('held filesystem DATA helper differs')
spec = importlib.util.spec_from_file_location('notice_catalogue_fs', path)
fs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fs)
SEAL = 'd66d49a2734e79c6f9d1f5a57fda98ab519d39016483da0f4f88a0f626576fd9'
SCOPE = 'EXACT_SOURCE_FILES_CONTAINING_CATALOGUED_NOTICE_CONTEXTS_ONLY_NO_LEGAL_ACCEPTANCE'


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def derive(directory):
    directory = fs.absolute(directory)
    raw_seal = fs.read(directory / 'seal.json', 65536)[0]
    fs.need(fs.pin(raw_seal)['sha256'] == SEAL, 'exact Root-supplied all108 factual seal required')
    seal = json.loads(raw_seal)
    fs.need(len(seal['files']) == seal['total_files'] == 15 and seal['total_bytes'] == 9701329,
            'finite sealed audit input set')
    rows = {}
    for name, pin in seal['files'].items():
        fs.relative(name)
        raw = fs.read(directory / name, 8 * 1024**2)[0]
        fs.need(fs.pin(raw) == pin, 'whole sealed factual audit input differs: ' + name)
        rows[name] = raw
    fs.need(sum(map(len, rows.values())) == seal['total_bytes'], 'complete sealed audit byte count')
    raw = rows['notice-catalogue.DRAFT.json']
    data = json.loads(raw)
    scan = json.loads(rows['actual108-notice-scan.DATA.json'])
    fs.need(len(data['components']) == scan['actual_components'] == 108
            and scan['all_actual_checksum_file_sets_and_hashes_match'] is True,
            'all108 factual catalogue source-marker correspondence')
    files = {}
    for component in data['components']:
        for context in component['actual_notice_context_spans']:
            name = 'rustc-1.99.0-src/vendor/' + component['component'] + '/' + context['path']
            row = files.setdefault(name, dict(bytes=context['wholefile_bytes'], sha256=context['wholefile_sha256'], contexts=[]))
            fs.need((row['bytes'], row['sha256']) == (context['wholefile_bytes'], context['wholefile_sha256']),
                    'one authentic whole-file pin per source path')
            row['contexts'].append({key: context[key] for key in ('lines', 'text', 'classification')})
    return encode(dict(schema=1, scope=SCOPE, holds_preserved=True, Root_review=None, accepted=None,
        catalogue_basis=dict(**fs.pin(raw), name='notice-catalogue.DRAFT.json', scope=data['scope'],
                             seal_sha256=SEAL, authority='SEALED_FACTUAL_DATA_NOT_LEGAL_ACCEPTANCE'),
        source_archive={key: scan['source_archive'][key] for key in ('bytes', 'sha256')},
        files={name: files[name] for name in sorted(files)},
        components=[{key: component[key] for key in ('component', 'manifest_authors_role_only',
            'declared_license_metadata_only', 'actual_source_named_notices', 'actual_explicit_source_author_attributions',
            'retained_exact_upstream_grant_bodies')} for component in sorted(data['components'], key=lambda c: c['component'])],
        retained_upstream_grant_bodies=data['retained_upstream_grant_bodies'],
        grant_scope='EXACT_RETAINED_AUDIT_BODIES_WITH_EXISTING_COMPONENT_BINDING_LIMITS_NOT_UNIVERSAL_GRANTS'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sealed-inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = derive(args.sealed_inputs)
    # Creation of one new metadata artifact; never execute audit scripts or overwrite inputs.
    with args.output.open('xb') as stream:
        stream.write(raw)
    args.output.chmod(0o644)
    print(json.dumps(fs.pin(raw), sort_keys=True))
