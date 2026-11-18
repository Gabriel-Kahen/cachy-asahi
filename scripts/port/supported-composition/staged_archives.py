#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join a held supported-Asahi proposal to exact authenticated Overlay583 archive DATA."""

import argparse
import base64
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('staged_archives_composition', HERE / 'compose.py')
T = load('staged_archives_overlay583', C.ROOT / 'scripts/install/overlay583_trial/trial.py')
INTAKE = load('staged_archives_intake', C.ROOT / 'scripts/platform/authenticate_missing.py')


def staged_records(staging, receipt_ref, reader):
    packet = T.choose(staging, selected_lock=T.PINS)
    raw = reader.read(receipt_ref)
    packet = T.admit(packet, raw, T.pin(raw))
    records = {}
    for name, identity in packet['packages'].items():
        version, repo = identity['version'], identity['repo']
        prefix = T.REPOS[repo] + '/' + name + '-' + version + '-'
        choices = [(arch, prefix + arch + '.pkg.tar.xz') for arch in ('aarch64', 'any')
                   if prefix + arch + '.pkg.tar.xz' in packet['files']]
        C.need(len(choices) == 1, 'ambiguous exact staged archive identity: ' + name)
        arch, leaf = choices[0]
        records[name] = {
            'version': version, 'arch': arch, 'filename': Path(leaf).name, 'staged_repository': repo,
            'archive': {'path': str(staging / leaf), **packet['files'][leaf]},
            'signature': {'path': str(staging / (leaf + '.sig')), **packet['files'][leaf + '.sig']},
            'recorded_signer': packet['signers'][2 if repo == T.BASE_REPO else 0],
            'signature_scope': 'historical-ALARM-package' if repo == T.BASE_REPO else 'project-TEST-overlay',
        }
    return records, packet['target']


def signature_relation(metadata, stage):
    field = metadata.get('PGPSIG')
    if field is None:
        return 'candidate-catalog-signature-missing'
    C.need(isinstance(field, list) and len(field) == 1 and isinstance(field[0], str)
           and 0 < len(field[0]) <= 128 * 1024, 'invalid candidate embedded signature')
    blob = base64.b64decode(field[0], validate=True)
    expected = {key: stage['signature'][key] for key in ('bytes', 'sha256')}
    if T.pin(blob) == expected:
        return 'exact-candidate-catalog-signature'
    return 'different-candidate-catalog-signature'


def intake_operand(repo, metadata, *, eligible, protected_change):
    if eligible:
        return 'available-from-staging', None
    if protected_change:
        return 'protected-version-conflict', None
    if repo == 'observed-Asahi-base':
        return 'observed-base-needs-exact-archive-binding', None
    if repo == 'project':
        return 'project-candidate-needs-separate-archive-source', None
    if repo not in ('core', 'extra', 'asahi-alarm'):
        return 'no-existing-intake-route', None
    try:
        spec = INTAKE.archive_spec(metadata, repo, 'missing-exact-tentative-candidate')
    except ValueError:
        return 'catalog-operand-refused-by-existing-intake', None
    category = ('catalog-archive-and-signature-pinned' if spec['signature_pin'] is not None
                else 'catalog-archive-pinned-signature-needs-authentication')
    return category, spec


def mapping(rows, expected_count, protected, staged):
    C.need(isinstance(rows, list) and len(rows) == expected_count and 0 < len(rows) <= 4096,
           'exact candidate inventory count required')
    mapped, seen = [], {}
    intake_counts = {}
    intake_specs = []
    for row in rows:
        identity = C.pin({key: row[key] for key in ('name', 'version', 'repo')})
        name, version = identity['name'], identity['version']
        metadata = row['metadata']
        C.need(name not in seen and metadata['NAME'] == [name] and metadata['VERSION'] == [version]
               and metadata['ARCH'] in (['aarch64'], ['any']), 'candidate identity or architecture differs')
        seen[name] = version
        stage = staged.get(name)
        protected_version = protected.get(name)
        changes_protected = protected_version is not None and protected_version != version
        eligible = False
        signature = None
        if stage is None:
            relation = 'absent-from-staging'
        elif stage['version'] != version:
            relation = 'different-staged-version'
        elif not all(key in metadata for key in ('FILENAME', 'CSIZE', 'SHA256SUM')):
            relation = 'candidate-archive-pin-missing'
        elif (metadata['ARCH'], metadata['FILENAME'], metadata['CSIZE'], metadata['SHA256SUM']) != (
                [stage['arch']], [stage['filename']], [str(stage['archive']['bytes'])], [stage['archive']['sha256']]):
            relation = 'different-archive-identity'
        else:
            relation = 'exact-staged-archive'
            signature = signature_relation(metadata, stage)
            eligible = (not changes_protected and signature == 'exact-candidate-catalog-signature'
                        and stage['signature_scope'] == 'historical-ALARM-package')
        category, spec = intake_operand(identity['repo'], metadata, eligible=eligible,
                                       protected_change=changes_protected)
        intake_counts.setdefault(identity['repo'], Counter())[category] += 1
        if spec is not None:
            intake_specs.append(spec)
        mapped.append({**identity, 'expected_protected_version': protected_version,
                       'changes_protected_version': changes_protected, 'archive_relation': relation,
                       'signature_relation': signature, 'staged': stage,
                       'may_supply_candidate_archive_bytes': eligible, 'intake_category': category})
    violations = [{'name': name, 'expected': version, 'candidate': seen.get(name)}
                  for name, version in sorted(protected.items()) if seen.get(name) != version]
    return {'package_count': len(rows), 'archive_relations': dict(Counter(row['archive_relation'] for row in mapped)),
            'eligible_archive_count': sum(row['may_supply_candidate_archive_bytes'] for row in mapped),
            'protected_conflicts': violations, 'packages': mapped, 'intake_counts_by_repository': intake_counts,
            'missing_catalog_intake_operands': intake_specs}


def evaluate(contract_ref, report_ref, staging, receipt_ref):
    reader = C.Reader()
    contract, report = (reader.document(ref) for ref in (contract_ref, report_ref))
    C.need(contract['kind'] == 'supported-Asahi-composition-inputs-v1'
           and report['kind'] == 'supported-Asahi-composition-DATA-proposal'
           and report['schema_version'] == contract['schema_version'] == 1
           and report['workflow'] == contract['workflow']
           and report['transaction_accepted'] is False and report['full_supported_system_accepted'] is False
           and all(ref in report['input_references'] for ref in (
               contract_ref, contract['image_inventory'], contract['protected_tuple'])),
           'exact unaccepted Asahi composition and original inputs required')
    _, original_count, protected = C.base_policy(reader, contract)
    expected = {row['name']: row['expected'] for row in report['protected']}
    C.need(len(expected) == len(report['protected']) and expected == protected
           and report['original_protected_count'] == original_count,
           'composition omitted or substituted an original protected tuple')
    staged, target = staged_records(staging, receipt_ref, reader)
    original = mapping(report['proposed_final_inventory'], report['final_package_count'], protected, staged)
    result = {
        'schema_version': 1, 'kind': 'supported-Asahi-staged-archive-mapping-DATA',
        'status': 'HOLD', 'transaction_accepted': False, 'full_supported_system_accepted': False,
        'fresh_signature_verification': False, 'target_installation': 'NOT RUN', 'hardware': 'NOT RUN',
        'selected_contract': contract_ref, 'composition_report': report_ref,
        'original_protected_tuple': contract['protected_tuple'], 'protected_count': len(protected),
        'authenticated_staging_preflight': receipt_ref, 'staged_target_lock': target,
        'original': {'metadata_prepare_status': report['metadata_prepare_status'],
                     'composition_blockers': report['blockers'], **original},
    }
    if (proposal := report.get('proposed_maintenance')) is not None:
        inventory_ref = proposal['final_inventory']
        inventory = reader.document(inventory_ref)
        C.need(proposal['approval_status'] == 'UNAPPROVED' and proposal['transaction_accepted'] is False
               and proposal['proposal_reference'] in report['input_references']
               and inventory['kind'] == 'UNAPPROVED-maintenance-metadata-inventory'
               and inventory['dependency_transaction_accepted'] is False,
               'exact unapproved maintenance inventory required')
        proposed = mapping(inventory['proposed_final_inventory'], proposal['final_package_count'], protected, staged)
        result['unapproved_maintenance'] = {
            'metadata_prepare_status': proposal['metadata_prepare_status'],
            'approval_status': 'UNAPPROVED', 'inventory': inventory_ref, **proposed,
        }
    reader.recheck()
    return result


def reference(path, digest):
    return {'path': str(path), 'size': path.stat().st_size, 'sha256': digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('contract', 'composition', 'preflight'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--staging', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        paths = (args.contract, args.composition, args.preflight)
        C.need(args.output.is_absolute() and not os.path.lexists(args.output)
               and T.ordinary(args.output.parent).is_dir() and not args.output.is_relative_to(args.staging),
               'new absolute output outside staging required')
        refs = [reference(path, digest) for path, digest in zip(paths, (
            args.contract_sha256, args.composition_sha256, args.preflight_sha256), strict=True)]
        report = evaluate(*refs[:2], args.staging, refs[2])
        raw = T.encoded(report)
        with args.output.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
        print(json.dumps({key: report['original'][key] for key in (
            'archive_relations', 'eligible_archive_count', 'protected_conflicts')}, sort_keys=True))
        return 2
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
