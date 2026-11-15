#!/usr/bin/env python3
"""Clarify holds from the actual audit; metadata-only, never read baseline payloads."""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import resource
import signal

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('ui_retained_audit_reconciliation', HERE/'audit.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


def reconcile(raw, baseline):
    report = json.loads(json.dumps(raw))
    oversize = defaultdict(list)
    for package in report['packages']:
        fields = package.get('metadata', {}).get('/.PKGINFO', {}).get('fields', {})
        build = package.get('metadata', {}).get('/.BUILDINFO', {}).get('fields', {})
        if build and (len(fields.get('pkgbase', [])) != 1 or build.get('pkgbase') != fields.get('pkgbase')):
            package['BUILDINFO_status'] = 'HOLD'
            package['BUILDINFO_issues'] = sorted(set(package.get('BUILDINFO_issues', []) + ['pkgbase']))
        for obj in package.get('ELF_objects', []):
            if obj['status'] == 'HOLD_OBJECT_CAP':
                oversize[Path(obj['path']).name].append({'package': package['name'], **obj})
    declared = defaultdict(set)
    for package in baseline['packages']:
        for offered in package['desc'].get('PROVIDES', []):
            match = re.fullmatch(r'(.+\.so)=(\d+)-64', offered)
            if match:
                declared[match[1] + '.' + match[2]].add(package['name'])

    def hold(library):
        basename = Path(library).name
        if oversize.get(basename):
            return 'HOLD_KNOWN_ADDITION_ELF_OBJECT_CAP', {'observed_object_candidates': oversize[basename]}
        if declared.get(basename):
            return 'HOLD_BASELINE111_PAYLOAD_SYMBOLS_NOT_READ', {'baseline_declared_packages': sorted(declared[basename])}
        return 'HOLD_PROVIDER_NOT_OBSERVED_BASELINE_UNREAD', {}

    for group in ['static_NEEDED_joins', 'GNU_version_name_joins']:
        for row in report[group]:
            if row.get('provider') is None and row['status'] != 'HOLD_UNSUPPORTED_SEARCH_PATH':
                row['status'], evidence = hold(row.get('needed', row.get('library')))
                row.update(evidence)
                row['declared_provider_is_not_payload_or_symbol_evidence'] = True
    objects = [obj for p in report['packages'] for obj in p.get('ELF_objects', [])]
    report['static_summary'] = {
        'signature_roles': dict(Counter(p.get('signer_role', 'MISSING') for p in report['packages'])),
        'BUILDINFO': dict(Counter(p.get('BUILDINFO_status', 'NOT_READ') for p in report['packages'])),
        'ELF_objects': dict(Counter(o['status'] for o in objects)),
        'NEEDED': dict(Counter(r['status'] for r in report['static_NEEDED_joins'])),
        'GNU_version_names': dict(Counter(r['status'] for r in report['GNU_version_name_joins'])),
        'package_dependencies': dict(Counter(r['status'] for r in report['actual_dependency_joins'])),
    }
    report['reconciliation_scope'] = 'Old139 observations and raw actual report preserved; no new archive reads; baseline declarations label holds only'
    if raw['summary']['planned'] == 44:
        report['final_holds'] = [h for h in report['final_holds'] if not h.startswith('Xvfb exact input')]
    report['acceptance'] = {'all_declared_inputs_authenticated': raw['summary']['byte_signature_metadata_pass'] == raw['summary']['planned'],
                            'all_observed_ELF_geometry': all(o['status'] == 'PASS_STATIC_ELF' for o in objects), 'full_symbol_ABI': 'NOT_ESTABLISHED',
                            'baseline111_payloads_read': False, 'native_build_runtime_install_M2_legal_release': 'NOT_ESTABLISHED'}
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(Path('/tmp')):
        parser.error('new private output required below/tmp')
    resource.setrlimit(resource.RLIMIT_AS, (128*1024**2, 128*1024**2)); signal.alarm(30)
    config = json.loads((HERE/'inputs.json').read_text())
    body = args.raw.read_bytes()
    raw = json.loads(body)
    baseline = json.loads(A.checked_bytes(config['inputs']['baseline111']))
    result = reconcile(raw, baseline)
    result['raw_actual_report_pin'] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    with args.output.open('x') as target: json.dump(result, target, indent=2, sort_keys=True); target.write('\n')
    print(json.dumps(result['static_summary'], sort_keys=True))
