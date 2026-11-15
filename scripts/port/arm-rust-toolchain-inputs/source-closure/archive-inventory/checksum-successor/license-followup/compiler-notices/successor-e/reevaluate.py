#!/usr/bin/env python3
"""Five exact grant/project-notice joins; no count credit for weaker attempts."""
import argparse
from fnmatch import fnmatchcase
import importlib.util
import json
from pathlib import Path, PurePosixPath
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_d', HERE.parent / 'successor-d/reevaluate.py')
preceding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preceding)
compiler = preceding.compiler
require, pin, blob = compiler.require, compiler.prior.pin, compiler.prior.blob


def jni_license(case, package, entries, read, receipts):
    if package['license'] != {'workspace': True}:
        require('MIT' in package['license'].split(' OR '), 'literal MIT alternative missing')
        return {'inherited_license_resolved': False}
    require(case['component'] == 'jni-0.22.4' and case['manifest_path'] == 'crates/jni/Cargo.toml', 'unexpected inherited package scope')
    body, url = preceding.primary_body(case, case['workspace_manifest'], 'Cargo.toml', entries, read, receipts)
    workspace = tomllib.loads(body.decode())['workspace']
    require('crates/*' in workspace['members'] and not any(fnmatchcase('crates/jni', pattern) for pattern in workspace.get('exclude', [])), 'JNI not a containing workspace member')
    require('MIT' in workspace['package']['license'].split(' OR '), 'workspace MIT alternative missing')
    return {'inherited_license_resolved': True, 'workspace_member_pattern': 'crates/*',
            'workspace_origin_url': url, 'workspace_pin': pin(body), 'workspace_git_blob_sha1': blob(body)}


def named_notice(case, package, captures, entries, read, receipts):
    body, url = preceding.primary_body(case, case['notice_file'], case['notice_upstream_path'], entries, read, receipts)
    if case['notice_file'] != case['grant_file']:
        require(case['component'] == 'wasite-1.0.2' and case['notice_upstream_path'] == package['readme'] == 'README.md', 'separate notice must be this exact package README')
        require(case['manifest_path'] == 'Cargo.toml', 'README project notice outside root package scope')
        record = next(r for r in captures if r['path'].endswith('/README.md'))
        require(record['complete_text'] and record['utf8_replacement_used'] is False, 'complete exact vendor README capture required')
        compiler.prior.check(body, {k: record[k] for k in ('bytes', 'sha256')})
        text = body.decode()
        require('# Wasite\n' in text and '## License\n' in text and 'Licensed under any of' in text and
                ' - MIT License,' in text and 'at your option.' in text, 'README project/MIT application scope missing')
        scope = 'EXPLICIT_ROOT_PROJECT_COPYRIGHT_IN_PACKAGE_README_WITH_MIT_ALTERNATIVE'
    else:
        scope = 'LITERAL_NOTICE_IN_COMPLETE_ANCESTOR_ROOT_GRANT'
    compiler.notice_review(body, case['manual_named_notice'])
    return {'literal': case['manual_named_notice'], 'origin_url': url, 'body_pin': pin(body),
            'git_blob_sha1': blob(body), 'scope': scope, 'vendor_README_correspondence': case['notice_file'] != case['grant_file']}


def network_summary(ledger):
    rows = ledger['requests']
    require(all(isinstance(r.get('bytes'), int) and 0 <= r['bytes'] <= 128 * 1024 for r in rows), 'invalid or oversized per-file body receipt')
    size, elapsed = sum(r['bytes'] for r in rows), ledger['stopped_epoch'] - ledger['started_epoch']
    require(len(rows) <= 50 and size == ledger['body_bytes'] and size <= 2 * 1024**2, 'aggregate network budget/accounting mismatch')
    require([r['ordinal'] for r in rows] == list(range(1, len(rows) + 1)), 'request ordinal mismatch')
    require(ledger.get('acquisition_closed') is True and 0 <= elapsed <= 900, 'acquisition deadline/closure mismatch')
    return {'new_actual_HTTP_requests': len(rows), 'new_response_body_bytes': size, 'acquisition_seconds': round(elapsed, 3),
            'redirect_requests': [r['ordinal'] for r in rows if r.get('HTTP') in (301, 302, 303, 307, 308)],
            'error_or_incomplete_requests': [r['ordinal'] for r in rows if r.get('HTTP', 0) >= 400 or not r.get('complete_body')],
            'offline_replay_requests': 0}


def evaluate(packet_path):
    data = json.loads((HERE / 'cases.json').read_text())
    def read(name):
        body = (HERE / name).read_bytes()
        compiler.prior.check(body, data['evidence_files'][name])
        return body
    for name in data['evidence_files']:
        read(name)
    baseline = preceding.evaluate(packet_path)
    require(baseline == json.loads(read('../successor-d/report.json')), 'preceding report replay changed')
    packet_body = packet_path.read_bytes()
    compiler.prior.check(packet_body, data['candidate_packet'])
    packet = json.loads(packet_body)
    require(packet['source_pin_verified'], 'authenticated source packet required')
    remaining = set(baseline['remaining_components'])
    priority = {r['component']: r for r in json.loads(read('../../priority-notes.json'))['all_case_membership_and_proof_availability']}
    ledger = json.loads(read('requests.json'))
    receipts = ledger['requests']
    # Successful joins must use complete HTTP bodies, never partial/error prefixes.
    complete_receipts = [r for r in receipts if r.get('complete_body') is True]
    results, closed = [], set()
    for case in data['cases']:
        component = case['component']
        require(component in remaining and packet['component_statuses'][component] == 'PASS', 'case outside authenticated checksum-PASS unresolved baseline')
        captures = [r for r in packet['candidates'] if r['crate'] == component]
        entries = compiler.tree_entries(case, read, complete_receipts)
        result = compiler.binding(case, captures, entries, read)
        orig = next(r for r in captures if r['path'].endswith('/Cargo.toml.orig'))
        package = tomllib.loads(orig['text'])['package']
        require(package['repository'] == 'https://github.com/' + case['repository'], 'original repository mismatch')
        inheritance = jni_license(case, package, entries, read, complete_receipts)
        require(PurePosixPath(case['manifest_path']).parent.is_relative_to(PurePosixPath(case['grant_upstream_path']).parent), 'grant outside package ancestor scope')
        grant, grant_url = preceding.primary_body(case, case['grant_file'], case['grant_upstream_path'], entries, read, complete_receipts)
        compiler.grant_review('MIT', grant)
        notice = named_notice(case, package, captures, entries, read, complete_receipts)
        result.update({'status': 'UPSTREAM_PACKAGE_SCOPED_GRANT_AND_NOTICE_EVIDENCE_COMPLETE', 'grant_origin_url': grant_url,
                       'grant_pin': pin(grant), 'grant_git_blob_sha1': blob(grant), 'selected_license_alternative': 'MIT',
                       'notice': notice, **inheritance, 'lock_membership': priority[component]['lock_membership'],
                       'actual_target_activation': 'NOT_PROVED', 'all_file_full_projection_legal_native_M2_release_acceptance': 'HELD'})
        results.append(result)
        closed.add(component)
    for attempt in data['unresolved_attempts']:
        require(attempt['component'] in remaining - closed and attempt['closure_credit'] == 0, 'unsuccessful source selection must stay held')
    # The real failed revision request and official redirect stay visible/accounted.
    require(receipts[12]['HTTP'] == 404 and receipts[15]['HTTP'] == 301, 'failed/redirect receipt changed')
    return {'schema': 1, 'baseline_unresolved': len(remaining), 'new_scoped_package_notice_cases_closed': len(closed),
            'closed_components': sorted(closed), 'remaining_unresolved': len(remaining - closed), 'remaining_components': sorted(remaining - closed),
            'cases': results, 'unresolved_attempts': data['unresolved_attempts'], 'network': network_summary(ledger),
            'scope': 'Exact package/version/commit plus actual complete MIT alternative and named root/project notice; not all-file/legal/target/release acceptance',
            'selection_limits': 'defmt-parser appears only in recorded Cargo-tools lock; other four outside both recorded locks; all target activation unproved',
            'source_object_mismatch_dirty_version_platform_and_other_holds': 'PRESERVED',
            'archives_checkout_download_build_package_source_native_actor_lease_trust_daemon_changes': 'NOT_RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-packet', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.resolve().is_relative_to(Path('/tmp')), 'new report must be below /tmp')
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    result = evaluate(args.candidate_packet)
    with args.output.open('x') as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({k: result[k] for k in ('new_scoped_package_notice_cases_closed', 'remaining_unresolved', 'network')}))
