#!/usr/bin/env python3
"""Four exact package-scoped grants/notices, preserving all broader holds."""
import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_c', HERE.parent / 'successor-c/reevaluate.py')
preceding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preceding)
compiler = preceding.compiler
require, pin, blob = compiler.require, compiler.prior.pin, compiler.prior.blob


def primary_body(case, file, path, entries, read, receipts):
    body = compiler.bound_file(case, file, path, entries, read, receipts)
    url = 'https://raw.githubusercontent.com/' + case['repository'] + '/' + case['commit'] + '/' + path
    preceding.receipt(receipts, url, body)
    return body, url


def grant_scope(case, captures, entries, read, receipts):
    manifest_parent = PurePosixPath(case['manifest_path']).parent
    if manifest_parent.is_relative_to(PurePosixPath(case['grant_upstream_path']).parent):
        return {'kind': 'PACKAGE_ANCESTOR_ROOT_GRANT'}
    # A narrow, explicit project declaration binds this otherwise sibling path.
    require(case['component'] == 'tenthash-1.1.0' and case['grant_upstream_path'] == 'licenses/MIT.txt', 'grant outside proved package scope')
    require(case['manifest_path'] == 'tenthash-rust/Cargo.toml', 'wrong TentHash package scope')
    expected = [('README.md', 'evidence/tenthash-root-README.md'),
                ('tenthash-rust/README.md', 'evidence/tenthash-rust-README.md')]
    require([(r['path'], r['file']) for r in case.get('scope_readmes', [])] == expected, 'both exact root/package scope declarations required')
    records = []
    for path, file in expected:
        body, url = primary_body(case, file, path, entries, read, receipts)
        text = body.decode()
        require('This project is licensed under either of' in text and 'MIT license (licenses/MIT.txt or ' in text and
                'at your option.' in text, 'explicit project MIT path declaration missing')
        records.append({'path': path, 'origin_url': url, 'body_pin': pin(body), 'git_blob_sha1': blob(body)})
    orig = next(r for r in captures if r['path'].endswith('/Cargo.toml.orig'))
    require(tomllib.loads(orig['text'])['package']['readme'] == 'README.md', 'package README declaration mismatch')
    require('# TentHash Rust' in read(expected[1][1]).decode() and
            'https://github.com/cessen/tenthash' in read(expected[1][1]).decode(), 'Rust package/project link missing')
    record = next(r for r in captures if r['path'].endswith('/README.md'))
    require(record['complete_text'], 'complete retained package README required')
    compiler.prior.check(read(expected[1][1]), {k: record[k] for k in ('bytes', 'sha256')})
    return {'kind': 'EXPLICIT_ANCESTOR_PROJECT_AND_PACKAGE_README_GRANT_PATH', 'readme_evidence': records,
            'package_README_matches_authenticated_vendor_capture': True}


def complete_grant(case, grant):
    if case['grant_kind'] == 'MIT':
        compiler.grant_review('MIT', grant)
    elif case['grant_kind'] == 'BSD-3-Clause':
        text = ' '.join(grant.decode().split())
        require(all(s in text for s in [
            'Redistribution and use in source and binary forms, with or without modification, are permitted',
            '1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.',
            '2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer',
            '3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products',
            'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"',
            'IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE', 'EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.']),
                'complete BSD-3-Clause grant/conditions/disclaimer required')
    else:
        raise ValueError('unreviewed grant kind')
    compiler.notice_review(grant, case['manual_named_notice'])


def network_summary(ledger):
    rows = ledger['requests']
    require(all(isinstance(r.get('bytes'), int) and r['bytes'] >= 0 for r in rows), 'invalid body accounting')
    size, elapsed = sum(r['bytes'] for r in rows), ledger['stopped_epoch'] - ledger['started_epoch']
    require(len(rows) <= 20 and size == ledger['body_bytes'] and size <= 16 * 1024**2, 'network budget/accounting mismatch')
    require([r['ordinal'] for r in rows] == list(range(1, len(rows) + 1)), 'request ordinal mismatch')
    require(ledger.get('acquisition_closed') is True and 0 <= elapsed <= 1200, 'acquisition deadline/closure mismatch')
    return {'new_actual_HTTP_requests': len(rows), 'new_response_body_bytes': size, 'acquisition_seconds': round(elapsed, 3),
            'redirect_or_error_requests': [r['ordinal'] for r in rows if r.get('HTTP') != 200], 'offline_replay_requests': 0}


def evaluate(packet_path):
    data = json.loads((HERE / 'cases.json').read_text())
    def read(file):
        body = (HERE / file).read_bytes()
        compiler.prior.check(body, data['evidence_files'][file])
        return body
    for file in data['evidence_files']:
        read(file)
    baseline = preceding.evaluate(packet_path)
    require(baseline == json.loads(read('../successor-c/report.json')), 'preceding replay changed')
    packet_body = packet_path.read_bytes()
    compiler.prior.check(packet_body, data['candidate_packet'])
    packet = json.loads(packet_body)
    require(packet['source_pin_verified'], 'authenticated source packet required')
    remaining = set(baseline['remaining_components'])
    priority = {r['component']: r for r in json.loads(read('../../priority-notes.json'))['all_case_membership_and_proof_availability']}
    ledger = json.loads(read('requests.json'))
    receipts = ledger['requests']
    cases, closed = [], set()
    for case in data['cases']:
        component = case['component']
        require(component in remaining and packet['component_statuses'][component] == 'PASS', 'case outside checksum-PASS unresolved baseline')
        captures = [r for r in packet['candidates'] if r['crate'] == component]
        entries = compiler.tree_entries(case, read, receipts)
        result = compiler.binding(case, captures, entries, read)
        orig = next(r for r in captures if r['path'].endswith('/Cargo.toml.orig'))
        declared = tomllib.loads(orig['text'])['package']
        require(case['grant_kind'] in declared['license'].replace('/', ' OR ').split(' OR '), 'selected grant not a declared license alternative')
        original_repository = declared['repository']
        require(original_repository == 'https://github.com/' + case['repository'] or
                original_repository == 'https://github.com/' + case['repository'] + '/tree/main/tenthash-rust' and component == 'tenthash-1.1.0',
                'original repository declaration mismatch')
        scope = grant_scope(case, captures, entries, read, receipts)
        grant, url = primary_body(case, case['grant_file'], case['grant_upstream_path'], entries, read, receipts)
        complete_grant(case, grant)
        result.update({'grant_kind': case['grant_kind'], 'grant_origin_url': url, 'grant_pin': pin(grant),
                       'grant_git_blob_sha1': blob(grant), 'named_root_notice': case['manual_named_notice'], 'scope_evidence': scope,
                       'status': 'UPSTREAM_PACKAGE_SCOPED_GRANT_AND_NOTICE_EVIDENCE_COMPLETE',
                       'lock_membership': priority[component]['lock_membership'], 'actual_target_activation': 'NOT_PROVED',
                       'full_vendor_projection_all_file_legal_native_release_acceptance': 'HELD'})
        cases.append(result)
        closed.add(component)
    attempt = data['framework_attempt']
    framework_case = {'repository': attempt['repository'], 'commit': attempt['commit'],
                      'tree_file': 'evidence/objc-framework-root-tree.json'}
    framework_entries = compiler.tree_entries(framework_case, read, receipts)
    overview, _ = primary_body(framework_case, 'evidence/objc-framework-LICENSE.md', 'LICENSE.md', framework_entries, read, receipts)
    primary_body(framework_case, 'evidence/objc-framework-Cargo.toml', 'Cargo.toml', framework_entries, read, receipts)
    require(attempt['closure_credit'] == 0 and b'unclear whether distributing derived works' in overview, 'framework unknown hold changed')
    return {'schema': 1, 'baseline_unresolved': len(remaining), 'new_scoped_package_notice_cases_closed': len(closed),
            'closed_components': sorted(closed), 'remaining_unresolved': len(remaining - closed), 'remaining_components': sorted(remaining - closed),
            'cases': cases, 'framework_attempt': attempt, 'network': network_summary(ledger),
            'scope': 'Exact matching package/version/commit plus complete selected grant and literal named notice; no all-file/legal/activation/release acceptance',
            'selection_limits': 'All four are authenticated compiler-source vendor components outside both recorded root/Cargo-tools locks; actual target activation unproved',
            'object_mismatch_original_dirty_version_platform_and_other_holds': 'PRESERVED',
            'archives_checkout_download_build_package_source_actor_lease_trust_daemon_changes': 'NOT_RUN'}


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
