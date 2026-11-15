#!/usr/bin/env python3
"""Offline successor: six exact ancestor-MIT notice joins, no activation claim."""
import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('compiler_notices', HERE.parent / 'reevaluate.py')
previous = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(previous)
require, pin, blob = previous.require, previous.prior.pin, previous.prior.blob


def success_receipt(receipts, url, body):
    return any(r.get('HTTP') == 200 and r['url'] == url and r.get('sha256') == pin(body)['sha256'] for r in receipts)


def exact_tree(case, read, receipts):
    """Verify the official alias redirect via its repository ID and metadata."""
    body = read(case['tree_file'])
    metadata_body = read(case['repository_metadata'])
    metadata = json.loads(metadata_body)
    require(metadata['full_name'] == case['repository'], 'repository metadata name mismatch')
    require(success_receipt(receipts, 'https://api.github.com/repos/' + case['repository'], metadata_body), 'repository metadata HTTP identity mismatch')
    initial = 'https://api.github.com/repos/' + case['tree_request_repository'] + '/git/trees/' + case['commit'] + '?recursive=1'
    if case['tree_request_repository'] == case['repository']:
        endpoint = initial
    else:
        endpoint = 'https://api.github.com/repositories/' + str(metadata['id']) + '/git/trees/' + case['commit'] + '?recursive=1'
        require(any(r.get('HTTP') == 301 and r['url'] == initial and r.get('location') == endpoint for r in receipts), 'official repository-ID redirect missing')
    require(success_receipt(receipts, endpoint, body), 'exact repository/commit tree receipt missing')
    tree = json.loads(body)
    require(tree.get('truncated') is False, 'complete primary tree required')
    return {r['path']: r for r in tree['tree']}


def inherited_license_repository(case, captures, entries, read):
    orig = next(r for r in captures if r['path'].endswith('/Cargo.toml.orig'))
    package = tomllib.loads(orig['text'])['package']
    if 'workspace_manifest' in case:
        root = read(case['workspace_manifest'])
        require(entries['Cargo.toml']['sha'] == blob(root), 'ancestor workspace Git blob mismatch')
        document = tomllib.loads(root.decode())
        require(str(PurePosixPath(case['manifest_path']).parent) in document['workspace']['members'], 'package is not a declared workspace member')
        workspace = document['workspace']['package']
        require(package['license'] == {'workspace': True} and package['repository'] == {'workspace': True}, 'expected inherited license/repository declaration changed')
        require(workspace['repository'] == 'https://github.com/' + case['repository'], 'inherited repository differs from primary identity')
        require('MIT' in workspace['license'].replace('/', ' OR ').split(' OR '), 'workspace MIT alternative not established')
        return {'inherited_license_repository_resolved': True, 'workspace_pin': pin(root),
                'workspace_origin_url': 'https://raw.githubusercontent.com/' + case['tree_request_repository'] + '/' + case['commit'] + '/Cargo.toml',
                'workspace_git_blob_sha1': blob(root), 'declared_license': workspace['license']}
    require(package['license'] == 'MIT', 'literal MIT declaration required')
    require(package['repository'] == 'https://github.com/' + case['tree_request_repository'], 'literal original repository differs from official alias')
    return {'inherited_license_repository_resolved': False, 'declared_license': package['license']}


def scope_notice(case, grant):
    require(PurePosixPath(case['manifest_path']).parent.is_relative_to(PurePosixPath(case['grant_upstream_path']).parent), 'grant outside package ancestor scope')
    previous.grant_review('MIT', grant)
    previous.notice_review(grant, case['manual_named_notice'])


def network_summary(ledger):
    rows = ledger['requests']
    require(all(isinstance(r.get('bytes'), int) and r['bytes'] >= 0 for r in rows), 'invalid request body accounting')
    count, size = len(rows), sum(r['bytes'] for r in rows)
    require(count <= 20 and size == ledger['body_bytes'] and size <= 16 * 1024**2, 'network budget exceeded or inconsistent')
    require([r['ordinal'] for r in rows] == list(range(1, count + 1)), 'request ordinal mismatch')
    elapsed = ledger['stopped_epoch'] - ledger['started_epoch']
    require(ledger.get('acquisition_closed') is True and 0 <= elapsed <= 900, 'acquisition deadline/closure mismatch')
    return {'new_actual_HTTP_requests': count, 'new_response_body_bytes': size, 'acquisition_seconds': round(elapsed, 3),
            'redirect_requests': [r['ordinal'] for r in rows if r.get('HTTP') in (301, 302, 303, 307, 308)],
            'failed_requests': [r['ordinal'] for r in rows if r.get('HTTP', 0) >= 400], 'offline_replay_requests': 0}


def evaluate(packet_path):
    data = json.loads((HERE / 'cases.json').read_text())
    def read(name):
        body = (HERE / name).read_bytes()
        previous.prior.check(body, data['evidence_files'][name])
        return body
    for name in data['evidence_files']:
        read(name)
    baseline = previous.evaluate(packet_path)
    require(baseline == json.loads(read('../report.json')), 'preceding replay changed')
    body = packet_path.read_bytes()
    previous.prior.check(body, data['candidate_packet'])
    packet = json.loads(body)
    require(packet['source_pin_verified'], 'authenticated source packet required')
    remaining = set(baseline['remaining_components'])
    ledger = json.loads(read('requests.json'))
    receipts = ledger['requests']
    priority = {r['component']: r for r in json.loads(read('../../priority-notes.json'))['all_case_membership_and_proof_availability']}
    lock = tomllib.loads(read('../../primary-b/Rust-Cargo.lock').decode())['package']
    miri = next(p for p in lock if p['name'] == 'miri' and p['version'] == '0.1.0')
    require('libffi' in miri['dependencies'], 'Miri lock edge changed')
    ffi_matches = [p for p in lock if p['name'] == 'libffi']
    require(len(ffi_matches) == 1 and ffi_matches[0]['version'] == '5.1.0', 'ambiguous or wrong-version Miri libffi edge')
    ffi_lock = ffi_matches[0]
    results, closed = [], set()
    for case in data['cases']:
        component = case['component']
        require(component in remaining and packet['component_statuses'][component] == 'PASS', 'case outside unresolved authenticated checksum-PASS baseline')
        captures = [r for r in packet['candidates'] if r['crate'] == component]
        entries = exact_tree(case, read, receipts)
        result = previous.binding(case, captures, entries, read)
        inherited = inherited_license_repository(case, captures, entries, read)
        if inherited['inherited_license_repository_resolved']:
            require(success_receipt(receipts, inherited['workspace_origin_url'], read(case['workspace_manifest'])), 'workspace exact-commit HTTP receipt missing')
        grant = read(case['grant_file'])
        require(entries[case['grant_upstream_path']]['sha'] == blob(grant), 'grant Git blob mismatch')
        require(success_receipt(receipts, case['grant_origin_url'], grant), 'grant URL/revision/body receipt mismatch')
        # Raw alias URLs must name this exact known official repository lineage.
        prefixes = ['https://raw.githubusercontent.com/' + repo + '/' + case['commit'] + '/'
                    for repo in (case['repository'], case['tree_request_repository'])]
        require(case['grant_origin_url'] in [prefix + case['grant_upstream_path'] for prefix in prefixes], 'grant origin outside exact primary lineage')
        scope_notice(case, grant)
        result.update(inherited)
        result.update({'grant_file': case['grant_file'], 'grant_origin_url': case['grant_origin_url'],
                       'grant_pin': pin(grant), 'grant_git_blob_sha1': blob(grant), 'grant_upstream_path': case['grant_upstream_path'],
                       'named_root_notice': case['manual_named_notice'], 'status': 'UPSTREAM_ROOT_GRANT_AND_NOTICE_EVIDENCE_COMPLETE',
                       'lock_membership': priority[component]['lock_membership'],
                       'static_root_lock_path': [['miri', '0.1.0', ''], ['libffi', ffi_lock['version'], ffi_lock.get('source', '')]] if component == 'libffi-5.1.0' else None,
                       'Linux_aarch64_cfg_features_resolved': False, 'all_file_license_and_legal_acceptance': 'HELD'})
        results.append(result)
        closed.add(component)
    for attempt in data['attempts']:
        require(attempt['component'] in remaining - closed, 'unsuccessful attempt must remain unresolved')
    return {'schema': 1, 'baseline_unresolved': len(remaining), 'new_scoped_notice_cases_closed': len(closed),
            'closed_components': sorted(closed), 'remaining_unresolved': len(remaining - closed), 'remaining_components': sorted(remaining - closed),
            'cases': results, 'unresolved_attempts': data['attempts'], 'network': network_summary(ledger),
            'selection_limits': 'libffi is a Miri root-lock dependency; optional/target activation unproved. PHF versions are authenticated vendored components outside both recorded root/Cargo-tools locks; no active compiler/runtime selection is claimed.',
            'scope': 'Exact package/version/commit plus ancestor MIT grant and literal named root notice; not all-file licensing or legal/release acceptance',
            'private_candidate_packet_published': False, 'original_dirty_version_recipe_and_platform_holds': 'PRESERVED',
            'archives_checkout_download_build_package_lease_trust_daemon_changes': 'NOT_RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-packet', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.resolve().is_relative_to(Path('/tmp')), 'new report output must be below /tmp')
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    result = evaluate(args.candidate_packet)
    with args.output.open('x') as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(json.dumps({k: result[k] for k in ('new_scoped_notice_cases_closed', 'remaining_unresolved', 'network')}))
