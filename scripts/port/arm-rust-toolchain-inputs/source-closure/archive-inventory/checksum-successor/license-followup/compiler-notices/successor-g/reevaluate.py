#!/usr/bin/env python3
"""A frozen zero-credit screen; absence of proof is never a package closure."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_f', HERE.parent / 'successor-f/reevaluate.py')
preceding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preceding)
compiler = preceding.compiler
require, pin, blob = compiler.require, compiler.prior.pin, compiler.prior.blob


def receipt(rows, url, body):
    require(any(r.get('HTTP') == 200 and r.get('complete_body') is True and r['url'] == url and
                r.get('sha256') == pin(body)['sha256'] for r in rows), 'exact complete primary HTTP receipt missing')


def root_entries(snapshot, read):
    body = read(snapshot['root_file'])
    rows = json.loads(read(snapshot['root_ledger']))['requests']
    initial = 'https://api.github.com/repos/' + snapshot['repository'] + '/git/trees/' + snapshot['commit']
    endpoint = initial
    if snapshot.get('official_api_repository_id'):
        endpoint = 'https://api.github.com/repositories/' + str(snapshot['official_api_repository_id']) + '/git/trees/' + snapshot['commit']
        require(any(r.get('HTTP') == 301 and r['url'] == initial and r.get('location') == endpoint and r.get('complete_body') is True
                    for r in rows), 'official repository-ID redirect missing')
    receipt(rows, endpoint, body)
    tree = json.loads(body)
    require(tree.get('truncated') is False, 'complete root metadata required')
    return {r['path']: r for r in tree['tree']}


def source_body(snapshot, file, path, entries, read, rows):
    body = read(file)
    require(entries[path]['type'] == 'blob' and entries[path]['sha'] == blob(body), 'root source Git blob mismatch')
    url = 'https://raw.githubusercontent.com/' + snapshot['repository'] + '/' + snapshot['commit'] + '/' + path
    receipt(rows, url, body)
    return body, url


def retain_hold(snapshot, readme, grant):
    require(snapshot['manual_named_notice'] is None and snapshot['package_manifest_to_Git_binding'] == 'NOT_PERFORMED_NO_ELIGIBLE_NOTICE_FOUND',
            'positive attribution/package scope requires a separate reviewed join')
    # Corroborates this limited manual screen, not a claim of absent ownership.
    lines = [line for line in readme.decode().splitlines() if re.search(r'(?i)copyright|©|&copy;', line)]
    require(not lines, 'changed README notice context requires manual review')
    if grant is not None:
        compiler.grant_review('MIT', grant)
        require(not any(re.match(r'(?i)^\s*(?:portions\s+)?copyright\b', line) for line in grant.decode().splitlines()),
                'changed named-grant notice context requires manual review')
    return {'status': 'UNRESOLVED_NO_NAMED_NOTICE_ESTABLISHED_IN_ACQUIRED_ROOT_FILES', 'closure_credit': 0,
            'package_manifest_to_Git_binding': snapshot['package_manifest_to_Git_binding'],
            'other_source_files_and_ownership': 'NOT_REVIEWED; no all-file absence claim'}


def network_summary(ledger):
    rows = ledger['requests']
    require(all(isinstance(r.get('bytes'), int) and 0 <= r['bytes'] <= 128 * 1024 for r in rows), 'invalid per-file body receipt')
    size, elapsed = sum(r['bytes'] for r in rows), ledger['stopped_epoch'] - ledger['started_epoch']
    require(len(rows) <= 50 and size <= 2 * 1024**2 and size == ledger['body_bytes'], 'network budget/accounting mismatch')
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
    require(baseline == json.loads(read('../successor-f/report.json')), 'preceding replay changed')
    packet_body = packet_path.read_bytes()
    compiler.prior.check(packet_body, data['candidate_packet'])
    packet = json.loads(packet_body)
    require(packet['source_pin_verified'], 'authenticated private source packet required')
    ledger = json.loads(read('requests.json'))
    roots, components = [], []
    for snapshot in data['snapshots']:
        entries = root_entries(snapshot, read)
        readme, readme_url = source_body(snapshot, snapshot['readme_file'], 'README.md', entries, read, ledger['requests'])
        grant, grant_data = None, {'body_acquisition': 'NOT_REPEATED_FOR_EXISTING_MATKLAD_ROOT_METADATA'}
        if snapshot['grant_file']:
            grant, grant_url = source_body(snapshot, snapshot['grant_file'], snapshot['grant_path'], entries, read, ledger['requests'])
            grant_data = {'origin_url': grant_url, 'body_pin': pin(grant), 'git_blob_sha1': blob(grant),
                          'status': 'COMPLETE_MIT_TEXT_AT_CANDIDATE_ROOT_ONLY'}
        held = retain_hold(snapshot, readme, grant)
        selected = []
        for component in snapshot['components']:
            require(component in baseline['remaining_components'] and packet['component_statuses'][component] == 'PASS', 'screen target outside unresolved checksum-PASS baseline')
            captures = [r for r in packet['candidates'] if r['crate'] == component]
            orig = next(r for r in captures if r['path'].endswith('/Cargo.toml.orig'))
            vcs = next(r for r in captures if r['path'].endswith('/.cargo_vcs_info.json'))
            for record in (orig, vcs):
                require(record['complete_text'], 'complete original metadata required')
                compiler.prior.check(record['text'].encode(), {k: record[k] for k in ('bytes', 'sha256')})
            source = json.loads(vcs['text'])
            require(source['git']['sha1'] == snapshot['commit'] and source['git'].get('dirty') is not True, 'declared source revision/dirty mismatch')
            package = tomllib.loads(orig['text'])['package']
            selected.append({'component': component, 'package_name': package['name'], 'version_declaration': package['version'],
                             'repository_declaration': package['repository'], 'declared_commit': source['git']['sha1'],
                             'package_manifest_scope_and_inherited_values': 'NOT_PROMOTED', 'closure_credit': 0})
            components.append(component)
        roots.append({'id': snapshot['id'], 'candidate_repository': snapshot['repository'], 'commit': snapshot['commit'],
                      'root_metadata_pin': pin(read(snapshot['root_file'])), 'grant': grant_data,
                      'README': {'origin_url': readme_url, 'body_pin': pin(readme), 'git_blob_sha1': blob(readme)},
                      'selected_components': selected, **held})
    require(len(components) == len(set(components)), 'duplicate screened component')
    require(ledger['requests'][2]['HTTP'] == 404, 'failed legacy revision receipt changed')
    return {'schema': 1, 'baseline_unresolved': baseline['remaining_unresolved'], 'new_scoped_package_notice_cases_closed': 0,
            'remaining_unresolved': baseline['remaining_unresolved'], 'remaining_components': baseline['remaining_components'],
            'screened_components': sorted(components), 'screened_component_count': len(components), 'root_snapshots': roots,
            'legacy_perf_sys4_request': 'HTTP_404_RETAINED; monorepo snapshot is not a promoted package equivalence proof',
            'scope': 'Pinned root metadata/grant/README screen only; no exact package manifest-to-Git scope or named attribution promoted',
            'source_projection_activation_all_file_legal_native_M2_release_and_prior_holds': 'PRESERVED',
            'archives_checkout_download_build_source_native_actor_package_lease_trust_daemon_changes': 'NOT_RUN', 'network': network_summary(ledger)}


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
    print(json.dumps({k: result[k] for k in ('new_scoped_package_notice_cases_closed', 'remaining_unresolved', 'screened_component_count', 'network')}))
