#!/usr/bin/env python3
"""Offline evidence joins for this finite compiler-notice followup."""
import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('prior_review', HERE.parent / 'reevaluate.py')
prior = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def network_summary(ledger):
    rows = ledger['requests']
    require(all(isinstance(r.get('bytes'), int) and r['bytes'] >= 0 for r in rows), 'invalid response-byte receipt')
    count, size = len(rows), sum(r['bytes'] for r in rows)
    require(count <= 40 and size <= 16 * 1024**2 and size == ledger['body_bytes'], 'network budget or byte accounting mismatch')
    require(ledger.get('acquisition_closed') is True and 0 <= ledger['stopped_epoch'] - ledger['started_epoch'] <= 1200, 'acquisition deadline or closure mismatch')
    require([r['ordinal'] for r in rows] == list(range(1, count + 1)), 'request ordinal mismatch')
    return {'new_actual_HTTP_requests': count, 'new_response_body_bytes': size,
            'failed_or_incomplete_requests': [r['ordinal'] for r in rows if r.get('HTTP') != 200],
            'replay_HTTP_requests': 0}


def tree_entries(case, read, receipts):
    """Join small non-recursive shards by directory Git IDs, or one full tree."""
    root_body = read(case['tree_file'])
    root = json.loads(root_body)
    require(root.get('truncated') is False, 'complete tree response required')
    endpoint = 'https://api.github.com/repos/' + case['repository'] + '/git/trees/' + case['commit']
    # The predecessor retains this official repository-ID redirect separately.
    if case['repository'] == 'rust-lang/polonius':
        endpoint = 'https://api.github.com/repositories/131730961/git/trees/' + case['commit']
        require(any(r.get('status') == 301 and r.get('location', r.get('Location', '')).split('?')[0] == endpoint for r in receipts), 'official repository redirect missing')
    require(any(r.get('HTTP', r.get('status')) == 200 and
                r.get('sha256') == prior.pin(root_body)['sha256'] and
                r['url'].split('?')[0] == endpoint for r in receipts), 'root tree exact-commit/repository receipt missing')
    entries = {r['path']: r for r in root['tree']}
    for shard in case.get('tree_shards', []):
        prefix = shard['prefix']
        parent = entries.get(prefix, {})
        require(parent.get('type') == 'tree', 'tree shard lacks ancestor directory')
        body = read(shard['file'])
        tree = json.loads(body)
        require(tree.get('truncated') is False and tree.get('sha') == parent['sha'], 'tree shard ancestor Git ID mismatch')
        require(any(r.get('HTTP') == 200 and r.get('sha256') == prior.pin(body)['sha256'] and
                    r['url'].split('?')[0] == 'https://api.github.com/repos/' + case['repository'] + '/git/trees/' + parent['sha']
                    for r in receipts), 'tree shard HTTP identity mismatch')
        for item in tree['tree']:
            path = prefix + '/' + item['path']
            require(path not in entries, 'overlapping tree shards')
            entries[path] = {**item, 'path': path}
    return entries


def binding(case, captures, entries, read):
    orig = next(r for r in captures if r['path'].endswith('/Cargo.toml.orig'))
    vcs_record = next(r for r in captures if r['path'].endswith('/.cargo_vcs_info.json'))
    for record in (orig, vcs_record):
        require(record['complete_text'], 'complete original metadata required')
        prior.check(record['text'].encode(), {k: record[k] for k in ('bytes', 'sha256')})
    body = orig['text'].encode()
    package = tomllib.loads(body.decode())['package']
    vcs = json.loads(vcs_record['text'])
    require(vcs['git']['sha1'] == case['commit'] and vcs['git'].get('dirty') is not True, 'commit mismatch or dirty source')
    if 'path_in_vcs' in vcs:
        declared = '/'.join(filter(None, [vcs['path_in_vcs'], 'Cargo.toml']))
        require(declared == case['manifest_path'], 'VCS manifest path mismatch')
    require(entries[case['manifest_path']]['sha'] == prior.blob(body), 'original manifest Git blob mismatch')
    version = package['version']
    inherited = version == {'workspace': True}
    if inherited:
        root = read(case['workspace_manifest'])
        require(entries['Cargo.toml']['sha'] == prior.blob(root), 'workspace manifest Git blob mismatch')
        workspace = tomllib.loads(root.decode())['workspace']['package']
        version = workspace['version']
        require(package.get('license') == {'workspace': True} and 'MIT' in workspace['license'].split(' OR '), 'workspace license alternative not established')
    require(case['component'] == package['name'] + '-' + version, 'exact package version mismatch')
    return {'component': case['component'], 'name': package['name'], 'version': version, 'commit': case['commit'],
            'repository': case['repository'], 'manifest_path': case['manifest_path'], 'manifest_pin': prior.pin(body),
            'manifest_git_blob_sha1': prior.blob(body), 'workspace_version_resolved': inherited,
            'source_not_marked_dirty': True, 'whole_source_tree_clean': 'NOT_PROVED'}


def bound_file(case, file, path, entries, read, receipts):
    body = read(file)
    require(entries[path]['type'] == 'blob' and entries[path]['sha'] == prior.blob(body), 'primary file Git blob mismatch')
    # A previously retained identical blob is valid content evidence only after
    # its independently pinned tree proves this exact repository/path scope.
    require(any(r.get('HTTP', r.get('status')) == 200 and r.get('sha256') == prior.pin(body)['sha256']
                for r in receipts), 'primary bytes have no successful HTTP receipt')
    return body


def file_notice_scope(manifest_path, source_path, grant_path):
    require(PurePosixPath(source_path).is_relative_to(PurePosixPath(manifest_path).parent), 'notice belongs to a sibling package')
    require(PurePosixPath(source_path).parent.is_relative_to(PurePosixPath(grant_path).parent), 'file grant outside ancestor scope')


def grant_review(kind, body):
    text = ' '.join(body.decode().split())
    if kind == 'MIT':
        markers = ('Permission is hereby granted', 'copyright notice', 'THE SOFTWARE IS PROVIDED')
    elif kind == 'Apache-2.0':
        markers = ('Apache License', 'Version 2.0, January 2004', 'Grant of Copyright License',
                   'Grant of Patent License', 'Redistribution.', 'Disclaimer of Warranty', 'END OF TERMS AND CONDITIONS')
    else:
        raise ValueError('unreviewed grant kind')
    require(all(s in text for s in markers), 'reviewed complete grant text changed')


def notice_review(body, literal):
    require(literal in body.decode().splitlines() and 'copyright' in literal.lower(), 'literal named notice missing')
    require(not any(s in literal.lower() for s in ('[yyyy]', '[name', '<year', '<owner')), 'template notice rejected')


def evaluate(packet_path):
    data = json.loads((HERE / 'cases.json').read_text())
    def read(name):
        body = (HERE / name).read_bytes()
        prior.check(body, data['evidence_files'][name])
        return body
    for name in data['evidence_files']:
        read(name)
    packet_body = packet_path.read_bytes()
    prior.check(packet_body, data['candidate_packet'])
    packet = json.loads(packet_body)
    require(packet['source_pin_verified'], 'authenticated packet required')
    baseline = prior.evaluate(packet_path)
    require(baseline == json.loads(read('../report.json')), 'baseline replay changed')
    remaining = set(baseline['remaining_components'])
    lock = tomllib.loads(read('../primary-b/Rust-Cargo.lock').decode())['package']
    compiler = prior.dependency_paths(lock, [['rustc-main', '0.0.0'], ['rustc_driver', '0.0.0']])
    tools = {}
    for name, version, chain in [
            ('comma', '1.0.0', [('clippy', '0.1.99'), ('ui_test', '0.30.7')]),
            ('levenshtein', '1.0.5', [('clippy', '0.1.99'), ('ui_test', '0.30.7')]),
            ('jaq-core', '3.1.0', [('jsondocck', '0.1.0')]),
            ('jaq-json', '2.0.1', [('jsondocck', '0.1.0')]),
            ('jaq-std', '3.0.1', [('jsondocck', '0.1.0')])]:
        # Check the selected path against the complete lock identities, without
        # claiming that unrelated tool dependency edges are resolvable.
        selected = []
        for pair in chain + [(name, version)]:
            matches = [p for p in lock if (p['name'], p['version']) == pair]
            require(len(matches) == 1, 'ambiguous selected tool package')
            selected.append(matches[0])
        for left, right in zip(selected, selected[1:]):
            valid = False
            for edge in left.get('dependencies', []):
                tokens = edge.split()
                if tokens[0] != right['name']:
                    continue
                source = ' '.join(tokens[2:]).strip('()') if len(tokens) > 2 else None
                matches = [p for p in lock if p['name'] == tokens[0] and
                           (len(tokens) == 1 or p['version'] == tokens[1]) and
                           (source is None or p.get('source', '') == source)]
                require(len(matches) == 1, 'ambiguous selected tool edge')
                valid |= matches[0] == right
            require(valid, 'selected tool lock edge missing')
        path = [[p['name'], p['version'], p.get('source', '')] for p in selected]
        tools[tuple(path[-1])] = path
    ledger = json.loads(read('requests.json'))
    receipts = ledger['requests'][:]
    for name in ('../primary-a/requests.json', '../primary-b/requests.json'):
        receipts += json.loads(read(name))['requests']
    results = []
    closed = set()
    for case in data['cases']:
        component = case['component']
        require(component in remaining and packet['component_statuses'][component] == 'PASS', 'case outside actual checksum-PASS unresolved baseline')
        captures = [r for r in packet['candidates'] if r['crate'] == component]
        entries = tree_entries(case, read, receipts)
        result = binding(case, captures, entries, read)
        examined = []
        for item in case.get('examined_files', []):
            body = bound_file(case, item['file'], item['path'], entries, read, receipts)
            examined.append({**item, 'body_pin': prior.pin(body), 'git_blob_sha1': prior.blob(body),
                             'origin_url': 'https://raw.githubusercontent.com/' + case['repository'] + '/' + case['commit'] + '/' + item['path']})
        result['examined_primary_files'] = examined
        result['named_root_notice'] = case['manual_named_notice']
        result['status'] = 'UNRESOLVED_GRANT'
        if case.get('grant_file'):
            grant = bound_file(case, case['grant_file'], case['grant_upstream_path'], entries, read, receipts)
            require(PurePosixPath(case['manifest_path']).parent.is_relative_to(PurePosixPath(case['grant_upstream_path']).parent), 'grant outside package ancestor scope')
            grant_review(case['grant_kind'], grant)
            result.update({'grant_file': case['grant_file'], 'grant_upstream_path': case['grant_upstream_path'],
                           'grant_origin_url': 'https://raw.githubusercontent.com/' + case['repository'] + '/' + case['commit'] + '/' + case['grant_upstream_path'],
                           'grant_pin': prior.pin(grant), 'grant_git_blob_sha1': prior.blob(grant), 'grant_kind': case['grant_kind'],
                           'status': 'UNRESOLVED_ATTRIBUTION'})
            if case['manual_named_notice']:
                notice_review(grant, case['manual_named_notice'])
                result['status'] = 'UPSTREAM_ROOT_GRANT_AND_NOTICE_EVIDENCE_COMPLETE'
                closed.add(component)
        if case.get('file_scoped_notice'):
            item = case['file_scoped_notice']
            body = bound_file(case, item['file'], item['path'], entries, read, receipts)
            notice_review(body, item['literal'])
            grant = bound_file(case, item['grant_file'], item['grant_upstream_path'], entries, read, receipts)
            grant_review('Apache-2.0', grant)
            file_notice_scope(case['manifest_path'], item['path'], item['grant_upstream_path'])
            require('Licensed under the Apache License, Version 2.0' in body.decode(), 'file grant application missing')
            result['file_scoped_notice'] = {**item, 'notice_pin': prior.pin(body), 'notice_git_blob_sha1': prior.blob(body),
                                            'notice_origin_url': 'https://raw.githubusercontent.com/' + case['repository'] + '/' + case['commit'] + '/' + item['path'],
                                            'grant_pin': prior.pin(grant), 'grant_origin_url': 'https://raw.githubusercontent.com/' + case['repository'] + '/' + case['commit'] + '/' + item['grant_upstream_path'], 'scope': item['path'] + ' ONLY; package attribution remains unresolved'}
        keys = [k for k in set(compiler) | set(tools) if k[:2] == (result['name'], result['version'])]
        require(len(keys) == 1, 'ambiguous source-qualified target lock identity')
        key = keys[0]
        result['static_compiler_lock_path'] = compiler.get(key)
        result['static_tool_lock_path'] = tools.get(key)
        result['Linux_aarch64_cfg_features_resolved'] = False
        result['all_file_license_and_legal_acceptance'] = 'HELD'
        results.append(result)
    held = data['held_request']
    require(ledger['requests'][held['request_ordinal'] - 1]['HTTP'] == 422, 'held request status changed')
    codegen = tomllib.loads(read('../primary-b/rustc_codegen_ssa-Cargo.toml').decode())
    direct = prior.direct_dependency_evidence(codegen, ['wasm-encoder'])
    return {'schema': 1, 'baseline_unresolved': len(remaining), 'cases': results,
            'new_scoped_notice_cases_closed': len(closed), 'closed_components': sorted(closed),
            'remaining_unresolved': len(remaining - closed), 'remaining_components': sorted(remaining - closed),
            'exact_version_commit_bindings': len(results), 'rechecked_prior_partial_bindings': 3, 'new_exact_version_commit_bindings': len(results) - 3, 'workspace_version_holds_resolved': sum(r['workspace_version_resolved'] for r in results),
            'file_scoped_notices_retained_without_package_closure': sum('file_scoped_notice' in r for r in results),
            'held_primary_request': held, 'network': network_summary(ledger),
            'direct_compiler_normal_dependency_evidence': direct,
            'selection_limits': 'Lock paths are static. self_cell and valuable incoming cfg/features unresolved; wasmparser0.219 is optional in encoder; other tool roots are not compiler roots.',
            'prior_dirty_missing_version_and_other_scope_holds': 'PRESERVED; remaining_components is complete',
            'archives_checkouts_downloads_builds_system_mutation': 'NOT_RUN',
            'closure_scope': 'Exact package/version/commit plus ancestor grant and named root-license notice only; no all-file/legal/release/binary/native acceptance'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-packet', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.resolve().is_relative_to(Path('/tmp')), 'new output must be below /tmp')
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    result = evaluate(args.candidate_packet)
    with args.output.open('x') as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(json.dumps({k: result[k] for k in ('new_scoped_notice_cases_closed', 'remaining_unresolved', 'network')}))
