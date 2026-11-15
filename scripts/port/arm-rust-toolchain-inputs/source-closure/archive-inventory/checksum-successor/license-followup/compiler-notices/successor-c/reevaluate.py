#!/usr/bin/env python3
"""One exact vendor source-file notice; zero package/all-file closure credit."""
import argparse
import importlib.util
import json
from pathlib import Path
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


baseline_review = module('successor_b', HERE.parent / 'successor-b/reevaluate.py')
compiler = baseline_review.previous
source_text = module('source_text', HERE / 'source_text.py')
require, pin, blob = compiler.require, compiler.prior.pin, compiler.prior.blob


def receipt(receipts, url, body):
    require(any(r.get('HTTP') == 200 and r['url'] == url and r.get('sha256') == pin(body)['sha256']
                for r in receipts), 'exact URL/body HTTP receipt missing')


def object_declarations(read, receipts, data, compiler_document):
    derived = {}
    for path, html, output in [('Cargo.toml', 'object-Cargo.toml.html', 'object-Cargo.toml'),
                               ('Cargo.toml.orig', 'object-Cargo.toml.orig.html', 'object-Cargo.toml.orig'),
                               ('.cargo_vcs_info.json', 'object-vcs.html', 'object-vcs.json')]:
        body = read('evidence/' + html)
        receipt(receipts, 'https://docs.rs/crate/object/0.38.1/source/' + path, body)
        derived[path] = source_text.extract(body)
        require(derived[path] == read('evidence/' + output), 'docs.rs extraction changed')
    vcs = json.loads(derived['.cargo_vcs_info.json'])
    commit = data['object_source']['commit']
    require(vcs['git']['sha1'] == commit and vcs['git'].get('dirty') is not True and vcs['path_in_vcs'] == '', 'object published VCS identity mismatch')
    tree_body = read('evidence/object-tree.json')
    receipt(receipts, 'https://api.github.com/repos/gimli-rs/object/git/trees/' + commit + '?recursive=1', tree_body)
    tree = json.loads(tree_body)
    require(tree.get('truncated') is False, 'complete object tree required')
    entry = next(r for r in tree['tree'] if r['path'] == 'Cargo.toml' and r['type'] == 'blob')
    require(entry['sha'] == blob(derived['Cargo.toml.orig']), 'object original manifest Git blob mismatch')
    original = tomllib.loads(derived['Cargo.toml.orig'].decode())
    normalized = tomllib.loads(derived['Cargo.toml'].decode())
    require(original['package']['name'] == normalized['package']['name'] == 'object' and
            original['package']['version'] == normalized['package']['version'] == '0.38.1', 'object source version mismatch')
    declaration = compiler_document['dependencies']['object']
    require(declaration['version'] == '0.38.1' and declaration.get('default-features') is False and
            declaration.get('optional') is not True and 'wasm' in declaration['features'], 'compiler object/wasm declaration changed')
    dependency = original['dependencies']['wasmparser']
    require(dependency == normalized['dependencies']['wasmparser'] ==
            {'version': '0.243.0', 'default-features': False, 'optional': True}, 'object parser dependency declaration changed')
    require(original['features']['wasm'] == normalized['features']['wasm'] == ['dep:wasmparser'], 'object wasm feature does not enable parser')
    return {'object_version': '0.38.1', 'published_source_commit': commit,
            'original_manifest_pin': pin(derived['Cargo.toml.orig']), 'original_manifest_git_blob_sha1': blob(derived['Cargo.toml.orig']),
            'docs_normalized_manifest_pin': pin(derived['Cargo.toml']),
            'compiler_normal_object_declaration': declaration, 'object_parser_declaration': dependency,
            'object_wasm_feature': original['features']['wasm'],
            'feature_declaration_chain_supported': True,
            'object_vendor_original_manifest_and_VCS_correspondence': 'NOT_PROVED; published-source metadata is independent of retained vendor metadata'}


def vendor_source_match(record, body):
    compiler.prior.check(body, {k: record[k] for k in ('bytes', 'sha256')})
    require(record['utf8_replacement_used'] is False, 'lossy captured source prefix')
    prefix = record['text'].encode()
    require(len(prefix) == record['captured_bytes'] and pin(prefix)['sha256'] == record['captured_prefix_sha256'] and
            body[:len(prefix)] == prefix, 'retained source prefix mismatch')
    return {'bytes': record['bytes'], 'sha256': record['sha256'], 'captured_prefix_bytes': record['captured_bytes'],
            'captured_prefix_sha256': record['captured_prefix_sha256'], 'complete_private_capture_text': record['complete_text']}


def network_summary(ledger):
    rows = ledger['requests']
    require(all(isinstance(r.get('bytes'), int) and r['bytes'] >= 0 for r in rows), 'invalid HTTP byte receipt')
    size, elapsed = sum(r['bytes'] for r in rows), ledger['stopped_epoch'] - ledger['started_epoch']
    require(len(rows) <= 20 and size <= 16 * 1024**2 and size == ledger['body_bytes'], 'network budget/accounting mismatch')
    require([r['ordinal'] for r in rows] == list(range(1, len(rows) + 1)), 'request ordinal mismatch')
    require(ledger.get('acquisition_closed') is True and 0 <= elapsed <= 1200, 'acquisition deadline/closure mismatch')
    return {'new_actual_HTTP_requests': len(rows), 'new_response_body_bytes': size, 'acquisition_seconds': round(elapsed, 3),
            'redirect_or_error_requests': [r['ordinal'] for r in rows if r.get('HTTP') != 200], 'offline_replay_requests': 0}


def evaluate(packet_path):
    data = json.loads((HERE / 'cases.json').read_text())
    def read(name):
        body = (HERE / name).read_bytes()
        compiler.prior.check(body, data['evidence_files'][name])
        return body
    for name in data['evidence_files']:
        read(name)
    baseline = baseline_review.evaluate(packet_path)
    require(baseline == json.loads(read('../successor-b/report.json')), 'preceding report replay changed')
    packet_body = packet_path.read_bytes()
    compiler.prior.check(packet_body, data['candidate_packet'])
    packet = json.loads(packet_body)
    require(packet['source_pin_verified'], 'authenticated source packet required')
    case = data['case']
    require(case['component'] in baseline['remaining_components'] and packet['component_statuses'][case['component']] == 'PASS', 'target must remain unresolved and checksum-PASS')
    receipts = json.loads(read('requests.json'))['requests']
    compiler_document = tomllib.loads(read('../../primary-b/rustc_codegen_ssa-Cargo.toml').decode())
    bridge = object_declarations(read, receipts, data, compiler_document)
    inventory = json.loads(read('../../../../reports/rust.json'))
    vendor_normalized = {k: inventory['vendor_components']['object-0.38.1']['Cargo.toml'][k] for k in ('bytes', 'sha256')}
    require(bridge['docs_normalized_manifest_pin'] != vendor_normalized, 'review the vendor correspondence status if normalized bytes now match')
    bridge['authenticated_vendor_normalized_manifest_pin'] = vendor_normalized
    bridge['normalized_vendor_byte_correspondence'] = 'UNRESOLVED_DIFFERENT_BYTES; no vendor feature-resolution credit'
    entries = compiler.tree_entries(case, read, receipts)
    captures = [r for r in packet['candidates'] if r['crate'] == case['component']]
    binding = compiler.binding(case, captures, entries, read)
    source = compiler.bound_file(case, case['source_file'], case['source_path'], entries, read, receipts)
    source_url = 'https://raw.githubusercontent.com/' + case['repository'] + '/' + case['commit'] + '/' + case['source_path']
    receipt(receipts, source_url, source)
    record = next(r for r in captures if r['path'] == case['vendor_source_path'])
    correspondence = vendor_source_match(record, source)
    grant = compiler.bound_file(case, case['grant_file'], case['grant_upstream_path'], entries, read, receipts)
    grant_url = 'https://raw.githubusercontent.com/' + case['repository'] + '/' + case['commit'] + '/' + case['grant_upstream_path']
    receipt(receipts, grant_url, grant)
    compiler.file_notice_scope(case['manifest_path'], case['source_path'], case['grant_upstream_path'])
    compiler.grant_review('Apache-2.0', grant)
    compiler.notice_review(source, case['manual_named_notice'])
    require('Licensed under the Apache License, Version 2.0' in source.decode(), 'source Apache application header missing')
    lock = tomllib.loads(read('../../primary-b/Rust-Cargo.lock').decode())['package']
    paths = compiler.prior.dependency_paths(lock, [['rustc-main', '0.0.0'], ['rustc_driver', '0.0.0']])
    matches = [path for key, path in paths.items() if key[:2] == ('wasmparser', '0.243.0')]
    require(len(matches) == 1 and ['object', '0.38.1'] in [row[:2] for row in matches[0]], 'exact compiler/object/parser lock path missing')
    return {'schema': 1, 'baseline_unresolved': baseline['remaining_unresolved'], 'new_package_root_notice_cases_closed': 0,
            'remaining_unresolved': baseline['remaining_unresolved'], 'remaining_components': baseline['remaining_components'],
            'new_exact_vendor_source_file_notice_joins': 1, 'workspace_version_holds_resolved': 1,
            'package_binding': binding, 'static_compiler_lock_path': matches[0], 'object_source_declarations': bridge,
            'file_notice': {'scope': case['source_path'] + ' ONLY; not package/all-file closure', 'literal_named_notice': case['manual_named_notice'],
                            'source_origin_url': source_url, 'source_commit': case['commit'], 'source_git_blob_sha1': blob(source),
                            'vendor_source_correspondence': correspondence, 'grant_origin_url': grant_url,
                            'grant_pin': pin(grant), 'grant_git_blob_sha1': blob(grant)},
            'Linux_aarch64_Cargo_cfg_feature_resolution': 'NOT_EXECUTED_OR_PROVED',
            'package_all_file_legal_native_M2_release_acceptance': 'HELD', 'all_original_dirty_version_recipe_platform_holds': 'PRESERVED',
            'archives_checkout_download_build_package_actor_lease_trust_daemon_changes': 'NOT_RUN',
            'network': network_summary(json.loads(read('requests.json')))}


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
    print(json.dumps({k: result[k] for k in ('new_package_root_notice_cases_closed', 'new_exact_vendor_source_file_notice_joins', 'remaining_unresolved', 'network')}))
