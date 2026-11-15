#!/usr/bin/env python3
"""One exact composite wrapper/submodule grant-notice join; distinct scopes."""
import argparse
import configparser
import importlib.util
import json
from pathlib import Path
import re
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_e', HERE.parent / 'successor-e/reevaluate.py')
preceding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preceding)
compiler = preceding.compiler
require, pin, blob = compiler.require, compiler.prior.pin, compiler.prior.blob
source_text = preceding.preceding.preceding.source_text


def restore_manifest(record, body):
    compiler.prior.check(body, {k: record[k] for k in ('bytes', 'sha256')})
    prefix = record['text'].encode()
    require(record['utf8_replacement_used'] is False and len(prefix) == record['captured_bytes'] and
            pin(prefix)['sha256'] == record['captured_prefix_sha256'] and body.startswith(prefix), 'original manifest prefix mismatch')
    return {**record, 'text': body.decode('utf-8', errors='strict'), 'complete_text': True}


def submodule_identity(case, entries, modules_body):
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(modules_body.decode())
    section = 'submodule "pq-src/source"'
    require(config.has_section(section) and config[section]['path'] == case['submodule_path'] and
            config[section]['url'] == 'https://github.com/' + case['submodule_repository'], 'declared submodule path/repository mismatch')
    entry = entries[case['submodule_path']]
    require(entry['type'] == 'commit' and entry['mode'] == '160000' and entry['sha'] == case['submodule_commit'], 'exact source Gitlink mismatch')
    return {'path': case['submodule_path'], 'repository': case['submodule_repository'], 'commit': entry['sha'], 'git_mode': entry['mode']}


def postgres_grant(body, notices):
    text = ' '.join(body.decode().split())
    require(all(s in text for s in [
        'Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted',
        'provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.',
        'IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE',
        'THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES',
        'THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS',
        'NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.']), 'complete PostgreSQL permission/notice/disclaimers required')
    actual_notices = [line for line in body.decode().splitlines() if line.startswith('Portions Copyright')]
    require(len(notices) == 2 and len(set(notices)) == 2 and notices == actual_notices, 'both distinct PostgreSQL copyright notices required')
    for notice in notices:
        compiler.notice_review(body, notice)


def network_summary(ledger):
    rows = ledger['requests']
    require(all(isinstance(r.get('bytes'), int) and 0 <= r['bytes'] <= 256 * 1024 for r in rows), 'invalid per-file body receipt')
    size, elapsed = sum(r['bytes'] for r in rows), ledger['stopped_epoch'] - ledger['started_epoch']
    require(len(rows) <= 50 and size == ledger['body_bytes'] and size <= 2 * 1024**2, 'network budget/accounting mismatch')
    require([r['ordinal'] for r in rows] == list(range(1, len(rows) + 1)), 'request ordinal mismatch')
    require(ledger.get('acquisition_closed') is True and 0 <= elapsed <= 900, 'acquisition deadline/closure mismatch')
    return {'new_actual_HTTP_requests': len(rows), 'new_response_body_bytes': size, 'acquisition_seconds': round(elapsed, 3),
            'redirect_or_error_requests': [r['ordinal'] for r in rows if r.get('HTTP') != 200 or not r.get('complete_body')], 'offline_replay_requests': 0}


def evaluate(packet_path):
    data = json.loads((HERE / 'cases.json').read_text())
    def read(name):
        body = (HERE / name).read_bytes()
        compiler.prior.check(body, data['evidence_files'][name])
        return body
    for name in data['evidence_files']:
        read(name)
    baseline = preceding.evaluate(packet_path)
    require(baseline == json.loads(read('../successor-e/report.json')), 'preceding replay changed')
    packet_body = packet_path.read_bytes()
    compiler.prior.check(packet_body, data['candidate_packet'])
    packet = json.loads(packet_body)
    require(packet['source_pin_verified'], 'authenticated source packet required')
    case = data['case']
    require(case['component'] in baseline['remaining_components'] and packet['component_statuses'][case['component']] == 'PASS', 'target outside unresolved checksum-PASS baseline')
    ledger = json.loads(read('requests.json'))
    receipts = [r for r in ledger['requests'] if r.get('complete_body') is True]
    captures = [r for r in packet['candidates'] if r['crate'] == case['component']]
    orig = next(r for r in captures if r['path'].endswith('/Cargo.toml.orig'))
    html = read(case['manifest_source_html'])
    preceding.preceding.preceding.receipt(receipts, case['manifest_source_url'], html)
    restored = source_text.extract(html)
    require(restored == read(case['restored_manifest']), 'restored manifest extraction changed')
    restored_record = restore_manifest(orig, restored)
    # Supplement in memory only; the frozen historical partial capture is untouched.
    joined_captures = [restored_record if r is orig else r for r in captures]
    entries = compiler.tree_entries(case, read, receipts)
    binding = compiler.binding(case, joined_captures, entries, read)
    package = tomllib.loads(restored.decode())['package']
    require(package['license'] == 'PostgreSQL' and package['repository'] == 'https://github.com/' + case['repository'] and
            package['readme'] == 'README.md' and 'source/src/interfaces/libpq/fe-exec.c' in package['include'], 'declared package/PostgreSQL source scope changed')
    wrapper, wrapper_url = preceding.preceding.primary_body(case, 'evidence/pq-wrapper-LICENSE-MIT', 'LICENSE-MIT', entries, read, receipts)
    compiler.grant_review('MIT', wrapper)
    compiler.notice_review(wrapper, case['wrapper_notice'])
    readme, readme_url = preceding.preceding.primary_body(case, 'evidence/pq-README.md', 'pq-src/README.md', entries, read, receipts)
    retained_readme = next(r for r in captures if r['path'].endswith('/README.md'))
    compiler.prior.check(readme, {k: retained_readme[k] for k in ('bytes', 'sha256')})
    require('Licensed under either of' in readme.decode() and 'MIT license ([LICENSE-MIT](LICENSE-MIT)' in readme.decode(), 'wrapper README MIT alternative missing')
    modules, modules_url = preceding.preceding.primary_body(case, 'evidence/pq-gitmodules', '.gitmodules', entries, read, receipts)
    identity = submodule_identity(case, entries, modules)
    child = {'repository': case['submodule_repository'], 'commit': case['submodule_commit'], 'tree_file': 'evidence/postgres-root-tree.json'}
    child_entries = compiler.tree_entries(child, read, receipts)
    grant, grant_url = preceding.preceding.primary_body(child, 'evidence/postgres-COPYRIGHT', 'COPYRIGHT', child_entries, read, receipts)
    postgres_grant(grant, case['postgres_notices'])
    configure, configure_url = preceding.preceding.primary_body(child, 'evidence/postgres-configure.ac', 'configure.ac', child_entries, read, receipts)
    version = re.search(r'AC_INIT\(\[PostgreSQL\], \[([^\]]+)\]', configure.decode())
    require(version is not None and version.group(1) == '17.4', 'exact child version metadata mismatch')
    remaining = sorted(set(baseline['remaining_components']) - {case['component']})
    generated = []
    for row in packet['candidates']:
        if row['crate'].startswith('ra-ap-rustc_') and row['path'].endswith('/Cargo.toml.orig'):
            description = tomllib.loads(row['text'])['package']['description']
            require('ce89c898570852a1bb441d77570596e50bf362c2' in description and
                    'https://github.com/rust-analyzer/rustc-auto-publish' in description, 'generated source declaration changed')
            require(row['crate'] in remaining, 'generated manifest hold must remain unresolved')
            generated.append(row['crate'])
    return {'schema': 1, 'baseline_unresolved': baseline['remaining_unresolved'], 'new_scoped_package_notice_cases_closed': 1,
            'closed_components': [case['component']], 'remaining_unresolved': len(remaining), 'remaining_components': remaining,
            'package_binding': binding, 'status': 'UPSTREAM_WRAPPER_AND_DECLARED_SUBMODULE_GRANT_NOTICE_EVIDENCE_COMPLETE',
            'package_declared_license': package['license'],
            'restored_manifest': {'original_capture_complete_text': orig['complete_text'], 'captured_prefix_bytes': orig['captured_bytes'],
                                  'restored_complete_pin': pin(restored), 'published_source_url': case['manifest_source_url'], 'private_capture_changed': False},
            'wrapper_scope': {'selected_README_alternative': 'MIT', 'notice': case['wrapper_notice'], 'grant_origin_url': wrapper_url,
                              'grant_pin': pin(wrapper), 'grant_git_blob_sha1': blob(wrapper), 'README_origin_url': readme_url,
                              'README_pin': pin(readme), 'ownership_transferred_to_bundled_C': False},
            'declared_bundled_source_scope': {**identity, 'gitmodules_origin_url': modules_url, 'gitmodules_pin': pin(modules),
                                            'grant_origin_url': grant_url, 'grant_pin': pin(grant), 'grant_git_blob_sha1': blob(grant), 'notices': case['postgres_notices'],
                                            'child_source_version_metadata': version.group(1), 'version_origin_url': configure_url, 'version_pin': pin(configure)},
            'license_expression_wrapper_vs_bundled_source_interpretation': 'HELD; both actual grants retained, no blanket MIT relabeling',
            'vendor_C_to_declared_submodule_full_projection_and_third_party_notices': 'HELD; no all-file coverage claimed',
            'generated_package_attempt': {'components': sorted(generated), 'declared_Rust_source_commit': 'ce89c898570852a1bb441d77570596e50bf362c2',
                                          'publisher_revision_and_generated_manifest_transformation': 'UNPROVED', 'missing_VCS_hold': 'PRESERVED', 'closure_credit': 0},
            'core_objc_attempt': {'components': ['block2-0.6.2', 'objc2-0.6.3'], 'complete_grant_not_established': True, 'closure_credit': 0},
            'actual_target_activation_all_file_legal_native_M2_release_acceptance': 'HELD',
            'object_mismatch_dirty_version_platform_and_prior_holds': 'PRESERVED',
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
    print(json.dumps({k: result[k] for k in ('new_scoped_package_notice_cases_closed', 'remaining_unresolved', 'network')}))
