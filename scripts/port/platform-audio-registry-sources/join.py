#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Join pinned official registry DATA to verified audio vendor member bytes."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tarfile

HERE = Path(__file__).resolve().parent
AUDITOR_SHA = '94b1c5c9196326354ec84d11b81c3cd114a3e0b9ba4fa914802db309cdb37d37'
PROFILE = 'e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8'
MAX_OBJECT, MAX_TOTAL = 16 * 1024**2, 256 * 1024**2


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('NONFINITE_OR_FLOAT_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def identity(name, version):
    need(type(name) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', name), 'REGISTRY_NAME')
    need(type(version) is str and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?', version), 'REGISTRY_VERSION')
    return name + '-' + version


def index_url(name):
    identity(name, '0.0.0')
    name = name.lower()
    prefix = '1' if len(name) == 1 else '2' if len(name) == 2 else '3/' + name[0] if len(name) == 3 else name[:2] + '/' + name[2:4]
    return 'https://index.crates.io/' + prefix + '/' + name


def archive_url(name, version):
    return 'https://static.crates.io/crates/' + name + '/' + identity(name, version) + '.crate'


def selected_index(raw, name, version):
    identity(name, version)
    need(0 < len(raw) <= MAX_OBJECT, 'INDEX_BYTE_LIMIT')
    selected = []
    for line in raw.splitlines():
        need(0 < len(line) <= 1024**2, 'INDEX_ROW_LIMIT')
        row = decode(line)
        need(type(row) is dict, 'INDEX_ROW_OBJECT')
        if row.get('name') == name and row.get('vers') == version:
            selected.append((row, line))
    need(len(selected) == 1, 'MISSING_OR_DUPLICATE_EXACT_INDEX_VERSION')
    row, line = selected[0]
    need(type(row.get('cksum')) is str and re.fullmatch('[0-9a-f]{64}', row['cksum']), 'INDEX_CHECKSUM')
    need(type(row.get('yanked')) is bool and type(row.get('v', 1)) is int and row.get('v', 1) in (1, 2), 'INDEX_SCHEMA')
    return {'row': row, 'row_bytes': len(line), 'row_sha256': digest(line)}


def registry_checksum(selected, vendor_checksum, raw):
    need(selected['row']['cksum'] == vendor_checksum, 'OFFICIAL_INDEX_VENDOR_CHECKSUM_DIFFERS')
    need(digest(raw) == selected['row']['cksum'], 'RAW_CRATE_REGISTRY_CHECKSUM_DIFFERS')


def trusted_auditor(checkout):
    path = checkout / 'scripts/port/platform-audio-vendor-audit/audit.py'
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ALIASED_TRUSTED_API')
    raw = path.read_bytes()
    need(len(raw) <= 65536 and digest(raw) == AUDITOR_SHA, 'TRUSTED_AUDITOR_PIN')
    spec = importlib.util.spec_from_file_location('registry_vendor_auditor', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def raw_members(a, raw, name, version, charge=None):
    need(0 < len(raw) <= MAX_OBJECT, 'RAW_CRATE_BYTE_LIMIT')
    # Retain the existing bounded parser, but refuse sparse representations
    # explicitly before it can reconstruct any sparse member.
    count, expanded = 0, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as stream:
        for member in stream:
            count += 1; expanded += member.size
            need(count <= a.MAX_MEMBERS and member.size <= a.MAX_FILE and expanded <= a.MAX_EXPANDED, 'RAW_CRATE_EXPANDED_LIMIT')
            need(member.sparse is None and not any(k.startswith('GNU.sparse.') for k in member.pax_headers), 'SPARSE_CRATE_MEMBER')
            if charge:
                charge(member.size)
    files = a.tar_data(raw)
    prefix = identity(name, version) + '/'
    need(all(path.startswith(prefix) for path in files), 'FOREIGN_CRATE_ROOT')
    return {path[len(prefix):]: body for path, body in files.items()}


def correspondence(a, raw, name, version, root, vendor_files, charge=None):
    files = raw_members(a, raw, name, version, charge)
    mapping = a.json_data(vendor_files[root + '/.cargo-checksum.json'])['files']
    need(set(mapping) == {path[len(root) + 1:] for path in vendor_files if path.startswith(root + '/')} - {'.cargo-checksum.json'}, 'VENDOR_FILE_MAP_DIFFERS')
    for path, expected in mapping.items():
        need(digest(vendor_files[root + '/' + path]) == expected, 'VENDOR_FILE_CHECKSUM_DIFFERS')
    missing, extra = sorted(set(mapping) - set(files)), sorted(set(files) - set(mapping))
    different = []
    for path in sorted(set(files) & set(mapping)):
        if files[path] != vendor_files[root + '/' + path]:
            different.append({'path': path, 'raw_sha256': digest(files[path]), 'vendor_sha256': mapping[path],
                              'raw_bytes': len(files[path]), 'vendor_bytes': len(vendor_files[root + '/' + path])})
    document = a.toml(files['Cargo.toml'])
    need(a.identity(document) == (name, version), 'RAW_MANIFEST_IDENTITY_DIFFERS')
    envelope = identity(name, version)
    license_observation = a.license_material(document, {envelope + '/' + k: v for k, v in files.items()}, envelope)
    return {'status': 'EXACT_MEMBER_BYTES' if not (missing or extra or different) else 'HOLD_MEMBER_DIFFERENCES',
            'raw_files': len(files), 'vendor_declared_files': len(mapping),
            'raw_regular_bytes': sum(map(len, files.values())),
            'missing': [{'path': p, 'vendor_sha256': mapping[p]} for p in missing],
            'extra': [{'path': p, 'raw_sha256': digest(files[p]), 'raw_bytes': len(files[p])} for p in extra],
            'different': different, 'raw_license_observation': license_observation}


def run(checkout, handoff, inputs_path, inputs_sha, material_root, output):
    a = trusted_auditor(checkout)
    intake = a.intake_module()
    raw = intake.ordinary(inputs_path, 1024**2)
    need(digest(raw) == inputs_sha, 'REGISTRY_INPUTS_PIN')
    inputs = decode(raw)
    need(set(inputs) == {'schema_version', 'kind', 'handoff_index_sha256', 'native_profile_sha256', 'vendor_audit_sha256',
                        'metadata', 'acquisition_receipt', 'sources'} and inputs['schema_version'] == 1
         and inputs['kind'] == 'finite-audio-official-registry-inputs-v1' and inputs['native_profile_sha256'] == PROFILE, 'REGISTRY_INPUTS_SCHEMA')
    audit, api = a.delivered(handoff, inputs['handoff_index_sha256'], PROFILE)
    need(a.digest(a.encoded(audit)) == inputs['vendor_audit_sha256'], 'RECOMPUTED_VENDOR_AUDIT_PIN')
    bundle = intake.ordinary(handoff / 'sources/bankstown/source.tar')
    _, bodies = api.verified(bundle, digest(bundle))
    vendor, vendor_files, _ = a.vendor_data(bodies['cargo-vendor-117.tar.xz'])
    need(len(vendor['crates']) == len(inputs['sources']) == 117, 'EXACT_117_IDENTITIES_REQUIRED')
    cache = {}
    def read(ref):
        need(set(ref) == {'path', 'size', 'sha256'}, 'MATERIAL_REFERENCE')
        a.relative(ref['path'])
        need(type(ref['size']) is int and 0 < ref['size'] <= MAX_OBJECT and re.fullmatch('[0-9a-f]{64}', ref['sha256']), 'MATERIAL_PIN')
        if ref['path'] not in cache:
            body = intake.ordinary(material_root / ref['path'], MAX_OBJECT)
            need(len(body) == ref['size'] and digest(body) == ref['sha256'], 'MATERIAL_BYTES_DIFFER')
            cache[ref['path']] = body
            need(sum(map(len, cache.values())) <= MAX_TOTAL, 'MATERIAL_AGGREGATE_LIMIT')
        need(len(cache[ref['path']]) == ref['size'] and digest(cache[ref['path']]) == ref['sha256'], 'CONTRADICTORY_MATERIAL_REFERENCE')
        return cache[ref['path']]
    metadata = decode(read(inputs['metadata']))
    need(metadata['source_handoff_index_sha256'] == inputs['handoff_index_sha256'] and metadata['native_profile_sha256'] == PROFILE, 'METADATA_HANDOFF_BINDING')
    reachable = {tuple(row['identity'][:2]) for record in metadata['packages'].values() for row in record['graph']['packages']
                 if row['identity'][2] == a.REGISTRY}
    receipt = decode(read(inputs['acquisition_receipt']))
    requests = {row['id']: row for row in receipt['objects']}
    reuse = {(row['name'], row['version']): row for row in receipt['cache_reuse']}
    need(len(requests) == len(receipt['objects']) and len(reuse) == len(receipt['cache_reuse']), 'DUPLICATE_ACQUISITION_RECORD')
    report = {'schema_version': 1, 'purpose': 'raw-registry-to-verified-audio-vendor-member-join',
              'status': 'SOURCE_DATA_JOIN_WITH_HOLDS', 'inputs_sha256': inputs_sha,
              'checker': {'bytes': Path(__file__).stat().st_size, 'sha256': digest(Path(__file__).read_bytes()),
                          'trusted_auditor_sha256': AUDITOR_SHA},
              'handoff_index_sha256': inputs['handoff_index_sha256'], 'vendor_audit_sha256': inputs['vendor_audit_sha256'],
              'native_profile_sha256': PROFILE, 'metadata_replay_reference': inputs['metadata'],
              'metadata_reachable_registry_identities': len(reachable), 'metadata_graph_scope': 'NEW_HOST_DEFAULT_FEATURE_METADATA_ONLY',
              'original_vendor_holds': audit['holds'], 'packages': [], 'errors': [],
              'original_source_publication_blockers': {name: row['publication_blockers'] for name, row in audit['source_bundles'].items()},
              'holds': ['REGISTRY_HTTPS_SNAPSHOT_IS_NOT_SIGNATURE_OR_CURRENT_SECURITY_ACCEPTANCE',
                        'ORIGINAL_COMPILER_STDLIB_LINKER_RUNTIME_SOURCE_CLOSURE_NOT_ESTABLISHED',
                        'ORIGINAL_NATIVE_FLAGS_FEATURES_BINARY_CORRESPONDENCE_NOT_ESTABLISHED',
                        'LICENSE_TEXT_PRESENCE_DOES_NOT_ACCEPT_TERMS_GRANTS_OR_COMPLETE_CORRESPONDING_SOURCE'],
              'signature_authentication': 'NOT_PERFORMED; independently fetched official HTTPS index snapshot/checksum join only',
              'security_or_revocation_freshness_accepted': False, 'original_compiler_flags_binary_correspondence': 'NOT_ESTABLISHED',
              'complete_corresponding_source_accepted': False, 'legal_acceptance': False,
              'code_execution': False, 'network': False, 'native_build': False, 'hardware': 'NOT RUN',
              'acquisition': {'https_requests': len(receipt['objects']), 'cache_reused': len(receipt['cache_reuse']),
                              'downloaded_body_bytes': receipt['downloaded_body_bytes'], 'receipt_reference': inputs['acquisition_receipt']}}
    seen, expanded_bytes = set(), 0
    def charge(size):
        nonlocal expanded_bytes
        expanded_bytes += size
        need(expanded_bytes <= MAX_TOTAL, 'RAW_AGGREGATE_EXPANDED_LIMIT')
    for source in inputs['sources']:
        need(set(source) == {'name', 'version', 'vendor_checksum', 'index_url', 'archive_url', 'index', 'archive', 'origin'}, 'SOURCE_RECORD_FIELDS')
        name, version = source['name'], source['version']; key = (name, version)
        identity(name, version); need(key not in seen, 'DUPLICATE_INPUT_IDENTITY'); seen.add(key)
        root = 'vendor/' + identity(name, version)
        need(root in vendor['crates'] and source['vendor_checksum'] == vendor['crates'][root]['package_checksum'], 'REGISTRY_VENDOR_IDENTITY')
        need(source['index_url'] == index_url(name) and source['archive_url'] == archive_url(name, version), 'OFFICIAL_EXACT_URLS_REQUIRED')
        index_request = requests['index-' + name.lower()]
        need(index_request['status'] == 200 and index_request['url'] == source['index_url']
             and index_request['material'] == source['index'], 'INDEX_ACQUISITION_ASSOCIATION')
        if source['origin'] == 'existing-Cargo-cache':
            need(key in reuse and reuse[key]['material'] == source['archive'], 'CACHE_PROVENANCE_ASSOCIATION')
        else:
            request = requests['crate-' + identity(name, version)]
            need(source['origin'] == 'official-static-HTTPS' and request['status'] == 200
                 and request['url'] == source['archive_url'] and request['material'] == source['archive'], 'CRATE_ACQUISITION_ASSOCIATION')
        row = {'name': name, 'version': version, 'reachable_in_new_metadata': key in reachable,
               'index_url': source['index_url'], 'index_snapshot': source['index'],
               'verified_vendor_package_checksum': source['vendor_checksum'],
               'archive_url': source['archive_url'], 'origin': source['origin']}
        try:
            selected = selected_index(read(source['index']), name, version)
            row['official_index'] = selected
            crate = read(source['archive'])
            registry_checksum(selected, source['vendor_checksum'], crate)
            row['archive'] = source['archive']
            row['correspondence'] = correspondence(a, crate, name, version, root, vendor_files, charge)
            if row['correspondence']['status'] != 'EXACT_MEMBER_BYTES':
                report['errors'].append({'name': name, 'version': version, 'code': 'MEMBER_DIFFERENCES'})
        except (ValueError, OSError, KeyError, TypeError, tarfile.TarError) as error:
            row['status'] = 'HOLD_INPUT_OR_FORMAT'; row['error'] = {'category': type(error).__name__, 'message': str(error)[:512]}
            report['errors'].append({'name': name, 'version': version, 'code': 'INPUT_OR_FORMAT'})
        report['packages'].append(row)
    need(seen == {(r['name'], r['version']) for r in vendor['crates'].values()} and reachable <= seen, 'COMPLETE_VENDOR_IDENTITY_SET')
    report['raw_crates_verified'] = sum('archive' in r for r in report['packages'])
    report['raw_expanded_bytes_charged'] = expanded_bytes
    report['exact_crates'] = sum(r.get('correspondence', {}).get('status') == 'EXACT_MEMBER_BYTES' for r in report['packages'])
    report['exact_member_files'] = sum(r.get('correspondence', {}).get('vendor_declared_files', 0) for r in report['packages']
                                      if r.get('correspondence', {}).get('status') == 'EXACT_MEMBER_BYTES')
    report['raw_license_text_candidates_present'] = sum(r.get('correspondence', {}).get('raw_license_observation', {}).get('text_presence', False) for r in report['packages'])
    if report['errors']:
        report['status'] = 'HOLD_REGISTRY_OR_MEMBER_JOIN_ERRORS'
    api.write_fresh(output, {'registry-source-join.json': encoded(report)})
    return report


if __name__ == '__main__':
    need(sys.flags.isolated, 'Python isolated mode (-I) required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-checkout', type=Path, default=HERE.parents[2])
    for name in ('handoff', 'inputs', 'materials', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--inputs-sha256', required=True)
    args = parser.parse_args()
    result = run(args.trusted_checkout, args.handoff, args.inputs, args.inputs_sha256, args.materials, args.output)
    print(json.dumps({k: result[k] for k in ('status', 'raw_crates_verified', 'exact_crates', 'exact_member_files', 'raw_license_text_candidates_present')}))
    raise SystemExit(bool(result['errors']))
