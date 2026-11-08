#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Compare two caller-authenticated local release SBOM exports, offline.

Reads only the explicitly selected SPDX and coverage documents. No archive,
network, subprocess, signature verification or package mutation is performed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

MAX_PACKAGES = 256
MAX_RELATIONSHIPS = 32768
MAX_NODES = 200000
MAX_DEPTH = 48
SOURCE = Path(__file__).with_name('source_delivery.py')


def helpers(path=SOURCE):
    spec = importlib.util.spec_from_file_location('sbom_comparison_source', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + '\n').encode()


def canonical(value):
    """Evidence lists are unordered multisets; retain duplicates and nulls."""
    if type(value) is dict:
        return {key: canonical(item) for key, item in value.items()}
    if type(value) is list:
        return sorted((canonical(item) for item in value), key=encoded)
    return value


def decode(raw, s):
    # Preflight nesting before invoking the JSON parser. Brackets in strings
    # (including escaped quotes) cannot affect the nesting counter.
    s.need(type(raw) is bytes and len(raw) <= s.MAX_JSON, 'JSON byte bound')
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            s.need(depth <= MAX_DEPTH, 'JSON depth bound')
        elif byte in (93, 125):
            depth -= 1
    value = s.decode(raw)
    stack, count = [value], 0
    while stack:
        item = stack.pop(); count += 1
        s.need(count <= MAX_NODES, 'JSON node bound')
        if type(item) is dict:
            stack.extend(item.keys()); stack.extend(item.values())
        elif type(item) is list:
            s.need(len(item) <= MAX_RELATIONSHIPS, 'JSON list bound')
            stack.extend(item)
        elif type(item) is str:
            s.need(len(item) <= s.MAX_JSON and not any(ord(c) < 32 or ord(c) == 127 for c in item),
                   'JSON string bound/control character')
        elif type(item) is int:
            s.need(abs(item) <= 2**63 - 1, 'JSON integer bound')
    return value


def rows(value, limit, s, label):
    s.need(type(value) is list and len(value) <= limit, label + ' list bound')
    return value


def text(value, s, label):
    s.need(type(value) is str and 0 < len(value) <= 4096, label + ' required')
    return value


def strings(value, s, label):
    for item in rows(value, MAX_RELATIONSHIPS, s, label):
        text(item, s, label)
    return value


def reference(row, s):
    s.need(type(row) is dict, 'evidence reference object required')
    s.relative(row.get('path')); s.sha(row.get('sha256'))
    s.need(type(row.get('bytes')) is int and 0 < row['bytes'] <= s.MAX_FILE,
           'evidence reference byte bound')
    return {key: row[key] for key in ('path', 'sha256', 'bytes')}


def load_export(directory, release_id, release_sha256, spdx_sha256, coverage_sha256, s):
    """Return only data from the two exact, hashed byte snapshots."""
    s.name(release_id)
    for pin in (release_sha256, spdx_sha256, coverage_sha256):
        s.sha(pin)
    raw_document = s.local_read(directory, 'sbom.spdx.json', s.MAX_JSON)
    raw_coverage = s.local_read(directory, 'coverage.json', s.MAX_JSON)
    s.need(s.digest(raw_document) == spdx_sha256, 'SPDX checksum mismatch')
    s.need(s.digest(raw_coverage) == coverage_sha256, 'coverage checksum mismatch')
    document, coverage = decode(raw_document, s), decode(raw_coverage, s)
    s.need(type(coverage.get('schema_version')) is int and coverage['schema_version'] == 1 and
           coverage.get('purpose') == 'release-sbom-coverage', 'coverage schema/purpose')
    s.need(coverage.get('release_id') == release_id and coverage.get('release_sha256') == release_sha256 and
           coverage.get('spdx_sha256') == spdx_sha256, 'export/release identity binding mismatch')
    s.need(type(coverage.get('synthetic')) is bool, 'synthetic flag required')
    s.need(document.get('spdxVersion') == 'SPDX-2.3' and document.get('SPDXID') == 'SPDXRef-DOCUMENT' and
           document.get('name') == 'cachy-asahi-' + release_id and
           document.get('dataLicense') == 'CC0-1.0', 'SPDX document identity/profile')
    s.need(type(document.get('documentNamespace')) is str and re.fullmatch(
        r'https://spdx.org/spdxdocs/cachy-asahi-[0-9a-f]{64}', document['documentNamespace']), 'SPDX namespace profile')
    inputs = {}
    for item in rows(coverage.get('input_files'), s.MAX_FILES, s, 'input files'):
        ref = reference(item, s)
        s.need(ref['path'] not in inputs, 'duplicate input path')
        inputs[ref['path']] = ref

    def joined(item):
        ref = reference(item, s)
        s.need(inputs.get(ref['path']) == ref, 'unbound evidence reference')
        return ref

    spdx = {}
    ids = {}
    for item in rows(document.get('packages'), MAX_PACKAGES, s, 'SPDX packages'):
        s.need(type(item) is dict, 'SPDX package object required')
        name = s.name(item.get('name'))
        sid = text(item.get('SPDXID'), s, 'SPDX package ID')
        s.need(name not in spdx and sid not in ids and sid != 'SPDXRef-DOCUMENT', 'duplicate SPDX package identity')
        spdx[name], ids[sid] = item, name
    packages, archives, artifact_hashes, provenance_paths = {}, set(), set(), set()
    for item in rows(coverage.get('packages'), MAX_PACKAGES, s, 'coverage packages'):
        s.need(type(item) is dict, 'coverage package object required')
        identity = s.identity(item.get('package')); name = identity['name']
        s.need(name not in packages and name in spdx, 'duplicate/foreign coverage package identity')
        package = spdx[name]
        sid = 'SPDXRef-Package-' + s.digest(encoded(identity))
        s.need(item.get('spdx_id') == package['SPDXID'] == sid and
               package.get('versionInfo') == identity['version'], 'SPDX/coverage package identity mismatch')
        checksums = package.get('checksums')
        s.need(checksums == [dict(algorithm='SHA256', checksumValue=identity['sha256'])],
               'SPDX/coverage artifact digest mismatch')
        archive, provenance = joined(item.get('archive')), joined(item.get('provenance'))
        s.need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(gz|xz|zst)',
                           text(package.get('packageFileName'), s, 'package filename')), 'package filename profile')
        s.need(archive['sha256'] == identity['sha256'] and archive['path'] == 'repo/' +
               text(package.get('packageFileName'), s, 'package filename'), 'archive identity mismatch')
        s.need(archive['path'] not in archives, 'duplicate package archive identity'); archives.add(archive['path'])
        s.need(archive['sha256'] not in artifact_hashes and provenance['path'] not in provenance_paths,
               'duplicate archive digest/provenance identity')
        artifact_hashes.add(archive['sha256']); provenance_paths.add(provenance['path'])
        s.sha(item.get('recipe_sha256'))
        declared = text(item.get('declared_license'), s, 'declared license')
        s.need(package.get('licenseDeclared') == declared and package.get('licenseConcluded') == 'NOASSERTION',
               'SPDX/coverage license mismatch or unsupported conclusion')
        raw = item.get('raw_license_declarations')
        s.fields(raw, ('pkginfo', 'release', 'provenance'))
        for values in raw.values():
            strings(values, s, 'raw licenses')
        license_paths = set()
        for ref in rows(item.get('bundled_license_evidence'), s.MAX_FILES, s, 'bundled licenses'):
            reference(ref, s)
            s.need(ref['path'].startswith('usr/share/licenses/'), 'bundled license path profile')
            s.need(ref['path'] not in license_paths, 'duplicate bundled license path')
            license_paths.add(ref['path'])
        sources = rows(item.get('pinned_source_references'), s.MAX_FILES, s, 'source references')
        urls = set()
        for source in sources:
            s.need(type(source) is dict, 'source reference object required')
            url = text(source.get('url'), s, 'source URL')
            s.need(url not in urls, 'duplicate source reference'); urls.add(url)
            for key in ('sha256', 'resolved_by_bundle_sha256'):
                if source.get(key) is not None:
                    s.sha(source[key])
            if source.get('commit') is not None:
                s.need(type(source['commit']) is str and re.fullmatch('[0-9a-f]{40}', source['commit']), 'source commit required')
            text(source.get('status'), s, 'source status')
        retained = item.get('retained_source')
        if retained is not None:
            s.need(type(retained) is dict, 'retained source object/null required')
            for key in ('bundle', 'recipe', 'source_map'):
                joined(retained.get(key))
            s.need(retained['recipe']['sha256'] == item['recipe_sha256'], 'retained recipe digest mismatch')
            notice_paths = set()
            for notice in rows(retained.get('notices'), s.MAX_FILES, s, 'source notices'):
                joined(notice)
                s.need(notice['path'] not in notice_paths, 'duplicate source notice path')
                notice_paths.add(notice['path'])
            for checksum in strings(retained.get('matched_license_sha256'), s, 'matched licenses'):
                s.sha(checksum)
            text(retained.get('profile'), s, 'source profile')
            strings(retained.get('issues'), s, 'source issues')
        for source in sources:
            if source.get('resolved_by_bundle_sha256') is not None:
                s.need(retained is not None and source['resolved_by_bundle_sha256'] == retained['bundle']['sha256'],
                       'source resolved bundle digest mismatch')
        source_info_raw = package.get('sourceInfo')
        s.need(type(source_info_raw) is str and 0 < len(source_info_raw.encode()) <= s.MAX_JSON, 'sourceInfo byte bound')
        source_info = decode(source_info_raw.encode(), s)
        s.need(canonical(source_info) == canonical(dict(architecture=identity['arch'], provenance=provenance['path'],
               retained_source_bundle=retained['bundle'] if retained else None, references=sources)),
               'SPDX/coverage source evidence mismatch')
        unresolved = strings(item.get('unresolved'), s, 'unresolved evidence')
        s.need(len(unresolved) == len(set(unresolved)) and item.get('status') ==
               ('UNRESOLVED' if unresolved else 'EVIDENCE_LINKED'), 'coverage unresolved status mismatch')
        for required in ('buildinfo', 'build_context', 'retained_build_record', 'retained_source'):
            s.need(required in item, 'missing coverage evidence field: ' + required)
        buildinfo = item['buildinfo']
        if buildinfo is not None:
            s.fields(buildinfo, ('sha256', 'installed', 'installed_lock_sha256'))
            s.sha(buildinfo['sha256']); s.sha(buildinfo['installed_lock_sha256'])
            installed = strings(buildinfo['installed'], s, 'buildinfo installed')
            installed_names = set()
            for entry in installed:
                parts = entry.rsplit('-', 3)
                s.need(len(parts) == 4 and all(parts), 'malformed buildinfo installed identity')
                s.name(parts[0])
                s.need(parts[0] not in installed_names, 'duplicate buildinfo installed identity')
                installed_names.add(parts[0])
            s.need(s.digest(('\n'.join(installed) + '\n').encode()) == buildinfo['installed_lock_sha256'],
                   'buildinfo installed lock digest mismatch')
        s.need(item['build_context'] is None or type(item['build_context']) is dict, 'build context object/null required')
        if item['retained_build_record'] is not None:
            joined(item['retained_build_record'])
        packages[name] = canonical(dict(identity=identity, artifact=archive,
            source_evidence=dict(recipe_sha256=item['recipe_sha256'], references=sources, retained=retained),
            license_evidence=dict(declared=declared, concluded=package['licenseConcluded'], raw=raw,
                                  bundled=item['bundled_license_evidence']),
            coverage=dict(status=item['status'], unresolved=unresolved), provenance=provenance,
            build_evidence={key: item[key] for key in ('buildinfo', 'build_context', 'retained_build_record')}))
    s.need(packages and set(packages) == set(spdx), 'nonempty exact SPDX/coverage package set required')
    s.need(type(coverage.get('package_count')) is int and coverage['package_count'] == len(packages) and
           type(coverage.get('unresolved_package_count')) is int and coverage['unresolved_package_count'] ==
           sum(bool(row['coverage']['unresolved']) for row in packages.values()), 'coverage count mismatch')
    relationships, seen, described = [], set(), set()
    for row in rows(document.get('relationships'), MAX_RELATIONSHIPS, s, 'relationships'):
        s.fields(row, ('spdxElementId', 'relationshipType', 'relatedSpdxElement'))
        left, kind, right = (row[key] for key in ('spdxElementId', 'relationshipType', 'relatedSpdxElement'))
        text(kind, s, 'relationship type')
        s.need(re.fullmatch('[A-Z][A-Z_]{0,63}', kind), 'malformed relationship type')
        s.need(type(left) is str and type(right) is str and left in ids.keys() | {'SPDXRef-DOCUMENT'} and
               right in ids.keys() | {'SPDXRef-DOCUMENT'}, 'unbound relationship endpoint')
        key = (left, kind, right)
        s.need(key not in seen, 'duplicate relationship'); seen.add(key)
        if left == 'SPDXRef-DOCUMENT' and kind == 'DESCRIBES' and right in ids:
            described.add(ids[right])
        relationships.append(dict(subject=ids.get(left, '$document'), relationship=kind,
                                  object=ids.get(right, '$document')))
    s.need(described == set(packages), 'incomplete document DESCRIBES relationships')
    return dict(identity=dict(release_id=release_id, release_sha256=release_sha256,
                spdx_sha256=spdx_sha256, coverage_sha256=coverage_sha256, synthetic=coverage['synthetic']),
                packages=packages, relationships=canonical(relationships))


def field_changes(before, after):
    # Same finite map-difference shape as maintenance/compare_releases.changes;
    # no importing that module's GPG/vercmp/release runtime for inert JSON.
    return [dict(name=name, before=before.get(name), after=after.get(name))
            for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]


def compare(before, after):
    changes = []
    left, right = before['packages'], after['packages']
    for name in sorted(left.keys() | right.keys()):
        old, new = left.get(name), right.get(name)
        if old is None or new is None:
            changes.append(dict(name=name, change='added' if old is None else 'removed', before=old, after=new))
        else:
            fields = field_changes(old, new)
            if fields:
                changes.append(dict(name=name, change='changed', fields=fields))
    def edges(export):
        return {encoded(row): row for row in export['relationships']}
    old_edges, new_edges = edges(before), edges(after)
    dependency_types = {'DEPENDS_ON', 'DEPENDENCY_OF', 'BUILD_DEPENDENCY_OF', 'DEV_DEPENDENCY_OF',
                        'OPTIONAL_DEPENDENCY_OF', 'PROVIDED_DEPENDENCY_OF', 'TEST_DEPENDENCY_OF', 'RUNTIME_DEPENDENCY_OF'}
    counts = {key: sum(row['relationship'] in dependency_types for row in export['relationships'])
              for key, export in (('before', before), ('after', after))}
    held = [dict(name=name, before=left.get(name, {}).get('coverage'), after=right.get(name, {}).get('coverage'),
                 before_license=left.get(name, {}).get('license_evidence', {}).get('declared'),
                 after_license=right.get(name, {}).get('license_evidence', {}).get('declared'))
            for name in sorted(left.keys() | right.keys()) if any(
                row and (row['coverage']['unresolved'] or row['license_evidence']['declared'] == 'NOASSERTION')
                for row in (left.get(name), right.get(name)))]
    return dict(schema_version=1, purpose='release-sbom-comparison', before=before['identity'], after=after['identity'],
        packages=changes, held_unknowns=held, relationships=dict(
            added=[new_edges[key] for key in sorted(new_edges.keys() - old_edges.keys())],
            removed=[old_edges[key] for key in sorted(old_edges.keys() - new_edges.keys())],
            dependency_relationship_count=counts, inventory_scope='RECORDED_RELATIONSHIPS_ONLY',
            dependency_completeness='NOT_ESTABLISHED', build_lock_is_dependency_graph=False),
        summary=dict(added=sum(row['change'] == 'added' for row in changes),
            removed=sum(row['change'] == 'removed' for row in changes),
            changed=sum(row['change'] == 'changed' for row in changes), held_unknowns=len(held)),
        signature_verification='NOT_PERFORMED_CALLER_MUST_AUTHENTICATE_ALL_INPUT_DIGESTS',
        legal_acceptance=False, security_assessment='NOT_PERFORMED', corresponding_source_completeness='NOT_ASSERTED',
        native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')


def human(report):
    totals = report['summary']
    lines = [report['before']['release_id'] + ' -> ' + report['after']['release_id'],
             '{added} added, {removed} removed, {changed} changed; {held_unknowns} held unknown.'.format(**totals)]
    for row in report['packages']:
        detail = ': ' + ', '.join(field['name'] for field in row['fields']) if 'fields' in row else ''
        lines.append(row['change'] + ' ' + row['name'] + detail)
    relations = report['relationships']
    lines.append('Recorded relationships: %d added, %d removed; dependency completeness NOT_ESTABLISHED.' %
                 (len(relations['added']), len(relations['removed'])))
    lines.append('Evidence comparison only; legal/security/source-completeness/release acceptance not asserted.')
    return '\n'.join(lines) + '\n'


def main(argv=None, s=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for side in ('before', 'after'):
        parser.add_argument('--' + side, type=Path, required=True, help='Explicit export directory')
        for key in ('release-id', 'release-sha256', 'spdx-sha256', 'coverage-sha256'):
            parser.add_argument('--' + side + '-' + key, required=True)
    parser.add_argument('--format', choices=('json', 'human'), default='json')
    args = parser.parse_args(argv)
    try:
        s = s or helpers()
        exports = [load_export(getattr(args, side), *(getattr(args, side + '_' + key) for key in
                    ('release_id', 'release_sha256', 'spdx_sha256', 'coverage_sha256')), s) for side in ('before', 'after')]
        report = compare(*exports)
        sys.stdout.write(encoded(report).decode() if args.format == 'json' else human(report))
        return 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
