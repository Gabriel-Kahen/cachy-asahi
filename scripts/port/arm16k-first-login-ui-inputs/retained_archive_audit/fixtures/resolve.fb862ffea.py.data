#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded catalog-only closure. Never install, download or execute packages.

vercmp adapts libalpm version.c, Pacman Development Team, copyright 2006-2024,
GPL version 2 or later, commit 138cbae58448b7fde90335526add3029875784ee.
Source SHA256: 28ee2f7ee82e5f526c1179c800688bdaa097c0f36a0df190f770d13c0a64a552.
No warranty; the corresponding COPYING is retained in the review artifacts.
"""
import argparse
import base64
import gzip
import hashlib
import io
import itertools
import json
import math
import os
from pathlib import Path
import re
import stat
import tarfile
import time

NAME = re.compile(r'[A-Za-z0-9@._+\-]+\Z')
VERSION = re.compile(r'(?:[0-9]+:)?[A-Za-z0-9._+~\-]+\Z')
DEPEND = re.compile(r'([A-Za-z0-9@._+\-]+)(?:(>=|<=|=|>|<)([^<>=]+))?\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
MAX_INPUT = 64 * 1024**2
MAX_DECODED = 1024 * 1024**2
MAX_METADATA_NODES = 8 * 1024**2
MAX_FILE_PATHS = 200000


class Refused(ValueError):
    pass


class Exhausted(Refused):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def json_document(raw):
    def reject(value):
        raise Refused('nonfinite-metadata')
    value = json.loads(raw, parse_constant=reject)
    deadline = time.monotonic() + 120
    finite_metadata(value, lambda: need(time.monotonic() <= deadline, 'resource-time'))
    return value


def finite_metadata(value, check):
    """Inspect all caller fields without serialization or recursive expansion."""
    nodes = size = 0
    active = set()
    stack = [('value', value, 0)]
    while stack:
        kind, item, depth = stack.pop()
        check()
        if kind == 'leave':
            active.remove(id(item))
            continue
        if kind == 'items':
            try:
                child = next(item)
            except StopIteration:
                continue
            stack.append(('items', item, depth))
            stack.append(('value', child, depth))
            continue
        nodes += 1
        need(nodes <= MAX_METADATA_NODES, 'resource-metadata-nodes')
        need(depth <= 128, 'resource-metadata-depth')
        if type(item) is float:
            need(math.isfinite(item), 'nonfinite-metadata')
            size += 8
        elif type(item) is int:
            size += max(1, (item.bit_length() + 7) // 8)
        elif type(item) is str:
            need(len(item) <= MAX_DECODED - size, 'resource-metadata-bytes')
            size += len(item.encode('utf-8'))
        elif item is None or type(item) is bool:
            size += 1
        else:
            need(type(item) in (dict, list), 'invalid-metadata-structure')
            need(id(item) not in active, 'invalid-metadata-cycle')
            active.add(id(item))
            stack.append(('leave', item, depth))
            children = itertools.chain.from_iterable(item.items()) if type(item) is dict else iter(item)
            stack.append(('items', iter(children), depth + 1))
        need(size <= MAX_DECODED, 'resource-metadata-bytes')


def _rpm(a, b):
    if a == b:
        return 0
    i = j = end_a = end_b = 0
    while i < len(a) and j < len(b):
        while i < len(a) and not a[i].isalnum():
            i += 1
        while j < len(b) and not b[j].isalnum():
            j += 1
        if i == len(a) or j == len(b):
            break
        if i - end_a != j - end_b:
            return 1 if i - end_a > j - end_b else -1
        numeric = a[i].isdigit()
        end_a, end_b = i, j
        while end_a < len(a) and (a[end_a].isdigit() if numeric else a[end_a].isalpha()):
            end_a += 1
        while end_b < len(b) and (b[end_b].isdigit() if numeric else b[end_b].isalpha()):
            end_b += 1
        if end_b == j:
            return 1 if numeric else -1
        one, two = a[i:end_a], b[j:end_b]
        if numeric:
            one, two = one.lstrip('0'), two.lstrip('0')
            if len(one) != len(two):
                return 1 if len(one) > len(two) else -1
        if one != two:
            return 1 if one > two else -1
        i, j = end_a, end_b
    if i == len(a) and j == len(b):
        return 0
    return -1 if (i == len(a) and not b[j].isalpha()) or (i < len(a) and a[i].isalpha()) else 1


def vercmp(a, b):
    """ASCII subset, exact libalpm segment/epoch/pkgrel comparison, no equivalence dedup."""
    def parts(value):
        need(isinstance(value, str) and 0 < len(value) <= 256 and value.isascii()
             and VERSION.fullmatch(value) and not value.endswith('-'), 'unsupported-version')
        epoch, version = value.split(':', 1) if ':' in value else ('0', value)
        version, release = version.rsplit('-', 1) if '-' in version else (version, None)
        need(bool(version) and (release is None or bool(release)), 'unsupported-version')
        return epoch, version, release
    first, second = parts(a), parts(b)
    for x, y in zip(first[:2], second[:2]):
        result = _rpm(x, y)
        if result:
            return result
    return _rpm(first[2], second[2]) if first[2] is not None and second[2] is not None else 0


def directive(text, provide=False):
    need(isinstance(text, str) and len(text) <= 512 and text.isascii(), 'invalid-directive')
    match = DEPEND.fullmatch(text)
    need(match is not None, 'invalid-directive')
    name, op, version = match.groups()
    need(not provide or op in (None, '='), 'invalid-provides-operator')
    if version is not None:
        vercmp(version, version)
    return name, op, version


def satisfies(effective, op, wanted):
    if op is None:
        return True
    if effective is None:
        return False
    result = vercmp(effective, wanted)
    return {'=': result == 0, '>=': result >= 0, '<=': result <= 0,
            '>': result > 0, '<': result < 0}[op]


class Limits:
    DEFAULTS = {'max_packages': 1024, 'max_edges': 16384, 'max_depth': 128,
                'max_seconds': 120, 'max_report_bytes': 16 * 1024**2}

    def __init__(self, **values):
        need(set(values) <= set(self.DEFAULTS), 'invalid-limit')
        for key, ceiling in self.DEFAULTS.items():
            value = values.get(key, ceiling)
            need(type(value) in ((int, float) if key == 'max_seconds' else (int,))
                 and 0 < value <= ceiling, 'invalid-limit')
            setattr(self, key, value)
        need(self.max_report_bytes >= 256, 'report-bound-too-small')


def identity(row):
    return {key: row[key] for key in ('name', 'version', 'repo')}


def archive_pin(archive):
    need(isinstance(archive, dict) and all(key in archive for key in
         ('filename', 'bytes', 'sha256', 'signature_sha256', 'signature_bytes')), 'invalid-archive-pin')
    need(isinstance(archive['filename'], str) and '/' not in archive['filename']
         and archive['filename'].endswith(('.pkg.tar.xz', '.pkg.tar.zst'))
         and type(archive['bytes']) is int and archive['bytes'] > 0
         and isinstance(archive['sha256'], str) and HASH.fullmatch(archive['sha256']), 'invalid-archive-pin')
    if archive['signature_bytes'] is None and archive['signature_sha256'] is None:
        return False
    need(type(archive['signature_bytes']) is int and archive['signature_bytes'] > 0
         and isinstance(archive['signature_sha256'], str) and HASH.fullmatch(archive['signature_sha256']), 'invalid-signature-pin')
    return True


def file_declarations(files):
    if files is None:
        return
    need(type(files) is list and len(files) <= MAX_FILE_PATHS
         and all(type(file) is str for file in files), 'invalid-file-list')
    need(len(files) == len(set(files)), 'duplicate-file-list')
    for file in files:
        need(0 < len(file) <= 4096 and not file.startswith('/')
             and all(part not in ('', '.', '..') for part in
                     (file[:-1] if file.endswith('/') else file).split('/'))
             and not re.search(r'[\x00-\x1f]', file), 'invalid-file-path')


def record(row):
    need(isinstance(row, dict), 'invalid-package-record')
    need(all(isinstance(row.get(key), str) and 0 < len(row[key]) <= 256
             for key in ('name', 'version', 'repo', 'arch')), 'invalid-package-identity')
    need(NAME.fullmatch(row['name']) and row['arch'] in ('aarch64', 'any'), 'invalid-package-identity')
    vercmp(row['version'], row['version'])
    if row.get('archive') is not None:
        archive_pin(row['archive'])
    for key in ('depends', 'provides', 'conflicts', 'replaces'):
        need(isinstance(row.get(key), list) and len(row[key]) <= 256, 'invalid-package-relations')
        for value in row[key]:
            directive(value, provide=key == 'provides')
    file_declarations(row.get('files'))
    return dict(row)


def witnesses(row, required):
    name, op, wanted = directive(required)
    ways = [(row['name'], row['version'], 'name')]
    ways += [(alias, version, raw) for raw in row['provides']
             for alias, _, version in [directive(raw, provide=True)]]
    return [{**identity(row), 'via': via, 'effective_version': version}
            for alias, version, via in ways if alias == name and satisfies(version, op, wanted)]


def resolve(anchors, catalog, roots, protected, *, limits=None, clock=time.monotonic, policy=None):
    """Explicit unique metadata selection; ambiguous alternatives are never chosen."""
    limits = limits or Limits()
    started = clock()
    result = {'schema_version': 1, 'purpose': 'unadopted-platform-residual-metadata-closure',
              'status': 'FAIL', 'metadata_graph_status': 'FAIL', 'selected': [], 'roots': [],
              'edges': [], 'cycles': [], 'blockers': [], 'policy_decisions': [],
              'transaction_accepted': False, 'archive_signature_authentication': 'NOT RUN',
              'ELF_runtime_installation_hardware': 'NOT RUN', 'system_mutation': False}
    selected, candidates, processed = {}, {}, set()
    blocked = set()

    def check():
        if clock() - started > limits.max_seconds:
            raise Exhausted('resource-time')

    def block(code, scope='graph', **details):
        entry = {'code': code, 'scope': scope, **details}
        key = encoded(entry)
        if key not in blocked:
            blocked.add(key)
            result['blockers'].append(entry)

    def add(row):
        check()
        if row['name'] in protected and row['version'] != protected[row['name']]:
            block('protected-replacement', package=row['name'], wanted=row['version'], protected=protected[row['name']])
            return False
        old = selected.get(row['name'])
        if old is not None:
            if identity(old) != identity(row):
                block('selected-version-contradiction', package=row['name'], selected=identity(old), wanted=identity(row))
                return False
            return True
        if len(selected) >= limits.max_packages:
            raise Exhausted('resource-package')
        selected[row['name']] = row
        return True

    def matching(rows, required):
        matches = []
        for row in rows:
            check()
            if witnesses(row, required):
                matches.append(row)
        return matches

    try:
        finite_metadata([anchors, catalog, roots, protected, policy], check)
        need(isinstance(anchors, list) and isinstance(catalog, list) and len(catalog) <= 32768, 'invalid-package-sets')
        need(isinstance(roots, list) and 0 < len(roots) <= 21, 'invalid-root-set')
        need(isinstance(protected, dict) and len(protected) <= 1024, 'invalid-protected-set')
        for name, version in protected.items():
            need(isinstance(name, str) and NAME.fullmatch(name), 'invalid-protected-identity')
            vercmp(version, version)
        anchor_rows, catalog_rows = [], []
        for source, target in [(anchors, anchor_rows), (catalog, catalog_rows)]:
            seen = set()
            for row in source:
                check()
                try:
                    item = record(row)
                except Refused as error:
                    if source is anchors:
                        raise
                    block('invalid-catalog-package', 'catalog', package=row.get('name') if isinstance(row, dict) else None,
                          reason=str(error))
                    continue
                key = (item['name'], item['version'], item['repo'])
                need(key not in seen, 'duplicate-package-identity')
                seen.add(key)
                target.append(item)
        for row in catalog_rows:
            aliases = {row['name'], *(directive(value, provide=True)[0] for value in row['provides'])}
            for alias in aliases:
                candidates.setdefault(alias, []).append(row)
        for row in anchor_rows:
            add(row)
        for name, version in protected.items():
            if name not in selected:
                block('missing-protected-anchor', package=name, protected=version)
        seen_roots = set()
        for root in roots:
            check()
            need(isinstance(root, dict) and set(root) == {'name', 'version', 'repo'}, 'invalid-root-pin')
            key = tuple(root[k] for k in ('name', 'version', 'repo'))
            need(key not in seen_roots, 'duplicate-root')
            seen_roots.add(key)
            matches = [row for row in candidates.get(root['name'], []) if identity(row) == root]
            if len(matches) != 1:
                block('unsatisfied-root-pin', package=root['name'], root=root)
                result['roots'].append({'root': root, 'status': 'UNRESOLVED'})
            else:
                result['roots'].append({'root': root, 'status': 'SELECTED' if add(matches[0]) else 'REFUSED'})

        def visit(name, path):
            check()
            if name in path:
                result['cycles'].append(path[path.index(name):] + [name])
                return
            if name in processed:
                return
            if len(path) >= limits.max_depth:
                raise Exhausted('resource-depth')
            row = selected[name]
            for required in row['depends']:
                check()
                if len(result['edges']) >= limits.max_edges:
                    raise Exhausted('resource-edge')
                alias = directive(required)[0]
                already = matching(list(selected.values()), required)
                eligible = already or matching(candidates.get(alias, []), required)
                alternatives = [proof for item in eligible for proof in witnesses(item, required)]
                edge = {'consumer': identity(row), 'requirement': required, 'alternatives': alternatives,
                        'status': 'UNRESOLVED', 'selected': None}
                result['edges'].append(edge)
                if len(eligible) > 1:
                    edge['status'] = 'AMBIGUOUS'
                    block('ambiguous-provider', package=name, requirement=required, alternatives=alternatives)
                elif not eligible:
                    block('unsatisfied-dependency', package=name, requirement=required,
                          rejected=[identity(item) for item in candidates.get(alias, [])])
                elif add(eligible[0]):
                    edge.update(status='SATISFIED', selected=identity(eligible[0]))
                    visit(eligible[0]['name'], path + [name])
            processed.add(name)

        for name in sorted(selected):
            visit(name, [])
        # Later roots can introduce alternate providers for earlier decisions.
        for edge in result['edges']:
            if edge['status'] == 'SATISFIED':
                eligible = matching(selected.values(), edge['requirement'])
                if len(eligible) > 1:
                    edge.update(status='AMBIGUOUS', alternatives=[proof for item in eligible
                        for proof in witnesses(item, edge['requirement'])])
                    block('ambiguous-provider', package=edge['consumer']['name'], requirement=edge['requirement'],
                          alternatives=[proof for item in eligible for proof in witnesses(item, edge['requirement'])])
        for name, row in selected.items():
            check()
            for field, code in [('conflicts', 'declared-conflict'), ('replaces', 'declared-replacement')]:
                for required in row[field]:
                    matches = [identity(other) for other in matching(
                        [other for other_name, other in selected.items() if other_name != name], required)]
                    if matches:
                        block(code, package=name, requirement=required, matches=matches)
        result['metadata_graph_status'] = 'FAIL' if result['blockers'] else 'PASS'
        ownership = {}
        for name, row in selected.items():
            check()
            archive = row.get('archive')
            if not isinstance(archive, dict) or not all(key in archive for key in
                    ('filename', 'bytes', 'sha256', 'signature_sha256', 'signature_bytes')):
                block('unknown-archive-pin', 'custody', package=name)
            else:
                if not archive_pin(archive):
                    block('unknown-signature-pin', 'custody', package=name)
            files = row.get('files')
            if files is None:
                block('unknown-file-ownership', 'ownership', package=name)
            else:
                for file in files:
                    if file.endswith('/'):
                        continue
                    ownership.setdefault(file, []).append(name)
            if row.get('hooks') is None:
                block('unknown-hooks', 'hooks', package=name)
            else:
                need(isinstance(row['hooks'], list) and all(isinstance(x, str) for x in row['hooks']), 'invalid-hook-decisions')
                if row['hooks']:
                    block('unreviewed-hooks', 'hooks', package=name)
            review = row.get('review') or {}
            need(isinstance(review, dict), 'invalid-review-record')
            for field in ('source_revision', 'license_review', 'grant_review', 'maintainer'):
                value = review.get(field)
                known = isinstance(value, str) and 0 < len(value) <= 256 and bool(value.strip()) and value.strip().upper() not in (
                    'UNKNOWN', 'UNRESOLVED', 'UNASSIGNED', 'NOT RUN', 'FAIL', 'UNREVIEWED')
                if field == 'source_revision':
                    known = bool(known and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value))
                status = 'RECORDED' if known else 'UNKNOWN'
                result['policy_decisions'].append({'package': name, 'field': field, 'status': status})
                if status == 'UNKNOWN':
                    block('unknown-' + field.replace('_', '-'), 'review', package=name)
        for path, owners in ownership.items():
            if len(owners) > 1:
                block('file-ownership-collision', 'ownership', path=path, packages=owners)
        result['selected'] = [selected[name] for name in sorted(selected)]
        result['duplicate_declarations'] = [{'package': name, 'field': field, 'directive': value, 'occurrences': row[field].count(value)}
            for name, row in selected.items() for field in ('depends', 'provides', 'conflicts', 'replaces')
            for value in sorted(set(row[field])) if row[field].count(value) > 1]
        result['archive_budget'] = {'declared_compressed_bytes': sum(row['archive']['bytes'] for row in selected.values() if row.get('archive')),
            'declared_signature_bytes': sum(row['archive']['signature_bytes'] or 0 for row in selected.values() if row.get('archive')),
            'complete': all(row.get('archive') is not None and row['archive']['signature_bytes'] is not None for row in selected.values()),
            'source_bytes': 'UNKNOWN', 'acquisition_authorized': False}
        result['status'] = 'FAIL' if result['blockers'] else 'PASS'
        check()
    except (Refused, KeyError, TypeError, RecursionError) as error:
        code = str(error) if isinstance(error, Refused) else 'invalid-evidence-structure'
        block(code)
        result['metadata_graph_status'] = result['status'] = 'FAIL'
        result['selected'] = [selected[name] for name in sorted(selected)]
    result['elapsed_seconds'] = max(0, clock() - started)
    if len(encoded(result)) > limits.max_report_bytes:
        result = {'status': 'FAIL', 'metadata_graph_status': 'FAIL',
                  'blockers': [{'code': 'resource-report', 'scope': 'graph'}]}
    return result


def bound(reference):
    need(isinstance(reference, dict) and set(reference) >= {'path', 'sha256'}, 'invalid-reference')
    size = reference.get('size', reference.get('bytes'))
    need(type(size) is int and 0 < size <= MAX_INPUT and HASH.fullmatch(reference['sha256']), 'invalid-reference')
    path = Path(reference['path'])
    need(path.is_absolute(), 'absolute-reference-required')
    for ancestor in [path, *path.parents]:
        need(not ancestor.is_symlink(), 'linked-reference-refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size, 'ordinary-reference-required')
        if 'mode' in reference:
            need(stat.S_IMODE(before.st_mode) == reference['mode'], 'reference-mode-differs')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(size + 1)
            after = os.fstat(stream.fileno())
    finally:
        if fd is not None:
            os.close(fd)
    need(all(getattr(before, key) == getattr(after, key) for key in
             ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')), 'reference-drift')
    need(len(raw) == size and digest(raw) == reference['sha256'], 'reference-binding-differs')
    return raw


def fields(raw):
    need(len(raw) <= 16 * 1024**2, 'catalog-member-bound')
    result, key = {}, None
    for line in raw.decode('utf-8').splitlines():
        if not line:
            key = None
        elif line.startswith('%') and line.endswith('%'):
            key = line[1:-1]
            need(re.fullmatch(r'[A-Z0-9_]+', key) and key not in result, 'invalid-catalog-field')
            result[key] = []
        else:
            need(key is not None and len(line) <= 16384, 'invalid-catalog-value')
            result[key].append(line)
    return result


def read_catalog(raw, repo, deadline):
    grouped, consumed, unavailable = {}, 0, set()
    class Decoded:
        def __init__(self):
            self.stream = gzip.GzipFile(fileobj=io.BytesIO(raw))
            self.bytes = 0

        def read(self, size):
            need(0 <= size <= 16 * 1024**2, 'catalog-read-bound')
            need(time.monotonic() <= deadline, 'resource-time')
            data = self.stream.read(min(size, MAX_DECODED - self.bytes + 1))
            self.bytes += len(data)
            need(self.bytes <= MAX_DECODED, 'catalog-decoded-bound')
            return data

        def close(self):
            self.stream.close()

    decoded = Decoded()
    with decoded.stream, tarfile.open(fileobj=decoded, mode='r|') as archive:
        for count, member in enumerate(archive):
            need(time.monotonic() <= deadline, 'resource-time')
            need(count < 100000, 'catalog-member-count')
            if member.isdir():
                continue
            need(member.isfile() and re.fullmatch(r'[^/]+/(desc|depends|files)', member.name), 'invalid-catalog-member')
            consumed += member.size
            need(consumed <= MAX_DECODED and member.size <= 16 * 1024**2, 'catalog-decoded-bound')
            directory, kind = member.name.rsplit('/', 1)
            need(directory not in ('.', '..') and len(directory) <= 512
                 and re.fullmatch(r'[A-Za-z0-9@._+~:\-]+', directory), 'invalid-catalog-member')
            if member.issparse() or any(key.startswith('GNU.sparse.') for key in member.pax_headers):
                unavailable.add(directory)
                grouped.pop(directory, None)
                continue
            if directory in unavailable:
                continue
            data = archive.extractfile(member).read(member.size + 1)
            need(len(data) == member.size, 'short-catalog-member')
            rows = grouped.setdefault(directory, {})
            need(kind not in rows, 'duplicate-catalog-member')
            rows[kind] = {'fields': fields(data), 'sha256': digest(data), 'bytes': len(data)}
    return grouped, sorted(unavailable)


def catalog_packages(grouped, repo, source):
    output = []
    for directory, members in grouped.items():
        need('desc' in members, 'missing-catalog-descriptor')
        combined = {}
        for kind, member in members.items():
            if kind == 'files':
                continue
            need(not set(combined) & set(member['fields']), 'duplicate-catalog-metadata')
            combined.update(member['fields'])
        def single(key):
            need(len(combined.get(key, [])) == 1, 'missing-catalog-identity')
            return combined[key][0]
        signature = base64.b64decode(single('PGPSIG'), validate=True) if combined.get('PGPSIG') else None
        output.append({'name': single('NAME'), 'version': single('VERSION'), 'repo': repo, 'arch': single('ARCH'),
            'depends': combined.get('DEPENDS', []), 'provides': combined.get('PROVIDES', []),
            'conflicts': combined.get('CONFLICTS', []), 'replaces': combined.get('REPLACES', []),
            'archive': {'filename': single('FILENAME'), 'bytes': int(single('CSIZE')), 'sha256': single('SHA256SUM'),
                        'signature_bytes': len(signature) if signature is not None else None,
                        'signature_sha256': digest(signature) if signature is not None else None},
            'files': None, 'hooks': None, 'review': None, 'licenses_declared': combined.get('LICENSE', []),
            'catalog_evidence': {'reference': source, 'directory': directory,
                                 'member_pins': {key: {k: v for k, v in row.items() if k != 'fields'} for key, row in members.items()}}})
    return output


def run_contract(contract, *, started=None):
    """Resolve the held B18 metadata contract, preserving its strict/proposal distinction."""
    started = time.monotonic() if started is None else started
    deadline = started + 120
    finite_metadata(contract, lambda: need(time.monotonic() <= deadline, 'resource-time'))
    need(contract.get('schema_version') == 1 and contract.get('kind') == 'B18-frozen-metadata-input-contract', 'invalid-contract')
    need(contract['policy']['python_protected_version'] == '3.14.7-1'
         and contract['policy']['coordinated_python3.14.8_incorporated'] is False
         and contract['policy']['proposal624_accepted'] is False, 'strict-policy-required')
    references = [contract['anchor_packages'], contract['protected_identities'], contract['roots_source_ref'],
                  *contract['source_refs'].values()]
    captured = {}
    for reference in references:
        need(time.monotonic() <= deadline, 'resource-time')
        if reference['path'] not in captured:
            captured[reference['path']] = bound(reference)
        else:
            need(digest(captured[reference['path']]) == reference['sha256'], 'contradictory-reference')
    anchor_document = json_document(captured[contract['anchor_packages']['path']])
    protected_document = json_document(captured[contract['protected_identities']['path']])
    classification = json_document(captured[contract['roots_source_ref']['path']])
    anchors = anchor_document['packages']
    protected = {row['name']: row['version'] for row in protected_document['packages']}
    need(len(anchors) == 261 and len({row['name'] for row in anchors}) == 261
         and len(protected) == 201 and protected['python'] == '3.14.7-1', 'exact-anchor-boundary-required')
    need(anchor_document['dependency_transaction_accepted'] is False
         and protected_document['dependency_transaction_accepted'] is False, 'anchor-acceptance-claim-refused')
    roots = [{key: row[key] for key in ('name', 'version', 'repo')} for row in contract['roots']]
    proposals = classification['provider_proposals']
    expected = [{'name': name, 'version': row['metadata']['VERSION'][0], 'repo': row['repo']}
                for name, row in sorted(proposals.items())]
    need(roots == expected and len(roots) == 21 and classification['all27_requests_still_open'], 'exact-residual-root-binding-required')
    catalog, all_catalog, diagnostics = [], [], []
    for reference in contract['catalogs']['databases']:
        need(reference['name'] in ('core', 'extra', 'asahi-alarm'), 'foreign-catalog')
        raw = captured.get(reference['path'])
        if raw is None:
            raw = bound(reference)
            captured[reference['path']] = raw
        grouped, unavailable = read_catalog(raw, reference['name'], deadline)
        rows = catalog_packages(grouped, reference['name'], reference)
        all_catalog.extend(rows)
        if reference['name'] in ('core', 'extra'):
            catalog.extend(rows)
        diagnostics.extend({'repo': reference['name'], 'entry': entry, 'reason': 'sparse-unavailable'} for entry in unavailable)
    for anchor in anchors:
        anchor['files'] = anchor['filelist']['fields'].get('FILES', [])
        anchor['observed_hook_facts'] = anchor['hooks']
        anchor['hooks'], anchor['review'] = None, None
        # An equal-version catalog declaration is not installed-payload authentication.
        same = [row for row in all_catalog if row['name'] == anchor['name'] and row['version'] == anchor['version']]
        if len(same) == 1:
            anchor['archive'] = same[0]['archive']
            anchor['archive_repo'] = same[0]['repo']
            anchor['archive_pin_scope'] = 'equal-version catalog declaration only; installed bytes NOT VERIFIED'
            anchor['archive_catalog_evidence'] = same[0]['catalog_evidence']
        else:
            observation = anchor.get('retained_archive_observation')
            if observation is not None:
                reference = observation['reference']
                anchor['archive'] = {'filename': Path(reference['path']).name, 'bytes': reference['size'],
                    'sha256': reference['sha256'], 'signature_bytes': None, 'signature_sha256': None}
                anchor['archive_repo'] = None
                anchor['archive_pin_scope'] = 'retained inert archive observation only; signature pin UNKNOWN'
            else:
                anchor['archive_pin_scope'] = 'UNKNOWN; no exact-version catalog or retained archive declaration'
    # File catalogs remain inert; hash-bound declared paths only, no extraction.
    file_refs = {}
    for repo, reference in contract['catalogs']['filelists'].items():
        raw = captured.get(reference['path'])
        if raw is None:
            raw = bound(reference)
            captured[reference['path']] = raw
        grouped, unavailable = read_catalog(raw, repo, deadline)
        file_refs[repo] = grouped
        diagnostics.extend({'repo': repo, 'entry': entry, 'reason': 'sparse-filelist-unavailable'} for entry in unavailable)
    for row in catalog:
        directory = row['catalog_evidence']['directory']
        entry = file_refs.get(row['repo'], {}).get(directory, {})
        if 'files' in entry:
            row['files'] = entry['files']['fields'].get('FILES', [])
            row['filelist_evidence'] = {'reference': contract['catalogs']['filelists'][row['repo']],
                'member': directory + '/files', 'sha256': entry['files']['sha256'], 'bytes': entry['files']['bytes']}
    remaining = deadline - time.monotonic()
    need(remaining > 0, 'resource-time')
    report = resolve(anchors, catalog, roots, protected, limits=Limits(max_seconds=min(remaining, 120)))
    report['input_references'] = [{**reference, 'sha256_rechecked': True} for reference in references]
    report['protected_decisions'] = [{'name': name, 'version': version,
        'status': 'PRESERVED' if any(row['name'] == name and row['version'] == version for row in report.get('selected', [])) else 'UNRESOLVED'}
        for name, version in sorted(protected.items())]
    report['strict_proposal_boundary'] = contract['prior_transactions_context_only']
    report['catalog_diagnostics'] = diagnostics
    if diagnostics:
        report['blockers'].append({'code': 'catalog-unavailable-entries', 'scope': 'catalog', 'count': len(diagnostics)})
        report['status'] = report['metadata_graph_status'] = 'FAIL'
    selected = {row['name']: row for row in report.get('selected', [])}
    report['original_requests'] = [{**row, 'resolution': 'OPEN-not-acquired-or-integrated',
        'provider_metadata_selected': row['proposed_provider_name'] in selected,
        'consumer_in_strict_graph': row['name'] in selected and selected[row['name']]['version'] == row['consumer_version'],
        'provider_ELF_identity_inspected': False} for row in classification['requests']]
    report['first_level_frontier'] = [{'requirement': required,
        'selected_witnesses': [proof for row in selected.values() for proof in witnesses(row, required)],
        'metadata_state': 'WITNESSES_RECORDED_ONLY'} for required in classification['candidate_direct_missing_mandatory_directives']]
    report['catalog_count'] = len(catalog)
    anchor_names = {row['name'] for row in anchors}
    extension = [row for name, row in selected.items() if name not in anchor_names]
    report['extension_budget'] = {'packages': len(extension), 'direct_roots': 21,
        'declared_compressed_bytes': sum(row['archive']['bytes'] for row in extension if row.get('archive')),
        'declared_signature_bytes': sum(row['archive']['signature_bytes'] or 0 for row in extension if row.get('archive')),
        'complete_archive_pins': all(row.get('archive') and row['archive']['signature_bytes'] is not None for row in extension),
        'source_bytes': 'UNKNOWN', 'acquisition_authorized': False}
    report['ownership_scope'] = 'declared image/file-catalog paths only; archive types, links, installed namespace and hook effects NOT VERIFIED'
    report['elapsed_seconds'] = time.monotonic() - started
    if report['elapsed_seconds'] > 120:
        report['blockers'].append({'code': 'resource-time', 'scope': 'graph'})
        report['status'] = report['metadata_graph_status'] = 'FAIL'
    if len(encoded(report)) > 16 * 1024**2:
        return {'status': 'FAIL', 'metadata_graph_status': 'FAIL', 'blockers': [{'code': 'resource-report'}]}
    # Recheck every retained input after in-memory processing, before publication.
    for reference in references:
        need(bound(reference) == captured[reference['path']], 'input-drift-after-resolution')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    started = time.monotonic()
    path = Path(args.contract)
    reference = {'path': str(path.absolute()), 'size': path.stat().st_size, 'sha256': args.contract_sha256}
    try:
        contract = json_document(bound(reference))
        report = run_contract(contract, started=started)
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as error:
        report = {'status': 'FAIL', 'metadata_graph_status': 'FAIL',
                  'blockers': [{'code': str(error) if isinstance(error, Refused) else 'invalid-contract-or-input'}],
                  'elapsed_seconds': time.monotonic() - started, 'transaction_accepted': False}
    raw = encoded(report)
    need(len(raw) <= 16 * 1024**2, 'resource-report')
    output = Path(args.output).absolute()
    owned = path.absolute().parent.parent
    need(owned.name == 'residual-transaction-20261012' and owned.parent.name == 'platform'
         and owned.parent.parent.name == 'artifacts' and output.is_relative_to(owned)
         and not any(p.is_symlink() for p in [output, *output.parents]), 'owned-artifact-output-required')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    print(json.dumps({'status': report['status'], 'metadata_graph_status': report['metadata_graph_status'],
                      'report_sha256': digest(raw), 'report_bytes': len(raw)}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
