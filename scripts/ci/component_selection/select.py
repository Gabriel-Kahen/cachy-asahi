#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure conservative component selection; no Git, API, network or subprocess."""
import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

MAX_DIFF = 1024 * 1024
MAX_PATHS = 2048
MAX_POLICY = 512 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def valid_path(value):
    return (type(value) is str and 0 < len(value) <= 4096 and
            not any(ord(c) < 32 or ord(c) == 127 for c in value) and '\\' not in value and
            not value.startswith('/') and PurePosixPath(value).as_posix() == value and
            all(part not in ('.', '..') for part in value.split('/')))


def dependency_signature(raw):
    """Conservative imports/call targets/string footprint; never execute code.

    A new import, loader/read call or string-built path changes the signature.
    Ordinary algorithm edits can remain narrow. This is a scheduling guard,
    not a proof about arbitrary Python effects or an adversarial-code sandbox.
    """
    require(type(raw) is bytes and len(raw) <= MAX_DIFF, 'source byte bound')
    tree = ast.parse(raw)
    def shape(node):
        # ast.dump's treatment of empty/optional fields changed after 3.12.
        # Normalize those fields ourselves so both supported parsers agree.
        if isinstance(node, ast.AST):
            return (type(node).__name__, [(name, shape(value)) for name, value in ast.iter_fields(node)
                                         if value is not None and value != []])
        if isinstance(node, list):
            return [shape(value) for value in node]
        return (type(node).__name__, repr(node))
    footprint = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            footprint.append(('import', json.dumps(shape(node), separators=(',', ':'))))
        elif isinstance(node, ast.Call):
            footprint.append(('call', json.dumps(shape(node.func), separators=(',', ':'))))
        elif isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            footprint.append(('literal', repr(node.value)))
    return hashlib.sha256(json.dumps(sorted(footprint), separators=(',', ':')).encode()).hexdigest()


def policy_check(policy):
    require(type(policy) is dict and type(policy.get('schema_version')) is int and policy['schema_version'] == 1, 'policy schema')
    groups = policy.get('groups')
    require(type(groups) is dict and set(groups) == {'static', 'full-port', 'parallel'}, 'policy groups')
    for name, group in groups.items():
        require(type(group) is dict and group.get('key') in ('component', 'lane'), 'matrix key')
        rows = group.get('rows')
        require(type(rows) is list and 0 < len(rows) <= 128, 'baseline matrix bound')
        identities = set()
        for row in rows:
            require(type(row) is dict and group['key'] in row and row.get('python') in ('3.12', '3.14'), 'matrix row')
            require(type(row[group['key']]) is str and re.fullmatch('[a-z][a-z0-9-]{0,63}', row[group['key']]), 'component ID')
            identity = (row[group['key']], row['python'])
            require(identity not in identities, 'duplicate baseline row'); identities.add(identity)
            require(set(row) <= {group['key'], 'python', 'tests'}, 'unexpected matrix field')
            if 'tests' in row:
                require(type(row['tests']) is int and row['tests'] > 0, 'test count')
    for key in ('full_paths', 'full_prefixes'):
        require(type(policy.get(key)) is list and len(policy[key]) <= MAX_PATHS, 'protected path list')
        require(len(set(policy[key])) == len(policy[key]), 'duplicate protected path')
        require(all(type(p) is str and valid_path(p.rstrip('/')) for p in policy[key]), 'protected path')
    require(all(p.endswith('/') for p in policy['full_prefixes']), 'protected prefix boundary')
    paths = policy.get('paths')
    require(type(paths) is dict and 0 < len(paths) <= MAX_PATHS, 'reviewed path map')
    for path, routes in paths.items():
        require(valid_path(path) and type(routes) is dict and routes, 'reviewed path route')
        require(set(routes) <= set(groups), 'unknown route group')
        for name, components in routes.items():
            known = {r[groups[name]['key']] for r in groups[name]['rows']}
            require(type(components) is list and components and len(components) == len(set(components)) and
                    all(c in known for c in components), 'unknown/duplicate component route')
    signatures = policy.get('dependency_signatures')
    require(type(signatures) is dict and set(signatures) == {p for p in paths if p.endswith('.py')}, 'dependency signature coverage')
    require(all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in signatures.values()), 'dependency signature')
    return policy


def select(policy, event, raw_diff, *, complete=False, truncated=False, signatures=None):
    """Only complete A/M records on reviewed exact paths may select narrowly.

    Git --name-status -z --no-renames uses status NUL path NUL. Rename/copy,
    deletion, type/unmerged changes and every malformed/unknown case go full.
    """
    policy_check(policy)
    changed = []
    reason = None
    if event not in ('pull_request', 'push'):
        reason = 'event_requires_full_suite'
    elif complete is not True or truncated is not False:
        reason = 'diff_unavailable_incomplete_or_truncated'
    elif type(raw_diff) is not bytes or len(raw_diff) > MAX_DIFF:
        reason = 'diff_byte_bound'
    else:
        try:
            fields = raw_diff.decode('utf-8').split('\0')
            if not raw_diff or fields[-1] != '' or len(fields) % 2 != 1:
                reason = 'empty_or_malformed_diff'
            else:
                fields.pop()
                require(len(fields) // 2 <= MAX_PATHS, 'diff_path_bound')
                for status, path in zip(fields[::2], fields[1::2]):
                    if status not in ('A', 'M'):
                        reason = 'deletion_rename_or_nonordinary_change'; break
                    if not valid_path(path) or path in changed:
                        reason = 'malformed_or_duplicate_path'; break
                    changed.append(path)
                if reason is None:
                    for path in sorted(changed):
                        if path in policy['full_paths'] or any(path.startswith(prefix) for prefix in policy['full_prefixes']):
                            reason = 'protected_or_common_path'; break
                        if path not in policy['paths']:
                            reason = 'unknown_path'; break
                        if path in policy['dependency_signatures'] and (type(signatures) is not dict or
                                signatures.get(path) != policy['dependency_signatures'][path]):
                            reason = 'dependency_footprint_unavailable_or_changed'; break
        except (UnicodeError, ValueError):
            reason = 'malformed_or_unbounded_diff'
    full = reason is not None
    selected = {name: set() for name in policy['groups']}
    if not full:
        for path in changed:
            for name, components in policy['paths'][path].items():
                selected[name].update(components)
    result = {}
    for name, group in policy['groups'].items():
        rows = [dict(row) for row in group['rows'] if full or row[group['key']] in selected[name]]
        # Empty selections keep a valid baseline operand plus an explicit false
        # run flag. Unavailable outputs independently fall back to the baseline.
        result[name] = dict(run=bool(rows), matrix=dict(include=rows or group['rows']),
                            selected_rows=len(rows), baseline_rows=len(group['rows']))
    return dict(schema_version=1, mode='full' if full else 'narrow',
                reason=reason or 'complete_reviewed_change_set', paths=sorted(changed), groups=result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, default=Path(__file__).with_name('dependencies.json'))
    parser.add_argument('--event', required=True)
    parser.add_argument('--diff', type=Path, required=True)
    parser.add_argument('--group', choices=('static', 'full-port', 'parallel'), required=True)
    parser.add_argument('--complete', action='store_true')
    parser.add_argument('--truncated', action='store_true')
    parser.add_argument('--github-output', type=Path)
    parser.add_argument('--source-root', type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        with args.policy.open('rb') as stream:
            policy_raw = stream.read(MAX_POLICY + 1)
        require(len(policy_raw) <= MAX_POLICY, 'policy byte bound')
        policy = policy_check(decode(policy_raw))
        try:
            with args.diff.open('rb') as stream:
                raw = stream.read(MAX_DIFF + 1)
        except OSError:
            raw = b''; args.complete = False
        signatures = {}
        # Read only changed, reviewed Python operands in the checkout. A missing,
        # aliased, oversized or syntactically changed dependency operand goes full.
        try:
            changed = raw.decode('utf-8').split('\0')[1::2]
            for path in changed:
                if path in policy['dependency_signatures']:
                    source = args.source_root / path
                    if source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)):
                        with source.open('rb') as stream:
                            signatures[path] = dependency_signature(stream.read(MAX_DIFF + 1))
        except (OSError, ValueError, SyntaxError, UnicodeError, RecursionError):
            signatures = {}
        report = select(policy, args.event, raw, complete=args.complete, truncated=args.truncated, signatures=signatures)
        if args.github_output:
            group = report['groups'][args.group]
            with args.github_output.open('a', encoding='utf-8') as output:
                output.write('run=' + str(group['run']).lower() + '\n')
                output.write('matrix=' + json.dumps(group['matrix'], sort_keys=True, separators=(',', ':')) + '\n')
                output.write('mode=' + report['mode'] + '\n')
        print(json.dumps(report, sort_keys=True, separators=(',', ':')))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        # No outputs on policy/tool failure: callers use their literal full
        # fallback and run when the selector job did not succeed.
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
