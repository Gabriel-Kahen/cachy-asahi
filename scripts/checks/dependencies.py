#!/usr/bin/env python3
"""Resolve declared dependencies against an explicit reviewed repository inventory.

Inventory is JSON: [{name, version, arch, provides: [name or name=version]}].
Does not query/update/install packages. Version comparisons use Arch vercmp.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from package_checks import discover, recipe, effective_values


def parse_dep(value):
    match = re.fullmatch(r'([A-Za-z0-9@._+:-]+)(?:(>=|<=|=|>|<)([^\s]+))?', value)
    if not match or bool(match[2]) != bool(match[3]):
        raise ValueError(f'invalid dependency: {value}')
    return match.groups()


def satisfies(actual, operator, wanted):
    if not operator:
        return True
    if not actual:
        return False
    result = int(subprocess.check_output(['vercmp', actual, wanted], text=True))
    return {'=': result == 0, '>': result > 0, '<': result < 0,
            '>=': result >= 0, '<=': result <= 0}[operator]


def resolve(reports, inventory):
    if not isinstance(inventory, list):
        raise ValueError('inventory must be a list')
    providers, errors = {}, []
    # Use a unique object as a sentinel for external repository providers
    # to avoid collision with a package literally named 'repository'
    REPO_ORIGIN = object()

    for item in inventory:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not item.get('name'):
            raise ValueError(f'invalid inventory item: {item}')
        if item.get('arch') not in ('aarch64', 'any') or not isinstance(item.get('version'), str) or not item.get('version'):
            raise ValueError(f'invalid aarch64 inventory item: {item.get("name")}')

        providers.setdefault(item['name'], []).append((item['version'], REPO_ORIGIN))
        provides = item.get('provides', [])
        if not isinstance(provides, list):
            raise ValueError(f'provides must be a list in item {item.get("name")}')
        for provide in provides:
            if not isinstance(provide, str) or not provide:
                raise ValueError(f'invalid provide string in item {item.get("name")}')
            name, operator, version = parse_dep(provide)
            if operator not in (None, '='):
                raise ValueError('provides may only use = version')
            providers.setdefault(name, []).append((version or None, REPO_ORIGIN))

    edges = {}
    for report in reports:
        data = report['metadata']
        version = data.get('pkgver', [''])[0] + '-' + data.get('pkgrel', [''])[0]
        if data.get('epoch', ['0'])[0] != '0':
            version = data['epoch'][0] + ':' + version
        for name in data.get('pkgname', []):
            if len(data['pkgname']) != 1:
                errors.append(f'{name}: split-package dependency inheritance needs explicit per-package inventory')
            if name in edges:
                raise ValueError(f'duplicate overlay package name: {name}')
            providers.setdefault(name, []).append((version, name))
            edges[name] = []
        for provide in effective_values(data, 'provides'):
            name, operator, provided_version = parse_dep(provide)
            if operator not in (None, '='):
                raise ValueError('provides may only use = version')
            providers.setdefault(name, []).append((provided_version or None, data['pkgname'][0]))

    for report in reports:
        data = report['metadata']
        for field in ('depends', 'makedepends', 'checkdepends'):
            for dependency in effective_values(data, field):
                name, operator, version = parse_dep(dependency)
                choices = [(v, p) for v, p in providers.get(name, []) if satisfies(v, operator, version)]
                if not choices:
                    errors.append(f'{data["pkgname"][0]}: unresolved {field} {dependency}')
                elif not any(p is REPO_ORIGIN for _, p in choices):
                    pkg_name = data['pkgname'][0]
                    edges[pkg_name].append(set(p for _, p in choices))

        for field in ('conflicts', 'replaces'):
            for dependency in effective_values(data, field):
                name, operator, version = parse_dep(dependency)
                if any(satisfies(v, operator, version) for v, _ in providers.get(name, [])):
                    errors.append(f'{data["pkgname"][0]}: {field} intersects inventory/overlay: {dependency}')

    order = []
    # All dependency groups must be satisfied; any completed provider satisfies a group.
    completed = set()
    pending = {name: [] for name in edges}
    for name, req_groups in edges.items():
        pending[name] = req_groups

    while True:
        ready_batch = []
        for name, req_groups in pending.items():
            # All requirement groups must be satisfied (AND)
            # A group is satisfied if at least one provider in it is completed (OR)
            if all(any(p in completed for p in group) for group in req_groups):
                ready_batch.append(name)

        if not ready_batch:
            break

        ready_batch.sort()
        order.extend(ready_batch)
        for name in ready_batch:
            completed.add(name)
            del pending[name]

    if pending:
        errors.append('overlay dependency cycle: ' + ', '.join(sorted(pending)))

    return {'errors': errors, 'build_order': order,
            'limit': 'Declared dependencies only; inventory must come from selected target repository snapshot.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        reports = [recipe(path) for path in discover(args.root)]
        if not reports:
            raise ValueError('no recipes found')
        errors = [error for report in reports for error in report['errors']]
        if errors:
            raise ValueError('; '.join(errors))
        result = resolve(reports, json.loads(args.inventory.read_text()))
        print(json.dumps(result, indent=2, sort_keys=True))
        return int(bool(result['errors']))
    except (OSError, ValueError, subprocess.SubprocessError, KeyError) as error:
        print(json.dumps({'errors': [str(error)]}, indent=2))
        return 1


if __name__ == '__main__':
    sys.exit(main())
