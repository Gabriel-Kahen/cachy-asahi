#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare exact package pins between authenticated retained mirror releases."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys
import tarfile

FIELDS = ('version', 'arch', 'package_sha256', 'recipe_sha256', 'srcinfo_sha256', 'source_profile')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def catalog_helper():
    # Installed project code only; no mirror member is imported or executed.
    path = Path(__file__).resolve().with_name('source_mirror_catalog.py')
    spec = importlib.util.spec_from_file_location('diff_trusted_catalog', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_changes(before, after):
    """Classify already verified selector DATA; this helper grants no authority."""
    def indexed(rows):
        need(type(rows) is list and len(rows) <= 256, 'bounded package catalog required')
        result = {}
        for row in rows:
            need(type(row) is dict and set(row) == {'package', *FIELDS}
                 and all(type(value) is str and value for value in row.values()), 'exact package selector fields')
            need(re.fullmatch('[a-z0-9][a-z0-9@._+-]*', row['package']) and row['package'] not in result,
                 'unique canonical package name required')
            need(all(re.fullmatch('[0-9a-f]{64}', row[key]) for key in
                     ('package_sha256', 'recipe_sha256', 'srcinfo_sha256')), 'exact selector digests required')
            result[row['package']] = row
        return result
    old, new = indexed(before), indexed(after)
    changes = []
    for name in sorted(old.keys() | new.keys()):
        left, right = old.get(name), new.get(name)
        changed = [key for key in FIELDS if left is not None and right is not None and left[key] != right[key]]
        status = 'added' if left is None else 'removed' if right is None else 'changed' if changed else 'unchanged'
        changes.append(dict(package=name, change=status, changed_fields=changed,
                            before=left, after=right))
    return changes


def compare(raw, mirror_sha256, from_release_sha256, to_release_sha256, catalog_module=None):
    catalog = catalog_module if catalog_module is not None else catalog_helper()
    # Both calls validate the entire history, including unselected recovery data.
    before = catalog.catalog(raw, mirror_sha256, from_release_sha256)
    after = catalog.catalog(raw, mirror_sha256, to_release_sha256)
    need(before['head_release_sha256'] == after['head_release_sha256']
         and before['retained_releases'] == after['retained_releases'], 'same authenticated mirror history required')
    changes = package_changes(before['packages'], after['packages'])
    counts = {key: sum(row['change'] == key for row in changes)
              for key in ('added', 'removed', 'changed', 'unchanged')}
    return dict(schema_version=1, purpose='release-source-mirror-diff',
        status='VERIFIED_OFFLINE_SOURCE_MIRROR_DIFF', mirror_sha256=mirror_sha256,
        from_release={key: before[key] for key in ('release_id', 'release_sha256')},
        to_release={key: after[key] for key in ('release_id', 'release_sha256')},
        head_release_sha256=before['head_release_sha256'], retained_releases=before['retained_releases'],
        counts=counts, packages=changes, synthetic=dict(before=before['synthetic'], after=after['synthetic']),
        legal_acceptance=False, corresponding_source_completeness='NOT_ASSERTED',
        native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')


class SingleValue(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if hasattr(namespace, self.dest):
            parser.error('repeated option refused: ' + option_string)
        setattr(namespace, self.dest, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    diff = commands.add_parser('diff', allow_abbrev=False)
    diff.add_argument('--bundle', required=True, action=SingleValue, default=argparse.SUPPRESS)
    diff.add_argument('--sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    diff.add_argument('--from-release-sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    diff.add_argument('--to-release-sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        catalog = catalog_helper()
        mirror = catalog.mirror_helper()
        result = compare(mirror.read_file(Path(args.bundle)), args.sha256,
                         args.from_release_sha256, args.to_release_sha256, catalog)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, tarfile.TarError, EOFError, RecursionError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
