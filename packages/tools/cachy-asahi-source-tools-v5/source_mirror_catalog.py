#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""List authenticated offline mirror packages and exact build-context pins."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tarfile


def mirror_helper():
    # Only the installed trusted helper is imported; mirrored Python stays DATA.
    path = Path(__file__).resolve().with_name('release_source_mirror.py')
    spec = importlib.util.spec_from_file_location('catalog_trusted_mirror', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog(raw, mirror_sha256, release_sha256, mirror_module=None):
    m = mirror_module if mirror_module is not None else mirror_helper()
    m.verify_any(raw, mirror_sha256, release_sha256)
    # Inspect only after verification of the entire mirror, including recovery releases.
    files = m.canonical_files(raw, mirror_sha256)
    if 'mirror.json' in files:
        selected = m.decode(files['mirror.json'])
        releases = [dict(release_id=selected['release_id'], release_sha256=selected['release_sha256'])]
        head = selected['release_sha256']
    else:
        history = m.decode(files['history.json'])
        releases = [{key: row[key] for key in ('release_id', 'release_sha256')} for row in history['releases']]
        row = next(row for row in history['releases'] if row['release_sha256'] == release_sha256)
        selected = m.decode(files['objects/' + row['manifest']['sha256']])
        head = history['head_release_sha256']
    packages = []
    for row in selected['packages']:
        identity = row['package']
        m.need('.SRCINFO' in row['source_files'], 'selected package lacks retained SRCINFO')
        packages.append(dict(package=identity['name'], version=identity['version'], arch=identity['arch'],
            package_sha256=identity['sha256'], recipe_sha256=row['recipe_sha256'],
            srcinfo_sha256=row['source_files']['.SRCINFO']['sha256'], source_profile=row['profile']))
    return dict(schema_version=1, purpose='release-source-mirror-catalog',
        status='VERIFIED_OFFLINE_SOURCE_MIRROR_CATALOG', mirror_sha256=mirror_sha256,
        release_sha256=release_sha256, release_id=selected['release_id'], head_release_sha256=head,
        retained_releases=releases, packages=packages, synthetic=selected['synthetic'],
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
    listing = commands.add_parser('list', allow_abbrev=False)
    listing.add_argument('--bundle', required=True, action=SingleValue, default=argparse.SUPPRESS)
    listing.add_argument('--sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    listing.add_argument('--release-sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        m = mirror_helper()
        result = catalog(m.read_file(Path(args.bundle)), args.sha256, args.release_sha256, m)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, tarfile.TarError, EOFError, RecursionError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
