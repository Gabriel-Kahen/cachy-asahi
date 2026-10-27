#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seal the complete additive Setup8 source; never launch build/native actors."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as C


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def freeze(root):
    root = C.safe(root.absolute())
    here = root / 'scripts/ci/setup8-native'
    C.need(here == Path(__file__).resolve().parent, 'explicit private/adopted context required')
    excluded = {str((here / n).relative_to(root)) for n in ('source-pins.json', 'source-manifest.json')}
    excluded |= {'.github/workflows/' + n for n in ('native-arm-build.yml', 'native-arm-setup8-candidate.yml')}
    names = set()
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        C.need('.git' not in relative.parts and not path.is_symlink(), 'ordinary standalone source context required')
        C.need(path.is_dir() or path.is_file(), 'ordinary source node required')
        if path.is_file() and relative.as_posix() not in excluded:
            C.need(path.stat().st_nlink == 1 and path.stat().st_size <= 16 * 1024**2, 'finite single-link input required')
            names.add(relative.as_posix())
    C.need(96 <= len(names) <= 127, 'finite additive pin count must leave room for pin-table manifest entry')
    pins = {n: C.digest(root / n) for n in sorted(names)}
    save(here / 'source-pins.json', pins)
    C.baseline(root).verify_source(root)
    profiles = {name: C.recipe(root, name) for name in C.NAMES}
    tree = ast.parse((root / C.recipe_path(C.CANDIDATE) / 'test_delivery.py').read_text())
    cases = sorted({n.targets[0].slice.value for n in ast.walk(tree)
                    if isinstance(n, ast.Assign) and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Subscript)
                    and isinstance(n.targets[0].value, ast.Attribute)
                    and isinstance(n.targets[0].value.value, ast.Name)
                    and n.targets[0].value.value.id == 'self' and n.targets[0].value.attr == 'cases'
                    and isinstance(n.targets[0].slice, ast.Constant)
                    and isinstance(n.targets[0].slice.value, str)})
    reinstall = ['post-package-reinstall-user-version-preserved']
    C.need(len(cases) == 13 and set(reinstall) <= set(cases), 'exact twelve delivery and one reinstall source assertions required')
    base = json.loads((root / 'scripts/ci/maintained-desktop574-inputs.json').read_text())
    packages = {row['name']: row for row in base['packages']}
    C.need(len(packages) == 574 and C.PACKAGE not in packages, 'exact original574 base required')
    manifest_names = names | {'scripts/ci/setup8-native/source-pins.json'}
    manifest = dict(schema_version=1, scope='TWO_UNSELECTED_SETUP7_SETUP8_PROFILES', version='0.3.0-1',
                    actual_source=None, actual_ref=None, actual_run=None, native_runtime='NOT_RUN',
                    source_pin_count=len(pins), profiles=profiles, versions=C.VERSIONS,
                    dependency_bindings={n: packages[n] for n in ('python', 'pacman', 'gnupg')},
                    baseline_source='9946417aaa22cd4a5aeb0db6dc422396aa031f4d',
                    baseline_manifest_sha256=C.digest(root / 'scripts/ci/setup7-native/source-manifest.json'),
                    owned_consumer_count=6, fresh_pair_count=2,
                    delivery_case_names=sorted(set(cases) - set(reinstall)), reinstall_case_names=reinstall,
                    files={n: dict(bytes=(root / n).stat().st_size, sha256=C.digest(root / n)) for n in sorted(manifest_names)})
    save(here / 'source-manifest.json', manifest)
    workflow = root / '.github/workflows/native-arm-setup8-candidate.yml'
    raw = workflow.read_text()
    # Permit an explicit reseal after coordinated edits; only the two exact proof hashes change.
    pattern = r"(printf '%s  %s\\n' )'[^']+'( \"\$SLICE/job.py\" )'[^']+'( \"\$SLICE/source-manifest.json\" \| sha256sum --check)"
    match = re.search(pattern, raw)
    C.need(match is not None, 'exact pre-secret proof stamp anchor required')
    stamped = match[1] + "'" + C.digest(here / 'job.py') + "'" + match[2] + "'" + C.digest(here / 'source-manifest.json') + "'" + match[3]
    raw = raw[:match.start()] + stamped + raw[match.end():]
    workflow.write_text(raw)
    (root / '.github/workflows/native-arm-build.yml').write_text(raw)
    C.verify_source(root)
    packet = root.parent
    files = {p.relative_to(root).as_posix(): dict(bytes=p.stat().st_size, sha256=C.digest(p), mode=stat.S_IMODE(p.stat().st_mode))
             for p in sorted(root.rglob('*')) if p.is_file()}
    save(packet / 'source-map.json', dict(schema_version=1, status='FROZEN_SOURCE_ONLY_NOT_NATIVE', files=files))
    contract = packet / 'workflow381-input-contract.json'
    data = json.loads(contract.read_text())
    data['source_rules'][0] = 'Root publishes exactly the constructor-emitted' + str(len(files)) + '-file context.'
    data['pins'] = dict(source_map_sha256=C.digest(packet / 'source-map.json'), manifest_sha256=C.digest(here / 'source-manifest.json'),
                        workflow_sha256=C.digest(workflow), input_lock_sha256=C.digest(root / 'scripts/ci/maintained-desktop574-inputs.json'),
                        baseline_recipe_sha256=C.digest(root / C.recipe_path(C.BASELINE) / 'PKGBUILD'),
                        candidate_recipe_sha256=C.digest(root / C.recipe_path(C.CANDIDATE) / 'PKGBUILD'))
    save(contract, data)
    return dict(status='FROZEN_SOURCE_ONLY_NOT_NATIVE', source_files=len(files), source_pin_count=len(pins),
                manifest_files=len(manifest_names), native='NOT_RUN', installed='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    print(json.dumps(freeze(parser.parse_args().source), sort_keys=True))
