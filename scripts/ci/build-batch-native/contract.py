# SPDX-License-Identifier: MIT
"""Finite two-package source/metadata contract. Imports perform no actors."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[3]
NAMES = ('cachy-asahi-fish-config', 'cachy-asahi-zsh-config')
BASE_INPUT = 'scripts/ci/maintained-desktop574-inputs.json'
BASE_PIN = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
HEX = re.compile('[0-9a-f]{64}')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def safe(path):
    path = Path(os.path.abspath(path))
    need(path == path.resolve() and not any(c in str(path) for c in ',\r\n'), 'ordinary absolute path required')
    return path


def digest(path):
    with safe(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def raw(path, limit=4 * 1024**2):
    path = safe(path)
    need(path.is_file() and path.stat().st_size <= limit, 'bounded ordinary input required: ' + str(path))
    return path.read_bytes()


def read(path):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw(path), object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def save(path, value):
    with safe(path).open('xb') as stream:
        stream.write(encoded(value))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def verify_source(root):
    root = safe(root)
    manifest = read(root / 'scripts/ci/build-batch-native/source-manifest.json')
    need(manifest['schema_version'] == 1 and len(manifest['files']) <= 128, 'closed finite source manifest required')
    for name, row in manifest['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'source path escape')
        path = root / name
        need(digest(path) == row['sha256'] and path.stat().st_mode & 0o777 == row['mode'], 'source body/mode differs: ' + name)
    return manifest


def baseline(root):
    need(digest(root / BASE_INPUT) == BASE_PIN, 'fixed native574 inventory differs')
    value = read(root / BASE_INPUT)
    need(len(value['packages']) == len({p['name'] for p in value['packages']}) == 574, 'exact574 required')
    return value


def recipes(root):
    build = load('native_trial_reviewed_build', root / 'scripts/build/build.py')
    out = {}
    for name in NAMES:
        directory = root / 'packages/shells' / name
        report = build.recipe(directory / 'PKGBUILD')
        need(not report['errors'], 'selected recipe inspection failed')
        metadata = build.normalize_metadata(report['metadata'])
        need(metadata['pkgname'] == [name] and metadata['arch'] == ['any'] and metadata['license'] == ['MIT'] and
             metadata['pkgver'] == ['0.1.0'] and metadata['pkgrel'] == ['1'], 'exact reviewed shell package required')
        need(all('://' not in p for p in metadata['source']), 'local-only trial sources required')
        out[name] = dict(directory=directory, report=report, metadata=metadata)
    return out


def topology(root, recipe_pins=None):
    """Use complete raw baseline metadata; missing recipe pins stay unknown."""
    selected = baseline(root)
    packages, sources, builds = [], [], []
    for row in selected['packages']:
        name = row['name']
        packages.append(dict(name=name, version=row['version'], arch=row['arch'], depend=row['depends'], provides=row['provides']))
        source_id = 'baseline-' + name if recipe_pins is not None else None
        if recipe_pins is not None:
            need(name in recipe_pins and HEX.fullmatch(recipe_pins[name]), 'actual baseline BUILDINFO pin required')
            sources.append(dict(id=source_id, recipe_sha256=recipe_pins[name],
                                sources=[dict(url=row['url'], sha256=row['sha256'])]))
        builds.append(dict(package=name, source_id=source_id, makedepend=[], checkdepend=[], toolchain=[],
                           disposition='external', owner='fixed signed native574 binary-input owner', hold_reason=None))
    for name, recipe in recipes(root).items():
        metadata = recipe['metadata']
        packages.append(dict(name=name, version='0.1.0-1', arch='any', depend=metadata['depends'], provides=metadata['provides']))
        sources.append(dict(id=name, recipe_sha256=recipe['report']['input_sha256']['PKGBUILD'],
                            sources=[dict(url=url, sha256=pin) for url, pin in zip(metadata['source'], metadata['sha256sums'])]))
        builds.append(dict(package=name, source_id=name, makedepend=metadata['makedepends'], checkdepend=metadata['checkdepends'],
                           toolchain=['base-devel'], disposition='build', owner='Root finite native batch trial', hold_reason=None))
    return dict(schema_version=1, metadata_role='pre-change-release', release_id='FINITE_TWO_SHELL_PACKAGE_REBUILD_TRIAL',
                snapshot_id=selected['snapshot_id'], packages=packages, sources=sources, build_dependencies=builds,
                changed=dict(sources=list(NAMES), toolchains=[], advisories=[]),
                capacity=dict(native_aarch64_slots=2, owner='Root allocated hosted ARM job',
                              reference='finite 8CPU/8GiB batch budget; sustainable capacity NOT_MEASURED'))


def archive_recipe_pin(path, row):
    """Read authenticated producer inputs; never substitute invented recipe pins."""
    need(digest(path) == row['sha256'] and path.stat().st_size == row['size'], 'selected baseline archive changed: ' + row['name'])
    bodies = {}
    with tarfile.open(path, 'r:xz') as archive:
        for index, member in enumerate(archive):
            need(index < 32, 'baseline metadata not in bounded leading members')
            name = member.name.removeprefix('./')
            if name in ('.PKGINFO', '.BUILDINFO'):
                need(name not in bodies and member.isfile() and member.size <= 1024**2, 'ordinary bounded baseline metadata required')
                bodies[name] = archive.extractfile(member).read()
            if len(bodies) == 2:
                break
    need(set(bodies) == {'.PKGINFO', '.BUILDINFO'}, 'baseline PKGINFO/BUILDINFO unavailable: ' + row['name'])
    def metadata(body):
        out = {}
        for line in body.decode().splitlines():
            if ' = ' in line:
                key, value = line.split(' = ', 1)
                out.setdefault(key, []).append(value)
        return out
    package, build = metadata(bodies['.PKGINFO']), metadata(bodies['.BUILDINFO'])
    expected = dict(pkgname=[row['name']], pkgver=[row['version']], arch=[row['arch']],
                    depend=sorted(row['depends']), provides=sorted(row['provides']))
    need(all(sorted(package.get(k, [])) == v for k, v in expected.items()), 'baseline archive metadata differs: ' + row['name'])
    pins = build.get('pkgbuild_sha256sum', [])
    need(len(pins) == 1 and HEX.fullmatch(pins[0]), 'baseline recipe hash unavailable: ' + row['name'])
    return pins[0]
