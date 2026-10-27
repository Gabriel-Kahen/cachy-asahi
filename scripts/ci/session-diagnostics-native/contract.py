# SPDX-License-Identifier: MIT
"""Exact corrected diagnostic package and finite native installed evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
NAMES = ('cachy-asahi-session-diagnostics',)
NAME = 'NO_COMPILED_PRODUCT_IN_THIS_LANE'
LABEL = 'org.cachy-asahi.session-diagnostics-native.job'
LANE = 'scripts/ci/session-diagnostics-native'
ACTOR = '.github/workflows/native-arm-session-diagnostics-candidate.yml'
ALIAS = '.github/workflows/native-arm-build.yml'
PACKAGE_MANIFEST_SHA256 = 'b83b5ab81e739b2497b5ab9d6039278180cf6f77254d7a6c63c65bf0678db0e7'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path required')
    return path


def frozen_files():
    manifest = HERE / 'package-manifest.json'
    need(digest(manifest) == PACKAGE_MANIFEST_SHA256, 'frozen package manifest differs')
    value = json.loads(manifest.read_bytes())
    rows = value['files']
    need(value['package'] == NAMES[0] and value['version'] == '0.1.0-3' and len(rows) == 12 and
         all(Path(name).name == name and set(row) == {'bytes', 'sha256'} for name, row in rows.items()),
         'exact twelve corrected package sources required')
    return rows


def verify_package(root):
    need({p.name for p in root.iterdir()} == set(frozen_files()), 'closed frozen package input set required')
    for name, row in frozen_files().items():
        path = safe(root / name)
        need(path.is_file() and path.stat().st_size == row['bytes'] and digest(path) == row['sha256'],
             'frozen package byte drift: ' + name)


def verify_source(source):
    safe(source)
    pins = json.loads((HERE / 'source-pins.json').read_bytes())
    need(type(pins) is dict and 32 <= len(pins) <= 128 and ACTOR in pins and ALIAS in pins,
         'complete source pins including registered alias required')
    for name, pin in pins.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and re.fullmatch('[0-9a-f]{64}', pin),
             'safe source pin required')
        path = safe(source / name)
        need(path.is_file() and path.stat().st_size <= 16 * 1024**2 and digest(path) == pin,
             'source dependency differs: ' + name)
    need((source / ACTOR).read_bytes() == (source / ALIAS).read_bytes(), 'registered workflow alias differs')
    verify_package(source / 'packages/tools' / NAMES[0])


def recipe(source, name):
    need(name in NAMES, 'unknown product')
    root = source / 'packages/tools' / name
    verify_package(root)
    checker = load('diagnostics_package_source', root / 'check_package.py')
    checker.check_source(root)
    checks = load('diagnostics_static_recipe', source / 'scripts/checks/package_checks.py')
    result = checks.recipe(root / 'PKGBUILD')
    meta = result['metadata']
    need(not result['errors'] and meta['pkgname'] == [name] and meta['pkgver'] == ['0.1.0'] and
         meta['pkgrel'] == ['3'] and meta['arch'] == ['any'] and meta['license'] == ['MIT'] and
         meta['depends'] == ['python>=3.11'] and meta['optdepends'] == checker.OPTIONAL and
         not any(meta.get(key) for key in ('install', 'backup', 'provides', 'conflicts', 'replaces', 'makedepends')) and
         len(meta['source']) == len(meta['sha256sums']) == 10, 'exact corrected metadata required')
    return dict(metadata=meta, input_sha256=result['input_sha256'])


def version(source, name):
    meta = recipe(source, name)['metadata']
    return meta['pkgver'][0] + '-' + meta['pkgrel'][0]


def files(name):
    need(name in NAMES, 'unknown payload')
    value = json.loads((HERE / 'product-spec.json').read_bytes())
    need(value['status'] == 'FROZEN_PACKAGE_BYTES_REVIEWED' and set(value['products']) == set(NAMES), 'frozen product map required')
    rows = value['products'][name]['payload']
    need(type(rows) is dict and len(rows) == 7, 'exact seven installed files required')
    for relative, row in rows.items():
        need(not Path(relative).is_absolute() and '..' not in Path(relative).parts and
             relative.startswith(('usr/bin/', 'usr/lib/' + name + '/', 'usr/share/doc/', 'usr/share/licenses/')) and
             type(row) is list and len(row) == 2 and Path(row[0]).name == row[0] and row[1] in (0o644, 0o755),
             'reviewed private installed payload map required')
    return rows


def payload(report, source, name):
    need(not report['errors'] and not report['elf'], 'script/data-only archive required')
    expected = files(name)
    rows = {n: row for n, row in report['members'].items() if row['type'] != '5' and n not in ('.PKGINFO', '.BUILDINFO', '.MTREE')}
    need(set(rows) == set(expected), 'exact diagnostic payload differs')
    parents = {str(p) for member in expected for p in Path(member).parents if str(p) != '.'}
    for relative, row in report['members'].items():
        if row['type'] == '5':
            need(relative in parents and row['mode'] == 0o755 and row['uid'] == row['gid'] == 0,
                 'unexpected payload directory or mode/owner')
    for relative, (original, mode) in expected.items():
        row = rows[relative]
        need(row['type'] == '0' and row['mode'] == mode and row['uid'] == row['gid'] == 0 and
             row['sha256'] == digest(source / 'packages/tools' / name / original), 'source/payload join differs: ' + relative)
    return rows


def check_log(path, name):
    need(name in NAMES and path.stat().st_size <= 16 * 1024**2, 'bounded package check log required')
    text = path.read_text(errors='replace')
    need(all(marker in text for marker in ('Starting check()', 'PASS_SOURCE', 'Ran 35 tests', 'Ran 7 tests')) and
         text.count('\nOK') >= 2, 'all native package controls and ownership regressions required')
    return dict(status='PASS_CHECK_EXIT', probe_controls=35, package_controls=7,
                method='real makepkg check() exit0; unchanged corrected SIGCHLD/WNOWAIT controls')


def validate_fixture(value, architecture, page_size):
    load('diagnostics_fixture_contract', HERE / 'fixture_contract.py').validate_fixture(value, architecture, page_size)


def validate_lifecycle(value):
    load('diagnostics_lifecycle_contract', HERE / 'fixture_contract.py').validate_lifecycle(value)
