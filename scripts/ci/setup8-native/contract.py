# SPDX-License-Identifier: MIT
"""Two exact setup recipe profiles and installed migration qualification gates."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import types

HERE = Path(__file__).resolve().parent
PACKAGE = 'cachy-asahi-setup'
BASELINE, CANDIDATE = 'cachy-asahi-setup7', 'cachy-asahi-setup8'
NAMES = (BASELINE, CANDIDATE)
NAME = 'NO_COMPILED_ADDON'
LABEL = 'org.cachy-asahi.setup8-native.job'
RECIPES = {BASELINE: 'packages/settings/cachy-asahi-setup', CANDIDATE: 'packages/tools/cachy-asahi-setup8'}
VERSIONS = {BASELINE: '0.1.0-7', CANDIDATE: '0.3.0-1'}
LEGACY = ('state', 'journal-before', 'journal-after', 'journal-commit', 'remove-journal')
OLD_PAIR = OLD5_PAIR = None


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def safe(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n')
         and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute source path required')
    return path


def pinned(root, name):
    table = json.loads((HERE / 'source-pins.json').read_text())
    path = safe(root / name)
    need(path.is_file() and path.stat().st_size <= 16 * 1024**2 and digest(path) == table[name], 'exact source pin differs')
    return path.read_text()


def load(name, path):
    if path.name == 'run.py' and path.parent.name == 'welcome-native':
        value = types.ModuleType(name);value.__file__ = str(path)
        exec(compile(build_source(path.parents[3]), str(path), 'exec'), value.__dict__)
        return value
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def baseline(root):
    return load('held_setup7_contract', root / 'scripts/ci/setup7-native/contract.py')


def recipe_path(name):
    need(name in NAMES, 'exact setup profile required')
    return RECIPES[name]


def recipe(root, name=CANDIDATE):
    directory = root / recipe_path(name)
    meta = load('setup8_metadata_reader', root / 'scripts/checks/package_checks.py').metadata((directory / '.SRCINFO').read_text())
    need(meta['pkgname'] == [PACKAGE] and meta['arch'] == ['any'] and meta['license'] == ['MIT'], 'exact any/MIT setup package identity required')
    need(meta['pkgver'][0] + '-' + meta['pkgrel'][0] == VERSIONS[name], 'new candidate archive identity must differ from baseline')
    raw = (directory / 'PKGBUILD').read_text()
    sources = shlex.split(re.search(r'^source=\((.*?)\)', raw, re.M | re.S)[1])
    sums = shlex.split(re.search(r'^sha256sums=\((.*?)\)', raw, re.M | re.S)[1])
    need(sources == meta['source'] and sums == meta['sha256sums'] and len(sources) == len(sums), 'literal source/metadata checksum table differs')
    need(all('/' not in n and n not in ('.', '..') and digest(directory / n) == h and re.fullmatch('[0-9a-f]{64}', h)
             for n, h in zip(sources, sums)), 'all local sources must have exact fixed pins')
    names = set(sources) | {'.SRCINFO', 'PKGBUILD', 'check-packaged.py'} if name == BASELINE else set(sources) | {'.SRCINFO', 'PKGBUILD'}
    result = {'metadata': meta, 'input_sha256': {n: digest(directory / n) for n in sorted(names)}}
    if name == BASELINE:
        need(result == baseline(root).recipe(root), 'held Setup7 recipe must remain byte-identical')
    else:
        need(sorted(meta['depends']) == ['gnupg', 'pacman', 'python>=3.11'], 'held runtime dependency set required')
    return result


def version(root, name):
    recipe(root, name)
    return VERSIONS[name]


def files(name=CANDIDATE):
    common = {**{'usr/bin/' + n: (n, 0o755) for n in ('cachy-asahi-setup', 'cachy-asahi-repository')},
              **{'usr/share/doc/' + PACKAGE + '/' + n: (n, 0o644) for n in ('README.md', 'repository-enrollment.md')},
              **{'usr/share/licenses/' + PACKAGE + '/' + n: (n, 0o644) for n in ('NOTICE', 'LICENSE')}}
    if name == BASELINE:
        return common
    need(name == CANDIDATE, 'exact setup payload profile required')
    return {**common, 'usr/bin/cachy-asahi-config-migrate': ('cachy-asahi-config-migrate', 0o755),
            'usr/lib/cachy-asahi/setup8/setup.py': ('setup.py', 0o644),
            'usr/lib/cachy-asahi/setup8/config_migrate.py': ('config_migrate.py', 0o644),
            'usr/share/doc/' + PACKAGE + '/configuration-migrations.md': ('configuration-migrations.md', 0o644)}


def payload(report, root, name):
    need(not report['errors'] and not report['elf'], 'script/data-only package required')
    rows = {n: r for n, r in report['members'].items() if r['type'] != '5' and n not in ('.PKGINFO', '.BUILDINFO', '.MTREE')}
    expected = files(name)
    need(set(rows) == set(expected), 'exact setup profile installed path set required')
    parents = {p.as_posix() for n in expected for p in Path(n).parents if p.as_posix() != '.'}
    need(all(n in parents for n, r in report['members'].items() if r['type'] == '5'), 'unexpected payload directory')
    for path, (leaf, mode) in expected.items():
        row = rows[path]
        need(row['type'] == '0' and row['mode'] == mode and row['uid'] == row['gid'] == 0
             and row['sha256'] == digest(root / recipe_path(name) / leaf), 'installed source/license/payload differs')
    return rows


def stage_recipe(root, output, name):
    output.mkdir(parents=True)
    for leaf in recipe(root, name)['input_sha256']:
        shutil.copyfile(root / recipe_path(name) / leaf, output / leaf)


def build_source(root):
    text = pinned(root, 'scripts/ci/welcome-native/run.py')
    before = "shutil.copytree(source/'packages/tools'/name,inputs)"
    need(text.count(before) == 1, 'held build-source anchor differs')
    return text.replace(before, 'C.stage_recipe(source,inputs,name)')


def stage_retained(context, checks, bind):
    need(OLD_PAIR is not None and OLD5_PAIR is not None, 'explicit old4/5 retained sources required')
    root = HERE.parents[2]
    held = baseline(root);held.OLD_PAIR = OLD_PAIR;held.OLD5_PAIR = OLD5_PAIR
    held.stage_retained(context, checks, bind)
    products = json.loads((context / 'products.json').read_text())
    need(set(products) == set(NAMES), 'both fresh pairs required')
    (context / 'baseline7-products.json').write_text(json.dumps({PACKAGE: products[BASELINE]}, sort_keys=True, indent=2) + '\n')
    # Held installed status controls compare against this original Setup7 source path.
    shutil.copytree(context / 'sources' / BASELINE, context / 'sources' / PACKAGE)
    # The source root may be private; ordinary fixture users read only /inputs.
    driver = context / 'setup8-delivery.py'
    shutil.copyfile(root / recipe_path(CANDIDATE) / 'test_delivery.py', driver)
    driver.chmod(0o644)


def check_log(path, name):
    text = path.read_text(errors='replace')
    need(path.stat().st_size <= 16 * 1024**2 and 'Starting check()' in text and 'OK' in text, 'actual normal makepkg check output required')
    if name == BASELINE:
        return baseline(HERE.parents[2]).check_log(path)
    need('Ran 29 tests' in text and 'Ran 4 tests' in text and 'PASS' in text and 'setup8' in text.lower(), 'migration/source/delivery package controls absent')
    return {'status': 'PASS_SETUP8_CHECK_EXIT', 'migration_source_tests': 29, 'installed_behavior': 'REQUIRED_SEPARATELY'}


def verify_source(root):
    table = json.loads((HERE / 'source-pins.json').read_text())
    manifest = json.loads((HERE / 'source-manifest.json').read_text())
    need(len(table) == manifest['source_pin_count'] and 96 <= len(table) <= 128, 'exact declared additive source closure required')
    for name in table:
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'contained source pin required')
        pinned(root, name)
    baseline(root).verify_source(root)
    for name in NAMES:recipe(root, name)


def validate_lifecycle(value, root=None):
    root = HERE.parents[2] if root is None else root
    need(value['status'] == 'PASS_SETUP8_INSTALLED_MIGRATION_AND_HELD_SETUP7_BASELINE', 'actual installed migration lifecycle required')
    baseline(root).validate_lifecycle(value['baseline7'])
    events = value['events']
    phases = [('install-setup7-for-migration', 575), ('upgrade-setup8', 575), ('repeat-setup8', 575),
              ('remove-setup8', 574), ('reinstall-setup8', 575), ('final-remove-setup8', 574)]
    need(type(events) is list and len(events) == 6, 'all six actual candidate transitions required')
    for row, (phase, count) in zip(events, phases):
        need(row['phase'] == phase and type(row['inventory_count']) is int and row['inventory_count'] == count
             and row['status'] == 'PASS' and row['homes_preserved'] is row['database_check'] is True,
             'actual migration package transition/preservation differs')
    need(value['system_config_preserved'] is value['user_state_preserved_on_alpm'] is value['full574_restored'] is True
         and value['native_architecture'] == 'aarch64' and type(value['actual_page_size']) is int
         and value['actual_page_size'] > 0 and value['hardware'] == 'NOT_RUN', 'native installed fixture scope differs')
    cases = value['upgrade_home']
    need(type(cases['uid']) is int and cases['uid'] > 0 and cases['status'] == 'PASS'
         and all(cases.get(k) is True for k in ('old7_owned_before_upgrade', 'preview_readonly', 'applied', 'repeat_readonly',
                    'outside_user_bytes_preserved', 'ledger_preserved_on_package_reinstall', 'new_cli_removal_preserved_user_bytes')),
         'actual old7→8 owned-user migration proof incomplete')
    delivery, reinstalled = value['migration_delivery'], value['migration_reinstall']
    expected_cases = json.loads((HERE / 'source-manifest.json').read_text())['delivery_case_names']
    pins = json.loads((HERE / 'source-pins.json').read_text())
    for row, status, names in ((delivery, 'PASS_SETUP8_DELIVERED_CLI_PRIVATE_FIXTURES', set(expected_cases)),
                              (reinstalled, 'PASS_SETUP8_DELIVERED_CLI_REINSTALL_FIXTURES', {'post-package-reinstall-user-version-preserved'})):
        need(type(row['uid']) is int and row['uid'] > 0 and row['scope'] == 'EXPLICIT_INERT_PRIVATE_FIXTURES_ONLY'
             and row['status'] == status and set(row['cases']) == names and all(v == 'PASS' for v in row['cases'].values())
             and row['architecture'] == 'aarch64' and type(row['actual_page_size']) is int
             and row['actual_page_size'] == value['actual_page_size']
             and row['profiles'] == ['fresh', 'existing', 'conflict', 'interrupted']
             and row['setup_sha256'] == pins[RECIPES[CANDIDATE] + '/cachy-asahi-setup']
             and row['engine_sha256'] == pins[RECIPES[CANDIDATE] + '/config_migrate.py']
             and row['launcher_sha256'] == pins[RECIPES[CANDIDATE] + '/cachy-asahi-config-migrate']
             and re.fullmatch('[0-9a-f]{64}', row['manifest_sha256'])
             and row['hardware'] == 'NOT_RUN' and row['performance'] == 'NOT_MEASURED'
             and row['release'] == 'NOT_ADMITTED' and row['private_fixtures_retired'] is False
             and type(row['fixture_work']) is str and row['fixture_work'].startswith('/tmp/'), 'source-held actual installed migration delivery receipt differs')
    need(delivery['actual_sigkill_returncode'] == -9 and reinstalled['actual_sigkill_returncode'] is None
         and delivery['manifest_sha256'] == reinstalled['manifest_sha256'] and delivery['fixture_work'] == reinstalled['fixture_work'],
         'actual interrupted installed engine and same manifest required')
    need(value['private_fixtures_retired'] is True and value['baseline_fixture_retirement'] == 'DISPOSABLE_CONTAINER_CLEANUP_REQUIRED',
         'new private fixtures retired while held baseline retirement remains owned-container scoped')
    need(value['private_fixtures_scope'] == 'EXPLICIT_DISPOSABLE_USER_HOMES_AND_PINNED_INERT_MANIFEST', 'fixture scope must remain explicit')
