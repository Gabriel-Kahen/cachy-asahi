# SPDX-License-Identifier: MIT
"""Versioned two-product/576 passive reader. Source and capsule code are DATA."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import client_v3_common as C
import lifecycle_rules_v1 as lifecycle_rules
from package_data import metadata, package

HERE = Path(__file__).resolve().parent
CODE_ROOT = HERE.parents[2]
LANE = 'scripts/ci/client-v3-native'
ROLES = {'runtime': 'cachy-asahi-repository-runtime', 'client': 'cachy-asahi-repository-client-v3'}
LABEL = 'org.cachy-asahi.client-v3-native.job'
BASE = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
HEX = r'[0-9a-f]{64}'
SOURCE = r'[0-9a-f]{40}'

def binding(raw):
    value = C.decode(raw)
    fields = {'schema', 'source_sha', 'ref', 'run', 'attempt', 'job', 'artifact', 'artifact_name', 'artifact_bytes',
              'artifact_sha256', 'source_authorization_sha256'}
    C.need(type(value) is dict and set(value) == fields and type(value['schema']) is int and value['schema'] == 1, 'exact versioned Root binding required')
    C.need(all(value[k] is not None for k in fields), 'NULL/unselected actual refused before opening evidence')
    C.need(type(value['source_sha']) is str and re.fullmatch(SOURCE, value['source_sha']) and
           type(value['ref']) is str and re.fullmatch(r'codex/[A-Za-z0-9._/-]+', value['ref']) and
           all(type(value[k]) is int and value[k] > 0 for k in ('run', 'job', 'artifact')) and
           type(value['attempt']) is int and value['attempt'] == 1 and type(value['artifact_bytes']) is int and
           0 < value['artifact_bytes'] <= C.ZIP_CAP and re.fullmatch(HEX, value['artifact_sha256']) and
           re.fullmatch(HEX, value['source_authorization_sha256']), 'typed exact Source/run/attempt/job/artifact selector required')
    expected = 'client-v3-native-component-' + str(value['run']) + '-1'
    C.name(value['ref'])
    C.need(value['artifact_name'] == expected, 'exact component artifact name required')
    return value

def run_metadata(run, jobs, artifact, selected):
    C.need(run.get('id') == selected['run'] and type(run.get('id')) is int and run.get('run_attempt') == 1 and
           run.get('head_sha') == selected['source_sha'] and run.get('head_branch') == selected['ref'] and
           run.get('workflow_id') == 381664314 and run.get('path') == '.github/workflows/native-arm-build.yml' and
           run.get('name') == 'native-arm-client-v3-component' and run.get('event') == 'workflow_dispatch' and
           run.get('repository', {}).get('full_name') == 'Gabriel-Kahen/cachy-asahi' and run.get('status') == 'completed',
           'exact terminal component run metadata required')
    C.need(type(jobs) is dict and type(jobs.get('total_count')) is int and jobs['total_count'] == len(jobs.get('jobs', [])) == 1,
           'complete sole native job metadata required')
    job = jobs['jobs'][0]
    C.need(job.get('id') == selected['job'] and job.get('run_id') == selected['run'] and job.get('run_attempt') == 1 and
           job.get('head_sha') == selected['source_sha'] and job.get('status') == 'completed' and
           job.get('labels') == ['ubuntu-24.04-arm'], 'actual sole hosted ARM job/context required')
    C.need(artifact.get('id') == selected['artifact'] and artifact.get('name') == selected['artifact_name'] and
           artifact.get('size_in_bytes') == selected['artifact_bytes'] and artifact.get('expired') is False and
           artifact.get('digest') == 'sha256:' + selected['artifact_sha256'], 'genuine selected original artifact metadata required')
    origin = artifact.get('workflow_run', {})
    C.need(origin.get('id') == selected['run'] and origin.get('head_sha') == selected['source_sha'] and
           origin.get('head_branch') == selected['ref'], 'artifact/Source/run/ref join required')
    return run['conclusion'] == job.get('conclusion') == 'success'

class SourceData:
    def __init__(self, root, authority, selected):
        self.root, self.authority = Path(root), authority
        C.need(type(authority.get('schema')) is int and authority['schema'] == 1 and authority.get('status') == 'ROOT_PUBLISHED_CLIENT_V3_NATIVE_SOURCE' and
               authority.get('source') == selected['source_sha'] and authority.get('ref') == selected['ref'] and
               re.fullmatch(SOURCE, authority.get('tree') or '') and type(authority.get('files')) is dict and
               1 <= len(authority['files']) <= 130, 'genuine Root published Source body/mode authorization required')
        self.rows = authority['files']
        actual = {p.relative_to(self.root).as_posix() for p in self.root.rglob('*') if p.is_file() or p.is_symlink()}
        C.need(actual == set(self.rows), 'complete Source DATA namespace required; no imports')
        for n, row in self.rows.items():
            C.need(type(row) is dict and set(row) == {'mode', 'oid', 'bytes', 'sha256'} and
                   type(row['oid']) is str and re.fullmatch(SOURCE, row['oid']), 'exact typed Source Git body row required')
            C.typed_pin({k: row[k] for k in ('bytes', 'sha256')}, 16 * 1024**2)
            raw = self.read(n)
            C.need(row.get('mode') == '100644' and row.get('oid') == hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                   'actual Source Git blob/mode join required')
        C.need(C.git_tree(self.rows) == authority['tree'], 'complete actual Source Git tree differs')
        for path in (CODE_ROOT / LANE).iterdir():
            if path.is_file() and path.name not in ('workflow.yml.in', 'input-policy.json'):
                C.need(self.read(LANE + '/' + path.name) == path.read_bytes(), 'Source producer differs from trusted maintained reader version')
        self.policy = C.decode(self.read(LANE + '/input-policy.json'))
        self.manifest = C.decode(self.read(LANE + '/source-manifest.json'))
        C.need(self.policy.get('status') == 'ROOT_BOUND_FINAL_PRODUCT_SOURCES' and self.policy.get('purpose') == 'CLIENT_V3_RUNTIME_FRESH_COMPONENT_V1' and
               self.policy.get('candidate_source') == '2dbe7fe5623fae9ed5940a26385400958c3ffb42' and
               self.policy.get('retained_input_carrier') == '3856733787d10820ab73f842e9f2bbf4fdb84181' and
               set(self.policy.get('products', {})) == set(ROLES), 'exact current two-product/qualified-carrier Source policy required')
        C.need(self.manifest.get('status') == 'FROZEN_ROOT_FINAL_SOURCES' and self.manifest.get('schema_version') == 1 and
               set(self.manifest.get('files', {})) == set(self.rows) - {LANE + '/source-manifest.json', '.github/workflows/native-arm-build.yml'},
               'complete Source manifest denominator required')
        for n, row in self.manifest['files'].items():
            C.need(C.pin(self.read(n)) == row, 'Source manifest/body join differs')
        for role, name in ROLES.items():
            row = self.policy['products'][role]
            C.need(row.get('name') == name and row.get('version') == '0.1.0-1' and row.get('source_sha') == self.policy['candidate_source'], 'exact two current recipes required')
        expected = set(C.decode(self.read(LANE + '/infrastructure-pins.json')))
        for row in self.policy['products'].values():
            expected.update(row['recipe_directory'] + '/' + n for n in row['source_files'])
        expected.update(LANE + '/' + p.name for p in (CODE_ROOT / LANE).iterdir() if p.is_file() and p.name not in ('workflow.yml.in', 'input-policy.json'))
        expected.update({LANE + '/input-policy.json', LANE + '/source-manifest.json', '.github/workflows/native-arm-build.yml'})
        C.need(set(self.rows) == expected, 'exact closed Source factory namespace required')

    def read(self, n):
        n = C.name(n)
        C.need(n in self.rows, 'unbound Source DATA read refused')
        raw = C.ordinary(self.root / n, 16 * 1024**2)
        C.need(C.pin(raw) == {k: self.rows[n][k] for k in ('bytes', 'sha256')}, 'Source DATA body differs')
        return raw

    def product(self, role):
        return self.policy['products'][role]

    def recipe(self, role):
        row = self.product(role)
        return metadata(self.read(row['recipe_directory'] + '/.SRCINFO'))

    def product_bytes(self, role, n):
        row = self.product(role)
        C.need(n in row['source_files'], 'unbound recipe file refused')
        raw = self.read(row['recipe_directory'] + '/' + C.name(n))
        C.need(C.pin(raw) == row['source_files'][n], 'recipe source pin differs')
        return raw

def archive(raw):
    files = C.zip_files(raw)
    C.need('retention.json' in files, 'original retention receipt required')
    retention = C.decode(files['retention.json'])
    C.need(type(retention) is dict and type(retention.get('files')) is dict and
           set(files) == set(retention['files']) | {'retention.json'}, 'whole original export; no supplements/missing bodies')
    for n, row in retention['files'].items():
        C.name(n)
        C.need(C.pin(files[n]) == C.typed_pin(row, 16 * 1024**2), 'actual retained whole body pin differs')
    C.need(sum(len(files[n]) for n in retention['files']) == retention.get('bytes') <= C.CAP, 'whole retained byte total differs')
    return files, retention

def runner_data(files, source):
    # Import only CURRENT trusted maintained code. Source is passed solely as pinned plaintext DATA.
    path = CODE_ROOT / LANE / 'adapter.py'
    spec = importlib.util.spec_from_file_location('_trusted_client_v3_reader_derivation', path)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    copies = {n: LANE + '/' + n for n in ('lifecycle.py', 'installed.py', 'runtime_image.py', 'rules.py', 'installed_v3.py', 'rename_after_real_verification.py', 'input-policy.json')}
    copies.update({'accepted/lifecycle.py': 'scripts/ci/welcome-native/lifecycle.py', 'accepted/root_upgrade.py': 'scripts/ci/full-root-upgrade/root_upgrade.py',
                   'fixture-client/test_client_v2.py': 'scripts/client/test_client_v2.py', 'fixture-client/client_v2.py': 'scripts/client/client_v2.py'})
    expected = {n: source.read(original) for n, original in copies.items()}
    expected['contract.py'] = adapter.text(source.root, 'contract.py').encode()
    for role in ('runtime-dependency', 'lifecycle'):
        prefix = 'emitted/' + role + '/'
        proof = C.decode(files[prefix + 'runner-derivations.json'])
        C.need(proof.get('schema') == 1 and proof.get('status') == 'SOURCE_CLOSED_ACTUAL_RUNTIME_RUNNER_DATA' and
               set(proof.get('files', {})) == set(expected), 'complete actual twelve-file runner required')
        for n, raw in expected.items():
            C.need(files.get(prefix + 'runner/' + n) == raw and proof['files'][n] == dict(**C.pin(raw), mode=0o644),
                   'actual emitted runner DATA differs from trusted derivation/Source copies')

def exact_export_names(files, source, report):
    wanted = {'retention.json', 'source-proof.json', 'ordered-cleanup.json', 'base/report.json', 'base/installed-packages.lock',
        'runtime/report.json', 'runtime/lifecycle.json', 'runtime/groups.json', 'runtime/runtime-image.json', 'runtime/runtime575.lock',
        'runtime/base-consumers/owner.json', 'runtime/apps-consumers/owner.json', 'runtime/runtime-dependency-image-image/report.json',
        'runtime/base-inventory.log', 'runtime/lifecycle.log', 'runtime/runtime-dependency-image-install.log', 'runtime/runtime-dependency-image-commit.log',
        'trust/TEST-public.asc'}
    wanted.update('harness/' + n.rsplit('/', 1)[1] for n in source.rows if n.startswith(LANE + '/'))
    runner_names = {'contract.py', 'lifecycle.py', 'installed.py', 'runtime_image.py', 'rules.py', 'installed_v3.py', 'rename_after_real_verification.py',
                    'input-policy.json', 'accepted/lifecycle.py', 'accepted/root_upgrade.py', 'fixture-client/test_client_v2.py', 'fixture-client/client_v2.py'}
    for role in ('runtime-dependency', 'lifecycle'):
        wanted.add('emitted/' + role + '/runner-derivations.json')
        wanted.update('emitted/' + role + '/runner/' + n for n in runner_names)
    for role, name in ROLES.items():
        wanted.update('source/' + name + '/' + n for n in source.product(role)['source_files'])
        wanted.add('runtime/' + name + '-comparison.json')
        for side, build in zip(('a', 'b'), report['products'][name]['builds']):
            prefix = 'runtime/' + name + '-' + side + '/'
            wanted.update(prefix + n for n in ('provenance.json', 'validation.json', 'expected-packages.lock', 'build.log'))
            wanted.update(prefix + 'artifacts/' + n for n in ('environment.txt', 'packages.lock', 'config.sha256', 'makepkg.conf', 'pacman.conf', 'generated.SRCINFO'))
            wanted.add('packages/' + name + '-' + side + '/' + C.name(build['archive']))
        wanted.add('trust/' + report['products'][name]['builds'][0]['archive'] + '.sig')
    C.need(set(files) == wanted, 'exact finite exported DATA namespace; no supplements')

def cleanup_data(files, base, report, proof):
    cleanup = C.decode(files['ordered-cleanup.json'])
    dependency = C.decode(files['runtime/runtime-dependency-image-image/report.json'])
    image = dependency['image']
    C.need(re.fullmatch('sha256:' + HEX, image) and image != base['image'] and dependency.get('status') == 'PASS_OWNED_SIGNED_DEPENDENCY_IMAGE' and
           dependency['ownership']['build_complete'] is True and dependency['ownership']['image'] == image and
           dependency['ownership']['token'] == hashlib.sha256((proof['consumer_token'] + ':runtime-dependency-image').encode()).hexdigest()[:16],
           'proof-bound distinct owned dependency image required')
    C.need(cleanup.get('status') == 'PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY' and
           cleanup.get('authority') == 'PASS_REMOVED_AFTER_ACTOR_RETIREMENT' and cleanup.get('borrowed_images_preserved') is True,
           'complete source-enforced ordered retirement required')
    names, owners = [], {}
    for group, count, expected in [('apps-consumers', 2, image), ('base-consumers', 5, base['image'])]:
        owner = C.decode(files['runtime/' + group + '/owner.json'])
        retired = cleanup['consumer_groups'][group]
        C.need(owner.get('schema_version') == 1 and owner.get('token') == proof['consumer_token'] and owner.get('label') == LABEL and
               owner.get('image') == expected and type(owner.get('containers')) is list and len(owner['containers']) == len(set(owner['containers'])) == count and
               all(re.fullmatch(r'cachy-asahi-product-(?:(?:probe|lifecycle)-)?[0-9a-f]{32}', n) for n in owner['containers']),
               'exact five-plus-two persisted consumer set required')
        C.need(retired.get('status') == 'PASS_CONSUMERS_RETIRED' and [r['container'] for r in retired['containers']] == list(reversed(owner['containers'])) and
               all(r.get('status') == 'PASS' and r.get('absence_verified') is True for r in retired['containers']), 'ordered actual consumer receipts required')
        names += owner['containers']
        owners[group] = owner
    C.need(len(set(names)) == 7, 'distinct seven native consumer identities required')
    retired = cleanup['dependency_images']['runtime-dependency-image']
    C.need(retired.get('status') == 'PASS' and retired.get('image') == dict(id=image, absence_verified=True) and
           cleanup['producer']['status'] == 'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and
           cleanup['producer']['consumer'] == cleanup['consumer_groups']['base-consumers'] and
           cleanup['producer']['producer'] == base['owned_cleanup'] and base['owned_cleanup']['probe']['absence_verified'] is True,
           'dependency image then producer/authority retirement joins required')
    return image, owners

def build_pairs(files, source, report, base, image, owners, lock, runtime_lock):
    environments = set()
    for role, name in ROLES.items():
        row = report['products'][name]
        expected_image = base['image'] if role == 'runtime' else image
        inventory = lock if role == 'runtime' else runtime_lock
        recipe = source.recipe(role)
        product = source.product(role)
        C.need(row.get('version') == '0.1.0-1' and row.get('build_image') == expected_image and row.get('build_inventory_sha256') == C.pin(inventory)['sha256'] and
               type(row.get('builds')) is list and len(row['builds']) == 2, 'exact role/version/image/inventory/native pair required')
        observed = []
        for side, build in zip(('a', 'b'), row['builds']):
            prefix = 'runtime/' + name + '-' + side + '/'
            provenance = C.decode(files[prefix + 'provenance.json'])
            C.need(provenance.get('status') == 'built-package-static-pass' and provenance.get('mode') == 'native' and
                   provenance.get('image') == provenance.get('image_id') == expected_image and
                   provenance.get('expected_packages_sha256') == C.pin(inventory)['sha256'] and
                   provenance.get('recipe_metadata') == recipe and
                   provenance.get('recipe_inputs') == {n: p['sha256'] for n, p in product['source_files'].items()} and
                   provenance.get('entry_script_sha256') == C.pin(source.read('scripts/build/container-entry.sh'))['sha256'],
                   'actual clean native build/complete source recipe/environment binding differs')
            environment = provenance['clean_environment_id']
            C.need(environment not in environments and environment in owners['base-consumers' if role == 'runtime' else 'apps-consumers']['containers'], 'fresh unique builder lease membership required')
            environments.add(environment)
            argv = provenance['command']
            C.need(type(argv) is list and argv[:4] == ['docker', 'run', '--name', environment] and
                   all(flag in argv for flag in ('--network=none', '--read-only', '--platform=linux/arm64', '--pids-limit=256', '--memory=3g', '--cpus=4', '--label=' + LABEL + '=' + report['ownership_token'])) and
                   not any('test-signing' in v or '/authority' in v for v in argv), 'read-only isolated exact native builder command required')
            archive_name = build['archive']
            C.need(archive_name == name + '-0.1.0-1-any.pkg.tar.xz', 'fixed two-leaf XZ package basename required')
            raw = files['packages/' + name + '-' + side + '/' + archive_name]
            C.need(C.pin(raw)['sha256'] == build['sha256'] == provenance['artifacts'].get(archive_name), 'actual original archive SHA join differs')
            for n, digest in provenance['files'].items():
                C.name(n)
                data = raw if n == 'artifacts/' + archive_name else files[prefix + n]
                C.need(C.pin(data)['sha256'] == digest, 'whole build evidence/provenance pin differs')
            C.need(files[prefix + 'expected-packages.lock'] == files[prefix + 'artifacts/packages.lock'] == inventory, 'complete exact build lock required')
            C.need(metadata(files[prefix + 'artifacts/generated.SRCINFO']) == recipe, 'generated/reviewed SRCINFO differs')
            config = files[prefix + 'artifacts/makepkg.conf'].decode()
            C.need(len(re.findall(r"(?m)^PKGEXT=['\"]\.pkg\.tar\.xz['\"]$", config)) == 1, 'observed exact XZ builder config required')
            environment_lines = files[prefix + 'artifacts/environment.txt'].decode().splitlines()
            C.need(len(environment_lines) >= 3 and 'aarch64' in environment_lines[0] and environment_lines[1] == '4096', 'complete native4K build environment required')
            log = files[prefix + 'build.log']
            C.need(b'Starting check()' in log and all(marker.encode() in log for marker in product['check_markers']) and
                   not re.search(br'\bskipped=[1-9]|\bOK \(skipped=', log), 'actual mandatory native check markers/no skips required')
            parsed = package(raw, archive_name, recipe, product['payload'], lambda n: source.product_bytes(role, n))
            validation = C.decode(files[prefix + 'validation.json'])
            C.need(validation.get('errors') == [] and validation.get('elf') is None and validation.get('payload') == parsed['payload'] and
                   validation.get('tests') == build.get('tests') and validation['package'].get('errors') == [] and not validation['package'].get('elf') and
                   validation['package'].get('members') == parsed['members'] and validation['package'].get('metadata') == parsed['metadata'] and
                   validation['package'].get('sha256') == parsed['sha256'], 'independent original package/retained inspection report differs')
            observed.append((raw, parsed))
        C.need(observed[0] == observed[1], 'independent complete archive/payload/PKGINFO/BUILDINFO pair differs')
        expected = dict(status='contents-reproduced', errors=[], packages={row['builds'][0]['archive']: dict(installed_contents_equal=True, pkginfo_equal=True, bytes_equal=True, buildinfo_equal=True)},
                        hardware_status='NOT RUN', independence_limit='Distinct recorded container runs; independent machine execution is not attested.')
        C.need(row['comparison'] == C.decode(files['runtime/' + name + '-comparison.json']) == expected, 'independent pair comparison/report join differs')
    C.need(len(environments) == 4, 'four clean native builders required')

def validate(files, retention, source, selected):
    C.need(retention.get('status') == 'PASS_NATIVE_RUNTIME_CLIENT_V3_FRESH_COMPONENT' and retention.get('errors') == [] and
           retention.get('hardware') == 'NOT_RUN' and retention.get('release') == 'NOT_ADMITTED', 'complete positive component retention required')
    proof = C.decode(files['source-proof.json'])
    identity = str(selected['run']) + ':1:' + selected['source_sha']
    C.need(proof.get('status') == 'SOURCE_PROOF_PASS' and proof.get('source_sha') == proof.get('workflow_sha') == selected['source_sha'] and
           proof.get('run_id') == str(selected['run']) and proof.get('run_attempt') == '1' and proof.get('source_files') == len(source.manifest['files']) and
           proof.get('job_token') == hashlib.sha256(('product-build-pair:' + identity).encode()).hexdigest()[:16] and
           proof.get('consumer_token') == hashlib.sha256(('tools-consumer:' + identity).encode()).hexdigest()[:32], 'actual original Source/run/token derivation differs')
    for n in source.rows:
        if n.startswith(LANE + '/'):
            C.need(files.get('harness/' + n.rsplit('/', 1)[1]) == source.read(n), 'actual retained harness DATA differs')
    for role, name in ROLES.items():
        for n in source.product(role)['source_files']:
            C.need(files.get('source/' + name + '/' + n) == source.product_bytes(role, n), 'actual retained source recipe DATA differs')
    runner_data(files, source)
    base = C.decode(files['base/report.json'])
    report = C.decode(files['runtime/report.json'])
    C.need(base.get('status') == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and re.fullmatch('sha256:' + HEX, base.get('image') or '') and
           base['ownership']['token'] == proof['job_token'] and base['owned_cleanup']['status'] == 'PASS' and
           base['owned_cleanup']['image'] == dict(id=base['image'], absence_verified=True), 'actual source-owned574 producer/retirement receipt required')
    C.need(report.get('status') == 'PASS_NATIVE_RUNTIME_CLIENT_V3_PAIRS_AND_FRESH_LIFECYCLE' and set(report.get('products', {})) == set(ROLES.values()) and
           report.get('base_image') == base['image'] and report.get('ownership_token') == proof['consumer_token'], 'exact same-source two-product parent report required')
    exact_export_names(files, source, report)
    lifecycle = C.decode(files['runtime/lifecycle.json'])
    C.need(report.get('lifecycle') == lifecycle, 'whole standalone/parent lifecycle differs')
    lifecycle_rules.validate(SimpleNamespace(need=C.need, re=re, ROLES=ROLES), lifecycle)
    image, owners = cleanup_data(files, base, report, proof)
    lock = files['base/installed-packages.lock']
    C.need(C.pin(lock)['sha256'] == BASE and len(lock.splitlines()) == 574, 'complete original574 lock required')
    runtime_lock = files['runtime/runtime575.lock']
    C.need(runtime_lock == ('\n'.join(sorted(lock.decode().splitlines() + [ROLES['runtime'] + ' 0.1.0-1'])) + '\n').encode(), 'exact Runtime575 lock required')
    dependency = C.decode(files['runtime/runtime-image.json'])
    C.need(dependency.get('status') == 'PASS_SIGNED_RUNTIME_DEPENDENCY_INSTALL' and dependency.get('package_count') == 575 and
           dependency.get('base574_preserved') is True and dependency.get('signatures') == 'REQUIRED_TEST_ONLY' and
           dependency.get('dependencies') == 'PASS_PACMAN_T_NO_WAIVERS' and dependency.get('expected_lock_sha256') == C.pin(runtime_lock)['sha256'] and
           dependency.get('runtime_sha256') == report['products'][ROLES['runtime']]['builds'][0]['sha256'], 'signed exact Runtime dependency receipt required')
    C.need(report['signer'].get('authority') == 'EPHEMERAL_TEST_ONLY' and re.fullmatch(r'[0-9A-F]{40}', report['signer'].get('fingerprint') or ''), 'isolated TEST signer receipt required')
    trust = {'trust/TEST-public.asc'} | {'trust/' + row['builds'][0]['archive'] + '.sig' for row in report['products'].values()}
    C.need({n for n in files if n.startswith('trust/')} == trust and all(0 < len(files[n]) <= 65536 for n in trust),
           'both whole original package signatures and public TEST ring required')
    build_pairs(files, source, report, base, image, owners, lock, runtime_lock)
    return dict(status='VALIDATED_CLIENT_V3_RUNTIME_NATIVE_FRESH_COMPONENT_DATA_ONLY', source=selected['source_sha'], run=selected['run'], attempt=1,
        native_admission=False, Doc315_qualification=False, Root_acceptance=None, products=2, clean_builds=4, installed_inventory=576,
        package_pairs='INDEPENDENT_ORIGINAL_XZ_BYTES_PAYLOAD_PKGINFO_BUILDINFO_JOIN', actual_runner_bytes='COMPLETE_BOTH_CONTEXTS_DATA_JOIN',
        lifecycle='SOURCE_ENFORCED_RECORDED_FIVE_PHASES_BOTH_HOMES', preservation_maps='PRIVATE_UNEXPORTED_SOURCE_ENFORCED_RECORDED',
        TEST_signatures='SOURCE_ENFORCED_RECORDED_NOT_RELEASE_TRUST', retirement='SOURCE_ENFORCED_RECORDED_NOT_LIVE_REOBSERVED',
        independent_machine='NOT_ATTESTED', version_upgrade='NOT_RUN', generic16K='NOT_RUN', M2='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED',
        collected_code_imports=0, actors=0)

def qualify(source_root, authorization_raw, selected, run, jobs, artifact, raw):
    C.need(C.pin(authorization_raw)['sha256'] == selected['source_authorization_sha256'], 'Root Source authorization pin differs')
    success = run_metadata(run, jobs, artifact, selected)
    source = SourceData(source_root, C.decode(authorization_raw), selected)
    C.need(C.pin(raw) == dict(bytes=selected['artifact_bytes'], sha256=selected['artifact_sha256']), 'complete original artifact size/SHA differs')
    files, retention = archive(raw)
    if not success:
        return dict(status='SOURCE_BOUND_CLIENT_V3_COMPONENT_FAILURE_DATA_NOT_ACCEPTANCE', Source=selected['source_sha'], run=selected['run'],
                    Root_acceptance=None, native_admission=False, retained_files=sorted(files), retention_status=retention.get('status'), actors=0, collected_code_imports=0)
    return validate(files, retention, source, selected)

def read_component(*, binding_path, binding_sha256, authorization_path, source_root, run_path, jobs_path, artifact_metadata_path, archive_path):
    return inspect_inputs(binding_path=binding_path, binding_sha256=binding_sha256, authorization_path=authorization_path,
        source_root=source_root, run_path=run_path, jobs_path=jobs_path, artifact_metadata_path=artifact_metadata_path, archive_path=archive_path)[0]

def inspect_inputs(*, binding_path, binding_sha256, authorization_path, source_root, run_path, jobs_path, artifact_metadata_path, archive_path):
    with C.passive():
        raw = C.ordinary(binding_path, 65536)
        C.need(C.pin(raw)['sha256'] == binding_sha256, 'explicit Root binding pin differs')
        selected = binding(raw)  # NULL selectors fail before Source, metadata or archive opens.
        original = C.ordinary(archive_path, C.ZIP_CAP)
        result = qualify(source_root, C.ordinary(authorization_path, 4 * 1024**2), selected,
            C.decode(C.ordinary(run_path, 2 * 1024**2)), C.decode(C.ordinary(jobs_path, 2 * 1024**2)),
            C.decode(C.ordinary(artifact_metadata_path, 2 * 1024**2)), original)
        files, retention = archive(original)
        return result, files, retention, selected

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for n in ('binding-path', 'authorization-path', 'source-root', 'run-path', 'jobs-path', 'artifact-metadata-path', 'archive-path'):
        parser.add_argument('--' + n, type=Path, required=True)
    parser.add_argument('--binding-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(read_component(**vars(args)), sort_keys=True))
