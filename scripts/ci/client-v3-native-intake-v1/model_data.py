# SPDX-License-Identifier: MIT
"""Synthetic test DATA only. Never a constructed Source, authority or native run."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import lzma
import client_v3_common as C
import package_data
import reader as R

def component(test):
    source, runner = test.runner_model()
    native = R.CODE_ROOT / R.LANE
    products = C.decode((native / 'input-policy.json').read_bytes())['products']
    original_read = source.read
    source.manifest = {'files': {'MODELED_NONCONSTRUCTED_SOURCE': {}}}
    source.rows = {R.LANE + '/' + p.name: {} for p in native.iterdir() if p.is_file() and p.name != 'workflow.yml.in'}
    source.product = lambda role: products[role]
    source.product_bytes = lambda role, n: (source.root / products[role]['recipe_directory'] / n).read_bytes()
    source.recipe = lambda role: package_data.metadata(source.product_bytes(role, '.SRCINFO'))
    files = dict(runner)
    for n in source.rows:
        files['harness/' + n.rsplit('/', 1)[1]] = original_read(n)
    for role, name in R.ROLES.items():
        for n in products[role]['source_files']:
            files['source/' + name + '/' + n] = source.product_bytes(role, n)
    target = C.decode((source.root / 'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
    lock = ''.join(r['name'] + ' ' + r['version'] + '\n' for r in sorted(target['packages'], key=lambda r: r['name'])).encode()
    assert C.pin(lock)['sha256'] == R.BASE
    runtime_lock = ('\n'.join(sorted(lock.decode().splitlines() + [R.ROLES['runtime'] + ' 0.1.0-1'])) + '\n').encode()
    selected = dict(source_sha='a' * 40, run=123)
    identity = '123:1:' + selected['source_sha']
    proof = dict(status='SOURCE_PROOF_PASS', source_sha=selected['source_sha'], workflow_sha=selected['source_sha'], run_id='123', run_attempt='1', source_files=1,
        job_token=hashlib.sha256(('product-build-pair:' + identity).encode()).hexdigest()[:16], consumer_token=hashlib.sha256(('tools-consumer:' + identity).encode()).hexdigest()[:32])
    base_image, image = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64
    names = ['cachy-asahi-product-' + format(n, '032x') for n in range(1, 8)]
    groups = {'base-consumers': names[:5], 'apps-consumers': names[5:]}
    base = dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION', image=base_image, ownership=dict(token=proof['job_token']),
                owned_cleanup=dict(status='PASS', image=dict(id=base_image, absence_verified=True), probe=dict(absence_verified=True)))
    dependency = dict(status='PASS_OWNED_SIGNED_DEPENDENCY_IMAGE', image=image, ownership=dict(build_complete=True, image=image,
        token=hashlib.sha256((proof['consumer_token'] + ':runtime-dependency-image').encode()).hexdigest()[:16]))
    retired = {g: dict(status='PASS_CONSUMERS_RETIRED', containers=[dict(container=n, status='PASS', absence_verified=True) for n in reversed(values)]) for g, values in groups.items()}
    cleanup = dict(status='PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY', authority='PASS_REMOVED_AFTER_ACTOR_RETIREMENT',
        borrowed_images_preserved=True, consumer_groups=retired, dependency_images={'runtime-dependency-image': dict(status='PASS', image=dict(id=image, absence_verified=True))},
        producer=dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP', consumer=retired['base-consumers'], producer=base['owned_cleanup']))
    report = dict(status='PASS_NATIVE_RUNTIME_CLIENT_V3_PAIRS_AND_FRESH_LIFECYCLE', base_image=base_image, ownership_token=proof['consumer_token'],
                  products={}, signer=dict(authority='EPHEMERAL_TEST_ONLY', fingerprint='A' * 40), lifecycle=test.lifecycle_model())
    for role, name in R.ROLES.items():
        recipe, product = source.recipe(role), source.product(role)
        pkginfo = dict(pkgname=[name], pkgver=['0.1.0-1'], arch=['any'], license=['MIT'], depend=recipe.get('depends', []))
        buildinfo = dict(format=['2'], pkgname=[name], pkgver=['0.1.0-1'], pkgarch=['any'], pkgbuild_sha256sum=[C.pin(source.product_bytes(role, 'PKGBUILD'))['sha256']])
        text = lambda rows: ''.join(k + ' = ' + v + '\n' for k, values in rows.items() for v in values).encode()
        entries = {'.PKGINFO': text(pkginfo), '.BUILDINFO': text(buildinfo), '.MTREE': b'MODELED MTREE\n'}
        entries.update({n: source.product_bytes(role, original) for n, (original, mode) in product['payload'].items()})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for n, raw in entries.items():
                row = tarfile.TarInfo(n)
                row.size = len(raw)
                row.mode = product['payload'][n][1] if n in product['payload'] else 0o644
                row.mtime = 1791748800
                archive.addfile(row, io.BytesIO(raw))
        raw = lzma.compress(buffer.getvalue())
        filename = name + '-0.1.0-1-any.pkg.tar.xz'
        parsed = package_data.package(raw, filename, recipe, product['payload'], lambda n: source.product_bytes(role, n))
        comparison = dict(status='contents-reproduced', errors=[], packages={filename: dict(installed_contents_equal=True, pkginfo_equal=True, bytes_equal=True, buildinfo_equal=True)},
            hardware_status='NOT RUN', independence_limit='Distinct recorded container runs; independent machine execution is not attested.')
        inventory, actor_image = (lock, base_image) if role == 'runtime' else (runtime_lock, image)
        builds = []
        for i, side in enumerate(('a', 'b')):
            environment = groups['base-consumers' if role == 'runtime' else 'apps-consumers'][i]
            prefix = 'runtime/' + name + '-' + side + '/'
            tests = dict(status='MODELED_SCHEMA_CHECK_EXIT_ONLY')
            validation = dict(errors=[], elf=None, payload=parsed['payload'], tests=tests,
                              package=dict(errors=[], elf={}, members=parsed['members'], metadata=parsed['metadata'], sha256=parsed['sha256']))
            records = {'validation.json': C.encoded(validation), 'expected-packages.lock': inventory,
                'build.log': ('Starting check()\n' + '\n'.join(product['check_markers'])).encode(),
                'artifacts/packages.lock': inventory, 'artifacts/generated.SRCINFO': source.product_bytes(role, '.SRCINFO'),
                'artifacts/environment.txt': b'Linux MODELED aarch64\n4096\nMODELED MAKEPKG\n',
                'artifacts/config.sha256': b'MODELED CONFIG DATA\n', 'artifacts/makepkg.conf': b"PKGEXT='.pkg.tar.xz'\n", 'artifacts/pacman.conf': b'MODELED PACMAN DATA\n'}
            provenance = dict(status='built-package-static-pass', mode='native', image=actor_image, image_id=actor_image, expected_packages_sha256=C.pin(inventory)['sha256'],
                recipe_metadata=recipe, recipe_inputs={n: p['sha256'] for n, p in product['source_files'].items()},
                entry_script_sha256=C.pin(original_read('scripts/build/container-entry.sh'))['sha256'], clean_environment_id=environment,
                command=['docker', 'run', '--name', environment, '--network=none', '--read-only', '--platform=linux/arm64', '--pids-limit=256', '--memory=3g', '--cpus=4', '--label=' + R.LABEL + '=' + proof['consumer_token']],
                artifacts={filename: C.pin(raw)['sha256']}, files={n: C.pin(v)['sha256'] for n, v in records.items()})
            provenance['files']['artifacts/' + filename] = C.pin(raw)['sha256']
            files.update({prefix + n: v for n, v in records.items()})
            files[prefix + 'provenance.json'] = C.encoded(provenance)
            files['packages/' + name + '-' + side + '/' + filename] = raw
            builds.append(dict(archive=filename, sha256=C.pin(raw)['sha256'], tests=tests))
        report['products'][name] = dict(version='0.1.0-1', build_image=actor_image, build_inventory_sha256=C.pin(inventory)['sha256'], builds=builds, comparison=comparison)
        files['runtime/' + name + '-comparison.json'] = C.encoded(comparison)
        files['trust/' + filename + '.sig'] = b'MODELED SIGNATURE DATA; SOURCE_ENFORCED ONLY\n'
    files.update({'source-proof.json': C.encoded(proof), 'ordered-cleanup.json': C.encoded(cleanup), 'base/report.json': C.encoded(base), 'base/installed-packages.lock': lock,
        'runtime/report.json': C.encoded(report), 'runtime/lifecycle.json': C.encoded(report['lifecycle']), 'runtime/groups.json': C.encoded({}),
        'runtime/runtime575.lock': runtime_lock, 'runtime/runtime-dependency-image-image/report.json': C.encoded(dependency),
        'runtime/runtime-image.json': C.encoded(dict(status='PASS_SIGNED_RUNTIME_DEPENDENCY_INSTALL', package_count=575, base574_preserved=True, signatures='REQUIRED_TEST_ONLY',
            dependencies='PASS_PACMAN_T_NO_WAIVERS', expected_lock_sha256=C.pin(runtime_lock)['sha256'], runtime_sha256=report['products'][R.ROLES['runtime']]['builds'][0]['sha256'])),
        'trust/TEST-public.asc': b'MODELED PUBLIC SIGNER DATA; NOT RELEASE TRUST\n'})
    for group, values in groups.items():
        files['runtime/' + group + '/owner.json'] = C.encoded(dict(schema_version=1, token=proof['consumer_token'], label=R.LABEL, image=base_image if group == 'base-consumers' else image, containers=values))
    for n in ('base-inventory', 'lifecycle', 'runtime-dependency-image-install', 'runtime-dependency-image-commit'):
        files['runtime/' + n + '.log'] = b'MODELED SOURCE LOG DATA\n'
    retention = dict(status='PASS_NATIVE_RUNTIME_CLIENT_V3_FRESH_COMPONENT', errors=[], hardware='NOT_RUN', release='NOT_ADMITTED', files={n: C.pin(v) for n, v in files.items()}, bytes=sum(map(len, files.values())))
    files['retention.json'] = C.encoded(retention)
    return files, retention, source, selected
