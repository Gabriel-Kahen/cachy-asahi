#!/usr/bin/env python3
"""Compose the fixed ten current development packages in one disposable job."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
SOURCES = {'product': 'a58fca33c4db5f2ab3ea6111f4d7842a932cc336',
           'updater': '1aea667aec50a62ba0ab2dad44be24a4dc3bd098',
           'desktop': '9a2e520dbdfce7e4af417595ff3de9e6a284ef04'}
BASE = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
FULL = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
FINAL = 'c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463'
UPDATER_V2 = '480053c0866a922138d85af2b9880fb0e10d7b2c'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def retain(raw, public):
    names = ['desktop574/report.json', 'desktop574/build.log', 'dependency.log',
             'lifecycle-fixture-summary.json', 'updater-v2-summary.json', 'setup4-summary.json']
    for name in ('ksmctl', 'topmem', 'zsh-autosuggestions', 'fish-bang-bang'):
        names += [f'cachy-asahi-{name}/{file}' for file in ('build.log', 'provenance.json', 'validation.json')]
    for name in names:
        path = raw / name
        if path.is_file():
            target = public / 'diagnostics' / name; target.parent.mkdir(parents=True, exist_ok=True)
            with path.open('rb') as stream:
                stream.seek(max(0, path.stat().st_size - 65536)); target.write_bytes(stream.read(65536))


def retain_updater(source, raw, public):
    native, materialized = raw / 'updater/native', raw / 'updater/materialized'
    if not native.is_dir(): return
    selected = raw / 'updater-public-selection'
    projector = module('composition_updater_projection', source / 'packages/tools/cachy-asahi-update/public-evidence.py')
    assert projector.project_evidence(native, selected, materialized if materialized.exists() else None)['projection'] == 'PASS'
    exporter = module('composition_updater_export', source / 'scripts/ci/integration_export.py')
    assert exporter.export_evidence(selected, public / 'updater-build')['evidence_export'] == 'PASS'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def command(argv, log, timeout):
    with log.open('wb') as stream:
        proc = subprocess.Popen(list(map(str, argv)), stdout=stream, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except BaseException:
            for sig, seconds in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                try: os.killpg(proc.pid, sig)
                except ProcessLookupError: pass
                try: proc.wait(timeout=seconds); break
                except subprocess.TimeoutExpired: continue
            raise
        assert code == 0, 'command failed: ' + log.name


def standard(build, recipe_pin, image, lock_pin=BASE):
    record = json.loads((build / 'provenance.json').read_text())
    assert record['status'] == 'built-package-static-pass' and record['mode'] == 'native'
    assert record['builder_host_arch'] in ('aarch64', 'arm64')
    assert record['image_id'] == image and record['expected_packages_sha256'] == lock_pin
    assert record['recipe_inputs']['PKGBUILD'] == recipe_pin and record['exit_code'] == 0
    paths = list((build / 'artifacts').glob('*.pkg.tar.*')); assert len(paths) == 1
    assert sha(paths[0]) == record['artifacts'][paths[0].name]
    return paths[0], record['artifacts'][paths[0].name]


def updater(source, root, cache, *, materializer_pin='2ce747b22ecf7fee9b31673cbcef9167041bbd754cd7e59dfd30534a294c17a3'):
    package = source / 'packages/tools/cachy-asahi-update'
    work = root / 'updater'; work.mkdir()
    command([sys.executable, '-I', '-B', package / 'materialize-inputs.py', '--output', work / 'materialized',
        '--pins-sha256', materializer_pin], work / 'materialize.log', 930)
    command([sys.executable, '-B', package / 'updater-native.py', 'freeze', '--source',
        work / 'materialized/private-sanitized/cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a-sanitized.tar.gz',
        '--vendor', work / 'materialized/private-cache/cachy-update-vendor.tar.gz', '--output', work / 'candidate'],
        work / 'freeze.log', 120)
    candidate = work / 'candidate/candidate.json'
    command([sys.executable, '-B', package / 'updater-native.py', 'build', '--candidate', candidate,
        '--candidate-sha256', sha(candidate), '--cache', cache, '--output', work / 'native'], work / 'build.log', 5400)
    native = work / 'native'
    result = json.loads((native / 'result.json').read_text())
    assert result['native_pair'] == 'PASS'
    image = (native / 'image-id').read_text().strip()
    assert result['image_id'] == image and sha(native / 'packages.lock') == '5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee'
    comparison = json.loads((native / 'comparison.json').read_text())
    assert not comparison['errors'] and all(comparison[k] is True for k in ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal'))
    packages = []
    for i in (1, 2):
        build = native / f'build-{i}'
        record = json.loads((build / 'provenance.json').read_text())
        assert record['native_compilation'] == 'PASS-private-native-package-static-checks'
        controller = json.loads((build / 'inputs/controller-input.json').read_text())
        assert sha(build / 'inputs/controller-input.json') == record['controller_sha256']
        assert controller['image_id'] == image and controller['builder_inventory_sha256'] == sha(native / 'packages.lock')
        paths = list((build / 'artifacts').glob('*.pkg.tar.*')); assert len(paths) == 1
        assert sha(paths[0]) == record['package_sha256']
        packages.append((paths[0], record['package_sha256']))
    assert packages[0][1] == packages[1][1]
    return packages[0]


def desktop(source, root, cache):
    helper = source / 'scripts/ci/maintained_desktop574.py'
    inputs = source / 'scripts/ci/maintained-desktop574-inputs.json'
    assert sha(inputs) == 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
    work = root / 'desktop574'; work.mkdir()
    context = work / 'context'; context.mkdir()
    for name in ('deps', 'keys'): (context / name).mkdir()
    (work / 'home').mkdir(mode=0o700)
    api = module('composition574', helper)
    # Reuse the already verified same-job cache, including all six frozen seeds.
    # Remaining exact public inputs are fetched by the unchanged pinned helper.
    for item in api.plan(json.loads(inputs.read_text()), context):
        old = cache / item['filename']
        if old.is_file() and not old.is_symlink() and old.stat().st_size == item['size'] and sha(old) == item['sha256']:
            shutil.copyfile(old, item['target'])
    command([sys.executable, '-I', '-B', helper, 'build', '--inputs', inputs, '--output', work], work / 'build.log', 2400)
    report = json.loads((work / 'report.json').read_text())
    image = (work / 'image-id').read_text().strip()
    assert report['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and report['image'] == image
    assert sha(work / 'installed-packages.lock') == FULL
    return image, work / 'installed-packages.lock'


def sign(inputs, root, packages):
    home = root / 'test-signing'; home.mkdir(mode=0o700)
    gpg = ['gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve',
           '--pinentry-mode', 'loopback', '--passphrase', '']
    subprocess.run(gpg + ['--quick-generate-key', 'TEST ONLY composition <composition@test.invalid>',
                         'ed25519', 'sign', '1d'], check=True, capture_output=True, timeout=30)
    listing = subprocess.check_output(gpg + ['--with-colons', '--list-keys'], text=True, timeout=30)
    fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    assert len(fingerprints) == 1 and re.fullmatch('[0-9A-F]{40}', fingerprints[0])
    (inputs / 'TEST-public.asc').write_bytes(subprocess.check_output(gpg + ['--armor', '--export', fingerprints[0]], timeout=30))
    for path in packages:
        subprocess.run(gpg + ['--output', str(path) + '.sig', '--detach-sign', str(path)], check=True, capture_output=True, timeout=30)
    return fingerprints[0]


def payload(report):
    rows = []
    for path, item in report['members'].items():
        if path.startswith('.') or item['type'] == '5': continue
        assert item['type'] in ('0', '2') and path.startswith('usr/')
        row = {'path': '/' + path, 'type': 'file' if item['type'] == '0' else 'symlink',
               'mode': item['mode']}
        if item['type'] == '2': row['target'] = item['link']
        else: row['sha256'] = item['sha256']
        rows.append(row)
    return rows


def setup4_checkpoint(successor, rows, projects, inputs):
    """Select v2 before the initial transaction only in explicit setup4 mode."""
    if successor is None:
        return rows, projects, FINAL
    row = successor['package']
    assert row['name'] == 'cachy-asahi-update' and row['version'] == '4.4.2-2'
    rows = [row if p['name'] == row['name'] else p for p in rows]
    projects = [dict(row, archive=row['filename']) if p['name'] == row['name'] else p for p in projects]
    shutil.copyfile(HERE / 'expected-updater-v2.lock', inputs / 'expected-installed.lock')
    assert sha(inputs / 'expected-installed.lock') == successor['expected_inventory_sha256']
    return rows, projects, successor['expected_inventory_sha256']


def compose(args, raw, public, result):
    py = sys.executable
    pins = json.loads((HERE / 'recipes.json').read_text())
    for row in pins:
        assert sha(args.product / row['recipe']) == row['sha256']
    assert json.loads((args.native / 'result.json').read_text())['native_build'] == 'PASS'
    bootstrap = json.loads((args.native / 'bootstrap.json').read_text())
    core = (args.native / 'image-id').read_text().strip()
    assert bootstrap['image_id'] == core and bootstrap['status'] == 'image-provisioned'
    assert sha(args.native / 'packages.lock') == bootstrap['packages_lock_sha256'] == BASE
    assert (args.fdk / 'result.txt').read_text() == 'FDK_PAIR=PASS\nEXIT=0\n'
    checks = module('composition_checks', args.product / 'scripts/checks/package_checks.py')
    build_api = module('composition_build', args.product / 'scripts/build/build.py')
    artifacts = {}
    result['phase'] = 'reuse-original-and-fdk-pairs'
    for row in pins:
        name = row['name']
        if name in ('cachy-asahi-update', 'cachy-asahi-ksmctl', 'cachy-asahi-topmem',
                    'cachy-asahi-zsh-autosuggestions', 'cachy-asahi-fish-bang-bang'): continue
        paths = [args.fdk / f'build-{i}' if name == 'cachy-asahi-fdk-aac' else args.native / f'{name}-{i}' for i in (1, 2)]
        pair = [standard(path, row['sha256'], core) for path in paths]
        assert pair[0][1] == pair[1][1]; artifacts[name] = pair[0]
    result['phase'] = 'build-four-small-current-recipes'
    for row in pins:
        if row['name'] in artifacts or row['name'] == 'cachy-asahi-update': continue
        recipe = args.product / Path(row['recipe']).parent
        report = checks.recipe(recipe / 'PKGBUILD'); assert not report['errors']
        reviewed = raw / (row['name'] + '-inputs.json'); save(reviewed, report['input_sha256'])
        output = raw / row['name']
        command([py, '-B', args.product / 'scripts/build/build.py', recipe, '--image', core,
            '--output', output, '--mode', 'native', '--network', 'none', '--timeout', '120',
            '--source-date-epoch', '1791748800', '--expected-packages', args.native / 'packages.lock',
            '--reviewed-inputs', reviewed], raw / (row['name'] + '.log'), 180)
        artifacts[row['name']] = standard(output, row['sha256'], core)
    result['phase'] = 'updater-exact354-pair'
    artifacts['cachy-asahi-update'] = updater(args.updater, raw, args.cache)
    result['phase'] = 'fresh-exact574-runtime-base'
    image, base_lock = desktop(args.desktop, raw, args.cache)
    assert image != core
    result['phase'] = 'authenticate-five-deduplicate-four'
    assert sha(HERE / 'dependencies/inputs.lock.json') == '9a8064cde23ad90c2352395bdd1f6f5a8e843b3db3468cd2cc5a90829dc32704'
    command([py, '-B', HERE / 'dependencies/acquire.py', '--source-root', args.updater,
        '--cache', args.cache, '--keydir', args.cache, '--output', raw / 'dependency-audit'], raw / 'dependency.log', 180)
    dependency = json.loads((HERE / 'dependencies/inputs.lock.json').read_text())
    base = dict(line.split(' ', 1) for line in base_lock.read_text().splitlines())
    assert base['xdg-utils'] == '1.2.1-2'
    inputs = raw / 'inputs'; inputs.mkdir()
    shutil.copyfile(base_lock, inputs / 'expectedbase.lock')
    assert sha(HERE / 'expected-installed.lock') == FINAL
    shutil.copyfile(HERE / 'expected-installed.lock', inputs / 'expected-installed.lock')
    shutil.copyfile(args.cache / 'archlinuxarm.gpg', inputs / 'archlinuxarm.gpg')
    projects, rows, hooks, archives = [], [], set(), []
    for row in pins:
        original, digest = artifacts[row['name']]
        assert sha(original) == digest
        report = checks.package(original); assert not report['errors'] and report['sha256'] == digest
        metadata = checks.metadata((args.product / Path(row['recipe']).parent / '.SRCINFO').read_text())
        assert not build_api.bind_artifact(metadata, report, row['sha256'])
        target = inputs / original.name; shutil.copyfile(original, target)
        assert sha(target) == digest
        pkg = report['metadata']['.PKGINFO']
        assert '.INSTALL' not in report['members']
        hooks.update(Path(path).name for path in report['members'] if path.endswith('.hook'))
        projects.append({'name': row['name'], 'version': row['version'], 'archive': target.name,
            'sha256': sha(target), 'depends': pkg.get('depend', []), 'provides': pkg.get('provides', []),
            'conflicts': pkg.get('conflict', []), 'payload': payload(report)})
        rows.append({'name': row['name'], 'version': row['version'], 'filename': target.name,
                     'sha256': sha(target), 'size': target.stat().st_size})
        archives.append(target)
    lifecycle = None
    if args.lifecycle:
        result['phase'] = 'prepare-development-lifecycle-inputs'
        preparation = module('composition_lifecycle_inputs', HERE / 'lifecycle_inputs.py')
        lifecycle, upgrades = preparation.prepare(args, raw, inputs, core, checks, build_api, sys.modules[__name__])
        archives.extend(upgrades)
    successor = None
    if args.updater_v2_source:
        result['phase'] = 'prepare-updater-v2-native-pair'
        preparation = module('composition_updater_v2_inputs', HERE / 'updater_v2_inputs.py')
        successor, archive = preparation.prepare(args, raw, inputs, checks, build_api, sys.modules[__name__])
        archives.append(archive)
    setup4 = None
    if args.setup4_pair:
        result['phase'] = 'prepare-retained-setup4-native-pair'
        preparation = module('composition_setup4_inputs', HERE / 'setup4_inputs.py')
        setup4, archive = preparation.prepare(args, raw, inputs, checks, build_api, sys.modules[__name__])
        archives.append(archive)
    fingerprint = sign(inputs, raw, archives)
    for row in rows:
        sig = inputs / (row['filename'] + '.sig')
        row.update(signature_sha256=sha(sig), signature_size=sig.stat().st_size)
    if lifecycle:
        for row in lifecycle['upgrades']:
            sig = inputs / (row['filename'] + '.sig')
            row.update(signature_sha256=sha(sig), signature_size=sig.stat().st_size)
    if successor:
        row = successor['package']; sig = inputs / (row['filename'] + '.sig')
        row.update(signature_sha256=sha(sig), signature_size=sig.stat().st_size)
    if setup4:
        row = setup4['package']; sig = inputs / (row['filename'] + '.sig')
        row.update(signature_sha256=sha(sig), signature_size=sig.stat().st_size)
    checkpoint_sha = FINAL
    if setup4:
        rows, projects, checkpoint_sha = setup4_checkpoint(successor, rows, projects, inputs)
        successor = None
    for row in dependency['packages']:
        if row['name'] == 'xdg-utils': continue
        assert row['name'] not in base
        for suffix, digest in (('', row['sha256']), ('.sig', row['signature_sha256'])):
            old = args.cache / (row['filename'] + suffix); assert sha(old) == digest
            shutil.copyfile(old, inputs / old.name)
        rows.append(row)
    plan = {'packages': rows, 'projects': projects, 'hooks': sorted(hooks),
        'signer_fingerprint': dependency['signer_fingerprint'], 'test_signer_fingerprint': fingerprint}
    if lifecycle: plan['lifecycle'] = lifecycle
    if successor: plan['updater_v2'] = successor
    if setup4: plan['setup4'] = setup4
    if getattr(args, 'measure_footprint', False):
        footprint = module('composition_footprint', HERE / 'footprint.py')
        assert setup4 and successor is None and setup4['expected_inventory_sha256'] == footprint.EXPECTED
        footprint.prepare(HERE.parents[2], raw / 'footprint-source')
        plan['footprint'] = {'limits': footprint.LIMITS, 'sources': footprint.SOURCES}
    if getattr(args, 'measure_footprint_only', False): plan['measurement_only'] = True
    save(inputs / 'plan.json', plan)
    save(public / 'packages.json', {r['name']: {'version': r['version'], 'sha256': r['sha256']} for r in rows})
    result['phase'] = 'signed-offline-composition'
    name = 'cachy-asahi-composition-' + uuid.uuid4().hex
    owned = {'container': name}
    save(args.output / 'owned.json', owned)
    if getattr(args, 'measure_footprint', False):
        volume = 'cachy-asahi-footprint-' + uuid.uuid4().hex
        assert footprint.volume_present(volume) == [], 'fresh footprint volume required'
        owned['footprint_volume'] = volume
        save(args.output / 'owned.json', owned)  # Track an unknown create outcome for scoped cleanup.
        footprint.create_volume(volume)
    argv = ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform=linux/arm64', '--user=0:0',
        '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256',
        '--memory=2g', '--cpus=2', '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=512m',
        '--env=CACHY_ASAHI_COMPOSITION=' + uuid.uuid4().hex, '--env=LC_ALL=C', '--env=PYTHONDONTWRITEBYTECODE=1']
    for cap in ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID', 'SYS_CHROOT', 'SETFCAP'): argv.append('--cap-add=' + cap)
    if lifecycle or setup4: argv.append('--cap-add=KILL')
    if getattr(args, 'measure_footprint', False): argv.append('--cap-add=FSETID')  # Preserve copied setgid modes.
    for source, target, ro in ((inputs, '/inputs', True), (HERE / 'container.py', '/runner.py', True), (public, '/out', False)):
        argv += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if ro else '')]
    if lifecycle or successor or setup4:
        argv += ['--mount', f'type=bind,src={HERE / "lifecycle.py"},dst=/lifecycle.py,readonly']
    if successor:
        argv += ['--mount', f'type=bind,src={HERE / "updater_v2.py"},dst=/updater-v2.py,readonly',
                 '--env=CACHY_ASAHI_UPDATER_RUNTIME=' + uuid.uuid4().hex]
    if setup4:
        argv += ['--mount', f'type=bind,src={HERE / "setup4.py"},dst=/setup4.py,readonly']
    if getattr(args, 'measure_footprint', False):
        argv += ['--mount', f'type=volume,src={owned["footprint_volume"]},dst=/measurement,volume-nocopy',
                 '--mount', f'type=bind,src={raw / "footprint-source"},dst=/measurement-source,readonly',
                 '--mount', f'type=bind,src={HERE / "footprint.py"},dst=/footprint.py,readonly']
    command(argv + ['--entrypoint=/usr/bin/python3', image, '-I', '-B', '/runner.py'],
            public / 'transaction.log', 2400 if getattr(args, 'measure_footprint', False) else 1200 if lifecycle or successor or setup4 else 480)
    result['composition'] = json.loads((public / 'result.json').read_text())
    if getattr(args, 'measure_footprint_only', False):
        assert result['composition']['status'] == 'MEASURED_SCOPED_COPY'
        assert result['composition']['footprint']['status'] == 'MEASURED_SCOPED_COPY'
        assert result['composition']['footprint']['source_inventory_preserved'] is True
        assert result['composition']['footprint']['source_database_preserved'] is True
        return
    assert result['composition']['status'] == 'PASS'
    if lifecycle:
        assert result['composition']['lifecycle']['status'] == 'PASS'
        assert result['composition']['final_package_count'] == 574
        assert result['composition']['final_inventory_sha256'] == FULL
    if successor:
        assert result['composition']['updater_v2']['status'] == 'PASS'
        assert result['composition']['final_package_count'] == 587
        assert result['composition']['final_inventory_sha256'] == FINAL
    if setup4:
        assert result['composition']['setup4']['status'] == 'PASS'
        if getattr(args, 'measure_footprint', False):
            assert result['composition']['setup4']['footprint']['status'] == 'MEASURED_SCOPED_COPY'
        assert result['composition']['installed_inventory_sha256'] == checkpoint_sha
        assert result['composition']['final_package_count'] == 587
        assert result['composition']['final_inventory_sha256'] == checkpoint_sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'updater', 'desktop', 'native', 'fdk', 'cache', 'output'): parser.add_argument('--' + name, required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--lifecycle', action='store_true', help='Run the explicit disposable lifecycle after v1 composition checks')
    mode.add_argument('--updater-v2-source', type=Path, help='Exact Source480053 checkout for v1 upgrade, real Check and v1 rollback')
    parser.add_argument('--setup4-pair', type=Path, help='Retained Source98 native pair for the explicit setup3-to-4-to-3 development trial; with approved v2 source, select v2 in the initial checkpoint')
    parser.add_argument('--measure-footprint', action='store_true', help='Measure the exact setup4/updater-v2 scoped copy on a private disk-backed volume')
    parser.add_argument('--measure-footprint-only', action='store_true',
                        help='Construct the exact setup4 checkpoint and measure before ownership/lifecycle checks')
    args = parser.parse_args()
    if args.measure_footprint_only and not args.measure_footprint:
        parser.error('--measure-footprint-only requires --measure-footprint')
    if getattr(args, 'measure_footprint', False) and not (args.setup4_pair and args.updater_v2_source):
        parser.error('--measure-footprint requires --setup4-pair and --updater-v2-source')
    if args.setup4_pair and args.lifecycle:
        parser.error('--setup4-pair is incompatible with --lifecycle')
    if args.setup4_pair:
        args.setup4_pair = args.setup4_pair.resolve(strict=True)
    assert platform.machine() == 'aarch64' and os.getuid() != 0
    for name, source in SOURCES.items():
        path = getattr(args, name).resolve(); setattr(args, name, path)
        assert subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip() == source
    if args.updater_v2_source:
        args.updater_v2_source = args.updater_v2_source.resolve(strict=True)
        assert subprocess.check_output(['git', '-C', str(args.updater_v2_source), 'rev-parse', 'HEAD'], text=True).strip() == UPDATER_V2
    for name in ('native', 'fdk', 'cache', 'output'):
        path = getattr(args, name).resolve(); setattr(args, name, path)
        assert ',' not in str(path) and '\n' not in str(path)
    assert args.output.parent == Path('/tmp').resolve(), 'held updater requires an owned /tmp work root'
    args.output.mkdir(mode=0o700)
    raw = args.output / 'private'; raw.mkdir(mode=0o700)
    public = args.output / 'public'; public.mkdir()
    result = {'status': 'FAIL', 'phase': 'startup', 'sources': dict(SOURCES),
              'hardware': 'NOT RUN', 'target_lifecycle': 'NOT RUN', 'release': 'NOT ACCEPTED'}
    if args.updater_v2_source: result['sources']['updater_v2'] = UPDATER_V2
    if args.setup4_pair: result['sources']['setup4'] = '98fecf28a3cde63a9dd7531501c2187825349310'
    previous = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        compose(args, raw, public, result)
        result.update(status='MEASURED_SCOPED_COPY' if args.measure_footprint_only else 'PASS', phase='completed')
        if args.measure_footprint_only:
            result.update(scope='setup4-checkpoint-scoped-copy-diagnostic',
                          setup_lifecycle='NOT RUN', transaction_acceptance='NOT ESTABLISHED')
    except BaseException as error:
        result['error_type'] = type(error).__name__
        raise
    finally:
        failures = []
        try: retain(raw, public)
        except (OSError, ValueError): failures.append('bounded-diagnostics')
        try: retain_updater(args.updater, raw, public)
        except Exception: failures.append('updater-public-projection')
        if args.updater_v2_source and (raw / 'updater-v2/updater/native').is_dir():
            try:
                (public / 'updater-v2').mkdir()
                retain_updater(args.updater_v2_source, raw / 'updater-v2', public / 'updater-v2')
            except Exception: failures.append('updater-v2-public-projection')
        owned = args.output / 'owned.json'
        container_absent = False
        if owned.exists():
            ownership = json.loads(owned.read_text())
            name = ownership['container']
            try:
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=20)
            except (OSError, subprocess.SubprocessError): failures.append('container-remove')
            try:
                assert subprocess.check_output(['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'], timeout=20) == b''
                container_absent = True
            except (OSError, subprocess.SubprocessError, AssertionError): failures.append('container-absence')
        if owned.exists() and ownership.get('footprint_volume'):
            try:
                assert container_absent, 'container absence required before volume cleanup'
                module('composition_footprint_cleanup', HERE / 'footprint.py').remove_volume(ownership['footprint_volume'])
                result['footprint_volume_cleanup'] = 'PASS-absence-verified'
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, AssertionError):
                failures.append('owned-footprint-volume')
        removed = set()
        for relative in ('updater/native/image-id', 'desktop574/image-id', 'updater-v2/updater/native/image-id'):
            path = raw / relative
            if not path.exists(): continue
            image = path.read_text().strip()
            try:
                assert re.fullmatch(r'sha256:[0-9a-f]{64}', image)
                assert image != (args.native / 'image-id').read_text().strip(), 'borrowed core image protected'
                if image in removed: continue
                subprocess.run(['docker', 'image', 'rm', '--no-prune', image], check=True, capture_output=True, timeout=30)
                observed = subprocess.run(['docker', 'image', 'inspect', image], capture_output=True, timeout=20)
                assert observed.returncode != 0 and 'No such image' in observed.stderr.decode(errors='replace')
                removed.add(image)
            except (OSError, subprocess.SubprocessError, AssertionError): failures.append('owned-image')
        for relative in ('test-signing', 'updater/native/gpg', 'updater-v2/updater/native/gpg'):
            home = raw / relative
            if home.exists():
                try: subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], check=True, capture_output=True, timeout=15)
                except (OSError, subprocess.SubprocessError): failures.append('owned-gpg')
        result['cleanup'] = {'status': 'FAIL' if failures else 'PASS', 'failures': failures,
                             'scope': 'owned composition container, selected new builder images and private trial files'
                                      + (' and exact owned footprint volume' if getattr(args, 'measure_footprint', False) else '')}
        if failures: result['status'] = 'FAIL'
        else: shutil.rmtree(raw)
        save(public / 'coordinator.json', result)
        signal.signal(signal.SIGTERM, previous)
        assert not failures, 'composition cleanup failed'


if __name__ == '__main__':
    main()
