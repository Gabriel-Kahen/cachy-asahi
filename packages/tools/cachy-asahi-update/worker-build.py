#!/usr/bin/env python3
"""Build the actual tray only after fresh bounded native metadata/input checks."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal

ELF_PREDICATES = frozenset(('UNKNOWN', 'elf-read-symlink', 'elf-read-type-link-size',
    'elf-read-bound', 'elf-read-drift', 'elf-header', 'elf-machine',
    'elf-program-headers', 'elf-load-alignment', 'elf-load-bounds', 'elf-load-absent'))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def require(value, message, predicate, diagnostic=None):
    if not value:
        error = ValueError(message)
        if diagnostic is not None:
            try:
                diagnostic.fail(predicate, error)
            except Exception:
                pass  # Diagnostic failure cannot replace the original refusal.
        raise error


def unit_evidence(metadata_data, compiler_data, binary, diagnostic=None):
    """Retain actual emitted Cargo unit features separately from metadata unions."""
    metadata = json.loads(metadata_data)
    packages = {row['id']: row for row in metadata['packages']}
    nodes = {row['id']: row for row in metadata['resolve']['nodes']}
    units, scripts, completed = [], [], False
    local_binary = False
    for line in compiler_data.splitlines():
        event = json.loads(line)
        kind = event.get('reason')
        if kind == 'build-finished':
            completed = event.get('success') is True
        if kind not in ('compiler-artifact', 'build-script-executed'):
            continue
        package_id = event['package_id']
        require(package_id in nodes and package_id in packages,
                'actual compilation unit outside verified metadata source graph', 'unit-source', diagnostic)
        package = packages[package_id]
        if kind == 'build-script-executed':
            require(any('custom-build' in target['kind'] for target in package['targets']),
                    'unreviewed actual build-script unit', 'unit-build-script', diagnostic)
            scripts.append(event)
            continue
        features = set(event['features'])
        require(features <= set(nodes[package_id]['features']),
                'actual unit feature outside verified metadata union', 'unit-feature', diagnostic)
        require(package['name'] != 'gettext-sys' or 'gettext-system' in features,
                'actual gettext unit lacks reviewed system branch', 'unit-gettext', diagnostic)
        require(package['name'] != 'system-deps' or 'binary' not in features,
                'actual system-deps unit activates unreviewed binary branch', 'unit-system-deps', diagnostic)
        if event.get('executable') == str(binary):
            local_binary |= package['name'] == 'arch-update-tray' and event['target']['kind'] == ['bin']
        units.append(event)
    require(completed and local_binary and units,
            'complete successful actual tray unit evidence required', 'unit-complete', diagnostic)
    compiled_scripts = {unit['package_id'] for unit in units if 'custom-build' in unit['target']['kind']}
    require({script['package_id'] for script in scripts} <= compiled_scripts,
            'build-script run has no retained compiled unit feature record', 'unit-build-script-record', diagnostic)
    return {'schema_version': 1, 'scope': 'actual emitted Cargo artifact/build-script records',
            'compiler_artifacts': units, 'build_script_runs': scripts,
            'metadata_union_limit': 'Metadata source candidates may include uncompiled packages or features.',
            'native_runtime': 'NOT RUN', 'hardware': 'NOT RUN'}


def build(args):
    base = Path(__file__).resolve().parent
    helper = module('updater_compile_diagnostic', base / 'worker-diagnostic.py')
    diagnostic = helper.Recorder(output=Path('/out'), bindings=helper.binding_values())
    with diagnostic.step('compile-worker-import'):
        worker = module('updater_compile_worker', base / 'worker-metadata.py')
        worker.set_diagnostic(diagnostic)
    output = Path('/out/target-metadata')
    controller_path = Path('/inputs/controller-input.json')
    controller_sha = os.environ.get('CACHY_ASAHI_CONTROLLER_SHA256')
    with diagnostic.step('compile-controller'):
        controller = worker.verify_controller(controller_path, controller_sha, worker.observe())
        diagnostic.controller_validated()
    with diagnostic.step('compile-metadata'):
        metadata, record, cfg, env = worker.metadata(args.manifest.absolute(), args.vendor.absolute(),
            args.cargo_audit.absolute(), controller['builder_inventory_sha256'], output,
            controller_path, controller_sha)
    # The data-only gate independently reads fresh logs/source/script/helper evidence.
    argv = ['/usr/bin/python', str(base / 'build-gate.py'),
            '--metadata', str(output / 'cargo-metadata.stdout'), '--worker', str(output / 'worker.json'),
            '--cfg', str(output / 'target-cfg.stdout'), '--manifest', str(args.manifest.absolute()),
            '--lock', str(args.manifest.absolute().with_name('Cargo.lock')),
            '--cargo-audit', str(args.cargo_audit.absolute()), '--vendor', str(args.vendor.absolute()),
            '--build-script-review', str(base / 'build-script-review.json'),
            '--additional-licenses', str(base / 'additional-cargo-licenses.json'),
            '--controller-input', str(controller_path), '--controller-input-sha256', controller_sha,
            '--retain-linux-source']
    gate_env = dict(env, CACHY_ASAHI_IMAGE_ID=record['image_id'],
                    CACHY_ASAHI_UPDATE_BUILD_NONCE=record['observed_worker']['nonce'],
                    CACHY_ASAHI_CONTROLLER_SHA256=controller_sha)
    with diagnostic.step('compile-gate'):
        worker.run(argv, args.manifest.parent, gate_env, output, 'compile-gate', timeout=180)
    target_dir = args.manifest.parent / 'target'
    with diagnostic.step('compile-target'):
        require(not target_dir.exists(), 'fresh empty Cargo target required', 'fresh-target', diagnostic)
    env.update(CARGO_TARGET_DIR=str(target_dir), CARGO_INCREMENTAL='0',
               SOURCE_DATE_EPOCH='1789753605', TZ='UTC',
               RUSTFLAGS='-C linker=/usr/bin/cc -C link-arg=-Wl,-z,max-page-size=16384')
    command = ['/usr/bin/cargo', 'build', '--release', '--frozen', '--offline', '--locked',
               '--target', worker.TARGET, '--jobs', '2', '--message-format=json-render-diagnostics', '-vv',
               '--manifest-path', str(args.manifest.absolute())]
    receipt = {'schema_version': 1, 'scope': 'private native Linux compile', 'command': command,
               'image_id': record['image_id'], 'input_sha256': record['sha256'],
               'build_environment': env, 'native_compilation': 'STARTING',
               'publication': 'NOT ACCEPTED', 'M2': 'NOT RUN'}
    try:
        with diagnostic.step('compile-cargo'):
            worker.run(command, args.manifest.parent, env, output, 'cargo-build', timeout=1200)
        binary = target_dir / worker.TARGET / 'release/arch-update-tray'
        with diagnostic.step('compile-elf'):
            gate = module('updater_compile_elf_gate', base / 'build-gate.py')
            try:
                binary_data = worker.regular(binary, 64 * 1024 * 1024, elf_observation=True)
                gate.elf(binary_data)
            except ValueError as error:
                predicate = 'UNKNOWN'
                try:
                    if type(error) is ValueError:
                        state = vars(error)
                        if type(state) is dict and len(state) == 1:
                            key, value = next(iter(state.items()))
                            if type(key) is str and key == 'updater_elf_predicate' and type(value) is str and value in ELF_PREDICATES:
                                predicate = value
                    diagnostic.fail(predicate, error)
                except Exception: pass  # Reporting cannot replace the original refusal.
                raise
        with diagnostic.step('compile-units'):
            units = unit_evidence(metadata, (output / 'cargo-build.stdout').read_bytes(), binary, diagnostic)
            (output / 'compilation-units.json').write_text(json.dumps(units, indent=2) + '\n')
        with diagnostic.step('compile-readelf'):
            worker.run(['/usr/bin/readelf', '-h', '-l', '-d', str(binary)],
                       args.manifest.parent, env, output, 'elf-inspection')
        # Preserve upstream Makefile's expected location without an implicit rebuild.
        with diagnostic.step('compile-copy'):
            destination = target_dir / 'release/arch-update-tray'
            destination.parent.mkdir(exist_ok=True)
            require(destination.parent.resolve(strict=True) == destination.parent and not destination.exists() and not destination.is_symlink(),
                    'canonical fresh upstream binary destination required', 'compile-destination', diagnostic)
            require(worker.regular(binary, 64 * 1024 * 1024) == binary_data,
                    'compiled binary changed during inspection', 'compile-binary-drift', diagnostic)
            shutil.copyfile(binary, destination)
            destination.chmod(0o755)
            shutil.copyfile(binary, output / 'arch-update-tray')
            receipt.update(native_compilation='PASS', binary_sha256=worker.digest(binary.read_bytes()),
                           compiler_output_sha256=worker.digest((output / 'cargo-build.stdout').read_bytes()),
                           compiler_diagnostic_sha256=worker.digest((output / 'cargo-build.stderr').read_bytes()),
                           elf_inspection_sha256=worker.digest((output / 'elf-inspection.stdout').read_bytes()),
                           compilation_units_sha256=worker.digest((output / 'compilation-units.json').read_bytes()),
                           elf_16k_segments='PASS-static; loader NOT RUN')
    except BaseException as error:
        receipt.update(native_compilation='FAIL', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        with diagnostic.step('compile-receipt'):
            (output / 'compile-result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    diagnostic.compiler_accepted()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--cargo-audit', type=Path, required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    build(args)
