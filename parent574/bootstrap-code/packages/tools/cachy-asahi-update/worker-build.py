#!/usr/bin/env python3
"""Build the actual tray only after fresh bounded native metadata/input checks."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat

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
    phase = 'unit-metadata-json'
    def check(value, message, predicate, diagnostic=None):
        nonlocal phase
        phase = None
        require(value, message, predicate, diagnostic)
        phase = 'unit-event-fields'
    try:
        metadata = json.loads(metadata_data)
        phase = 'unit-metadata-fields'
        packages = {row['id']: row for row in metadata['packages']}
        nodes = {row['id']: row for row in metadata['resolve']['nodes']}
        units, scripts, completed = [], [], False
        local_binary = False
        for line in compiler_data.splitlines():
            phase = 'unit-compiler-json'
            event = json.loads(line)
            phase = 'unit-event-fields'
            kind = event.get('reason')
            if kind == 'build-finished':
                completed = event.get('success') is True
            if kind not in ('compiler-artifact', 'build-script-executed'):
                continue
            package_id = event['package_id']
            check(package_id in nodes and package_id in packages,
                    'actual compilation unit outside verified metadata source graph', 'unit-source', diagnostic)
            package = packages[package_id]
            if kind == 'build-script-executed':
                check(any('custom-build' in target['kind'] for target in package['targets']),
                        'unreviewed actual build-script unit', 'unit-build-script', diagnostic)
                scripts.append(event)
                continue
            features = set(event['features'])
            check(features <= set(nodes[package_id]['features']),
                    'actual unit feature outside verified metadata union', 'unit-feature', diagnostic)
            check(package['name'] != 'gettext-sys' or 'gettext-system' in features,
                    'actual gettext unit lacks reviewed system branch', 'unit-gettext', diagnostic)
            check(package['name'] != 'system-deps' or 'binary' not in features,
                    'actual system-deps unit activates unreviewed binary branch', 'unit-system-deps', diagnostic)
            if event.get('executable') == str(binary):
                local_binary |= package['name'] == 'arch-update-tray' and event['target']['kind'] == ['bin']
            units.append(event)
        check(completed and local_binary and units,
                'complete successful actual tray unit evidence required', 'unit-complete', diagnostic)
        phase = 'unit-event-fields'
        compiled_scripts = {unit['package_id'] for unit in units if 'custom-build' in unit['target']['kind']}
        check({script['package_id'] for script in scripts} <= compiled_scripts,
                'build-script run has no retained compiled unit feature record', 'unit-build-script-record', diagnostic)
        return {'schema_version': 1, 'scope': 'actual emitted Cargo artifact/build-script records',
                'compiler_artifacts': units, 'build_script_runs': scripts,
                'metadata_union_limit': 'Metadata source candidates may include uncompiled packages or features.',
                'native_runtime': 'NOT RUN', 'hardware': 'NOT RUN'}
    except Exception as error:
        if diagnostic is not None and phase is not None:
            try:
                diagnostic.fail(phase, error)
            except Exception:
                pass  # Reporting cannot replace the original refusal/control.
        raise


def stat_identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink'))


def output_identity(path):
    return stat_identity(path.lstat())


def close_descriptor(fd, primary):
    try:
        os.close(fd)
    except BaseException:
        if primary is None:
            raise
        # Keep the first refusal/control exception; never claim cleanup success.


def elf_output_bytes(fd, singly_linked):
    def fail(message, predicate):
        error = ValueError(message)
        error.updater_elf_predicate = predicate
        raise error
    limit = 64 * 1024 * 1024
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or (singly_linked and before.st_nlink != 1)
            or before.st_size > limit):
        fail('bounded regular compiler output required', 'elf-read-type-link-size')
    data = bytearray()
    while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
        data.extend(chunk)
        if len(data) > limit:
            fail('compiler output exceeded bound', 'elf-read-bound')
    identity = stat_identity(before)
    if len(data) != before.st_size or stat_identity(os.fstat(fd)) != identity:
        fail('compiler output changed while reading', 'elf-read-drift')
    return bytes(data), identity


def cargo_output(worker, binary):
    # Only the fresh Cargo executable permits aliases. Its actual descriptor
    # must match the selected path before reading, including ancestor ABA swaps.
    before = output_identity(binary)
    for path in (binary, *binary.parents):
        if path.is_symlink():
            error = ValueError('Cargo output symlink refused')
            error.updater_elf_predicate = 'elf-read-symlink'
            raise error
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    primary = None
    try:
        require(stat_identity(os.fstat(fd)) == before,
                'Cargo descriptor differs from selected path', 'compile-binary-drift')
        data, identity = elf_output_bytes(fd, False)
        require(identity == before == output_identity(binary),
                'Cargo output path changed while capturing bytes', 'compile-binary-drift')
        return data, identity
    except BaseException as error:
        primary = error
        raise
    finally:
        close_descriptor(fd, primary)


def write_compiled_output(worker, destination, data):
    parent_identity = output_identity(destination.parent)
    require(destination.parent.resolve(strict=True) == destination.parent,
            'canonical compiled binary destination required', 'compile-destination')
    parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    primary = None
    try:
        require(stat_identity(os.fstat(parent)) == parent_identity
                and output_identity(destination.parent) == parent_identity
                and destination.parent.resolve(strict=True) == destination.parent,
                'compiled binary parent changed before creation', 'compile-destination')
        fd = os.open(destination.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        inner_primary = None
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                require(0 < written <= len(remaining), 'complete compiled binary write required', 'compile-copy')
                remaining = remaining[written:]
            os.fchmod(fd, 0o755)
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            reread, identity = elf_output_bytes(fd, True)
            parent_now = os.fstat(parent)
            current_parent = destination.parent.lstat()
            require(reread == data
                    and stat_identity(os.stat(destination.name, dir_fd=parent, follow_symlinks=False)) == identity
                    and output_identity(destination) == identity
                    and (parent_now.st_dev, parent_now.st_ino) == (current_parent.st_dev, current_parent.st_ino)
                    and destination.parent.resolve(strict=True) == destination.parent,
                    'compiled binary snapshot custody changed', 'compile-binary-drift')
            return identity
        except BaseException as error:
            inner_primary = error
            raise
        finally:
            close_descriptor(fd, inner_primary)
    except BaseException as error:
        primary = error
        raise
    finally:
        close_descriptor(parent, primary)


def cargo_snapshot(worker, binary, destination):
    data, identity = cargo_output(worker, binary)
    snapshot_identity = write_compiled_output(worker, destination, data)
    require(cargo_output(worker, binary) == (data, identity),
            'Cargo output changed during snapshot', 'compile-binary-drift')
    return data, identity, snapshot_identity


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
               '--target', worker.TARGET, '--jobs', '2', '--message-format=json-render-diagnostics',
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
                binary_data, binary_identity, snapshot_identity = cargo_snapshot(worker, binary, output / 'arch-update-tray')
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
            unit_phase = 'unit-log-read'
            try:
                compiler_data = (output / 'cargo-build.stdout').read_bytes()
                unit_phase = None
                units = unit_evidence(metadata, compiler_data, binary, diagnostic)
                unit_phase = 'unit-receipt-write'
                (output / 'compilation-units.json').write_text(json.dumps(units, indent=2) + '\n')
            except Exception as error:
                if unit_phase is not None:
                    try:
                        diagnostic.fail(unit_phase, error)
                    except Exception:
                        pass  # Reporting cannot replace the original refusal/control.
                raise
        with diagnostic.step('compile-readelf'):
            worker.run(['/usr/bin/readelf', '-h', '-l', '-d', str(output / 'arch-update-tray')],
                       args.manifest.parent, env, output, 'elf-inspection')
        # Preserve upstream Makefile's expected location without an implicit rebuild.
        with diagnostic.step('compile-copy'):
            destination = target_dir / 'release/arch-update-tray'
            destination.parent.mkdir(exist_ok=True)
            require(destination.parent.resolve(strict=True) == destination.parent and not destination.exists() and not destination.is_symlink(),
                    'canonical fresh upstream binary destination required', 'compile-destination', diagnostic)
            require(cargo_output(worker, binary) == (binary_data, binary_identity)
                    and worker.regular(output / 'arch-update-tray', 64 * 1024 * 1024) == binary_data
                    and output_identity(output / 'arch-update-tray') == snapshot_identity,
                    'compiled binary changed during inspection', 'compile-binary-drift', diagnostic)
            write_compiled_output(worker, destination, binary_data)
            receipt.update(native_compilation='PASS', binary_sha256=worker.digest(binary_data),
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
