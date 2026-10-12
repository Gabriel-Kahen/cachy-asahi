#!/usr/bin/env python3
"""Fresh Cargo metadata only in the bounded native worker; never compile crates."""
import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import time
import tomllib
from pathlib import Path

TARGET = 'aarch64-unknown-linux-gnu'
ROOTS = {'/inputs': 'ro', '/out': 'rw', '/tmp': 'rw'}
PSEUDO = {'/proc', '/dev', '/dev/pts', '/dev/shm', '/sys', '/sys/fs/cgroup'}
MASKS = {'/proc/acpi', '/proc/asound', '/proc/interrupts', '/proc/kcore', '/proc/keys',
         '/proc/timer_list', '/proc/latency_stats', '/proc/scsi', '/sys/firmware',
         '/sys/devices/virtual/powercap', '/proc/bus', '/proc/fs', '/proc/irq',
         '/proc/sys', '/proc/sysrq-trigger'}
STANDARD = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
            '/builder-entry.sh', '/expected-packages.lock'}
TOOLS = ('pacman', 'rustc', 'rustdoc', 'cargo', 'gcc', 'cc', 'ld', 'pkg-config',
         'make', 'scdoc', 'git', 'python', 'bash')
PINS = {'manifest': 'fcae83c668f4aa18800450ca165d87cd929cbf1141f33177628c32e451a2582a',
        'lock': '0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753',
        'audit': '01d8fdc321d58f0153019b576db5abfd3e4a66320d5c26507cb40df7e9ff7ff8'}
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
CHAR_DEVICES = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
                '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0),
                '/dev/pts/ptmx': (5, 2)}


DIAGNOSTIC = None


def set_diagnostic(recorder):
    global DIAGNOSTIC
    DIAGNOSTIC = recorder


def diagnose(method, *args, **kwargs):
    if DIAGNOSTIC is not None:
        try:
            return getattr(DIAGNOSTIC, method)(*args, **kwargs)
        except Exception:
            pass  # Observations never replace the worker's original result.


@contextlib.contextmanager
def diagnostic_step(operation):
    scope = diagnose('step', operation)
    if scope is not None:
        try:
            scope.__enter__()
        except Exception:
            scope = None
    try:
        yield
    except BaseException as error:
        if scope is not None:
            try:
                scope.__exit__(type(error), error, error.__traceback__)
            except Exception:
                pass
        raise
    else:
        if scope is not None:
            try:
                scope.__exit__(None, None, None)
            except Exception:
                pass


def refuse(message, predicate):
    error = ValueError(message)
    diagnose('fail', predicate, error)
    raise error


def digest(data):
    return hashlib.sha256(data).hexdigest()


def mount_table(data):
    table = {}
    for line in data.splitlines():
        parts = line.split()
        split = parts.index('-')
        name = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), parts[4])
        if name in table:
            raise ValueError('stacked mount refused')
        table[name] = {'flags': parts[5].split(','), 'fs': parts[split + 1]}
    return table


def unsafe_device(path, mode, device):
    if stat.S_ISBLK(mode):
        return True
    if not stat.S_ISCHR(mode):
        return False
    pair = os.major(device), os.minor(device)
    if path in CHAR_DEVICES:
        return pair != CHAR_DEVICES[path]
    return not (re.fullmatch(r'/dev/pts/[0-9]+', path)
                and 136 <= pair[0] <= 143 and pair[1] <= 255)


def observe():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    marker = Path('/.dockerenv')
    devices = any(Path(p).exists() for p in ('/dev/dri', '/dev/snd', '/dev/input', '/dev/mem', '/dev/kvm', '/dev/fuse'))
    for path in Path('/dev').rglob('*'):
        info = path.lstat()
        devices |= unsafe_device(str(path), info.st_mode, info.st_rdev)
    cgroup = Path('/sys/fs/cgroup')
    masked_null = {}
    for name in MASKS:
        path = Path(name)
        if path.exists():
            info = path.stat()
            masked_null[name] = stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3)
    return {'uid': os.geteuid(), 'arch': platform.machine(),
            'marker': marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            'caps': {key: int(status[key].strip(), 16) for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd')},
            'nnp': status['NoNewPrivs'].strip(), 'mounts': mount_table(Path('/proc/self/mountinfo').read_text()),
            'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()), 'devices': devices,
            'masked_null': masked_null,
            'socket': any(Path(p).exists() for p in ('/run/docker.sock', '/var/run/docker.sock')),
            'pids': (cgroup / 'pids.max').read_text().strip(),
            'memory': (cgroup / 'memory.max').read_text().strip(),
            'cpu': (cgroup / 'cpu.max').read_text().strip(),
            'image_id': os.environ.get('CACHY_ASAHI_IMAGE_ID'),
            'nonce': os.environ.get('CACHY_ASAHI_UPDATE_BUILD_NONCE')}


def guard(facts):
    if (facts['uid'] == 0 or facts['arch'] != 'aarch64' or not facts['marker']
            or set(facts['caps']) != {'CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd'}
            or any(facts['caps'].values()) or facts['nnp'] != '1'
            or facts['interfaces'] != ['lo'] or facts['devices'] or facts['socket']):
        refuse('bounded nonroot native Docker worker required; host execution refused', 'worker-boundary')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', facts.get('image_id') or '') or not re.fullmatch(r'[0-9a-f]{32}', facts.get('nonce') or ''):
        refuse('fresh worker identity required', 'worker-identity')
    table = facts['mounts']
    if table.get('/', {}).get('fs') not in ('overlay', 'fuse-overlayfs') or 'ro' not in table['/']['flags']:
        refuse('read-only disposable root required', 'root-readonly')
    for root, flag in ROOTS.items():
        if flag not in table.get(root, {}).get('flags', []):
            refuse('fixed worker mount contract differs', 'mount-contract')
        if any(path.startswith(root + '/') for path in table):
            refuse('nested worker mount refused', 'mount-nesting')
    if table['/tmp']['fs'] != 'tmpfs' or 'ro' not in table.get('/expected-packages.lock', {}).get('flags', []):
        refuse('private tmpfs and read-only expected builder lock required', 'private-tmpfs')
    for path, entry in table.items():
        if path not in {'/'} | set(ROOTS) | PSEUDO | MASKS | STANDARD:
            refuse('unexpected worker mount: ' + path, 'unexpected-mount')
        if path in MASKS and 'ro' not in entry['flags'] and not facts.get('masked_null', {}).get(path):
            refuse('masked runtime mount must be read-only', 'mask-readonly')
        if path in ('/sys', '/sys/fs/cgroup') and 'ro' not in entry['flags']:
            refuse('system observation mount must be read-only', 'system-readonly')
        if path == '/builder-entry.sh' and 'ro' not in entry['flags']:
            refuse('builder entry mount must be read-only', 'entry-readonly')
    for path, fs in {'/proc': 'proc', '/sys': 'sysfs', '/sys/fs/cgroup': 'cgroup2',
                     '/dev': 'tmpfs', '/dev/pts': 'devpts', '/dev/shm': 'tmpfs'}.items():
        if path in table and table[path]['fs'] != fs:
            refuse('unexpected runtime mount filesystem', 'runtime-filesystem')
    try:
        quota, period = map(int, facts['cpu'].split())
        limits = (0 < int(facts['pids']) <= 512 and 0 < int(facts['memory']) <= 4 * 1024**3
                  and 0 < quota <= 4 * period and period > 0)
    except (ValueError, TypeError):
        limits = False
    if not limits:
        refuse('finite worker CPU/memory/PID limits required', 'worker-limits')


def regular(path, limit, singly_linked=True):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('input symlink refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or (singly_linked and info.st_nlink != 1)
                or info.st_size > limit):
            raise ValueError('bounded singly-linked regular input required')
        data = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('input exceeded bound')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if len(data) != info.st_size or any(getattr(info, k) != getattr(after, k) for k in fields):
            raise ValueError('input changed while reading')
        return bytes(data)
    finally:
        os.close(fd)


def load(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def vendor_preflight(vendor, audit, lock, manifest):
    """Rehash the complete retained all-target ledger; no Cargo/source execution."""
    local = (manifest['package']['name'], manifest['package']['version'])
    locked = {(row['name'], row['version']): row for row in lock['package']}
    rows = audit['registry_sources']
    ledger = {(row['name'], row['version']): row for row in rows}
    if (lock.get('version') != 4 or len(lock['package']) != 168 or len(locked) != 168
            or len(rows) != 167 or len(ledger) != 167 or audit.get('locked_packages') != 168
            or audit.get('registry_packages') != 167 or audit.get('failures')
            or audit.get('source_checksum_closure') != 'PASS'
            or locked.get(local, {}).get('source') is not None
            or set(ledger) != set(locked) - {local}):
        refuse('complete original vendor/lock ledger required', 'vendor-ledger')
    expected_dirs = {name + '-' + version for name, version in ledger}
    if {p.name for p in vendor.iterdir()} != expected_dirs:
        refuse('vendor package directory set differs', 'vendor-directories')
    total = count = 0
    deadline = time.monotonic() + 120
    for key, row in ledger.items():
        root = vendor / (key[0] + '-' + key[1])
        if root.is_symlink() or not root.is_dir():
            refuse('vendor package directory unsafe', 'vendor-directory')
        if (row['registry'] != REGISTRY or locked[key].get('source') != REGISTRY
                or row['checksum'] != 'PASS' or row['archive_sha256'] != locked[key].get('checksum')):
            refuse('vendor archive/registry binding differs', 'vendor-registry')
        checksums = load(regular(root / '.cargo-checksum.json', 8 * 1024 * 1024))
        files = checksums['files']
        if (checksums['package'] != row['archive_sha256'] or len(files) > 20000
                or digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()) != row['source_files_sha256']):
            refuse('vendor file ledger differs', 'vendor-file-ledger')
        for name, expected in files.items():
            if (not isinstance(name, str) or name.startswith('/') or '\\' in name
                    or any(part in ('', '.', '..') for part in name.split('/'))
                    or not re.fullmatch(r'[0-9a-f]{64}', expected)):
                refuse('unsafe vendor ledger path/hash', 'vendor-path')
        found = set()
        for path in root.rglob('*'):
            count += 1
            if count > 250000 or time.monotonic() > deadline:
                refuse('vendor traversal bound', 'vendor-traversal')
            if path.is_symlink():
                refuse('vendor symlink refused', 'vendor-link')
            if path.is_dir():
                continue
            name = path.relative_to(root).as_posix()
            data = regular(path, 64 * 1024 * 1024)
            total += len(data)
            if total > 1024 * 1024 * 1024:
                refuse('vendor expanded bound', 'vendor-expanded')
            if name != '.cargo-checksum.json':
                if name not in files or digest(data) != files[name]:
                    refuse('vendor file hash/extra differs', 'vendor-file')
                found.add(name)
        if found != set(files) or files.get('Cargo.toml') != row['normalized_manifest_sha256']:
            refuse('vendor file missing/manifest differs', 'vendor-file')
    return {'registry_packages': len(ledger), 'files': count, 'bytes': total}


def verify_controller(path, expected_sha, facts, recipe_root=Path('/inputs/recipe')):
    """Verify external controller binding before even querying a worker tool.

    The controller must authenticate its own image/tool provenance externally.
    Its embedded tool-pins digest uses canonical compact sorted JSON bytes.
    """
    guard(facts)
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha or ''):
        refuse('external controller digest required', 'controller-hash-format')
    if not path.is_relative_to('/inputs') or not recipe_root.is_relative_to('/inputs'):
        refuse('immutable controller/recipe input paths required', 'controller-input-paths')
    data = regular(path, 8 * 1024 * 1024)
    if digest(data) != expected_sha:
        refuse('controller digest differs', 'controller-digest')
    contract = load(data)
    required = {'schema_version', 'image_id', 'nonce', 'builder_inventory_sha256',
                'tool_pins_sha256', 'tool_pins', 'recipe_input_sha256', 'entry_script_sha256'}
    if (set(contract) != required or contract['schema_version'] != 1
            or contract['image_id'] != facts['image_id'] or contract['nonce'] != facts['nonce']):
        refuse('controller schema/worker identity differs', 'controller-binding')
    for key in ('builder_inventory_sha256', 'tool_pins_sha256', 'entry_script_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', contract[key]):
            refuse('controller hash invalid', 'controller-hash-field')
    pins = contract['tool_pins']
    if (set(pins) != {'schema_version', 'tools', 'builder_inventory_sha256'}
            or pins['schema_version'] != 1
            or pins['builder_inventory_sha256'] != contract['builder_inventory_sha256']
            or digest(json.dumps(pins, sort_keys=True, separators=(',', ':')).encode()) != contract['tool_pins_sha256']
            or not {'/usr/bin/' + tool for tool in TOOLS} <= set(pins['tools'])):
        refuse('authenticated tool-pin schema/hash differs', 'tool-ledger')
    expected = regular(Path('/expected-packages.lock'), 1024 * 1024)
    if digest(expected) != contract['builder_inventory_sha256']:
        refuse('controller builder lock differs', 'builder-lock')
    for name, pin in pins['tools'].items():
        alias = Path(name)
        if (not alias.is_absolute() or alias.parent != Path('/usr/bin')
                or set(pin) != {'resolved_path', 'sha256'}
                or not re.fullmatch(r'[0-9a-f]{64}', pin['sha256'])):
            refuse('unsafe authenticated tool path/hash', 'tool-pin-path')
        resolved = alias.resolve(strict=True)
        if (str(resolved) != pin['resolved_path'] or not resolved.is_relative_to('/usr')
                or digest(regular(resolved, 256 * 1024 * 1024, singly_linked=False)) != pin['sha256']):
            refuse('authenticated tool resolution/content differs', 'tool-resolution')
    if digest(regular(Path('/builder-entry.sh'), 4 * 1024 * 1024)) != contract['entry_script_sha256']:
        refuse('controller entry script differs', 'entry-digest')
    recipe = contract['recipe_input_sha256']
    if not recipe or not isinstance(recipe, dict):
        refuse('recipe input ledger required', 'recipe-ledger')
    for name, expected in recipe.items():
        if (not isinstance(name, str) or name.startswith('/') or '\\' in name
                or any(part in ('', '.', '..') for part in name.split('/'))
                or not re.fullmatch(r'[0-9a-f]{64}', expected)
                or digest(regular(recipe_root / name, 512 * 1024 * 1024)) != expected):
            refuse('controller recipe input differs', 'recipe-input')
    diagnose('controller_validated')
    return contract


def preflight(manifest, vendor, audit):
    blobs = {'manifest': regular(manifest, 1024 * 1024),
             'lock': regular(manifest.with_name('Cargo.lock'), 1024 * 1024),
             'audit': regular(audit, 8 * 1024 * 1024)}
    if {key: digest(data) for key, data in blobs.items()} != PINS:
        refuse('original source pin differs', 'source-pins')
    source_audit = load(blobs['audit'])
    if source_audit.get('cargo_lock_sha256') != PINS['lock']:
        refuse('audit lock binding differs', 'audit-lock')
    summary = vendor_preflight(vendor, source_audit, tomllib.loads(blobs['lock'].decode()),
                               tomllib.loads(blobs['manifest'].decode()))
    return blobs, summary


def run(argv, cwd, env, output, stem, timeout=60):
    """Bound output/time; preserve original failure even if cleanup fails."""
    child, selector, streams = None, None, {}
    reason, cleanup = None, []
    attempted, returned, returncode, failure_code, original_error = False, False, None, None, None
    try:
        attempted = True
        diagnose('command_start', stem)
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, start_new_session=True)
        except BaseException as error:
            failure_code = 'UNKNOWN' if isinstance(error, KeyboardInterrupt) else 'command-spawn'
            raise
        streams = {child.stdout: bytearray(), child.stderr: bytearray()}
        selector = selectors.DefaultSelector()
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            if time.monotonic() >= deadline:
                failure_code = 'command-timeout'
                raise ValueError('worker command timeout')
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    remaining = 16 * 1024 * 1024 - sum(map(len, streams.values()))
                    streams[key.fileobj].extend(data[:remaining])
                    if len(data) > remaining:
                        failure_code = 'command-output-limit'
                        raise ValueError('worker command output bound')
        child.wait(timeout=max(.01, deadline - time.monotonic()))
        returned, returncode = True, child.returncode
        if child.returncode:
            # makepkg's returned code does not identify its first inner predicate.
            failure_code = 'UNKNOWN' if stem in {'makepkg', 'source-verification'} else 'command-nonzero'
            raise ValueError('worker command failed')
    except BaseException as error:
        original_error = error
        failure_code = failure_code or ('command-wait-timeout' if isinstance(error, subprocess.TimeoutExpired) else 'UNKNOWN')
        reason = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        control = original_error if original_error is not None and not isinstance(original_error, Exception) else None
        cleanup_failure = None

        def finish(action, absent=False):
            nonlocal control, cleanup_failure
            # One retry completes an interrupted owned action without an
            # unbounded cancellation loop. Reaping never alters natural return.
            for _ in range(2):
                try:
                    action()
                    return
                except Exception as error:
                    if absent and isinstance(error, ProcessLookupError):
                        return
                    cleanup.append(type(error).__name__ + ': ' + str(error))
                    if cleanup_failure is None and control is None:
                        cleanup_failure = error
                    return
                except BaseException as error:
                    cleanup.append(type(error).__name__ + ': ' + str(error))
                    if control is None:
                        control = error

        if child is not None:
            finish(lambda: os.killpg(child.pid, signal.SIGKILL), absent=True)
            finish(lambda: child.wait(timeout=2))
        if selector is not None:
            finish(selector.close)
        for stream, data in streams.items():
            finish(lambda: (output / (stem + ('.stdout' if stream is child.stdout else '.stderr'))).write_bytes(data))
            finish(stream.close)
        finish(lambda: (output / (stem + '.command.json')).write_text(json.dumps({
            'argv': argv, 'exit_code': child.returncode if child else None,
            'failure': reason, 'cleanup_errors': cleanup}) + '\n'))
        issued_error, issued_code = original_error, failure_code
        if issued_error is None and cleanup_failure is not None:
            issued_error = ValueError('worker command cleanup failed: ' + '; '.join(cleanup))
            issued_code = 'command-cleanup'
        if issued_error is None and control is not None:
            issued_error, issued_code = control, 'UNKNOWN'
        try:
            diagnose('command_result', stem, attempted, returned, returncode,
                     failure_code=issued_code, error=issued_error)
        except Exception as error:
            if issued_error is None:
                issued_error = ValueError('worker command cleanup failed: ' + type(error).__name__ + ': ' + str(error))
                diagnose('fail', 'command-cleanup', issued_error)
        except BaseException as error:
            if control is None:
                control = error
        if control is not None:
            # Cache the issued command result first, then independently latch
            # cancellation without replacing an earlier business first cause.
            try:
                diagnose('fail', 'UNKNOWN', control)
            except BaseException:
                pass  # The first latched control exception is propagated below.
            raise control
        if original_error is None and issued_error is not None:
            raise issued_error
    return bytes(streams[child.stdout])


def metadata(manifest, vendor, audit, builder_sha, output, controller_path, controller_sha):
    with diagnostic_step('metadata-observe'):
        facts = observe()
    with diagnostic_step('metadata-guard'):
        guard(facts)  # Before any Cargo/tool command or output creation.
    with diagnostic_step('metadata-paths'):
        if (not manifest.is_relative_to('/tmp') or not vendor.is_relative_to('/tmp')
                or manifest.resolve(strict=True) != manifest or vendor.resolve(strict=True) != vendor):
            refuse('source/vendor must be private worker scratch paths', 'scratch-paths')
    with diagnostic_step('metadata-ambient'):
        for parent in manifest.parents:
            if (parent / '.cargo/config.toml').exists() or (parent / '.cargo/config').exists():
                refuse('ambient Cargo configuration refused', 'ambient-cargo-config')
    with diagnostic_step('metadata-output'):
        if output != Path('/out/target-metadata'):
            refuse('fixed fresh worker metadata output required', 'metadata-output')
    with diagnostic_step('metadata-controller'):
        controller = verify_controller(controller_path, controller_sha, facts)
    with diagnostic_step('metadata-builder'):
        if controller['builder_inventory_sha256'] != builder_sha:
            refuse('controller builder pin differs', 'builder-pin')
    with diagnostic_step('metadata-source'):
        blobs, vendor_summary = preflight(manifest, vendor, audit)
        manifest_data, lock_data, audit_data = (blobs[key] for key in ('manifest', 'lock', 'audit'))
    with diagnostic_step('metadata-builder'):
        expected = regular(Path('/expected-packages.lock'), 1024 * 1024)
        if not re.fullmatch(r'[0-9a-f]{64}', builder_sha) or digest(expected) != builder_sha:
            refuse('expected builder inventory differs from controller pin', 'builder-lock')
        if any(Path('/usr/bin/' + tool).exists() for tool in ('emcc', 'freebsd-version')):
            refuse('unexpected platform probe tools present', 'forbidden-tool')
    with diagnostic_step('metadata-output'):
        output.mkdir(parents=True, exist_ok=False)
    with diagnostic_step('metadata-home'):
        home = Path('/tmp/cachy-update-metadata-' + facts['nonce'])
        home.mkdir(mode=0o700, exist_ok=False)
        cargo_home = home / 'cargo'
        cargo_home.mkdir(mode=0o700)
        (cargo_home / 'config.toml').write_text('[source.crates-io]\nreplace-with="vendored"\n[source.vendored]\ndirectory=' + json.dumps(str(vendor)) + '\n')
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'HOME': str(home), 'CARGO_HOME': str(cargo_home),
               'CARGO_NET_OFFLINE': 'true', 'RUSTC': '/usr/bin/rustc', 'RUSTDOC': '/usr/bin/rustdoc'}
    with diagnostic_step('metadata-inventory'):
        inventory = run(['/usr/bin/pacman', '-Q'], home, env, output, 'inventory')
        if b''.join(sorted(inventory.splitlines(keepends=True))) != expected:
            refuse('actual worker package inventory differs from frozen extension', 'builder-inventory')
    with diagnostic_step('metadata-rust-version'):
        verbose = run(['/usr/bin/rustc', '-vV'], home, env, output, 'rustc-version').decode()
        release = re.search(r'^release: (\d+)\.(\d+)\.(\d+)', verbose, re.M)
        if not release or tuple(map(int, release.groups())) < (1, 92, 0) or ('host: ' + TARGET) not in verbose.splitlines():
            refuse('reviewed native Rust >=1.92 required', 'rust-version')
    with diagnostic_step('metadata-target-cfg'):
        cfg = run(['/usr/bin/rustc', '--print', 'cfg', '--target', TARGET], home, env, output, 'target-cfg')
    with diagnostic_step('metadata-cargo'):
        argv = ['/usr/bin/cargo', 'metadata', '--format-version', '1', '--offline', '--locked',
                '--filter-platform', TARGET, '--manifest-path', str(manifest)]
        data = run(argv, manifest.parent, env, output, 'cargo-metadata')
    with diagnostic_step('metadata-recheck'):
        # Bind receipt to source bytes still present after metadata resolution.
        final_blobs, final_vendor = preflight(manifest, vendor, audit)
        if final_blobs != blobs or final_vendor != vendor_summary:
            refuse('worker source changed during metadata', 'source-drift')
        verify_controller(controller_path, controller_sha, facts)
    with diagnostic_step('metadata-receipt'):
        record = {'schema_version': 1, 'host': TARGET, 'target': TARGET, 'image_id': facts['image_id'],
                  'manifest_path': str(manifest), 'metadata_argv': argv, 'observed_worker': facts,
                  'builder_inventory_sha256': builder_sha, 'rustc_vv_sha256': digest(verbose.encode()),
                  'tool_sha256': {tool: controller['tool_pins']['tools']['/usr/bin/' + tool]['sha256']
                                  for tool in ('cargo', 'rustc', 'pacman')},
                  'verified_tool_pins': controller['tool_pins'], 'controller_sha256': controller_sha,
                  'vendor_preflight': vendor_summary,
                  'sha256': {'manifest': digest(manifest_data), 'lock': digest(lock_data), 'audit': digest(audit_data),
                             'metadata': digest(data), 'cfg': digest(cfg)},
                  'build_script_execution': 'NOT RUN', 'native_compilation': 'NOT RUN',
                  'provenance_limit': 'controller must independently bind image/daemon/launch; this receipt is not hardware attestation'}
        (output / 'worker.json').write_text(json.dumps(record, indent=2) + '\n')
    return data, record, cfg, env


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--cargo-audit', type=Path, required=True)
    parser.add_argument('--builder-lock-sha256', required=True)
    parser.add_argument('--controller-input', type=Path, default=Path('/inputs/controller-input.json'))
    parser.add_argument('--controller-sha256', default=os.environ.get('CACHY_ASAHI_CONTROLLER_SHA256'))
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    metadata(args.manifest.absolute(), args.vendor.absolute(), args.cargo_audit.absolute(),
             args.builder_lock_sha256, Path('/out/target-metadata'),
             args.controller_input.absolute(), args.controller_sha256)
