# SPDX-License-Identifier: MIT
"""Selected callback for native_arm.main(integration_consumers=consumer).

The Root bootstrap and the ordinary producer/interpreter/OS are trusted. This is
file/lease custody at a fixed callback, not an unforgeable Python capability or
proof about caller frames, arbitrary descendants or all executed runtime bytes.
No actor runs on import or from an unissued template registration.
"""
from pathlib import Path
import hashlib
import os
import stat
import sys
import time
import types

import boundary
import parent_bridge
import baseline_bridge

CLI = 'scripts/ci/private-library-cli/'
BODIES = ('boundary', 'parent_bridge', 'entry', 'operations', 'owned_build',
          'baseline_bridge', 'evidence', 'consumer_adapter')
SELECTION_KEYS = ('schema_version', 'purpose', 'identity', 'nonce', 'clock',
    'original_entry_monotonic', 'sources', 'inputs', 'producer_sources',
    'tool_pins', 'environment', 'output_path', 'credentials', 'cache_path')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def read_pin(ref, *, deadline=None):
    """Read a Root-issued regular file and retain its exact byte/identity join."""
    boundary.file_ref(ref)
    path = parent_bridge.checked_path(ref['path'])
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    first = None
    try:
        if deadline is not None:
            need(time.monotonic() < deadline, 'ORIGINAL_DEADLINE_EXHAUSTED')
        need(parent_bridge.identity(os.fstat(fd)) == ref['identity'], 'ISSUED_FILE_IDENTITY')
        raw = parent_bridge.read_fd(fd, min(8 * 1024**2, ref['bytes']))
        need(len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256'] and
             parent_bridge.identity(path.lstat()) == ref['identity'], 'ISSUED_FILE_PIN')
        return raw
    except BaseException as error:
        first = error
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            if first is None:
                raise
            first.add_note('ISSUED_FILE_CLOSE_UNCERTAIN:' + type(error).__name__)


def observe_runtime(pins, deadline):
    """Observe three selected executable files and the current same-job socket.

    The interpreter's stdlib, extension libraries, loader and kernel and the
    Docker daemon are ordinary trusted platform components, not a byte manifest.
    """
    boundary.exact(pins, ('interpreter', 'docker', 'gpgv', 'socket'))
    observed = {}
    for name in ('interpreter', 'docker', 'gpgv'):
        pin = pins[name]
        boundary.exact(pin, ('path', 'sha256'))
        boundary.pin(pin['sha256'])
        need(pin['sha256'] != '0' * 64, 'ROOT_TOOL_PIN_NOT_ISSUED')
        path = parent_bridge.checked_path(pin['path'])
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o755 and info.st_size <= 128 * 1024**2,
             'ROOT_TOOL_FILE')
        descriptor = dict(path=str(path), sha256=pin['sha256'], bytes=info.st_size,
                          identity=parent_bridge.identity(info))
        # Interpreter files can exceed the protocol's ordinary evidence cap.
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        first = None
        try:
            need(time.monotonic() < deadline, 'ORIGINAL_DEADLINE_EXHAUSTED')
            raw = parent_bridge.read_fd(fd, 128 * 1024**2)
            need(hashlib.sha256(raw).hexdigest() == descriptor['sha256'] and
                 parent_bridge.identity(os.fstat(fd)) == descriptor['identity'] ==
                 parent_bridge.identity(path.lstat()), 'ROOT_TOOL_OBSERVATION')
        except BaseException as error:
            first = error
            raise
        finally:
            try:
                os.close(fd)
            except BaseException as error:
                if first is None:
                    raise
                first.add_note('TOOL_OBSERVATION_CLOSE_UNCERTAIN:' + type(error).__name__)
        descriptor.pop('bytes')
        observed[name] = descriptor
    need(observed['interpreter']['path'] == str(Path(sys.executable).resolve()),
         'PARENT_SELECTED_INTERPRETER')
    boundary.exact(pins['socket'], ('path', 'identity'))
    socket = pins['socket']
    need(socket['path'] == '/run/docker.sock', 'FIXED_DOCKER_SOCKET')
    info = parent_bridge.checked_path(socket['path']).lstat()
    current = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink]
    need(stat.S_ISSOCK(info.st_mode) and current == socket['identity'], 'ROOT_SOCKET_OBSERVATION')
    observed['socket'] = dict(path=socket['path'], identity=current)
    need(time.monotonic() < deadline, 'ORIGINAL_DEADLINE_EXHAUSTED')
    return observed


def selection_shape(selected):
    """Reject unfinished templates before the original producer can be invoked."""
    source = selected['sources']
    boundary.exact(source, ('root', 'manifest_sha256', 'files'))
    boundary.path(source['root'])
    need(type(source['files']) is dict and 8 <= len(source['files']) <= 512,
         'ROOT_PROJECT_FILE_SET')
    for path, row in source['files'].items():
        boundary.relative(path)
        boundary.exact(row, ('sha256', 'bytes', 'mode'))
        boundary.pin(row['sha256'])
        boundary.integer(row['bytes'], 0, 8 * 1024**2)
        need(row['sha256'] != '0' * 64 and row['mode'] in (0o444, 0o555), 'ROOT_PROJECT_PIN')
    need(all(CLI + name + '.py' in source['files'] for name in BODIES) and
         hashlib.sha256(boundary.encoded(source['files'])).hexdigest() == source['manifest_sha256'],
         'ROOT_PROJECT_MANIFEST')
    boundary.exact(selected['inputs'], ('contract_sha256', 'materialization_plan_sha256',
        'jbigkit_inputs_sha256', 'libtiff_inputs_sha256'))
    for pin in selected['inputs'].values():
        boundary.pin(pin)
        need(pin != '0' * 64, 'ROOT_INPUT_PIN_NOT_ISSUED')
    boundary.exact(selected['producer_sources'], ('native_arm', 'integration'))
    for row in selected['producer_sources'].values():
        boundary.exact(row, ('path', 'sha256', 'bytes', 'mode'))
        boundary.path(row['path'])
        boundary.pin(row['sha256'])
        boundary.integer(row['bytes'], 1, 8 * 1024**2)
        need(row['sha256'] != '0' * 64 and row['mode'] in (0o444, 0o555, 0o644, 0o755),
             'ROOT_PRODUCER_PIN_NOT_ISSUED')
    boundary.exact(selected['tool_pins'], ('interpreter', 'docker', 'gpgv', 'socket'))
    for name in ('interpreter', 'docker', 'gpgv'):
        row = selected['tool_pins'][name]
        boundary.exact(row, ('path', 'sha256'))
        boundary.path(row['path'])
        boundary.pin(row['sha256'])
        need(row['sha256'] != '0' * 64, 'ROOT_TOOL_PIN_NOT_ISSUED')
    boundary.exact(selected['tool_pins']['socket'], ('path', 'identity'))
    boundary.identity(selected['tool_pins']['socket']['identity'], 6)
    need(selected['tool_pins']['socket']['path'] == '/run/docker.sock', 'FIXED_DOCKER_SOCKET')
    boundary.path(selected['output_path'])
    boundary.exact(selected['credentials'], ('uid', 'gid'))
    need(selected['credentials'] == {'uid': os.getuid(), 'gid': os.getgid()}, 'PARENT_SELECTED_CREDENTIALS')
    env = selected['environment']
    boundary.exact(env, boundary.ENV_KEYS)
    need(env['PATH'] == '/usr/bin:/bin' and env['DOCKER_HOST'] == 'unix:///run/docker.sock' and
         env['DOCKER_BUILDKIT'] == '0' and env['LC_ALL'] == 'C' and
         env['GITHUB_SHA'] == selected['identity']['source_commit'] and
         env['PYTHONDONTWRITEBYTECODE'] == '1', 'ROOT_FIXED_ENVIRONMENT')
    for name in ('HOME', 'DOCKER_CONFIG', 'TMPDIR'):
        path = parent_bridge.checked_path(env[name])
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
             info.st_uid == os.getuid() and info.st_gid == os.getgid(), 'ROOT_PRIVATE_ENVIRONMENT_DIRECTORY')


class Consumer:
    """One fixed same-job callback; only the selected Root bootstrap constructs it."""
    def __init__(self, registration_pin, native_modules, *, cache):
        raw = read_pin(registration_pin)
        self.selection = boundary.decode(raw)
        selected = self.selection
        boundary.exact(selected, SELECTION_KEYS)
        need(type(selected['schema_version']) is int and selected['schema_version'] == 1 and
             selected['purpose'] == 'project-libraries-cli-root-selection', 'ROOT_SELECTION_SCHEMA')
        boundary.exact(selected['identity'], boundary.IDENTITY_KEYS)
        for key in ('code_commit', 'source_commit', 'data_commit'):
            boundary.pin(selected['identity'][key], 40)
            need(selected['identity'][key] != '0' * 40, 'ROOT_IDENTITY_NOT_ISSUED')
        for key in ('packet_sha256', 'peer_sha256', 'plan_sha256'):
            boundary.pin(selected['identity'][key])
            need(selected['identity'][key] != '0' * 64, 'ROOT_IDENTITY_NOT_ISSUED')
        boundary.pin(selected['nonce'], 32)
        need(selected['nonce'] != '0' * 32, 'ROOT_NONCE_NOT_ISSUED')
        selection_shape(selected)
        clock = boundary.decode(read_pin(selected['clock']))
        boundary.validate_clock(clock, selected['identity'], parent_bridge.clock_domain())
        entry = selected['original_entry_monotonic']
        boundary.finite(entry)
        cutoff = min(clock['deadline_monotonic'] - 120, entry + 10080)
        need(clock['issued_monotonic'] <= entry <= time.monotonic() < cutoff,
             'ORIGINAL_CONSUMER_ENTRY_OR_CUTOFF')
        self.initial_runtime = observe_runtime(selected['tool_pins'], cutoff)
        self.original_clock, self.cutoff = clock, cutoff
        need(type(native_modules) is dict and set(native_modules) == {'native_arm', 'integration'} and
             all(type(value) is types.ModuleType for value in native_modules.values()),
             'SELECTED_PRODUCER_MODULES')
        self.modules = native_modules
        self.cache = parent_bridge.checked_path(str(cache))
        need(str(self.cache) == selected['cache_path'] and self.cache.is_dir(),
             'TRUSTED_PRODUCER_CACHE_ARGUMENT')
        self.registration_pin = dict(registration_pin)
        self.registration_bytes = raw
        self.used = False
        self.result = self.record = None
        self.registration = baseline_bridge.register_consumer(
            sys.modules[__name__], registration_pin,
            native_modules['integration'].Controller, native_modules)
        try:
            need(time.monotonic() < cutoff, 'ORIGINAL_DEADLINE_EXHAUSTED')
        except BaseException as error:
            self.registration.held.close(error)
            raise

    def __call__(self, controller):
        """Called by original integration.Controller.run before its finally cleanup."""
        need(not self.used, 'CONSUMER_REPLAY_REFUSED')
        self.used = True
        selected = self.selection
        need(read_pin(self.registration_pin) == self.registration_bytes, 'ROOT_SELECTION_CHANGED')
        clock = boundary.decode(read_pin(selected['clock']))
        domain = parent_bridge.clock_domain()
        boundary.validate_clock(clock, selected['identity'], domain)
        entry = selected['original_entry_monotonic']
        boundary.finite(entry)
        cutoff = min(clock['deadline_monotonic'] - 120, entry + 10080)
        need(clock['issued_monotonic'] <= entry <= time.monotonic() < cutoff,
             'ORIGINAL_CONSUMER_ENTRY_OR_CUTOFF')
        # The complete project file list is issued by Root; it includes this
        # fixed adapter, the driver and lease code, without a stdlib manifest.
        source = selected['sources']
        need(type(source) is dict and all(CLI + name + '.py' in source.get('files', {})
             for name in BODIES), 'EIGHT_SELECTED_BODIES_REQUIRED')
        need(source['files'][CLI + 'consumer_adapter.py']['sha256'] == hashlib.sha256(
             Path(__file__).read_bytes()).hexdigest(), 'SELECTED_CONSUMER_BODY')
        output = parent_bridge.checked_path(selected['output_path'])
        need(not output.exists() and not output.is_symlink(), 'FRESH_CONSUMER_OUTPUT')
        output.mkdir(mode=0o700)
        info = output.lstat()
        need(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid() and
             info.st_gid == os.getgid(), 'OWNED_CONSUMER_OUTPUT')
        runtime = observe_runtime(selected['tool_pins'], cutoff)
        need(runtime == self.initial_runtime, 'ORIGINAL_RUNTIME_OBSERVATION_DRIFT')
        record = dict(schema_version=1, lane=boundary.LANE, identity=selected['identity'],
            clock=clock, entry_monotonic=entry, cutoff_monotonic=cutoff,
            nonce=selected['nonce'], runtime=runtime,
            sources=source, inputs=selected['inputs'], baseline=None,
            output=dict(path=str(output), identity=parent_bridge.identity(info)),
            credentials=selected['credentials'], environment=selected['environment'],
            budget=dict(commands=1, command_log_bytes={'1': 0}, log_bytes=0, fetches=0, fetch_bytes=0))
        self.record = record
        # Original native_arm.main has audited/built/compared before this callback.
        # Registration/Lease independently bind its files and live owned image;
        # serialized producer summaries are not the authority to borrow it.
        # Actual cache was supplied as the producer's trusted bootstrap argument,
        # with a matching Root-issued path. Child JSON cannot choose another one.
        try:
            with self.registration.consumer_scope(controller):
                lease = self.registration.borrow(controller, record, self.cache,
                    original_clock=clock, original_entry=entry)
                record['baseline'] = lease.wire
                boundary.validate_input(record, observed_domain=domain)
                self.result = parent_bridge.launch(record, lease)
        except BaseException as error:
            if self.result is not None:
                # Parent-owned lease descriptors close after launch returns.
                # Their uncertainty invalidates even an earlier checked result.
                self.result['status'] = 'FAIL'
                self.result['cancelled'] = self.result.get('cancelled', False) or isinstance(error, KeyboardInterrupt)
                if self.result.get('first_cause') is None:
                    self.result['first_cause'] = boundary.failure_record(error)
                failures = self.result.setdefault('cleanup_errors', [])
                if len(failures) < 128:
                    failures.append(boundary.failure_record(error))
            raise
        need(self.result is not None and self.result['status'] == 'PRIVATE_CHECKED',
             'LIBRARY_PRIVATE_TERMINAL_NOT_CHECKED')
        # This is an internal callback result. Root's completed-job finalization
        # and public metadata publication remain separate workflow obligations.
        return self.result


def make_consumer(registration_pin, native_modules, *, cache):
    """The reviewed bootstrap supplies real Root-issued pins, never a template."""
    return Consumer(registration_pin, native_modules, cache=cache)


def run_original(registration_pin, native_modules, *, cache, native_output, integration_output, report=None):
    """Concrete trusted bootstrap seam with one cache argument for both owners.

    Root loads the pinned producer modules inside its existing original-clock
    supervision context and supplies fresh output paths. Bare unwrapped main
    does not add such supervision. Existing acquisition, signature, eight-build/
    four-comparison and integration work remains unchanged. Return the original
    exit code and private terminal separately for Root's finalization/publication.
    """
    consumer = make_consumer(registration_pin, native_modules, cache=cache)
    if report is not None:
        need(type(report) is dict and not report, 'FRESH_ROOT_REPORT')
        report['consumer'] = consumer
    first = None
    code = None
    try:
        root = Path(native_modules['native_arm'].__file__).parent.parent.parent
        sources = consumer.selection['sources']['files']
        paths = {'inputs': 'scripts/ci/inputs.lock.json', 'recipes': 'scripts/ci/recipes.lock.json',
                 'integration': 'scripts/ci/integration.lock.json'}
        argv = ['integration', '--cache', str(consumer.cache), '--output', str(native_output),
                '--integration-output', str(integration_output)]
        for name, path in paths.items():
            need(time.monotonic() < consumer.cutoff, 'ORIGINAL_DEADLINE_EXHAUSTED')
            need(path in sources, 'ORIGINAL_PRODUCER_INPUT_NOT_SELECTED')
            raw = (root / path).read_bytes()
            need(hashlib.sha256(raw).hexdigest() == sources[path]['sha256'],
                 'ORIGINAL_PRODUCER_INPUT_CHANGED')
            argv.extend(('--' + name, str(root / path), '--' + name + '-sha256', sources[path]['sha256']))
        need(time.monotonic() < consumer.cutoff, 'ORIGINAL_DEADLINE_EXHAUSTED')
        code = native_modules['native_arm'].main(argv, integration_consumers=consumer)
        need(type(code) is int, 'ORIGINAL_PRODUCER_EXIT_SHAPE')
        if code == 0:
            need(consumer.used and consumer.result is not None and
                 consumer.result['status'] == 'PRIVATE_CHECKED', 'ORIGINAL_CONSUMER_WAS_NOT_COMPLETED')
        return code, consumer.result
    except BaseException as error:
        first = error
        raise
    finally:
        # Main can fail or skip its callback. "used" also includes a callback
        # refused before scope entry, so actual descriptor retirement is tested.
        held = consumer.registration.held
        if not held.closed and not consumer.registration.retained:
            try:
                held.close(first)
            except BaseException as error:
                if consumer.result is not None:
                    consumer.result['status'] = 'FAIL'
                if first is not None:
                    first.add_note('UNUSED_REGISTRATION_CLOSE_UNCERTAIN:' + type(error).__name__)
                elif code is not None and code != 0:
                    # Preserve the original nonzero producer exit; uncertainty
                    # remains reachable and cannot turn that exit into success.
                    parent_bridge.HELD.append(dict(kind='UNUSED_REGISTRATION_CLOSE_UNCERTAIN',
                        producer_exit_code=code, exception_type=type(error).__name__))
                else:
                    raise
