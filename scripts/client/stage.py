#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded frozen-client source tests in the coordinator's existing native builder.

No image building, downloads, package installation, signing-key export or CI dispatch.
Only a sanitized receipt leaves the disposable container; no raw test logs do.
"""
import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
GUARD_SHA = '4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100'
PACKAGES_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
FROZEN = {
    'scripts/client/client.py': '48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7',
    'scripts/client/test_client.py': '74ec58c2e442ba941d040d0bd8f52d74538ea38a4ccd6d2404729834e9795cd8',
    'scripts/release/release.py': 'e4ab44f7cc020ae1d705b64362e8b1b05fa0c29c19ce64d886116055619c0435',
    'scripts/release/test_release.py': '7ee9e693d4574c6bb11dcc927937475742b9fa7a6f8e988608532c1e1bab5f2e',
    'scripts/release/source_delivery.py': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e',
}
TOOLS = ('python', 'gpg', 'gpgconf', 'repo-add', 'bsdtar', 'vercmp', 'pacman')
LIMIT = 1024 * 1024
TIMEOUT = 300
PURPOSE = 'frozen-48-client-native-source-tests'
TEST_COUNT = 48
LOCAL_ENDPOINTS = {'unix:///var/run/docker.sock', 'unix:///run/docker.sock'}
# Derived from current checksum-pinned client48 Source; no additional client behavior.
TEST_IDS = frozenset({
    'client_stage_tests.GPGTests.test_apply_then_readonly_and_idempotent_verification',
    'client_stage_tests.GPGTests.test_bad_database_signature_with_resigned_manifest_and_envelope',
    'client_stage_tests.GPGTests.test_bad_package_signature_even_with_resigned_manifest_and_envelope',
    'client_stage_tests.GPGTests.test_builder_refuses_overwrite_and_output_inside_bundle',
    'client_stage_tests.GPGTests.test_cli_default_is_readonly_and_failure_is_nonzero',
    'client_stage_tests.GPGTests.test_envelope_signature_tamper_missing_and_wrong_signer',
    'client_stage_tests.GPGTests.test_existing_release_stage_bundle_is_consumed_without_interface_changes',
    'client_stage_tests.GPGTests.test_expired_future_namespace_and_stable_fail_without_state_change',
    'client_stage_tests.GPGTests.test_full_apply_precommit_cleanup_and_sync_failures_preserve_existing_checkpoint',
    'client_stage_tests.GPGTests.test_higher_sequence_then_replay_and_same_sequence_altered_bytes',
    'client_stage_tests.GPGTests.test_invalid_metadata_signature_on_fresh_higher_sequence',
    'client_stage_tests.GPGTests.test_payload_tamper_and_bundle_mix_do_not_advance',
    'client_stage_tests.GPGTests.test_real_expired_key_rejected_without_checkpoint',
    'client_stage_tests.GPGTests.test_real_revoked_public_certificate_rejected',
    'client_stage_tests.GPGTests.test_real_sha1_signature_rejected',
    'client_stage_tests.GPGTests.test_real_subkey_verification_and_no_default_or_external_keyring_mutation',
    'client_stage_tests.GPGTests.test_real_wrong_primary_in_mixed_keyring_is_rejected',
    'client_stage_tests.GPGTests.test_release_record_signature_failure_prevents_apply',
    'client_stage_tests.GPGTests.test_signed_envelope_targets_must_match_actual_bytes',
    'client_stage_tests.GPGTests.test_sources_actual_signed_lookup_export_and_unchanged_envelope_checkpoint',
    'client_stage_tests.GPGTests.test_sources_cli_readonly_lookup_and_apply_flag_refused',
    'client_stage_tests.GPGTests.test_sources_exact_requested_identity_and_unsafe_output',
    'client_stage_tests.GPGTests.test_sources_export_rechecks_material_after_last_association',
    'client_stage_tests.GPGTests.test_sources_generic_bundle_not_declared_never_exports',
    'client_stage_tests.GPGTests.test_sources_material_changes_after_describe_refused_before_lookup_and_export',
    'client_stage_tests.GPGTests.test_sources_provenance_and_index_coverage_cannot_be_foreign_even_resigned',
    'client_stage_tests.GPGTests.test_sources_reject_material_tamper_missing_and_spec_signed_map_disagreement',
    'client_stage_tests.GPGTests.test_sources_reopen_substitution_refused_without_export',
    'client_stage_tests.GPGTests.test_valid_resign_race_cannot_change_consumed_signature_bytes',
    'client_stage_tests.PortableTests.test_atomic_checkpoint_mode_and_precommit_failure',
    'client_stage_tests.PortableTests.test_bad_expired_revoked_and_multiple_statuses',
    'client_stage_tests.PortableTests.test_checkpoint_private_mode_symlink_and_malformed',
    'client_stage_tests.PortableTests.test_checkpoint_read_does_not_modify_bytes_or_mtime',
    'client_stage_tests.PortableTests.test_envelope_rejects_stable_unknown_fields_and_schema_bool',
    'client_stage_tests.PortableTests.test_freshness_future_expiry_and_maximum_lifetime',
    'client_stage_tests.PortableTests.test_full_status_identity_subkey_and_weak_digest',
    'client_stage_tests.PortableTests.test_gpg_exit_zero_is_not_enough_and_isolation_is_explicit',
    'client_stage_tests.PortableTests.test_input_symlink_components_hardlinks_and_fifo_refused',
    'client_stage_tests.PortableTests.test_json_rejects_duplicate_float_nonfinite_and_nonobject',
    'client_stage_tests.PortableTests.test_lock_excludes_other_apply_and_readonly_checks',
    'client_stage_tests.PortableTests.test_paths_reject_traversal_empty_and_noncanonical',
    'client_stage_tests.PortableTests.test_read_bounds',
    'client_stage_tests.PortableTests.test_rollback_same_sequence_changes_namespace_signer_and_clock',
    'client_stage_tests.PortableTests.test_sequence_rejects_bool_zero_negative_large_and_float',
    'client_stage_tests.PortableTests.test_source_helper_loads_exact_sibling_bytes_ignoring_cwd_module',
    'client_stage_tests.PortableTests.test_sources_primary_survives_owned_root_close_uncertainty',
    'client_stage_tests.PortableTests.test_state_private_permissions_owner_symlink_and_missing',
    'client_stage_tests.PortableTests.test_sync_failure_before_and_after_commit_has_distinct_outcome',
})


SIGNALS = {signal.SIGTERM, signal.SIGINT}
CANCELLED = False


class Cancelled(KeyboardInterrupt):
    pass


def interrupt(*_):
    global CANCELLED
    CANCELLED = True
    raise Cancelled()


@contextmanager
def defer_signals():
    def remember(*_):
        global CANCELLED
        CANCELLED = True
    previous = {sig: signal.signal(sig, remember) for sig in SIGNALS}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextmanager
def cancellation_handlers():
    global CANCELLED
    CANCELLED = False
    previous = {sig: signal.signal(sig, interrupt) for sig in SIGNALS}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pin(value):
    need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid-sha256')
    return value


def read(path, limit=LIMIT):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink-input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit, 'nonregular-or-unbounded-input')
        data = bytearray()
        while block := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(block)
            need(len(data) <= limit, 'input-byte-bound')
        need(len(data) == info.st_size, 'input-read-drift')
        return bytes(data)
    finally:
        os.close(fd)


def decode(data):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def checked(path, expected):
    data = read(path)
    need(digest(data) == pin(expected), 'input-pin-mismatch')
    return data


def inventory(data):
    rows = {}
    for line in data.decode('ascii').splitlines():
        parts = line.split(' ')
        need(len(parts) == 2 and re.fullmatch(r'[A-Za-z0-9@._+:-]+', parts[0])
             and re.fullmatch(r'[A-Za-z0-9._+:~-]+', parts[1]) and parts[0] not in rows, 'invalid-inventory')
        rows[parts[0]] = parts[1]
    need(len(rows) == 341 and data == ''.join(f'{k} {rows[k]}\n' for k in sorted(rows)).encode(), 'full-341-inventory-required')
    return rows


def bootstrap(data, lock, image):
    record = decode(data)
    need(record.get('status') == 'image-provisioned' and record.get('image_id') == image
         and record.get('inputs_sha256') == INPUTS_SHA
         and record.get('packages_lock_sha256') == digest(lock) == PACKAGES_SHA, 'bootstrap-binding-mismatch')
    inventory(lock)
    return record


def bounded(command, timeout=30, limit=LIMIT, env=None, cwd=None):
    """Bounded pipe draining; cancellation cannot lose an untracked child."""
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    process = None
    data = bytearray()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, env=env, cwd=cwd,
                                   preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'command-timeout')
                for key, _ in selector.select(min(remaining, 0.2)):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        data.extend(block)
                        need(len(data) <= limit, 'command-output-bound')
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(data)
    finally:
        with defer_signals():
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            if process is not None:
                for signum in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(process.pid, signum)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=5)
                process.stdout.close()


def successful(command, **options):
    code, data = bounded(command, **options)
    need(code == 0, 'command-failed')
    return data


def controlled_env(home):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(home / 'tmp'),
            'GNUPGHOME': str(home / 'gnupg'), 'XDG_RUNTIME_DIR': str(home / 'runtime'),
            'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_DATA_HOME': str(home / 'data'),
            'XDG_STATE_HOME': str(home / 'state'), 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}


def source_pins(root, stage_sha, guard_sha):
    need(guard_sha == GUARD_SHA, 'unreviewed-guard-source')
    pins = dict(FROZEN, **{'scripts/client/stage.py': pin(stage_sha), 'scripts/ci/source_suites.py': pin(guard_sha)})
    return {name: checked(root / name, sha) for name, sha in pins.items()}, pins


def worker_guard(guard_sha):
    path = Path('/source/scripts/ci/source_suites.py')
    need(guard_sha == GUARD_SHA, 'unreviewed-guard-source')
    checked(path, guard_sha)
    spec = importlib.util.spec_from_file_location('client_stage_guard', path)
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    record = guard.environment(Path('/source'), Path('/out'))
    guard.guard(record)
    need(guard.READONLY_PROC <= set(record['mounts']), 'missing-protected-proc-mount')
    need(os.geteuid() == os.getegid() == int(os.environ['CACHY_ASAHI_CLIENT_UID']), 'uid-gid-mismatch')
    return record


def process_ids():
    result = set()
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name) == os.getpid():
            continue
        try:
            status = (path / 'status').read_text()
        except FileNotFoundError:
            continue
        uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)', status, re.M)
        need(uid and int(uid[1]) == int(uid[2]) == os.geteuid(), 'unexpected-process-owner')
        result.add(int(path.name))
    return result


def cleanup_processes():
    """PID1 in a private container: collect daemonized fixture agents too."""
    need(os.getpid() == 1, 'worker-must-be-private-pid1')
    for signum in (signal.SIGTERM, signal.SIGKILL):
        for pid in process_ids():
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
            if not process_ids():
                return True
            time.sleep(0.05)
    return not process_ids()


class Result(unittest.TestResult):
    """Known identifiers/status only; no traceback, key bytes or test diagnostics."""
    def __init__(self):
        super().__init__()
        self.rows = []

    def record(self, test, status):
        ident = test.id()
        need(ident in TEST_IDS, 'unexpected-test-identifier')
        self.rows.append({'test': ident, 'status': status})

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, 'PASS')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, 'FAIL')

    def addError(self, test, err):
        super().addError(test, err)
        # setUpClass/tearDownClass holders do not use ordinary method ids.
        self.rows.append({'test': 'fixture-or-test-error', 'status': 'FAIL'})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows.append({'test': 'skipped-source-test', 'status': 'FAIL'})

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.rows.append({'test': 'failed-source-subtest', 'status': 'FAIL'})


def run_tests(home):
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    spec = importlib.util.spec_from_file_location('client_stage_tests', '/source/scripts/client/test_client.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    need(suite.countTestCases() == TEST_COUNT, 'frozen-test-count-mismatch')
    result = Result()
    # Even accidental prints and uncaught assertion diagnostics stay in tmpfs.
    with (home / 'private-test.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
        suite.run(result)
    return {'tests': result.testsRun, 'skipped': len(result.skipped), 'failures': len(result.failures),
            'errors': len(result.errors), 'outcomes': result.rows,
            'status': 'PASS' if result.testsRun == TEST_COUNT and result.wasSuccessful() and not result.skipped else 'FAIL'}


def finalize_receipt(path, report):
    """Only structured evidence; a signal during write/fsync cannot leave PASS."""
    def encode():
        data = json.dumps(report, indent=2, sort_keys=True).encode() + b'\n'
        need(len(data) <= LIMIT, 'receipt-byte-bound')
        return data
    with defer_signals():
        if CANCELLED:
            report.update(status='FAIL', cancelled=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encode())
            stream.flush()
            os.fsync(stream.fileno())
            if CANCELLED and (report['status'] != 'FAIL' or report.get('cancelled') is not True):
                report.update(status='FAIL', cancelled=True)
                stream.seek(0)
                stream.truncate()
                stream.write(encode())
                stream.flush()
                os.fsync(stream.fileno())


def worker(args):
    need(Path(__file__).absolute() == Path('/source/scripts/client/stage.py'), 'fixed-worker-source-required')
    observed = worker_guard(args.guard_sha256)  # Refuse host before reading contract or writing.
    need(os.getpid() == 1, 'worker-must-be-private-pid1')
    need(not list(Path('/tmp').iterdir()) and not list(Path('/out').iterdir()), 'fresh-worker-mounts-required')
    contract_data = checked('/source/client-stage-inputs.json', args.contract_sha256)
    contract = decode(contract_data)
    need(set(contract) == {'schema_version', 'purpose', 'image_id', 'bootstrap_sha256', 'packages_sha256', 'source_sha256', 'uid'}, 'contract-fields')
    need(contract['schema_version'] == 1 and contract['purpose'] == PURPOSE
         and contract['image_id'] == os.environ.get('CACHY_ASAHI_IMAGE_ID')
         and contract['uid'] == os.geteuid(), 'worker-contract-identity')
    source_pins(Path('/source'), contract['source_sha256']['scripts/client/stage.py'], args.guard_sha256)
    need(contract['source_sha256'] == {**FROZEN, 'scripts/client/stage.py': digest(read(__file__)),
                                     'scripts/ci/source_suites.py': args.guard_sha256}, 'source-contract-mismatch')
    lock = checked('/source/packages.lock', contract['packages_sha256'])
    bootstrap(checked('/source/bootstrap.json', contract['bootstrap_sha256']), lock, contract['image_id'])
    need(read('/builder-packages.lock') == lock, 'image-lock-mismatch')
    actual = successful(['/usr/bin/pacman', '-Q'])
    need(inventory(actual) == inventory(lock), 'installed-package-inventory-mismatch')
    need(all(shutil.which(name, path='/usr/bin:/bin') for name in TOOLS), 'required-real-test-tools-missing')
    home = Path(os.environ['HOME'])
    need(home == Path('/tmp/client-stage') and not home.exists(), 'fresh-private-home-required')
    os.umask(0o077)
    home.mkdir(mode=0o700)
    env = controlled_env(home)
    os.environ.clear()
    os.environ.update(env)
    for field in ('TMPDIR', 'GNUPGHOME', 'XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME'):
        Path(env[field]).mkdir(mode=0o700)
    receipt = {'schema_version': 1, 'purpose': PURPOSE, 'status': 'FAIL', 'image_id': contract['image_id'],
               'bootstrap_sha256': contract['bootstrap_sha256'], 'packages_sha256': contract['packages_sha256'],
               'source_sha256': contract['source_sha256'], 'architecture': observed['arch'], 'uid': os.geteuid(),
               'native_client_tests': 'NOT RUN', 'hardware': 'NOT RUN', 'production_acceptance': 'NOT RUN',
               'cleanup': {'processes': 'FAIL', 'private_tmpfs': 'FAIL'}}
    try:
        os.chdir(home)
        receipt['suite'] = run_tests(home)
        receipt['native_client_tests'] = receipt['suite']['status']
    except (Cancelled, ValueError, OSError):
        receipt['native_client_tests'] = 'FAIL'
        receipt['suite'] = {'tests': None, 'skipped': None, 'failures': None, 'errors': None,
                            'outcomes': [], 'status': 'FAIL', 'aborted': True}
    finally:
        with defer_signals():
            process_clean = cleanup_processes()
            receipt['cleanup']['processes'] = 'PASS' if process_clean else 'FAIL'
            os.chdir('/tmp')
            shutil.rmtree(home)
            receipt['cleanup']['private_tmpfs'] = 'PASS' if not home.exists() and not list(Path('/tmp').iterdir()) else 'FAIL'
    with defer_signals():
        receipt['status'] = 'PASS' if not CANCELLED and receipt['native_client_tests'] == 'PASS' and set(receipt['cleanup'].values()) == {'PASS'} else 'FAIL'
        finalize_receipt('/out/worker-receipt.json', receipt)
    return 0 if receipt['status'] == 'PASS' else 1


def validate_receipt(record):
    fields = {'schema_version', 'purpose', 'status', 'image_id', 'bootstrap_sha256', 'packages_sha256',
              'source_sha256', 'architecture', 'uid', 'native_client_tests', 'hardware',
              'production_acceptance', 'cleanup', 'suite'}
    need((set(record) == fields or (set(record) == fields | {'cancelled'}
         and record['cancelled'] is True and record['status'] == 'FAIL')) and record['schema_version'] == 1 and record['purpose'] == PURPOSE
         and record['architecture'] in ('aarch64', 'arm64') and type(record['uid']) is int and record['uid'] > 0
         and record['status'] in ('PASS', 'FAIL') and record['native_client_tests'] in ('PASS', 'FAIL')
         and record['hardware'] == record['production_acceptance'] == 'NOT RUN', 'invalid-worker-receipt')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', record['image_id'])
         and record['packages_sha256'] == PACKAGES_SHA
         and all(re.fullmatch(r'[0-9a-f]{64}', value) for value in
                 [record['bootstrap_sha256'], *record['source_sha256'].values()]), 'invalid-receipt-pins')
    need(record['cleanup'].keys() == {'processes', 'private_tmpfs'}
         and all(x in ('PASS', 'FAIL') for x in record['cleanup'].values()), 'invalid-cleanup-receipt')
    suite = record['suite']
    suite_fields = {'tests', 'skipped', 'failures', 'errors', 'outcomes', 'status'}
    counts = ('tests', 'skipped', 'failures', 'errors')
    aborted = set(suite) == suite_fields | {'aborted'} and suite['aborted'] is True
    need((aborted and all(suite[k] is None for k in counts) and suite['outcomes'] == []
          and record['status'] == record['native_client_tests'] == suite['status'] == 'FAIL')
         or (set(suite) == suite_fields and all(type(suite[k]) is int and 0 <= suite[k] <= 100 for k in counts)
             and suite['status'] in ('PASS', 'FAIL') and len(suite['outcomes']) <= 100), 'invalid-suite-receipt')
    ids = []
    for row in suite['outcomes']:
        need(set(row) == {'test', 'status'} and row['status'] in ('PASS', 'FAIL')
             and (re.fullmatch(r'client_stage_tests\.(PortableTests|GPGTests)\.test_[a-z0-9_]+', row['test'])
                  or row['test'] in ('fixture-or-test-error', 'skipped-source-test', 'failed-source-subtest')), 'invalid-outcome-receipt')
        ids.append(row['test'])
    if record['status'] == 'PASS' or record['native_client_tests'] == 'PASS' or suite['status'] == 'PASS':
        need(record['native_client_tests'] == suite['status'] == 'PASS' and suite['tests'] == TEST_COUNT
             and suite['skipped'] == suite['failures'] == suite['errors'] == 0
             and len(ids) == len(set(ids)) == TEST_COUNT and set(ids) == TEST_IDS and all(x['status'] == 'PASS' for x in suite['outcomes']), 'incomplete-client-suite')


def docker_command(endpoint, *arguments):
    need(endpoint in LOCAL_ENDPOINTS, 'local-docker-required')
    return ['docker', '--host=' + endpoint, *arguments]


def container_command(image, name, source, output, uid, contract_sha, guard_sha, *, endpoint):
    return docker_command(endpoint, 'create') + ['--pull=never', '--name', name, '--network=none', '--ipc=private',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user', f'{uid}:{uid}',
            '--cpus=2', '--memory=1g', '--memory-swap=1g', '--pids-limit=64', '--ulimit=nofile=256:256',
            '--tmpfs', f'/tmp:rw,nosuid,nodev,exec,size=256m,mode=0700,uid={uid},gid={uid}',
            '--mount', f'type=bind,src={source},dst=/source,readonly',
            '--mount', f'type=bind,src={output},dst=/out',
            '--env', 'HOME=/tmp/client-stage', '--env', 'PATH=/usr/bin:/bin', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--env', f'CACHY_ASAHI_IMAGE_ID={image}', '--env', f'CACHY_ASAHI_CLIENT_UID={uid}',
            '--entrypoint=/usr/bin/python', image, '-I', '-B', '/source/scripts/client/stage.py', 'worker',
            '--contract-sha256', contract_sha, '--guard-sha256', guard_sha]


def inspect_container(record, image, source, output, uid):
    c, h = record['Config'], record['HostConfig']
    need(record['Image'] == image and c['User'] == f'{uid}:{uid}' and h['ReadonlyRootfs'] is True
         and h['NetworkMode'] == 'none' and not h['Privileged'] and h['CapDrop'] == ['ALL']
         and not h.get('CapAdd') and any(x in ('no-new-privileges', 'no-new-privileges:true') for x in h['SecurityOpt'])
         and h['Memory'] == h['MemorySwap'] == 1024**3 and h['NanoCpus'] == 2 * 10**9
         and h['PidsLimit'] == 64 and h['IpcMode'] == 'private'
         and not h['PidMode'] and not h['UTSMode'] and not h.get('Devices') and not h.get('DeviceRequests')
         and not h.get('VolumesFrom') and not h.get('PortBindings'), 'container-isolation-mismatch')
    need(set(x.split('=', 1)[0] for x in c['Env']) == {'HOME', 'PATH', 'PYTHONDONTWRITEBYTECODE',
         'CACHY_ASAHI_IMAGE_ID', 'CACHY_ASAHI_CLIENT_UID'}, 'ambient-container-environment')
    mounts = record['Mounts']
    binds = [m for m in mounts if m['Type'] == 'bind']
    need(len(binds) == 2 and {(m['Destination'], m['Source'], m['RW']) for m in binds}
         == {('/source', str(source), False), ('/out', str(output), True)}, 'container-bind-mismatch')
    need(all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp' and m['RW'] is True)
             for m in mounts), 'unexpected-container-mount')
    need(h['Tmpfs'] == {'/tmp': f'rw,nosuid,nodev,exec,size=256m,mode=0700,uid={uid},gid={uid}'}, 'container-tmpfs-mismatch')


def stopped_state(record):
    state = record['State']
    need(state['Status'] == 'exited' and state['Running'] is False and state['Paused'] is False
         and state['Restarting'] is False and state['Dead'] is False and state['OOMKilled'] is False
         and type(state['ExitCode']) is int and state['ExitCode'] == 0 and state['Error'] == '', 'container-did-not-exit-cleanly')
    return {'status': 'exited', 'exit_code': 0, 'oom_killed': False}


def remove_container(name, cid, env, *, endpoint):
    # Removal can report missing after a create error; daemon-confirmed absence is decisive.
    bounded(docker_command(endpoint, 'rm', '--force', '--volumes', cid or name), env=env)
    remaining = successful(docker_command(endpoint, 'container', 'ls', '--all', '--quiet', '--no-trunc',
                                          '--filter', 'name=^/' + name + '$'), env=env)
    need(not remaining.strip(), 'container-removal-unconfirmed')
    if cid:
        remaining = successful(docker_command(endpoint, 'container', 'ls', '--all', '--quiet', '--no-trunc',
                                              '--filter', 'id=' + cid), env=env)
        need(not remaining.strip(), 'container-id-removal-unconfirmed')


def run_stage(args):
    """Same-job coordinator interface. Requires the already-provisioned local image."""
    with cancellation_handlers():
        return controller(args)


def controller(args):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and os.geteuid() != 0, 'native-nonroot-coordinator-required')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image), 'immutable-image-required')
    uid = os.geteuid()
    env = {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LC_ALL': 'C'}
    context = decode(successful(['docker', 'context', 'inspect'], env=env))[0]
    endpoint = context['Endpoints']['docker']['Host']
    daemon = docker_command(endpoint)  # Every later operation bypasses mutable default-context selection.
    arch = successful(daemon + ['info', '--format', '{{.Architecture}}'], env=env).decode().strip()
    need(arch in ('aarch64', 'arm64'), 'native-daemon-required')
    image = decode(successful(daemon + ['image', 'inspect', args.image], env=env))[0]
    need(image['Id'] == args.image and image['Architecture'] == 'arm64' and image['Os'] == 'linux', 'native-image-required')
    lock = checked(args.packages, args.packages_sha256)
    boot = checked(args.bootstrap, args.bootstrap_sha256)
    bootstrap(boot, lock, args.image)
    files, pins = source_pins(Path(args.source), args.stage_sha256, args.guard_sha256)
    output = Path(args.output).absolute()
    need(not output.exists() and not output.is_symlink() and not any(p.is_symlink() for p in output.parents), 'fresh-output-required')
    output.mkdir(mode=0o700)
    report = {'schema_version': 1, 'purpose': PURPOSE, 'status': 'FAIL', 'native_client_tests': 'NOT RUN',
              'image_id': args.image, 'docker_endpoint': endpoint, 'bootstrap_sha256': args.bootstrap_sha256, 'packages_sha256': args.packages_sha256,
              'source_sha256': pins, 'container_cleanup': 'NOT RUN', 'hardware': 'NOT RUN', 'production_acceptance': 'NOT RUN'}
    name = 'cachy-asahi-client-' + os.urandom(12).hex()
    cid, temp, attempted = None, None, False
    try:
        with defer_signals():
            temp = tempfile.TemporaryDirectory(prefix='client-stage-controller-')
        need(not CANCELLED, 'stage-cancelled')
        source, public = Path(temp.name) / 'source', Path(temp.name) / 'public'
        source.mkdir(mode=0o700)
        public.mkdir(mode=0o700)
        for relative, data in files.items():
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o444)
        (source / 'packages.lock').write_bytes(lock)
        (source / 'bootstrap.json').write_bytes(boot)
        contract = {'schema_version': 1, 'purpose': PURPOSE, 'image_id': args.image,
                    'bootstrap_sha256': args.bootstrap_sha256, 'packages_sha256': args.packages_sha256,
                    'source_sha256': pins, 'uid': uid}
        data = json.dumps(contract, sort_keys=True).encode()
        (source / 'client-stage-inputs.json').write_bytes(data)
        attempted = True  # The unique name is tracked before Docker can create anything.
        cid = successful(container_command(args.image, name, source, public, uid, digest(data), args.guard_sha256, endpoint=endpoint), env=env).decode().strip()
        need(re.fullmatch(r'[0-9a-f]{64}', cid), 'container-id-invalid')
        inspected = decode(successful(daemon + ['inspect', cid], env=env))[0]
        inspect_container(inspected, args.image, source, public, uid)
        code, raw = bounded(daemon + ['start', '--attach', cid], timeout=TIMEOUT, limit=LIMIT, env=env)
        report['attach_bytes'], report['attach_sha256'] = len(raw), digest(raw)
        # Raw attach/test diagnostics are discarded and never projected publicly.
        worker_record = decode(read(public / 'worker-receipt.json'))
        validate_receipt(worker_record)
        need(worker_record['source_sha256'] == pins and worker_record['image_id'] == args.image
             and worker_record['packages_sha256'] == args.packages_sha256
             and worker_record['bootstrap_sha256'] == args.bootstrap_sha256
             and worker_record['uid'] == uid, 'worker-receipt-binding-mismatch')
        report['worker'] = worker_record
        report['native_client_tests'] = worker_record['native_client_tests']
        need(code == 0 and worker_record['status'] == 'PASS', 'native-worker-failed')
        need(worker_record['cleanup'] == {'processes': 'PASS', 'private_tmpfs': 'PASS'}, 'worker-cleanup-failed')
        inspected = decode(successful(daemon + ['inspect', cid], env=env))[0]
        inspect_container(inspected, args.image, source, public, uid)
        report['container_state'] = stopped_state(inspected)
        report['status'] = 'PASS'
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report['failure_category'] = type(error).__name__
    finally:
        with defer_signals():
            if attempted:
                report['container_cleanup'] = 'FAIL'
                try:
                    # A malformed create id must never become a Docker option/filter.
                    safe_id = cid if isinstance(cid, str) and re.fullmatch(r'[0-9a-f]{64}', cid) else None
                    remove_container(name, safe_id, env, endpoint=endpoint)
                    report['container_cleanup'] = 'PASS'
                except (ValueError, OSError, subprocess.SubprocessError):
                    report['status'] = 'FAIL'
            report['controller_tmp_removed'] = 'NOT RUN' if temp is None else 'FAIL'
            if temp is not None:
                try:
                    temp.cleanup()
                    need(not Path(temp.name).exists(), 'controller-temporary-removal-unconfirmed')
                    report['controller_tmp_removed'] = 'PASS'
                except (ValueError, OSError):
                    report['status'] = 'FAIL'
            if CANCELLED or report['container_cleanup'] != 'PASS' or report['controller_tmp_removed'] != 'PASS':
                report['status'] = 'FAIL'
            if CANCELLED:
                report['cancelled'] = True
            finalize_receipt(output / 'receipt.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    worker_cli = commands.add_parser('worker')
    for name in ('contract-sha256', 'guard-sha256'):
        worker_cli.add_argument('--' + name, required=True)
    controller = commands.add_parser('run')
    for name in ('image', 'bootstrap', 'bootstrap-sha256', 'packages', 'packages-sha256', 'source', 'stage-sha256', 'guard-sha256', 'output'):
        controller.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'worker':
            with cancellation_handlers():
                return worker(args)
        report = run_stage(args)
        print(json.dumps({'status': report['status'], 'native_client_tests': report['native_client_tests'],
                          'container_cleanup': report['container_cleanup']}))
        return 0 if report['status'] == 'PASS' else 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        print('FAIL: client stage boundary/input refusal', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
