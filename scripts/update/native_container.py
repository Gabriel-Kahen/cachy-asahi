#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the existing 39 tiny checks directly in the owned native ARM container."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import unittest


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def guard():
    need(os.getuid() == os.geteuid() == 0 and os.uname().machine == 'aarch64'
         and Path('/.dockerenv').is_file(), 'native root container required')
    need(re.fullmatch('[0-9a-f]{32}', os.environ.get('CACHY_ASAHI_BOUND_UPDATE', '')),
         'explicit owned container marker required')
    need(os.environ.get('PATH') == '/usr/bin:/bin' and os.environ.get('HOME') == '/tmp/home'
         and os.environ.get('TMPDIR') == '/tmp', 'private container environment required')
    interfaces = {line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
    need(interfaces == {'lo'}, 'network-none container required')
    mounts = {row.split()[4]: row.split()[5].split(',') for row in Path('/proc/self/mountinfo').read_text().splitlines()}
    need('ro' in mounts.get('/source', []) and 'rw' in mounts.get('/workspace', [])
         and 'ro' in mounts.get('/', []) and '/tmp' in mounts, 'isolated source/workspace mounts required')
    Path('/tmp/home').mkdir(mode=0o700, exist_ok=True)


def load(name):
    path = Path('/source/scripts/update') / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


SCALE_DRIFT_TEST = 'test_scale_update.ScaleTransactions.test_scale_input_drift_after_prepare_refused'
SCALE_DRIFT_STAGES = {'invoke','child-exit','child-output-size','child-json','trust-stable',
    'package-lock-absent','workspace-clean','refusal-status','commit-not-started','checkpoint-unchanged',
    'fixture-unchanged','checkpoint-empty','scale-error-match','complete'}
SCALE_DRIFT_PHASES = {'configuration','checkpoint-lock','package-manager-lock','observe-before','prepare',
    'commit','observe-after','checkpoint','completed','scale-reporting','scale-configuration','worker'}
SCALE_DRIFT_ERRORS = {'ValueError','Invalid','OSError','TimeoutError','RuntimeError','AssertionError','Error','KeyboardInterrupt'}
SCALE_DRIFT_REASONS = {'scale configuration changed':'SCALE_DRIFT',
    'root observation deadline':'ROOT_DEADLINE','archive deadline exhausted':'ARCHIVE_DEADLINE',
    'insufficient or unknown filesystem free inode count':'CAPACITY_INODES',
    'insufficient future transaction bytes/inodes':'CAPACITY_FUTURE',
    # Runtime.tree wraps observation failures; retain the known deadline label.
    'unsupported root observation: root observation deadline':'ROOT_DEADLINE',
    'release exceeds tiny-root package limit':'PREPARE_PACKAGE_LIMIT',
    'aggregate package inputs exceed tiny-root limit':'PREPARE_INPUT_LIMIT',
    'archive exceeds tiny-root caller limit':'PREPARE_ARCHIVE_LIMIT',
    'package writes protected platform/trust path':'PREPARE_PROTECTED_PATH',
    'package writes protected service':'PREPARE_PROTECTED_SERVICE',
    'package payload overlap':'PREPARE_PAYLOAD_OVERLAP',
    'loaded package identity differs':'PREPARE_PACKAGE_IDENTITY',
    'selected package writes actual protected ownership':'PREPARE_PROTECTED_OWNERSHIP',
    'prepared add inventory differs':'PREPARED_ADD',
    'prepared remove inventory differs':'PREPARED_REMOVE',
    'base trust changed before commit':'PRECOMMIT_BASE_TRUST',
    'protected payload changed before commit':'PRECOMMIT_PROTECTED_PAYLOAD',
    'update configuration changed':'PRECOMMIT_UPDATE_CONFIGURATION',
    'original bundle drifted':'SNAPSHOT_SOURCE_BUNDLE',
    'original input identity drifted':'SNAPSHOT_SOURCE_IDENTITY',
    'original input bytes drifted':'SNAPSHOT_SOURCE_BYTES',
    'authenticated snapshot drifted':'SNAPSHOT_AUTHENTICATED',
    'authenticated result changed':'SNAPSHOT_RESULT',
    'metadata is expired or issued in the future':'METADATA_TIME',
    'projected node limit':'PROJECTED_NODES',
    'projected depth limit':'PROJECTED_DEPTH',
    'unsupported projected shape':'PROJECTED_SHAPE',
    'projected file byte limit':'PROJECTED_FILE_BYTES',
    'projected file content observation missing':'PROJECTED_FILE_OBSERVATION',
    'invalid projected symlink':'PROJECTED_SYMLINK',
    'projected byte limit':'PROJECTED_BYTES',
    'unaudited auxiliary executable or alias refused':'PROJECTED_AUXILIARY',
    'platform policy release mismatch':'PLATFORM_RELEASE',
    'complete bounded protected inventory required':'PLATFORM_INVENTORY',
    'protected package change refused':'PLATFORM_CHANGE',
    'protected kernel ownership change refused':'PLATFORM_KERNEL_OWNERSHIP',
    'platform transition release evidence mismatch':'PLATFORM_RELEASE_EVIDENCE',
    'platform transition validation absent from signed release':'PLATFORM_VALIDATION_EVIDENCE'}
# These prefixes are composed by the existing Alpm.ok / Runtime.tree / authorize
# calls. Export only the call-site label, never their runtime suffix or operands.
SCALE_DRIFT_PREPARE_PREFIXES = (('signed package load: ','ALPM_SIGNED_LOAD'),
    ('add authenticated package: ','ALPM_ADD'),('prepare immutable transaction: ','ALPM_PREPARE'),
    ('unsupported root observation: ','ROOT_OBSERVATION'),('platform policy refused: ','PLATFORM_POLICY'))


# Exact alpm_strerror messages at upstream54d94116164b0b2202c6061c4a59c6f3e70820d8.
# All fixed strings occur in the pinned native16.0.1 ELF. One source message
# aliases two enum names; retain both rather than infer an unavailable errno.
ALPM_LOAD_ERRNOS = {
    'out of memory!':'ALPM_ERR_MEMORY',
    'unexpected system error':'ALPM_ERR_SYSTEM',
    'permission denied':'ALPM_ERR_BADPERMS',
    'could not find or read file':'ALPM_ERR_NOT_A_FILE',
    'could not find or read directory':'ALPM_ERR_NOT_A_DIR',
    'wrong or NULL argument passed':'ALPM_ERR_WRONG_ARGS',
    'not enough free disk space':'ALPM_ERR_DISK_SPACE',
    'library not initialized':'ALPM_ERR_HANDLE_NULL',
    'library already initialized':'ALPM_ERR_HANDLE_NOT_NULL',
    'unable to lock database':'ALPM_ERR_HANDLE_LOCK',
    'could not open database':'ALPM_ERR_DB_OPEN',
    'could not create database':'ALPM_ERR_DB_CREATE',
    'database not initialized':'ALPM_ERR_DB_NULL',
    'database already registered':'ALPM_ERR_DB_NOT_NULL',
    'could not find database':'ALPM_ERR_DB_NOT_FOUND',
    'invalid or corrupted database':'ALPM_ERR_DB_INVALID',
    'invalid or corrupted database (PGP signature)':'ALPM_ERR_DB_INVALID_SIG',
    'database is incorrect version':'ALPM_ERR_DB_VERSION',
    'could not update database':'ALPM_ERR_DB_WRITE',
    'could not remove database entry':'ALPM_ERR_DB_REMOVE',
    'invalid url for server':'ALPM_ERR_SERVER_BAD_URL',
    'no servers configured for repository':'ALPM_ERR_SERVER_NONE',
    'transaction already initialized':'ALPM_ERR_TRANS_NOT_NULL',
    'transaction not initialized':'ALPM_ERR_TRANS_NULL|ALPM_ERR_TRANS_NOT_INITIALIZED',
    'duplicate target':'ALPM_ERR_TRANS_DUP_TARGET',
    'duplicate filename':'ALPM_ERR_TRANS_DUP_FILENAME',
    'transaction not prepared':'ALPM_ERR_TRANS_NOT_PREPARED',
    'transaction aborted':'ALPM_ERR_TRANS_ABORT',
    'operation not compatible with the transaction type':'ALPM_ERR_TRANS_TYPE',
    'transaction commit attempt when database is not locked':'ALPM_ERR_TRANS_NOT_LOCKED',
    'failed to run transaction hooks':'ALPM_ERR_TRANS_HOOK_FAILED',
    'could not find or read package':'ALPM_ERR_PKG_NOT_FOUND',
    'operation cancelled due to ignorepkg':'ALPM_ERR_PKG_IGNORED',
    'invalid or corrupted package':'ALPM_ERR_PKG_INVALID',
    'invalid or corrupted package (checksum)':'ALPM_ERR_PKG_INVALID_CHECKSUM',
    'invalid or corrupted package (PGP signature)':'ALPM_ERR_PKG_INVALID_SIG',
    'package missing required signature':'ALPM_ERR_PKG_MISSING_SIG',
    'cannot open package file':'ALPM_ERR_PKG_OPEN',
    'cannot remove all files for package':'ALPM_ERR_PKG_CANT_REMOVE',
    'package filename is not valid':'ALPM_ERR_PKG_INVALID_NAME',
    'package architecture is not valid':'ALPM_ERR_PKG_INVALID_ARCH',
    'missing PGP signature':'ALPM_ERR_SIG_MISSING',
    'invalid PGP signature':'ALPM_ERR_SIG_INVALID',
    'could not satisfy dependencies':'ALPM_ERR_UNSATISFIED_DEPS',
    'conflicting dependencies':'ALPM_ERR_CONFLICTING_DEPS',
    'conflicting files':'ALPM_ERR_FILE_CONFLICTS',
    'failed to initialize download':'ALPM_ERR_RETRIEVE_PREPARE',
    'failed to retrieve some files':'ALPM_ERR_RETRIEVE',
    'invalid regular expression':'ALPM_ERR_INVALID_REGEX',
    'libarchive error':'ALPM_ERR_LIBARCHIVE',
    'download library error':'ALPM_ERR_LIBCURL',
    'gpgme error':'ALPM_ERR_GPGME',
    'error invoking external downloader':'ALPM_ERR_EXTERNAL_DOWNLOAD',
    'compiled without signature support':'ALPM_ERR_MISSING_CAPABILITY_SIGNATURES',
    'unexpected error':'ALPM_STRERROR_DEFAULT',
}


SCALE_SIGNATURE_STATUS = {'NEWSIG','KEY_CONSIDERED','SIG_ID','GOODSIG','VALIDSIG','BADSIG','ERRSIG','NO_PUBKEY',
    'EXPSIG','EXPKEYSIG','REVKEYSIG','TRUST_UNDEFINED','TRUST_NEVER','TRUST_MARGINAL','TRUST_FULLY',
    'TRUST_ULTIMATE','NODATA','FAILURE','ERROR','UNEXPECTED','KEYEXPIRED','SIGEXPIRED','KEYREVOKED'}


def scale_drift_diagnostic(test):
    """Project only this fixture's fixed labels/facts; never its raw result/error."""
    if test.id() != SCALE_DRIFT_TEST:return None
    raw=getattr(test,'_scale_drift_diagnostic',None)
    raw=raw if type(raw) is dict else {}
    row=raw.get('row');row=row if type(row) is dict else {}
    def label(value,allowed):
        return value if type(value) is str and value in allowed else 'OTHER' if value is not None else 'UNAVAILABLE'
    def fact(value):
        return value if type(value) is bool or type(value) is str and value == 'UNKNOWN' else 'UNAVAILABLE'
    error=row.get('error')
    category='UNAVAILABLE'
    if type(error) is str:
        category=SCALE_DRIFT_REASONS.get(error)
        if category is None:
            category=next((label for prefix,label in SCALE_DRIFT_PREPARE_PREFIXES if error.startswith(prefix)),'OTHER')
    alpm_errno='UNAVAILABLE'
    if type(error) is str and error.startswith('signed package load: '):
        alpm_errno=ALPM_LOAD_ERRNOS.get(error[len('signed package load: '):],'UNRECOGNIZED')
    probe=row.get('test_scale_post_load_signature');probe=probe if type(probe) is dict else {}
    statuses=probe.get('gpg_status')
    statuses=(sorted(set(statuses)) if type(statuses) is list and len(statuses)<=len(SCALE_SIGNATURE_STATUS)
              and all(type(tag) is str and tag in SCALE_SIGNATURE_STATUS for tag in statuses) else [])
    gpg_exit=probe.get('gpg_exit')
    gpg_exit=(gpg_exit if type(gpg_exit) is int and gpg_exit in (0,1,2) or
              type(gpg_exit) is str and gpg_exit in {'OTHER','TIMEOUT','UNAVAILABLE'} else 'UNAVAILABLE')
    signature_probe=dict(state=label(probe.get('state'),{'NOT_RUN','STARTED','INPUT_REFUSED','OUTPUT_BOUND',
        'OBSERVED','TIMEOUT','DIAGNOSTIC_ERROR'}),gpg_exit=gpg_exit,gpg_status=statuses,
        unknown_status=fact(probe.get('unknown_status')),archive_equal=fact(probe.get('archive_equal')),
        signature_equal=fact(probe.get('signature_equal')),inputs_stable=fact(probe.get('inputs_stable')))
    return dict(stage=label(raw.get('stage'),SCALE_DRIFT_STAGES),
        status=label(row.get('status'),{'PASS','FAIL'}),phase=label(row.get('phase'),SCALE_DRIFT_PHASES),
        error_type=label(row.get('error_type'),SCALE_DRIFT_ERRORS),
        error_category=category,alpm_errno=alpm_errno,post_load_signature=signature_probe,
        commit_started=fact(row.get('commit_started')),packages_committed=fact(row.get('packages_committed')),
        checkpoint_changed=fact(row.get('checkpoint_changed')),callback_reached=fact(row.get('test_scale_precommit_reached')))


class Results(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.lines = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.lines.append(test.id() + ' PASS')

    def addFailure(self, test, error):
        super().addFailure(test, error)
        line=test.id() + ' FAIL ' + error[0].__name__
        diagnostic=scale_drift_diagnostic(test)
        if diagnostic is not None:line += ' ' + json.dumps(diagnostic,sort_keys=True,separators=(',',':'))
        self.lines.append(line)

    def addError(self, test, error):
        super().addError(test, error)
        self.lines.append(test.id() + ' ERROR ' + error[0].__name__)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.lines.append(test.id() + ' SKIP')


def main():
    record = dict(status='FAIL', architecture=os.uname().machine, tests=0, failures=0, errors=0, skips=0,
                  production='NOT ESTABLISHED', full587='NOT RUN', hardware='NOT RUN', fixture_architecture='any')
    result = Results()
    authorized = False
    try:
        guard()
        authorized = True
        need(sys.argv[1:] in ([], ['--scale-fixtures']), 'unknown fixture selection')
        scaled = sys.argv[1:] == ['--scale-fixtures']
        selected = [('test_snapshot', 10), ('test_platform_policy', 10), ('test_bound_update', 19)]
        if scaled:
            selected += [('test_archive_stream', 20), ('test_full_root', 12), ('test_capacity', 4),
                         ('test_supervision', 6), ('test_measure_copy', 5), ('test_generic_policy', 6),
                         ('test_scale_update', 14)]
        expected = sum(count for _, count in selected)
        record['fixture_suite'] = 'synthetic-scale-and-tiny' if scaled else 'tiny'
        sys.path.insert(0, '/source/scripts/update')
        library = Path('/usr/lib/libalpm.so.16.0.1')
        record['libalpm_sha256'] = hashlib.sha256(library.read_bytes()).hexdigest()
        worker = load('bound_update')
        need(record['libalpm_sha256'] == worker.install.NATIVE_LIBRARY_SHA, 'native libalpm pin differs')
        suite = unittest.TestSuite()
        for name, count in selected:
            tests = unittest.defaultTestLoader.loadTestsFromModule(load(name))
            need(tests.countTestCases() == count, 'existing suite case count differs')
            suite.addTests(tests)
        suite.run(result)
        record.update(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors), skips=len(result.skipped))
        need(result.wasSuccessful() and result.testsRun == expected and not result.skipped, 'native fixture suite failed')
        record['status'] = 'PASS'
    except BaseException as error:
        record['error_type'] = type(error).__name__
    # Only fixed, bounded schemas and test identifiers leave the container; no traceback/key material.
    if not authorized:
        return 1
    output = Path('/workspace')
    lines = '\n'.join(result.lines) + '\n'
    need(len(lines.encode()) <= 32768, 'sanitized test log bound')
    (output / 'tests.log').write_text(lines)
    (output / 'result.json').write_text(json.dumps(record, sort_keys=True) + '\n')
    return int(record['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
