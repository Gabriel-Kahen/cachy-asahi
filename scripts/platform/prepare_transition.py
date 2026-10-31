#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freshly authenticate a bound transition and prepare only a private ALPM DB.

Exit0 is private metadata preparation, never platform compatibility/installation.
Exit2 retains actual failed preparation; exit1 refuses incomplete/unverified data.
"""
import argparse
import atexit
import ctypes as C
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

# Fresh source cache before any project import: -B alone still permits old PYC reads.
sys.dont_write_bytecode = True
_source_cache = tempfile.TemporaryDirectory(prefix='private-platform-source-cache-', dir=os.environ.get('TMPDIR'))
sys.pycache_prefix = _source_cache.name
os.environ['PYTHONPYCACHEPREFIX'] = _source_cache.name
os.environ['TMPDIR'] = _source_cache.name
atexit.register(_source_cache.cleanup)
spec = importlib.util.spec_from_file_location('prepare_transition_planner', Path(__file__).with_name('platform_transition.py'))
p = importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
t, need, auth = p.transaction, p.need, p.recovery.auth
MAX_BYTES = 512 * 1024**2
SOURCE_FILES = (
    'scripts/platform/prepare_transition.py', 'scripts/platform/platform_transition.py',
    'scripts/platform/transaction.py', 'scripts/platform/recovery_preflight.py',
    'scripts/platform/tuple_audit.py', 'scripts/platform/recovery_inputs.py',
    'scripts/platform/authenticate_missing.py', 'scripts/platform/archive_coverage.py',
    'scripts/platform/capture.py', 'scripts/port/preview.py', 'scripts/port/authenticate.py',
    'scripts/ci/native_arm.py', 'scripts/checks/package_checks.py',
    'scripts/integration/lifecycle.py', 'scripts/release/compare_releases.py', 'scripts/release/release.py',
)


def runtime_sources(reference):
    need(Path(__file__).resolve() == (p.ROOT/'scripts/platform/prepare_transition.py').resolve()
         and Path(p.__file__).resolve() == (p.ROOT/'scripts/platform/platform_transition.py').resolve(),
         'executed source paths differ from bound runtime paths')
    pins = p.document(reference)
    need(set(pins) == {'schema_version', 'kind', 'files'} and type(pins['schema_version']) is int
         and pins['schema_version'] == 1 and pins['kind'] == 'private-platform-prepare-source-closure'
         and isinstance(pins['files'], dict) and set(pins['files']) == set(SOURCE_FILES),
         'whole private preparation source closure required')
    for name, pin in pins['files'].items():
        p.audit.read_bound(p.ROOT / name, pin)
    return pins['files']


def catalogue_record(name, row, archive):
    record = dict(row)
    filename = record.get('FILENAME', [f"{name}-{row['VERSION'][0]}-{row['ARCH'][0]}.pkg.tar.xz"])
    need(isinstance(filename, list) and len(filename) == 1 and filename[0] not in ('', '.', '..')
         and Path(filename[0]).name == filename[0], 'unsafe catalogue filename')
    record['FILENAME'] = filename
    for key, value in (('CSIZE', str(archive['size'])), ('SHA256SUM', archive['sha256'])):
        need(key not in record or record[key] == [value], 'archive/catalog pin mismatch: ' + name)
        record[key] = [value]
    return record


class PrepareAlpm(t.Alpm):
    # Reviewed installed16.0.1 alpm.h; deliberately no commit/download binding.
    SYMBOLS = t.Alpm.SYMBOLS | {
        'alpm_get_localdb': (C.c_void_p, [C.c_void_p]),
        'alpm_remove_pkg': (C.c_int, [C.c_void_p, C.c_void_p]),
    }


def private_parent(path):
    need(path.is_absolute() and '..' not in path.parts and not any(x.is_symlink() for x in (path, *path.parents)),
         'absolute output without symlink aliases required')
    info = path.parent.stat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700 and not path.exists(),
         'fresh output in owned mode0700 parent required')


def changes(before, after, old_archives, new_archives):
    return [name for name in sorted(set(before) | set(after))
            if p.preflight.semantic(before.get(name)) != p.preflight.semantic(after.get(name))
            or old_archives.get(name, {}).get('archive', {}).get('sha256') !=
               new_archives.get(name, {}).get('archive', {}).get('sha256')]


def prepare_metadata(work, before, candidate, changed):
    """Private engine for strict admission and explicitly inert fixture controls.

This function performs no authentication and cannot grant production admission.
It accepts only a fresh empty owned scratch directory, creates metadata only,
and never reads an installed database or package payload.
"""
    need(work.is_absolute() and work.name.startswith('private-platform-prepare-')
         and not any(x.is_symlink() for x in (work, *work.parents)), 'private scratch path refused')
    info = work.stat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700 and not list(work.iterdir()),
         'fresh empty owned mode0700 scratch required')
    before = p.audit.packages(list(before.values()));candidate = p.audit.packages(list(candidate.values()))
    need(isinstance(changed, list) and len(changed) == len(set(changed)) and set(changed) <= set(before) | set(candidate),
         'exact unique change roots required')
    for row in [*before.values(), *candidate.values()]:
        t.clean(row)
    for name in ('root', 'db/sync', 'gpg', 'cache', 'hooks'):
        (work / name).mkdir(parents=True, mode=0o700)
    t.preview.write_local(work / 'db/local', before)
    t.write_catalog(work / 'db/sync/transition.db', candidate)
    api, error, started = PrepareAlpm(), C.c_int(), False
    handle = api.alpm_initialize(os.fsencode(work/'root'), os.fsencode(work/'db'), C.byref(error))
    need(bool(handle), 'private ALPM initialize refused')
    questions, callback_errors, errors = [], [], []
    Callback = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p)

    @Callback
    def answer(context, pointer):
        try:
            question = C.cast(pointer, C.POINTER(t.Question)).contents
            question.answer = 0
            questions.append({'type': question.type, 'answer': 0, 'policy': 'deny-unapproved-question'})
        except Exception as exc:
            callback_errors.append(str(exc)[:1000])

    try:
        for function, value in ((api.alpm_option_add_architecture, b'aarch64'),
                                (api.alpm_option_set_logfile, os.fsencode(work/'alpm.log')),
                                (api.alpm_option_set_gpgdir, os.fsencode(work/'gpg')),
                                (api.alpm_option_add_cachedir, os.fsencode(work/'cache')),
                                (api.alpm_option_add_hookdir, os.fsencode(work/'hooks'))):
            need(function(handle, value) == 0, 'private ALPM option refused')
        need(api.alpm_option_set_questioncb(handle, C.cast(answer, C.c_void_p), None) == 0,
             'private ALPM callback refused')
        local = api.alpm_get_localdb(handle)
        sync = api.alpm_register_syncdb(handle, b'transition', 0)
        need(bool(local) and bool(sync), 'private ALPM database registration refused')
        # NOLOCK|NOSCRIPTLET|NOHOOKS. NEEDED deliberately absent: explicit reinstallation works.
        flags = (1 << 17) | (1 << 10) | (1 << 7)
        need(api.alpm_trans_init(handle, flags) == 0, 'private ALPM transaction init refused')
        started = True
        for name in changed:
            database = sync if name in candidate else local
            package = api.alpm_db_get_pkg(database, name.encode())
            need(bool(package), 'exact changed root missing from private DB: ' + name)
            wanted = candidate[name] if name in candidate else before[name]
            need(api.alpm_pkg_get_version(package).decode() == wanted['VERSION'][0], 'private root version drift')
            result = api.alpm_add_pkg(handle, package) if name in candidate else api.alpm_remove_pkg(handle, package)
            if result:
                code = api.alpm_errno(handle)
                errors.append({'kind': 'root-request-error', 'package': name, 'errno': code,
                               'diagnostic': api.alpm_strerror(code).decode()})
        details = t.Ptr()
        result = api.alpm_trans_prepare(handle, C.byref(details))
        code = api.alpm_errno(handle) if result else 0
        try:
            for pointer in t.pointers(details):
                if code == 45:
                    missing = C.cast(pointer, C.POINTER(t.Missing)).contents
                    errors.append({'kind': 'unsatisfied-dependency', 'package': missing.target.decode(),
                                   'requires': api.dependency(missing.depend),
                                   'causing_package': missing.causingpkg.decode() if missing.causingpkg else None})
                    api.alpm_depmissing_free(pointer)
                elif code == 46:
                    conflict = C.cast(pointer, C.POINTER(t.Conflict)).contents
                    errors.append({'kind': 'package-conflict', 'package1': api.package(conflict.package1),
                                   'package2': api.package(conflict.package2), 'reason': api.dependency(conflict.reason)})
                    api.alpm_conflict_free(pointer)
                else:
                    errors.append({'kind': 'unparsed-prepare-error', 'errno': code})
        finally:
            api.alpm_list_free(details)
        add = [api.package(value) for value in t.pointers(api.alpm_trans_get_add(handle))]
        remove = [api.package(value) for value in t.pointers(api.alpm_trans_get_remove(handle))]
        final = dict(before)
        for row in remove:
            final.pop(row['name'], None)
        for row in add:
            need(row['repo'] == 'transition' and candidate.get(row['name'], {}).get('VERSION') == [row['version']],
                 'unapproved actual addition/provider')
            final[row['name']] = candidate[row['name']]
        expected_add = {n for n in changed if n in candidate}
        expected_remove = {n for n in changed if n not in candidate}
        mismatch = [n for n in sorted(set(final) | set(candidate))
                    if p.preflight.semantic(final.get(n)) != p.preflight.semantic(candidate.get(n))]
        exact = not mismatch and {r['name'] for r in add} == expected_add and {r['name'] for r in remove} == expected_remove
        need(not list((work/'root').rglob('*')), 'private root unexpectedly contains payload')
        passed = result == 0 and not (errors or questions or callback_errors) and exact
        return {'status': 'PASS-private-metadata-prepare' if passed else 'FAIL-private-metadata-prepare',
                'scope': 'host-private-metadata-only', 'private_paths': {'root': str(work/'root'), 'database': str(work/'db')}, 'libalpm_version': api.version, 'flags': flags,
                'prepare_exit': result, 'prepare_errno': code, 'prepare_diagnostic': api.alpm_strerror(code).decode(),
                'add': add, 'remove': remove, 'errors': errors, 'questions': questions,
                'callback_errors': callback_errors, 'final_candidate_exact': exact,
                'final_metadata_mismatches': mismatch, 'commit_called': False, 'hooks_run': False,
                'host_database_used': False, 'package_authentication_performed': False,
                'production_admitted': False, 'hardware_accepted': False}
    finally:
        if started:
            api.alpm_trans_release(handle)
        api.alpm_release(handle)


def worker(work, before, candidate, changed):
    request = json.dumps({'work': str(work), 'before': before, 'candidate': candidate, 'changed': changed}).encode()
    need(len(request) <= 8 * p.recovery.MIB, 'prepare worker input bound exceeded')
    try:
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--prepare-worker'],
                                input=request, capture_output=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError('private ALPM prepare deadline exceeded') from None
    need(result.returncode == 0 and not result.stderr and len(result.stdout) <= 8 * p.recovery.MIB,
         'bounded private ALPM worker refused')
    return p.audit.load_json(result.stdout)


def authenticate(joins, certificates, work):
    verified, copied, total = {}, {}, 0
    started = time.monotonic()
    for side, packages in joins.items():
        for name, binding in sorted(packages.items()):
            need(time.monotonic() - started <= 300, 'authentication assessment deadline exceeded')
            claim = binding['retained_signature_claim'];signer = claim['primary_fingerprint']
            labels = [label for label, values in auth.KEYS.items() if values[0] == signer]
            need(len(labels) == 1 and labels[0] in certificates, 'pinned certificate required for every package')
            label = labels[0];certificate = certificates[label]
            need(certificate['sha256'] == auth.KEYS[label][1], 'certificate pin refused')
            cert_bytes = auth.bound_bytes(certificate, p.recovery.MIB)
            cert_path = work / (label + '.gpg')
            if not cert_path.exists():
                t.write_bytes(cert_path, cert_bytes)
            refs = [binding['archive'], binding['signature']]
            key = p.digest({'archive': refs[0], 'signature': refs[1], 'certificate': certificate})
            if key not in copied:
                targets = []
                for field, ref, maximum in zip(('archive', 'signature'), refs, (300_000_000, 65536)):
                    total += ref['size'];need(total <= MAX_BYTES, 'aggregate authenticated bytes exceeded')
                    data = auth.bound_bytes(ref, maximum);path = work / (key + '.' + field)
                    t.write_bytes(path, data);targets.append(path)
                verification, observation = auth.verify(work, cert_path, *targets, signer)
                copied[key] = {'archive': refs[0], 'signature': refs[1], 'certificate': certificate,
                               'verification': verification, 'observation': observation}
            verified.setdefault(side, {})[name] = dict(copied[key], provenance=binding['provenance'])
    return verified


def run(contract, output):
    need(set(contract) == {'schema_version', 'transition_contract', 'transition_report', 'certificates', 'runtime_sources'}
         and type(contract['schema_version']) is int and contract['schema_version'] == 1,
         'private preparation contract refused')
    private_parent(output)
    all_source_pins = runtime_sources(contract['runtime_sources'])
    source = p.document(contract['transition_contract']);retained = p.document(contract['transition_report'])
    need(retained.get('contract_sha256') == contract['transition_contract']['sha256'], 'plan/contract digest binding refused')
    fresh = p.run(source)
    def body(report):
        return {key: value for key, value in report.items() if key not in ('source_sha256', 'contract_sha256')}
    need(body(fresh) == body(retained), 'retained plan differs from exact fresh assessment')
    need(fresh['status'] == 'PASS-offline-data-plan' and fresh['software_data_bound'] is True
         and not fresh['conditions'], 'fully bound compatible data plan required')
    # Path relocation is allowed; source bytes are not. Require all recorded direct helper hashes.
    expected = {Path(name).name: pin for name, pin in fresh['source_sha256'].items()}
    observed = {Path(name).name: pin for name, pin in retained['source_sha256'].items()}
    need(len(observed) == len(retained['source_sha256']) and observed == expected, 'plan source pin mismatch')
    before, candidate = p.inventory(source['before_release']), p.inventory(source['candidate_release'])
    joins = fresh['archive_provenance_joins']
    need(set(joins['before']) == set(before) and set(joins['candidate']) == set(candidate),
         'complete before/candidate archive and provider coverage required')
    certs = contract['certificates']
    need(isinstance(certs, dict) and set(certs) <= set(auth.KEYS), 'certificate labels refused')
    roots = changes(before, candidate, joins['before'], joins['candidate'])
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='private-platform-auth-', dir=output.parent) as scratch:
        authentication = authenticate(joins, certs, Path(scratch))
        need(time.monotonic() - started <= 300, 'authentication assessment deadline exceeded')
    catalogs = {name: catalogue_record(name, row, joins['candidate'][name]['archive'])
                for name, row in candidate.items()}
    with tempfile.TemporaryDirectory(prefix='private-platform-prepare-', dir=output.parent) as scratch:
        actual = worker(Path(scratch), before, catalogs, roots)
    need(runtime_sources(contract['runtime_sources']) == all_source_pins, 'runtime sources changed during preparation')
    report = {'schema_version': 1, 'kind': 'authenticated-private-platform-transition-prepare',
              'status': actual['status'], 'all_required_package_signatures_freshly_verified': True, 'input_references': contract, 'before_release': source['before_release'],
              'candidate_release': source['candidate_release'], 'protected_tuple': source['protected_tuple'],
              'coordinated_policy': source['coordinated_policy'], 'retained_recovery_assets': source['retained_recovery_assets'],
              'source_sha256': all_source_pins,
              'fresh_package_signature_verification': authentication, 'changed_roots': roots,
              'transaction': actual, 'private_workspace_removed': True, 'commit_called': False,
              'host_database_used': False, 'installation_accepted': False, 'hardware_accepted': False,
              'dependency_transaction_accepted': False, 'recovery_accepted': False, 'production_admitted': False,
              'limitations': ['Fresh cryptographic verification is not independent owner trust or installed-byte correspondence.',
                             'Private metadata preparation checks dependency/package conflicts, not payload/file conflicts, hooks or ABI.',
                             'Boot, firmware, audio/protection and M2 recovery compatibility remain NOT RUN.']}
    p.audit.write_private(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, required=True);parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True);args = parser.parse_args()
    try:
        contract = p.audit.load_json(p.audit.read_bound(args.contract, args.contract_sha256))
        report = run(contract, args.output)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError, EOFError) as error:
        parser.exit(1, 'private platform preparation refused: ' + str(error) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(args.output), 'hardware_accepted': False}))
    return 0 if report['status'] == 'PASS-private-metadata-prepare' else 2


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare-worker']:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * p.recovery.MIB, 512 * p.recovery.MIB))
        resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
        try:
            raw = sys.stdin.buffer.read(8 * p.recovery.MIB + 1)
            need(len(raw) <= 8 * p.recovery.MIB, 'prepare worker input bound')
            request = p.audit.load_json(raw)
            result = prepare_metadata(Path(request['work']), request['before'], request['candidate'], request['changed'])
            encoded = json.dumps(result).encode();need(len(encoded) <= 8 * p.recovery.MIB, 'prepare worker output bound')
            sys.stdout.buffer.write(encoded)
        except Exception:
            raise SystemExit(1)
        raise SystemExit(0)
    raise SystemExit(main())
