# SPDX-License-Identifier: MIT
"""Future publication proof, public retained DATA transport and eight-input seed.

No phase invokes a compiler, GPG, ALPM or Docker. Construction never calls these
phases. Full carrier authentication and signed native admission remain owner work.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import binding, input_contract, load, need, pin, read, save, source_bytes, verify_source

PROFILE = '4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
CARRIER_SOURCE = 'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def identity(info):
    return {name: getattr(info, name) for name in FIELDS}


def ordinary_directory(path, private=False):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary directory ancestry')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and (stat.S_IMODE(info.st_mode) == 0o700 if private else not info.st_mode & 0o022),
         'existing owned directory with required permissions: ' + str(path))


def admit(root, args, phase):
    verify_source(root, args.map_sha256)
    profile, _, _ = input_contract(root)
    own = binding(args.source_sha, args.ref, args.run_id, os.environ)
    need((phase == 'cache' or args.execute) and platform.system() == 'Linux'
         and platform.machine() in ('aarch64', 'arm64') and os.getuid() == os.geteuid() != 0
         and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ARCH') == 'ARM64'
         and os.environ.get('RUNNER_OS') == 'Linux', 'explicit same-source unprivileged native ARM workflow required')
    need(not any(k.startswith(('GIT_', 'LD_', 'DOCKER_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_'))
                 for k in os.environ), 'ambient Git/loader/daemon/private transport overrides refused')
    temp = Path(os.environ['RUNNER_TEMP']).absolute()
    ordinary_directory(temp)
    need(args.work == temp / 'native-developer-work' and args.cache == temp / 'alarm-cache'
         and args.carrier == temp / 'pgo-hosted-retained' and not temp.is_relative_to(root)
         and not root.is_relative_to(temp), 'fixed external work/cache/full-carrier paths')
    need(not any(p.is_symlink() for p in (root, *root.parents, args.work, args.cache, args.carrier)), 'no input/output aliases')
    return own, profile


def basis(root):
    path = root / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py'
    spec = importlib.util.spec_from_file_location('_provision_sealed_pgo102', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def git_environment(home):
    """Public DATA transport never inherits credentials or Git configuration."""
    previous = dict(os.environ)
    os.environ.clear()
    os.environ.update(PATH=os.defpath, HOME=str(home), LANG='C', LC_ALL='C',
        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_NO_REPLACE_OBJECTS='1',
        GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    try:
        yield
    finally:
        os.environ.clear(); os.environ.update(previous)


def actor_logs(actor, work):
    for row in actor.rows:
        path = Path(row['log'])
        need(path.is_relative_to(work), 'owned actor log path')
        row.update(retained_log=str(path.relative_to(work)), log_pin=pin(read(path)))
    return actor.rows


def retired(rows, work):
    need(bool(rows), 'actual proof/transport actors required')
    for row in rows:
        relative = Path(row['retained_log'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'retained actor log path')
        need(row['status'] == 'PASS' and row['exit'] == 0 and row['natural_exit'] is True
             and row['group_absent'] is True and row['retirement'] == 'REAPED'
             and row['ownership_lost'] is False and row['forced_cleanup'] is False
             and row['exit_observed_via_waitpid'] is True and row['leader_held_until_group_inspection'] is True
             and pin(read(work / relative)) == row['log_pin'], 'same-owner direct wait and retained output required')


def receipt_base(root, args, own):
    return dict(schema=1, binding=own, source_map_sha256=args.map_sha256, source_root=str(root),
                work=str(args.work), cache=str(args.cache), carrier_path=str(args.carrier),
                native='NOT_RUN', GPG='NOT_RUN', ALPM='NOT_RUN', acceptance=False,
                physical_M2='NOT_RUN', release='NOT_ADMITTED')


def prior_proof(root, args, own):
    ordinary_directory(args.work, private=True)
    ordinary_directory(args.work / 'home', private=True)
    proof = load(args.work / 'proof.json')
    expected = receipt_base(root, args, own)
    need(all(proof.get(k) == value for k, value in expected.items())
         and proof['status'] == 'PASS_EXACT_PUBLISHED_SOURCE_PROOF_ONLY', 'exact prior same-source publication proof')
    manifest = load(root / 'native/source-map.json')
    need(set(proof['files']) == set(manifest['files']) | {'native/source-map.json'}, 'complete prior proof membership')
    for name, row in proof['files'].items():
        body = source_bytes(root, name)
        need(pin(body) == {k: row[k] for k in ('bytes', 'sha256')}
             and row['blob'] == hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
             and row['mode'] == ('100755' if (root / name).stat().st_mode & 0o111 else '100644'), 'prior proof byte/mode drift')
    retired(proof['actors'], args.work)
    return proof


def carrier_profile(root):
    raw = read(root / 'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json')
    need(pin(raw)['sha256'] == PROFILE, 'whole original full-carrier profile')
    profile = json.loads(raw)
    need(profile['source'] == CARRIER_SOURCE and profile['actual'] is None
         and len(profile['files']) == 1154 and sum(r['bytes'] for r in profile['files'].values()) == 1046432165,
         'original1154 complete retained DATA carrier')
    return profile


def proof(root, args):
    own, _ = admit(root, args, 'proof')
    need(not os.path.lexists(args.work), 'fresh one-shot publication proof workspace')
    args.work.mkdir(mode=0o700); (args.work / 'home').mkdir(mode=0o700)
    need((root / '.git').is_dir() and not (root / '.git').is_symlink(), 'explicit ordinary publication Git directory')
    actor = basis(root).Actors(args.work / 'proof-actors', 120)
    report = dict(receipt_base(root, args, own), status='FAIL_PUBLICATION_PROOF', files={})
    try:
        with git_environment(args.work / 'home'):
            git = ['/usr/bin/git', '--no-replace-objects', '--git-dir=' + str(root / '.git'),
                   '--work-tree=' + str(root), '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false']
            head = actor.run([*git, 'rev-parse', '--verify', 'HEAD'], timeout=15)
            need(head == own['source'], 'same published source HEAD')
            tree = actor.run([*git, 'ls-tree', '-rz', '--full-tree', own['source']], timeout=30)
            for value in tree.split('\0'):
                if not value:
                    continue
                metadata, name = value.split('\t', 1); mode, kind, digest = metadata.split()
                relative = Path(name)
                need(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name
                     and name not in report['files'] and kind == 'blob' and mode in ('100644', '100755'), 'ordinary unique published Git leaf')
                body = source_bytes(root, name)
                need(mode == ('100755' if (root / name).stat().st_mode & 0o111 else '100644')
                     and digest == hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest(), 'published Git blob/filesystem/mode join')
                report['files'][name] = dict(mode=mode, blob=digest, **pin(body))
            need(set(report['files']) == set(load(root / 'native/source-map.json')['files']) | {'native/source-map.json'}, 'complete closed published Git membership')
        report['status'] = 'PASS_EXACT_PUBLISHED_SOURCE_PROOF_ONLY'
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        raise
    finally:
        report['actors'] = actor_logs(actor, args.work)
        save(args.work / 'proof.json', report)
    return report


def transport(root, args):
    own, _ = admit(root, args, 'transport')
    prior_proof(root, args, own)
    ordinary_directory(args.cache, private=True)
    need(not os.path.lexists(args.carrier) and not (args.work / 'input-transport-owner.json').exists(), 'fresh one-shot full-carrier transport; no retry')
    profile = carrier_profile(root)
    profile_raw = read(root / 'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json')
    evidence = args.work / 'retained-transport-evidence'
    report = dict(receipt_base(root, args, own), status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',
        role='RETAINED_INPUT_TRANSPORT_DATA', carrier_source=CARRIER_SOURCE, profile_sha256=PROFILE,
        expected_carrier_files=1154, expected_carrier_bytes=1046432165, budget_seconds=480,
        retry=False, partial_data_retained=True, actors=[], canonical_transport=None,
        full_carrier_proof='DEFERRED_TO_OWNER_PREPARE_NATIVE248',
        authentication='ORIGINAL_FULL_CARRIER_PREPARE_AND_NATIVE_SIGNATURE_AUDIT_REQUIRED')
    original_error = None; deadline = time.monotonic() + 480
    try:
        from retained_transport import deliver
        result = deliver(root, args.carrier, evidence, profile_raw, PROFILE)
        report['canonical_transport'] = result
        need(result['status'] == 'PASS_EXACT_RETAINED_GIT_DATA_ONLY', 'complete exact carrier delivery required')
        from transport_proof import export
        report['transport_proof'] = export(args.work, own, args.map_sha256, result, profile)
        need(time.monotonic() < deadline, 'original480 transport envelope exhausted')
        report.update(status='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY', carrier_head=CARRIER_SOURCE)
    except BaseException as error:
        original_error = error
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        if report['canonical_transport'] is None:
            try:
                report['canonical_transport'] = load(evidence / 'receipt.json')
            except Exception:
                pass
        raise
    finally:
        try:
            from transport_retention import retain
            report['transport_diagnostic'] = retain(args.work, own, args.map_sha256,
                report['canonical_transport'], original_error)
        except Exception:
            report['transport_diagnostic'] = dict(status='REFUSED_TRANSPORT_DIAGNOSTIC_INTERNAL')
        save(args.work / 'input-transport-owner.json', report)
    return report


def transport_retired(phase, work, profile, own, map_hash):
    """Canonical owned-process supervision, never fabricated PGO actor fields."""
    need(phase['binding'] == own and phase['source_map_sha256'] == map_hash
         and phase['actors'] == [] and phase['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY',
         'same-source exact canonical transport required')
    from transport_proof import validate
    certificate = load(Path(work) / 'transport-proof.json')
    need(certificate == phase['transport_proof'], 'unchanged transport certificate')
    validate(certificate, phase['canonical_transport'], profile, own, map_hash,
             lambda name: read(Path(work) / name))


def copy_transport_public(work, output, own, map_hash):
    """Finite proof/guarded diagnostics only; never carrier/material bytes."""
    from capsule import _ordinary
    from public_projection import PRIVATE_MARKER
    work, output = Path(work), Path(output)
    for name in ('transport-diagnostic.json', 'transport-proof.json'):
        source = work / name
        if not source.exists():
            continue
        raw = _ordinary(source, 16*1024**2); value = json.loads(raw)
        need(value.get('binding') == own and value.get('source_map_sha256') == map_hash
             and not PRIVATE_MARKER.search(raw), 'same-source privacy-qualified transport DATA')
        target = output / name
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o600)
    proof = work / 'transport-proof'
    if proof.exists():
        need(proof.is_dir() and not proof.is_symlink(), 'ordinary transport proof directory')
        destination = output / 'transport-proof'; destination.mkdir(mode=0o700)
        names = sorted(p.name for p in proof.iterdir()); need(len(names) <= 64, 'bounded transport proof count')
        total = 0
        for name in names:
            need(name == 'receipt.json' or re.fullmatch(r'[0-9]{4}\.(stdout|stderr)', name), 'fixed transport proof leaf')
            raw = _ordinary(proof / name, 16*1024**2 if name == 'receipt.json' else 4*1024**2); total += len(raw)
            need(total <= 16*1024**2 and not PRIVATE_MARKER.search(raw), 'bounded privacy-qualified transport proof')
            with (destination / name).open('xb') as stream:
                stream.write(raw)
            (destination / name).chmod(0o600)


def tick(deadline):
    need(time.monotonic() < deadline, 'eight-input DATA seed deadline exhausted')


def checked_file(path, row, deadline, destination=None):
    tick(deadline)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary package/signature input ancestry')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['size']
         and 0 < before.st_size <= 64 * 1024**2, 'bounded singlelink exact package/signature leaf')
    digest = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024**2), b''):
            tick(deadline); size += len(data)
            need(size <= row['size'], 'input grew while copying')
            digest.update(data)
            if destination is not None:
                destination.write(data)
    need(identity(before) == identity(path.lstat()) and size == row['size']
         and digest.hexdigest() == row['sha256'], 'stable exact package/signature bytes')
    tick(deadline)
    return dict(bytes=size, sha256=digest.hexdigest())


def cache_inventory(cache, deadline):
    result = {}
    for path in sorted(cache.iterdir()):
        tick(deadline); info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and not info.st_mode & 0o022 and len(result) < 1024, 'finite owned ordinary cache namespace')
        result[path.name] = identity(info)
    return result


def cache(root, args):
    deadline = time.monotonic() + 120
    own, profile = admit(root, args, 'cache')
    prior_proof(root, args, own)
    ordinary_directory(args.cache, private=True); ordinary_directory(args.carrier, private=True)
    previous = load(args.work / 'input-transport-owner.json')
    need(all(previous.get(k) == value for k, value in receipt_base(root, args, own).items())
         and previous['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and previous['carrier_head'] == CARRIER_SOURCE and previous['profile_sha256'] == PROFILE,
         'exact completed same-owner transport DATA required')
    transport_retired(previous, args.work, carrier_profile(root), own, args.map_sha256)
    need(not (args.work / 'input-cache-owner.json').exists(), 'one-shot eight-input cache DATA seed; no retry')
    full = carrier_profile(root)
    before = cache_inventory(args.cache, deadline)
    report = dict(receipt_base(root, args, own), status='FAIL_EIGHT_INPUT_CACHE_DATA', budget_seconds=120,
        retry=False, files={}, full_carrier_proof='DEFERRED_TO_OWNER_PREPARE_NATIVE248',
        existing_metadata_before=before, existing_bytes='NO_EXISTING_FILE_WRITES_OR_REPLACEMENTS',
        authentication='EXACT_HASHED_DATA_ONLY_ORIGINAL_OWNER_PREPARE_AND_GPG_STILL_REQUIRED')
    save(args.work / 'input-cache-owner.json', report)  # One-shot marker precedes every cache mutation.
    try:
        rows = []
        for row in profile['additions']['rows']:
            rows.extend((row, dict(filename=row['filename'] + '.sig', size=row['signature_size'], sha256=row['signature_sha256'])))
        need(len(rows) == 16 and len({r['filename'] for r in rows}) == 16, 'exact eight archive/signature pairs')
        for row in rows:
            tick(deadline); name = row['filename']
            need(re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}', name) and name not in ('.', '..'), 'cache input filename')
            relative = 'packages/' + name
            need(full['files'].get(relative) == dict(bytes=row['size'], sha256=row['sha256']), 'exact selected full-carrier member pin')
            source, target = args.carrier / relative, args.cache / name
            if os.path.lexists(target):
                checked_file(source, row, deadline)
                receipt = checked_file(target, row, deadline)
                report['files'][name] = dict(status='EXACT_EXISTING_FILE_PRESERVED', **receipt)
                continue
            descriptor, temporary = tempfile.mkstemp(prefix='.native-developer-extra-', suffix='.partial', dir=args.cache)
            partial = Path(temporary)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    receipt = checked_file(source, row, deadline, stream)
                    stream.flush(); os.fsync(stream.fileno())
                need(checked_file(partial, row, deadline) == receipt, 'copied retained DATA differs')
                os.link(partial, target)  # Atomic publication, refuses every existing target.
            finally:
                partial.unlink(missing_ok=True)
            report['files'][name] = dict(status='EXACT_DATA_ATOMIC_NO_REPLACE_COPY', **receipt)
        after = cache_inventory(args.cache, deadline)
        need(all(after.get(name) == value for name, value in before.items())
             and set(after) == set(before) | {r['filename'] for r in rows}, 'all prior cache inode metadata preserved; only fixed16 leaves added')
        report.update(status='PASS_EIGHT_INPUT_CACHE_DATA_ONLY', existing_metadata_after={n: after[n] for n in before},
                      added=sorted(set(after) - set(before)))
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        raise
    finally:
        save(args.work / 'input-cache-owner.json', report)
    return report


MATRIX_OPERATION = 'platform-namespace-policy-matrix-v1'
MATRIX_SCOPE = 'namespace-policy'
MATRIX_JSON = ('result.json', 'diagnostic.json', 'owner.json', 'source-proof.json')
MATRIX_ROOT_JSON = ('source-proof.json', 'receipt.json', 'cleanup.json', 'image-ledger.json', 'image-retirement.json')


def matrix_json(raw):
    def pairs(rows):
        result = {}
        for name,value in rows:
            need(name not in result, 'duplicate matrix DATA key'); result[name] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _:need(False,'nonfinite matrix DATA'))


def matrix_name(name):
    """Fixed public DATA family; no directory walk or guest-tree fallback."""
    return (name in MATRIX_ROOT_JSON or name == 'matrix-projection.json'
            or name in {MATRIX_SCOPE+'/'+leaf for leaf in MATRIX_JSON}
            or name == MATRIX_SCOPE+'/outer-cleanup.json'
            or re.fullmatch(r'namespace-policy/(?:logs|outer-logs)/[0-9]{4}\.log', name) is not None)


def matrix_calls(payloads):
    """The actual actor receipt chooses each public log, never its actor index."""
    owner_name = MATRIX_SCOPE+'/owner.json'
    logs = {name for name in payloads if name.startswith(MATRIX_SCOPE+'/logs/')}
    if owner_name not in payloads:
        need(not logs, 'matrix logs require their original owner receipt')
        return
    owner = matrix_json(payloads[owner_name]); calls = owner.get('calls')
    need(type(calls) is list and len(calls) <= 128, 'finite actual matrix actor receipts')
    selected = set(); diagnostic = matrix_json(payloads.get(MATRIX_SCOPE+'/diagnostic.json',b'{}'))
    for row in calls:
        leaf = row.get('public_log')
        if leaf is None:
            need(row.get('log_pin') is None and row.get('output_retention') == 'REFUSED_CAP_OR_MISSING'
                 and diagnostic.get('status') == 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN',
                 'only explicit unretained output in UNKNOWN diagnostic')
            continue
        need(type(leaf) is str and re.fullmatch(r'logs/[0-9]{4}\.log', leaf)
             and leaf not in selected and row.get('output_retention') == 'COMPLETE',
             'unique original complete matrix actor public_log')
        selected.add(leaf); name = MATRIX_SCOPE+'/'+leaf
        need(name in payloads and pin(payloads[name]) == row.get('log_pin'),
             'matrix receipt/public_log/complete original body pin')
    need(logs == {MATRIX_SCOPE+'/'+name for name in selected}, 'complete matrix actor-log inverse')


def matrix_outer_capture(payloads, work, own, map_hash):
    """Only original retirement actors; no bootstrap key/import log export."""
    from capsule import _ordinary
    from public_projection import PRIVATE_MARKER
    cleanup = matrix_json(payloads.get('cleanup.json',b'{}')); actors = cleanup.get('actors',[])
    need(type(actors) is list and len(actors) <= 32, 'bounded original outer cleanup actors')
    calls = []; total = 0; errors = []
    for row in actors:
        try:
            path = Path(row['log'])
            need(path.is_relative_to(work/'retirement-actors') and path.parent == work/'retirement-actors',
                 'actual fixed outer retirement actor log')
            raw = _ordinary(path,1024**2); total += len(raw)
            need(total <= 2*1024**2 and pin(raw) == row.get('log_pin') and not PRIVATE_MARKER.search(raw),
                 'privacy-qualified original outer cleanup body/pin')
            name = MATRIX_SCOPE+'/outer-logs/%04d.log'%len(calls)
            calls.append(dict(actor=row,public_log=name,log_pin=pin(raw))); payloads[name] = raw
        except Exception as error:
            errors.append(dict(type=type(error).__name__,code='OUTER_CLEANUP_LOG_NOT_QUALIFIED'))
    value = dict(schema=1,operation=MATRIX_OPERATION,binding=own,source_map_sha256=map_hash,
        status='ORIGINAL_OUTER_RETIREMENT_DATA_ONLY',cleanup=pin(payloads['cleanup.json']) if 'cleanup.json' in payloads else None,
        calls=calls,errors=errors,native='NOT_ADMITTED',acceptance=False)
    payloads[MATRIX_SCOPE+'/outer-cleanup.json'] = (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def matrix_outer_complete(payloads, own, map_hash):
    """Rejoin actual cleanup rows/bodies and absence queries, not status alone."""
    receipt = matrix_json(payloads.get('receipt.json',b'{}')); cleanup = matrix_json(payloads.get('cleanup.json',b'{}'))
    need(receipt.get('binding') == own and receipt.get('source_map_sha256') == map_hash
         and receipt.get('operation') == MATRIX_OPERATION
         and receipt.get('status') == 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
         and receipt.get('native') == 'NOT_ADMITTED' and receipt.get('acceptance') is False
         and 'error' not in receipt and not receipt.get('cancellation_during_cleanup'),
         'actual owner first failure/cancellation remains UNKNOWN')
    need(cleanup.get('status') == 'PASS_EXACT_OWNED_RESOURCES_RETIRED', 'outer resource retirement required')
    diagnostic = matrix_json(payloads.get(MATRIX_SCOPE+'/diagnostic.json',b'{}'))
    need(receipt.get('namespace_policy') == diagnostic
         and diagnostic.get('status') == 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
         and diagnostic.get('first_failure') is None and diagnostic.get('cases') == 4
         and diagnostic.get('cleanup',{}).get('status') == 'PASS_EXACT_MATRIX_OWNED_RESOURCES_RETIRED',
         'actual prepared-image/case cleanup and no original matrix failure')
    value = matrix_json(payloads[MATRIX_SCOPE+'/outer-cleanup.json'])
    need(type(value.get('schema')) is int and value.get('schema') == 1 and value.get('operation') == MATRIX_OPERATION and value.get('binding') == own
         and value.get('source_map_sha256') == map_hash and value.get('errors') == []
         and value.get('cleanup') == pin(payloads['cleanup.json']), 'same original outer cleanup proof')
    actors = cleanup.get('actors'); calls = value.get('calls')
    need(type(actors) is list and actors and type(calls) is list and len(calls) == len(actors) <= 32,
         'complete actual outer retirement actor inverse')
    selected = set(); bodies = {}
    for row,call in zip(actors,calls):
        name = call.get('public_log')
        need(type(name) is str and re.fullmatch(r'namespace-policy/outer-logs/[0-9]{4}\.log',name)
             and name not in selected and call.get('actor') == row and name in payloads
             and pin(payloads[name]) == call.get('log_pin') == row.get('log_pin'),
             'outer actual actor/public_log/manifest/body join')
        selected.add(name); bodies[row['log']] = payloads[name]
        need(row.get('status') == 'PASS' and type(row.get('exit')) is int and row['exit'] == 0
             and all(row.get(k) is True for k in ('natural_exit','group_absent','exit_observed_via_waitpid','leader_held_until_group_inspection'))
             and row.get('retirement') == 'REAPED' and row.get('ownership_lost') is False
             and row.get('forced_cleanup') is False, 'natural direct original outer retirement')
    need(selected == {name for name in payloads if name.startswith(MATRIX_SCOPE+'/outer-logs/')},
         'closed selected outer log namespace')
    absence = cleanup.get('daemon_absence'); need(type(absence) is dict, 'original final daemon absence queries')
    docker = ['/usr/bin/docker','--host=unix:///var/run/docker.sock']
    for kind,argv in [('containers',docker+['ps','-aq','--no-trunc','--filter','label=org.cachy-asahi.native-developer='+own['token']]),
                      ('images',docker+['image','ls','--no-trunc','-q','--filter','label=org.cachy-asahi.native-developer='+own['token']])]:
        row = absence[kind]['actor']
        need(row in actors and row['argv'] == argv and absence[kind]['output'] == ''
             and row['log'] in bodies and not bodies[row['log']].strip(), 'raw actual empty outer daemon query')
    retirement = cleanup.get('image_retirement')
    need(type(retirement) is dict and retirement.get('status') == 'PASS_EXACT_OWNED_IMAGE_ALIASES_RETIRED'
         and retirement.get('binding') == own and retirement.get('source_map_sha256') == map_hash,
         'same-source original legacy image retirement')
    return True


def project_matrix(root, work, own, map_hash):
    """Separate fixed diagnostic projection; never ALPM/native success retention."""
    from capsule import _ordinary
    from public_projection import PRIVATE_MARKER
    work = Path(work); output = work/'public'; destination = work/'matrix-projection'
    verify_source(root, map_hash)
    need(not destination.exists() and not (work/'matrix-projection-intent.json').exists(),
         'one matrix diagnostic projection, no replay')
    save(work/'matrix-projection-intent.json', dict(schema=1, operation=MATRIX_OPERATION,
        binding=own, source_map_sha256=map_hash, native='NOT_ADMITTED', acceptance=False))
    payloads = {}; current = None; source_pin = None; refusals = []
    try:
        candidates = [(name, output/name) for name in MATRIX_ROOT_JSON if (output/name).exists()]
        scope = output/MATRIX_SCOPE
        if scope.exists():
            need(scope.is_dir() and not scope.is_symlink(), 'ordinary fixed matrix DATA scope')
            names = set(path.name for path in scope.iterdir())
            need(names <= set(MATRIX_JSON)|{'logs'}, 'fixed matrix evidence namespace')
            candidates += [(MATRIX_SCOPE+'/'+name,scope/name) for name in MATRIX_JSON if (scope/name).exists()]
            logs = scope/'logs'
            if logs.exists():
                need(logs.is_dir() and not logs.is_symlink(), 'ordinary matrix log directory')
                names = sorted(path.name for path in logs.iterdir())
                need(len(names) <= 128 and all(re.fullmatch(r'[0-9]{4}\.log', n) for n in names),
                     'fixed bounded matrix log names')
                candidates += [(MATRIX_SCOPE+'/logs/'+name,logs/name) for name in names]
        total = 0
        for name, path in candidates:
            current = name; source_pin = None
            try:
                raw = _ordinary(path, 16*1024**2 if '/logs/' in name else 1024**2)
                source_pin = pin(raw); total += len(raw)
                need(total <= 26*1024**2 and not PRIVATE_MARKER.search(raw),
                     'bounded privacy-qualified matrix diagnostic DATA')
                if name.endswith('.json'):
                    value = matrix_json(raw)
                    if name.startswith(MATRIX_SCOPE+'/') and name != MATRIX_SCOPE+'/result.json':
                        need(type(value) is dict and type(value.get('schema')) is int and value.get('schema') == 1
                             and value.get('operation') == MATRIX_OPERATION and value.get('binding') == own
                             and value.get('source_map_sha256') == map_hash, 'same-source actual matrix receipt')
                    if name == MATRIX_SCOPE+'/result.json':
                        need(type(value) is dict and value.get('binding') == own
                             and value.get('source_map_sha256') == map_hash,
                             'same-source raw matrix result even when incomplete')
                    if name in ('source-proof.json','receipt.json'):
                        need(value.get('binding') == own, 'same-owner original Source/owner receipt')
                    if name == 'receipt.json':need(value.get('operation') == MATRIX_OPERATION, 'matrix-only owner receipt')
                payloads[name] = raw
            except Exception as error:
                refusals.append(dict(code='MATRIX_DIAGNOSTIC_DATA_REFUSED',type=type(error).__name__,file=current,original_pin=source_pin))
    except Exception as error:
        # Retain a safe refusal without discarding/replacing the original native
        # error or routing any matrix bytes through another component retainer.
        refusals.append(dict(code='MATRIX_DIAGNOSTIC_DATA_REFUSED',type=type(error).__name__,file=current,original_pin=source_pin))
    try:matrix_calls(payloads)
    except Exception as error:refusals.append(dict(code='MATRIX_ACTOR_LOG_JOIN_UNKNOWN',type=type(error).__name__))
    try:matrix_outer_capture(payloads,work,own,map_hash)
    except Exception as error:refusals.append(dict(code='OUTER_CLEANUP_CAPTURE_UNKNOWN',type=type(error).__name__))
    diagnostic_name = MATRIX_SCOPE+'/diagnostic.json'
    if diagnostic_name not in payloads:
        value = dict(schema=1,operation=MATRIX_OPERATION,binding=own,source_map_sha256=map_hash,
            status='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN',native='NOT_ADMITTED',acceptance=False,
            first_failure=dict(code='MATRIX_OWNER_NOT_REACHED_OR_DIAGNOSTIC_REFUSED',projection_refusal=refusals))
        payloads[diagnostic_name] = (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    diagnostic = matrix_json(payloads[diagnostic_name])
    need(diagnostic.get('status') in ('DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE','DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN')
         and diagnostic.get('native') == 'NOT_ADMITTED' and diagnostic.get('acceptance') is False,
         'honest separate matrix diagnostic status')
    complete = False
    try:
        complete = (diagnostic['status'] == 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
                    and MATRIX_SCOPE+'/result.json' in payloads and not refusals
                    and matrix_outer_complete(payloads,own,map_hash))
    except Exception as error:refusals.append(dict(code='OUTER_OWNER_OR_RETIREMENT_UNKNOWN',type=type(error).__name__))
    rows = {name:dict(kind='file',mode=0o600,**pin(raw)) for name,raw in payloads.items()}
    receipt = dict(schema=1,kind='fixed-namespace-policy-diagnostic-projection-v1',operation=MATRIX_OPERATION,
        binding=own,source_map_sha256=map_hash,status='FIXED_NAMESPACE_POLICY_DIAGNOSTIC_PROJECTION',
        diagnostic_status='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE' if complete else 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN',
        selected=rows,native='NOT_ADMITTED',ALPM='NOT_RUN',acceptance=False,projection_refusal=refusals,
        source_producers={name:pin(source_bytes(root,name)) for name in
            ('native/owner.py','native/provision.py','native/platform_namespace_policy_v1.py','native/platform-namespace-policy-v1.json')})
    payloads['matrix-projection.json'] = (json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()
    need(len(payloads) <= 171 and sum(map(len,payloads.values())) <= 28*1024**2,
         'lower fixed matrix projection count/byte cap')
    destination.mkdir(mode=0o700)
    for name, raw in sorted(payloads.items()):
        need(matrix_name(name), 'fixed matrix projected leaf')
        target = destination/name; target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with target.open('xb') as stream:need(stream.write(raw) == len(raw), 'whole exclusive diagnostic output')
        target.chmod(0o600)
    files = {name:dict(kind='file',mode=0o600,**pin(raw)) for name,raw in payloads.items()}
    save(destination/'artifacts.json',dict(schema=1,binding=own,source_map_sha256=map_hash,files=files))
    return receipt


def read_matrix_capsule(capsule_path, expected_binding, independent_expected):
    """Matching trusted-local passive DATA reader; Root authority is external."""
    from capsule import open_capsule
    from public_projection import PRIVATE_MARKER
    import platform_namespace_policy_v1 as matrix
    need(type(expected_binding) is dict and set(expected_binding) == {'source','ref','run','map_sha256'},
         'four explicit Root selectors required')
    need(type(expected_binding['source']) is str and re.fullmatch('[0-9a-f]{40}',expected_binding['source'])
         and type(expected_binding['ref']) is str and expected_binding['ref'].startswith('refs/heads/codex/')
         and type(expected_binding['run']) is str and re.fullmatch('[1-9][0-9]*',expected_binding['run'])
         and type(expected_binding['map_sha256']) is str and re.fullmatch('[0-9a-f]{64}',expected_binding['map_sha256']),
         'NULL/unbound matrix selectors refused before opening capsule')
    own = {key:expected_binding[key] for key in ('source','ref','run')}
    own.update(attempt=1,token=hashlib.sha256((own['source']+':'+own['ref']+':'+own['run']).encode()).hexdigest()[:24])
    matrix.binding(own); map_hash = expected_binding['map_sha256']
    need(type(independent_expected) is dict and independent_expected.get('binding') == own
         and independent_expected.get('source_parent') == matrix.PARENT
         and independent_expected.get('source_map_sha256') == map_hash,
         'independent Root Source/sole-parent/map authority, never artifact marker strings')
    root = Path(__file__).resolve().parents[1]
    verify_source(root,map_hash)
    need(independent_expected.get('body_sha256') == pin(source_bytes(root,matrix.MODULE))['sha256']
         and independent_expected.get('contract_sha256') == pin(source_bytes(root,matrix.CONTRACT))['sha256'],
         'actual trusted-local Source module/contract body joins')
    view = open_capsule(capsule_path); manifest = view.load('artifacts.json'); view.verify_manifest(manifest)
    need(type(manifest['schema']) is int and manifest['schema'] == 1 and manifest['binding'] == own and manifest['source_map_sha256'] == map_hash,
         'exact matrix capsule Source/ref/run/attempt/token/map')
    files = manifest['files']; need(0 < len(files) <= 171 and sum(row['bytes'] for row in files.values()) <= 28*1024**2,
                                   'lower fixed matrix namespace bound')
    for name,row in files.items():
        need(matrix_name(name) and row['kind'] == 'file' and row['mode'] == 0o600
             and row['bytes'] <= (16*1024**2 if '/logs/' in name else 1024**2)
             and pin(view.read(name)) == {key:row[key] for key in ('bytes','sha256')}
             and not PRIVATE_MARKER.search(view.read(name)),
             'matrix closed ordinary namespace and full actual body pins')
    projection = view.load('matrix-projection.json')
    need(type(projection['schema']) is int and projection['schema'] == 1 and projection['kind'] == 'fixed-namespace-policy-diagnostic-projection-v1'
         and projection['operation'] == MATRIX_OPERATION and projection['binding'] == own
         and projection['source_map_sha256'] == map_hash and projection['native'] == 'NOT_ADMITTED'
         and projection['ALPM'] == 'NOT_RUN' and projection['acceptance'] is False
         and set(files) == set(projection['selected'])|{'matrix-projection.json'},
         'same-source separate fixed diagnostic projection, no ALPM success route')
    for name,row in projection['selected'].items():
        need(files[name] == row and pin(view.read(name)) == {key:row[key] for key in ('bytes','sha256')},
             'projection/manifest/index/body inverse')
    need(projection['source_producers'] == {name:pin(source_bytes(root,name)) for name in
        ('native/owner.py','native/provision.py','native/platform_namespace_policy_v1.py','native/platform-namespace-policy-v1.json')},
        'exact trusted Source producers')
    payloads = {name:view.read(name) for name in projection['selected']}; joins = []
    try:matrix_calls(payloads)
    except Exception as error:joins.append(dict(code='MATRIX_ACTOR_LOG_JOIN_UNKNOWN',type=type(error).__name__))
    diagnostic = view.load(MATRIX_SCOPE+'/diagnostic.json')
    need(type(diagnostic.get('schema')) is int and diagnostic.get('schema') == 1 and diagnostic.get('operation') == MATRIX_OPERATION
         and diagnostic.get('binding') == own and diagnostic.get('source_map_sha256') == map_hash
         and diagnostic.get('status') in ('DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE','DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN')
         and diagnostic.get('native') == 'NOT_ADMITTED' and diagnostic.get('acceptance') is False,
         'actual complete or incomplete matrix diagnostic DATA only')
    raw_result = view.load(MATRIX_SCOPE+'/result.json') if MATRIX_SCOPE+'/result.json' in files else None
    interpretation = dict(status='UNKNOWN',reason='incomplete experiment or resource retirement',native='NOT_ADMITTED',acceptance=False)
    qualification = None; source_qualification = None; runtime_qualification = None
    try:matrix_outer_complete(payloads,own,map_hash)
    except Exception as error:joins.append(dict(code='OUTER_OWNER_OR_RETIREMENT_UNKNOWN',type=type(error).__name__))
    try:
        source_qualification = matrix.validate_source_proof(view.load(MATRIX_SCOPE+'/source-proof.json'),root,independent_expected)
    except Exception as error:joins.append(dict(code='RAW_SOURCE_PARENT_FULL_MAP_JOIN_UNKNOWN',type=type(error).__name__))
    complete = (projection['diagnostic_status'] == 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
                and diagnostic['status'] == 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
                and projection.get('projection_refusal') == [] and not joins and raw_result is not None)
    if complete:
        contract = matrix.contract(load(root/matrix.CONTRACT))
        try:
            runtime_qualification = matrix.validate_runtime_evidence(view.load(MATRIX_SCOPE+'/owner.json'),raw_result,
                payloads,independent_expected,view.load(MATRIX_SCOPE+'/source-proof.json'))
            qualification = matrix.validate_result(raw_result,contract,independent_expected)
            interpretation = matrix.interpret(raw_result,contract,independent_expected)
        except (ValueError,KeyError,TypeError,AttributeError,RecursionError) as error:
            complete = False
            joins.append(dict(code='RUNTIME_OR_MATRIX_DATA_JOIN_UNKNOWN',type=type(error).__name__))
            interpretation = dict(status='UNKNOWN',reason=type(error).__name__+': '+str(error)[:256],native='NOT_ADMITTED',acceptance=False)
    return dict(status='VALIDATED_NAMESPACE_POLICY_MATRIX_DIAGNOSTIC_DATA_ONLY',binding=own,
        source_map_sha256=map_hash,raw_projection_status=projection['diagnostic_status'],
        projection_status='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE' if complete else 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN',
        raw_diagnostic=diagnostic,raw_result=raw_result,qualification=qualification,
        source_qualification=source_qualification,runtime_qualification=runtime_qualification,
        join_refusals=joins,interpretation=interpretation,
        ALPM='NOT_RUN',native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED',acceptance=False)


def retain(root, args):
    own, _ = admit(root, args, 'cache')
    proof = prior_proof(root, args, own)
    output = args.work / 'public'
    projected = args.work / 'public-projection'
    from capsule import pack
    upload = args.work / 'upload'
    need(not upload.exists(), 'fresh public capsule output directory')
    if getattr(args,'operation','source184') == MATRIX_OPERATION:
        projected = args.work/'matrix-projection'
        if not (projected/'artifacts.json').is_file():
            project_matrix(root,args.work,own,args.map_sha256)
        manifest = load(projected/'artifacts.json')
        need(manifest['binding'] == own and manifest['source_map_sha256'] == args.map_sha256
             and all(matrix_name(name) for name in manifest['files']), 'same-source fixed matrix projection only')
        upload.mkdir(mode=0o700)
        capsule = pack(projected,upload/'public-tree.tar')
        return dict(status='NAMESPACE_POLICY_DIAGNOSTIC_CAPSULED_NO_ALPM_ACCEPTANCE',capsule=capsule,
                    native='NOT_ADMITTED',ALPM='NOT_RUN',acceptance=False)
    if (projected / 'artifacts.json').is_file():
        output = projected
        manifest = load(output / 'artifacts.json')
        need(manifest['binding'] == own and manifest['source_map_sha256'] == args.map_sha256, 'same-owner native output retained without mutation')
        upload.mkdir(mode=0o700)
        capsule = pack(output, upload / 'public-tree.tar')
        return dict(status='EXISTING_NATIVE_PUBLIC_EVIDENCE_CAPSULED_WITHOUT_MUTATION', capsule=capsule)
    if output.exists():
        from safe_diagnostic import create
        report = create(args.work, own, args.map_sha256)
        upload.mkdir(mode=0o700)
        pack(args.work / 'safe-diagnostic', upload / 'public-tree.tar')
        return report
    need(not output.exists(), 'fresh diagnostic public directory')
    output.mkdir(mode=0o700); logs = output / 'provision-logs'; logs.mkdir()
    report = dict(receipt_base(root, args, own), status='DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY', phases={})
    for name in ('proof.json', 'input-transport-owner.json', 'input-cache-owner.json'):
        path = args.work / name
        if not path.is_file():
            continue
        row = load(path)
        need(row['binding'] == own and row['source_map_sha256'] == args.map_sha256, 'diagnostic exact same-run input receipt')
        for number, actor in enumerate(row.get('actors', [])):
            relative = Path(actor['retained_log'])
            need(not relative.is_absolute() and '..' not in relative.parts, 'diagnostic actor path')
            data = read(args.work / relative)
            need(pin(data) == actor['log_pin'], 'original actor diagnostic pin')
            target = logs / (name + '-%03d.log' % number); target.write_bytes(data)
        report['phases'][name] = row
    try:
        copy_transport_public(args.work, output, own, args.map_sha256)
    except Exception:
        report['transport_public_retention'] = 'REFUSED_BOUNDED_TRANSPORT_DATA'
    save(output / 'provision-diagnostic.json', report)
    rows = {str(p.relative_to(output)): dict(kind='file', mode=stat.S_IMODE(p.lstat().st_mode), **pin(read(p))) for p in output.rglob('*') if p.is_file()}
    need(sum(row['bytes'] for row in rows.values()) <= 32*1024**2, 'bounded diagnostic artifact')
    save(output / 'artifacts.json', dict(schema=1, binding=own, source_map_sha256=args.map_sha256, files=rows))
    from public_projection import project
    project(root, output, projected)
    upload.mkdir(mode=0o700)
    pack(projected, upload / 'public-tree.tar')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('proof', 'transport', 'cache', 'retain'))
    for name in ('work', 'cache', 'carrier'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha', 'ref', 'run-id', 'map-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--operation',choices=('source184','platform-alpm-v1',MATRIX_OPERATION),default='source184')
    args = parser.parse_args()
    def cancel(number, frame):
        raise KeyboardInterrupt('hosted DATA phase cancellation')
    handlers = {n: signal.signal(n, cancel) for n in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = globals()[args.phase](Path(__file__).resolve().parents[1], args)
        print(json.dumps(dict(status=result['status']), sort_keys=True))
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
