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


def retain(root, args):
    own, _ = admit(root, args, 'cache')
    proof = prior_proof(root, args, own)
    output = args.work / 'public'
    projected = args.work / 'public-projection'
    from capsule import pack
    upload = args.work / 'upload'
    need(not upload.exists(), 'fresh public capsule output directory')
    if (projected / 'artifacts.json').is_file():
        output = projected
        manifest = load(output / 'artifacts.json')
        need(manifest['binding'] == own and manifest['source_map_sha256'] == args.map_sha256, 'same-owner native output retained without mutation')
        upload.mkdir(mode=0o700)
        capsule = pack(output, upload / 'public-tree.tar')
        return dict(status='EXISTING_NATIVE_PUBLIC_EVIDENCE_CAPSULED_WITHOUT_MUTATION', capsule=capsule)
    if output.exists():
        if load(root / 'native/source-map.json').get('image_operation') == 'image-tools-alpm-v1':
            from image_host_diagnostics_v1 import create_safe as create
        else:
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
