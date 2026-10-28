# SPDX-License-Identifier: MIT
"""Future publication proof, public retained DATA transport for original341.

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
    need(args.execute and platform.system() == 'Linux'
         and platform.machine() in ('aarch64', 'arm64') and os.getuid() == os.geteuid() != 0
         and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ARCH') == 'ARM64'
         and os.environ.get('RUNNER_OS') == 'Linux', 'explicit same-source unprivileged native ARM workflow required')
    need(not any(k.startswith(('GIT_', 'LD_', 'DOCKER_', 'CACHY_OLD_FOUR_', 'CACHY_RETAINED_'))
                 for k in os.environ), 'ambient Git/loader/daemon/private transport overrides refused')
    temp = Path(os.environ['RUNNER_TEMP']).absolute()
    ordinary_directory(temp)
    need(args.work == temp / 'native-debugger-work' and args.cache == temp / 'alarm-cache'
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
    actor = basis(root).Actors(args.work / 'input-transport-actors', 480)
    report = dict(receipt_base(root, args, own), status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',
        role='RETAINED_INPUT_TRANSPORT_DATA', carrier_source=CARRIER_SOURCE, profile_sha256=PROFILE,
        expected_carrier_files=1154, expected_carrier_bytes=1046432165, budget_seconds=480,
        retry=False, partial_data_retained=True, full_carrier_proof='DEFERRED_TO_OWNER_PREPARE_NATIVE248',
        authentication='ORIGINAL_FULL_CARRIER_PREPARE_AND_NATIVE_SIGNATURE_AUDIT_REQUIRED')
    try:
        args.carrier.mkdir(mode=0o700)
        with git_environment(args.work / 'home'):
            git = ['/usr/bin/git', '--no-replace-objects', '-c', 'credential.helper=', '-c', 'http.extraHeader=',
                   '-c', 'http.sslVerify=true', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
                   '-c', 'protocol.https.allow=always', '-c', 'core.fsmonitor=false']
            actor.run([*git, 'init', '--template=', str(args.carrier)], timeout=10)
            actor.run([*git, '-C', str(args.carrier), '-c', 'http.lowSpeedLimit=65536', '-c', 'http.lowSpeedTime=60',
                'fetch', '--depth=1', '--no-tags', '--no-recurse-submodules',
                'https://github.com/Gabriel-Kahen/cachy-asahi.git', profile['source']], timeout=400)
            fetched = actor.run([*git, '-C', str(args.carrier), 'rev-parse', '--verify', 'FETCH_HEAD'], timeout=10)
            need(fetched == CARRIER_SOURCE, 'exact fetched immutable carrier commit')
            actor.run([*git, '-C', str(args.carrier), 'checkout', '--detach', CARRIER_SOURCE], timeout=45)
            head = actor.run([*git, '-C', str(args.carrier), 'rev-parse', '--verify', 'HEAD'], timeout=10)
            need(head == CARRIER_SOURCE, 'exact retained DATA checkout HEAD')
        report.update(status='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY', carrier_head=head)
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        raise
    finally:
        report['actors'] = actor_logs(actor, args.work)
        save(args.work / 'input-transport-owner.json', report)
    return report


def retain(root, args):
    own, _ = admit(root, args, 'retain')
    proof = prior_proof(root, args, own)
    output = args.work / 'public'
    from capsule import pack
    upload = args.work / 'upload'
    need(not upload.exists(), 'fresh public capsule output directory')
    if (output / 'artifacts.json').is_file():
        manifest = load(output / 'artifacts.json')
        need(manifest['binding'] == own and manifest['source_map_sha256'] == args.map_sha256, 'same-owner native output retained without mutation')
        upload.mkdir(mode=0o700)
        capsule = pack(output, upload / 'public-tree.tar')
        return dict(status='EXISTING_NATIVE_PUBLIC_EVIDENCE_CAPSULED_WITHOUT_MUTATION', capsule=capsule)
    need(not output.exists(), 'fresh diagnostic public directory')
    output.mkdir(mode=0o700); logs = output / 'provision-logs'; logs.mkdir()
    report = dict(receipt_base(root, args, own), status='DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY', phases={})
    for name in ('proof.json', 'input-transport-owner.json'):
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
    save(output / 'provision-diagnostic.json', report)
    rows = {str(p.relative_to(output)): dict(kind='file', mode=stat.S_IMODE(p.lstat().st_mode), **pin(read(p))) for p in output.rglob('*') if p.is_file()}
    need(sum(row['bytes'] for row in rows.values()) <= 32*1024**2, 'bounded diagnostic artifact')
    save(output / 'artifacts.json', dict(schema=1, binding=own, source_map_sha256=args.map_sha256, files=rows))
    upload.mkdir(mode=0o700)
    pack(output, upload / 'public-tree.tar')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('proof', 'transport', 'retain'))
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
