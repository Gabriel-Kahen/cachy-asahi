#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Local current-clock crypto observation of retained public run bytes.

Not an admission authority: no native custody, private status history, full CID,
base collector or build provenance is supplied by this observation.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile
import time
import types

ROOT = Path(__file__).absolute().parents[4]
DEP_PIN = '654f24486a9f52ab4cef8d7d89ca2f06c6a2856db48caa1fb812e62ed948bcbb'
PUBLIC = ROOT / 'artifacts/ci/38259350917/development-decoded/development-integration-public-repository-public-artifacts/repository-public-artifacts'
OUT = Path(__file__).absolute().with_name('retained-public-38259350917.json')


def main():
    path = Path(__file__).absolute().parents[1] / 'dependencies.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != DEP_PIN:
        raise ValueError('observation dependency pin drift')
    dependencies = types.ModuleType('observed_dependencies'); dependencies.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), dependencies.__dict__)
    modules = dependencies.load_collector(ROOT); common, crypto = modules['common'], modules['crypto']
    dependencies.authenticate_all(ROOT)
    manifest_raw = common.read(PUBLIC / 'public-artifact-manifest.json')
    manifest = common.decode(manifest_raw)
    mapped = manifest['files']
    loaded = {name: common.read(PUBLIC / name) for name in mapped}
    common.need(len(mapped) == 112 and all(len(loaded[name]) == row['bytes'] and common.digest(loaded[name]) == row['sha256']
                for name, row in mapped.items()), 'retained manifest byte drift')
    repository_audit = {'status': 'NOT RUN'}
    try:
        crypto.audit_repositories(loaded)
        repository_audit = {'status': 'PASS'}
    except common.Refused as error:
        repository_audit = {'status': 'FAIL', 'error': str(error),
            'known_first_difference': 'baseline-A fish/zsh PKGINFO url=[empty string], DB URL omitted'}
    objects = []
    for label, role in (('baseline-A', 'signer-A'), ('updated-B', 'signer-B')):
        prefix = 'TEST-repositories/' + label + '/'
        for data in mapped:
            if not data.startswith(prefix): continue
            name = data[len(prefix):]
            if re.search(r'\.pkg\.tar\.(xz|gz)$', name) or name in ('integration.db.tar.gz', 'integration.files.tar.gz'):
                objects.append({'path': data, 'signature': data + '.sig', 'signer': role})
    objects.append({'path': 'TEST-repository-aliases.json', 'signature': 'TEST-repository-aliases.json.sig', 'signer': 'signer-B'})
    objects.sort(key=lambda row: row['path']); common.need(len(objects) == 15, 'retained fifteen objects required')
    result = {'schema_version': 1, 'purpose': 'retained-public-cryptographic-observation', 'status': 'FAIL',
        'eligible_native_authority': False, 'native_admission': 'NOT RUN', 'native_client_restaging': 'NOT RUN',
        'original_local_certification': 'NOT VERIFIED', 'retained_native_positive_status_history': 'NOT SUPPLIED',
        'hardware_validation': 'NOT RUN', 'installation': 'NOT RUN', 'production_trust': 'NOT RUN',
        'run_id': '38259350917', 'source_commit': manifest['source_commit'], 'input_root': str(PUBLIC),
        'public_manifest_sha256': common.digest(manifest_raw), 'public_artifact_map_sha256': common.digest(common.encoded(mapped)),
        'collector_source_map_sha256': dependencies.COLLECTOR_MAP_SHA256,
        'observed_environment': {'architecture': platform.machine(), 'page_size': os.sysconf('SC_PAGE_SIZE')},
        'repository_structure_audit': repository_audit,
        'commands': [], 'snapshot_integrity': [], 'terminal_authorization': []}
    work = None
    with common.cancellation_handlers():
        try:
            with common.defer_cancellation(): work = Path(tempfile.mkdtemp(prefix='retained-public-observation-'))
            commands = common.Commands(work, allowed=('gpg', 'gpgconf', 'gpg-connect-agent'))
            result['commands'] = commands.records
            captured = work / 'captured'; captured.mkdir(mode=0o700)
            for name, data in loaded.items():
                target = captured / name; target.parent.mkdir(parents=True, exist_ok=True)
                common.write_new(target, data)
            homes, fingerprints, expiry = {}, {}, {}
            now = int(time.time()); result['observed_at'] = now
            def argv(role):
                return ['gpg', '--batch', '--no-options', '--no-autostart', '--homedir', str(homes[role]),
                        '--no-auto-key-retrieve', '--auto-key-locate', 'clear']
            for role in ('signer-A', 'signer-B', 'verifier'):
                homes[role] = work / role; homes[role].mkdir(mode=0o700)
                certificate = captured / ('TEST-' + role + '-public.asc')
                output, _ = commands.run(argv(role) + ['--with-colons', '--import-options', 'show-only', '--dry-run', '--import', str(certificate)])
                rows = [row.split(':') for row in output.decode().splitlines()]
                pub = [row for row in rows if row[0] == 'pub']; fpr = [row[9] for row in rows if row[0] == 'fpr']
                common.need(len(pub) == len(fpr) == 1 and pub[0][1] != 'r' and int(pub[0][5]) <= now < int(pub[0][6])
                            and not any(row[0] in ('sec', 'ssb') for row in rows), 'actual current certificate identity/validity')
                fingerprints[role], expiry[role] = fpr[0], int(pub[0][6])
                commands.run(argv(role) + ['--import', str(certificate)])
                output, _ = commands.run(argv(role) + ['--with-colons', '--check-sigs', fpr[0]])
                checks = [row.split(':') for row in output.decode().splitlines() if row.startswith('sig:')]
                common.need(checks and all(row[1] == '!' and row[4] == fpr[0][-16:] for row in checks), 'actual certificate self signatures')
            def verify(obj, phase):
                out, err = commands.run(argv(obj['signer']) + ['--status-fd', '1', '--verify',
                    str(captured / obj['signature']), str(captured / obj['path'])], expected=None)
                proof = crypto.verify_phase(out, fingerprints[obj['signer']], phase, commands.records[-1]['exit_code'])
                return {**obj, **proof, 'data_sha256': mapped[obj['path']]['sha256'],
                    'signature_sha256': mapped[obj['signature']]['sha256'], 'machine_status': out.decode(),
                    'stdout_sha256': common.digest(out), 'stderr_sha256': common.digest(err)}
            result['snapshot_integrity'] = [verify(obj, 'positive') for obj in objects]
            commands.run(argv('signer-A') + ['--import', str(captured / 'TEST-signer-A-revoked-public.asc')])
            output, _ = commands.run(argv('signer-A') + ['--with-colons', '--list-keys'])
            rows = [row.split(':') for row in output.decode().splitlines()]
            common.need([row[9] for row in rows if row[0] == 'fpr'] == [fingerprints['signer-A']]
                        and len([row for row in rows if row[0] == 'pub' and row[1] == 'r']) == 1, 'actual revoked certificate identity')
            output, _ = commands.run(argv('signer-A') + ['--with-colons', '--check-sigs', fingerprints['signer-A']])
            revocations = [row.split(':') for row in output.decode().splitlines() if row.startswith('rev:')]
            common.need(revocations and all(row[1] == '!' and row[4] == fingerprints['signer-A'][-16:] for row in revocations),
                        'actual self revocation signature')
            result['terminal_authorization'] = [verify(obj, 'revoked' if obj['signer'] == 'signer-A' else 'positive') for obj in objects]
            for row in result['terminal_authorization']:
                row['authorization'] = 'REVOKED' if row['signer'] == 'signer-A' else 'VALID_AT_OBSERVATION'
            common.need(all(common.digest(common.read(PUBLIC / name)) == mapped[name]['sha256'] for name in mapped), 'retained input drift')
            common.need(all(common.digest(common.read(path, 128 * 1024**2)) == commands.pins[name] for name, path in commands.paths.items()),
                        'tool drift after observations')
            common.need(not any((home / socket).exists() for home in homes.values()
                                for socket in ('S.gpg-agent', 'S.gpg-agent.extra', 'S.gpg-agent.browser', 'S.gpg-agent.ssh')),
                        'public observation agent socket')
            dependencies.authenticate_all(ROOT)
            result.update(status='PASS-public-signature-observation', fingerprints=fingerprints, certificate_expiry=expiry,
                          current_A_authorization='REVOKED', tool_sha256=commands.pins, completed_at=int(time.time()))
        finally:
            if work is not None:
                with common.defer_cancellation():
                    shutil.rmtree(work); common.need(not work.exists(), 'observation private absence')
                    result['private_work_cleanup'] = 'PASS'
    common.write_new(OUT, common.encoded(result))
    print(json.dumps({'status': result['status'], 'observed_objects': len(objects), 'snapshot_only': 15,
                     'terminal_A_revoked': 7, 'terminal_B_valid_at_observation': 8, 'native_admission': 'NOT RUN',
                     'output_sha256': common.digest(common.encoded(result))}, sort_keys=True))


if __name__ == '__main__': main()
