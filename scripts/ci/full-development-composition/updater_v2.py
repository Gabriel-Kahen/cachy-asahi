#!/usr/bin/env python3
"""Signed v1-to-v2 package upgrade, existing real Check, then exact v1 rollback."""
import hashlib
import re
import shutil

NAME = 'cachy-asahi-update'
EXPECTED = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'


def expected_inventory(source, v1, composition):
    data = (source / 'expected-updater-v2.lock').read_bytes()
    composition.need(hashlib.sha256(data).hexdigest() == EXPECTED, 'v2 inventory pin differs')
    result = composition.lock(data.decode())
    composition.need(len(result) == len(v1) == 587 and v1[NAME] == '4.4.2-1'
                     and result == v1 | {NAME: '4.4.2-2'}, 'v2 changes more than updater release')
    return result


def successor(plan, source, composition):
    row = plan['updater_v2']['package']
    composition.need(row['name'] == NAME and row['version'] == '4.4.2-2'
                     and re.fullmatch(r'[A-Za-z0-9+_.:@-]+\.pkg\.tar\.(?:xz|zst|gz)', row['filename']),
                     'exact updater v2 archive required')
    composition.pin(source / row['filename'], row['sha256'], row['size'])
    composition.pin(source / (row['filename'] + '.sig'), row['signature_sha256'], row['signature_size'])
    fields = composition.archive_metadata(row, source)
    old, = [p for p in plan['projects'] if p['name'] == NAME]
    for declared, actual in (('depends', 'depend'), ('provides', 'provides'), ('conflicts', 'conflict')):
        composition.need(sorted(old[declared]) == sorted(row[declared]) == sorted(fields.get(actual, [])),
                         'v2 changed dependency/provider policy')
    listing = composition.run(['pacman', '-Qqlp', str(source / row['filename'])]).splitlines()
    composition.need({p for p in listing if not p.endswith('/')} == {p['path'] for p in row['payload']},
                     'v2 archive payload list differs')
    return row


def check(work, source, plan, v2, composition):
    fixture_path = source / 'updater-v2-real-check.py'
    row = plan['updater_v2']['check_fixture']
    composition.pin(fixture_path, row['sha256'], row['size'])
    fixture = composition.load('composition_real_check', fixture_path)
    signing = work / 'updater-v2-check-signing'; signing.mkdir(mode=0o700)
    gpg = ['gpg', '--batch', '--no-options', '--homedir', str(signing), '--no-auto-key-retrieve',
           '--pinentry-mode', 'loopback', '--passphrase', '']
    try:
        composition.run(gpg + ['--quick-generate-key', 'TEST ONLY Check <check@test.invalid>',
                               'ed25519', 'sign', '1d'])
        listing = composition.run(gpg + ['--with-colons', '--list-keys'])
        fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        composition.need(len(fingerprints) == 1 and re.fullmatch('[0-9A-F]{40}', fingerprints[0]),
                         'one disposable Check TEST signer required')
        result = fixture.exercise(work, signing, fingerprints[0], expected_inventory=v2)
        composition.need(result['status'] == 'PASS' and len(result['cases']) == 7,
                         'real Check failed at ' + result.get('phase', 'unknown'))
        return fixture, result
    finally:
        composition.run(['gpgconf', '--homedir', str(signing), '--kill', 'all'])
        shutil.rmtree(signing)


def run(pacman, plan, v1, source, work, composition, payload_helper):
    composition.guard()
    phase = 'successor-inputs'
    try:
        composition.need(composition.inventory() == v1, 'v2 upgrade requires exact v1 composition')
        v2 = expected_inventory(source, v1, composition)
        row = successor(plan, source, composition)
        projects = [row if p['name'] == NAME else p for p in plan['projects']]
        depends = sorted({d for p in projects for d in p['depends']})
        phase = 'signed-v1-to-v2-upgrade'
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-U', str(source / row['filename'])])
        composition.need(composition.inventory() == v2, 'v2 signed upgrade changed other installed versions')
        composition.run(pacman + ['-Dk'])
        composition.run(pacman + ['-T', *depends])
        payload_helper.payloads(pacman, projects, composition)
        phase = 'real-installed-check-seven-cases'
        fixture, cases = check(work, source, plan, v2, composition)
        composition.need(cases['installed_packages'] == 588, 'Check fixture inventory count differs')
        phase = 'remove-inert-check-baseline'
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-R', fixture.NAME])
        composition.need(composition.inventory() == v2 and not fixture.PAYLOAD.exists()
                         and not fixture.PAYLOAD.is_symlink(), 'Check fixture did not restore exact v2 inventory')
        composition.run(pacman + ['-Dk'])
        phase = 'signed-exact-v1-package-rollback'
        original, = [p for p in plan['packages'] if p['name'] == NAME]
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-U', str(source / original['filename'])])
        composition.need(composition.inventory() == v1, 'v1 rollback changed installed inventory')
        composition.run(pacman + ['-Dk'])
        composition.run(pacman + ['-T', *depends])
        payload_helper.payloads(pacman, plan['projects'], composition)
        return {'status': 'PASS', 'upgrade': 'PASS-signed-local-pacman-v1-to-v2',
                'v2_package_sha256': row['sha256'], 'v2_inventory_sha256': EXPECTED,
                'check_cases': cases, 'inert_fixture_removed': True, 'v1_rollback': 'PASS-signed-local-pacman',
                'final_package_count': 587, 'real_updater_commit': 'NOT RUN',
                'hardware': 'NOT RUN', 'target_update_recovery': 'NOT RUN'}
    except Exception as error:
        raise RuntimeError('updater v2 composition failed at ' + phase + ': ' + str(error)) from error
