#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future signed disposable ALPM lifecycle; sealed selection precedes all actors."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import string
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import execution_selection, load, need, pin, read, save, verify_source

PLACEHOLDERS = {'collect_dir', 'session', 'session_sha256', 'bundle_dir', 'archive',
                'archive_sha256', 'release_id', 'release_sha256', 'source_commit'}

def contract_fields(contract):
    """Validate formatting and explicit collector output contract before imports."""
    found = {}
    for verb in ('collect', 'create', 'verify'):
        fields = set()
        for argument in contract[verb]:
            for literal, field, spec, conversion in string.Formatter().parse(argument):
                need(field is None or field in PLACEHOLDERS and not spec and conversion is None,
                     'only reviewed finite CLI placeholders')
                if field is not None: fields.add(field)
        found[verb] = fields
    need('session' in found['collect'] or 'collect_dir' in found['collect'] and
         type(contract.get('session_relative')) is str, 'sealed collector session output contract required')
    if 'session' not in found['collect']:
        path = Path(contract['session_relative'])
        need(not path.is_absolute() and '..' not in path.parts and path.as_posix() == contract['session_relative'] and str(path) != '.',
             'reviewed relative collector session output')
    need({'session', 'session_sha256', 'bundle_dir'} <= found['create'], 'creation must bind the actual collected session and pin')
    need({'archive', 'archive_sha256'} <= found['verify'], 'verification must bind the actual archive and pin')
    return found

def expand(argv, values):
    return [argument.format_map(values) for argument in argv]

def inventory(commands):
    raw = commands.run(['/usr/bin/pacman', '-Q'])
    return ''.join(line + '\n' for line in sorted(raw.splitlines())).encode()

def snapshot(directory):
    files = {}
    for path in directory.rglob('*'):
        need(not path.is_symlink(), 'ordinary synthetic user output only')
        if path.is_file(): files[str(path.relative_to(directory))] = pin(read(path))
    need(len(files) <= 256 and sum(row['bytes'] for row in files.values()) <= 16 * 1024**2, 'bounded user output snapshot')
    return files

def publish(source, output, name, public):
    body = read(source)
    target = output / name
    target.parent.mkdir(parents=True, exist_ok=True)
    need(not target.exists() and not target.is_symlink(), 'fresh public member')
    target.write_bytes(body)
    public[name] = pin(body)

def verify_status(raw, fingerprint):
    rows = [line.split()[1:] for line in raw.splitlines() if line.startswith('[GNUPG:] ')]
    bad = {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYEXPIRED', 'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'ERROR', 'NODATA', 'NO_PUBKEY'}
    need(not any(row and row[0] in bad for row in rows), 'failed/expired/revoked signature status refused')
    valid = [row for row in rows if row and row[0] == 'VALIDSIG']
    need(len(valid) == 1 and valid[0][1] == fingerprint and valid[0][-1] == fingerprint,
         'exact TEST primary-key signature fingerprint')

def run(root, output, checksum, source_sha):
    verify_source(root, checksum)
    policy = execution_selection(root)
    selected = policy['selected_package']
    fields = contract_fields(selected['cli_contract'])
    need(re.fullmatch('[0-9a-f]{40}', source_sha or ''), 'actual native source SHA required for declared collection identity')
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.getuid() == os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'dedicated native ARM disposable root required')
    original = read(root / 'native/original341.lock')
    need(read(Path('/builder-packages.lock')) == original and len(original.splitlines()) == 341, 'exact original341 image inventory')
    # Import only new helper and retained owned-child code after every selection gate.
    spec = importlib.util.spec_from_file_location('_support_native_guest_helpers', root / 'native/guest.py')
    guest = importlib.util.module_from_spec(spec); spec.loader.exec_module(guest)
    guest.output_directory(output)
    account = pwd.getpwnam('alarm')
    commands = guest.Commands(root, output, {0, account.pw_uid})
    report = dict(schema=1, status='FAIL', source_map_sha256=checksum, architecture=platform.machine(),
        page_size=os.sysconf('SC_PAGE_SIZE'), inventory=pin(original), package_identity=selected['package'],
        recipe_sha256=selected['recipe_sha256'], phases=[], public_files={},
        native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    temporary = Path('/tmp/support-lifecycle')
    need(not temporary.exists(), 'fresh private lifecycle root'); temporary.mkdir(mode=0o755)
    keyhome, alpmhome = temporary / 'signing-key', temporary / 'alpm-keyring'
    keyhome.mkdir(mode=0o700); alpmhome.mkdir(mode=0o700)
    protected = {str(path): pin(read(path)) for path in (Path('/etc/pacman.conf'), Path('/etc/pacman.d/mirrorlist')) if path.is_file()}
    signing = dict(private_key_removed=False, fake_signature_time_used=False, production_trust='UNTOUCHED')
    public = report['public_files']
    env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME=str(temporary))
    try:
        need(inventory(commands) == original, 'actual original341 inventory before lifecycle')
        selected_archive = Path('/packages/package.pkg.tar')
        product, special = guest.package_archive(selected_archive, root, selected, original)
        report['package'] = product
        archive = temporary / 'package.pkg.tar'; shutil.copyfile(selected_archive, archive)
        gpg = ['/usr/bin/gpg', '--no-options', '--homedir', str(keyhome), '--batch', '--yes',
               '--pinentry-mode', 'loopback', '--passphrase', '']
        started = int(time.time())
        commands.run(gpg + ['--quick-generate-key', 'support ALPM TEST ONLY <test@invalid>', 'ed25519', 'sign', '1d'], env=env, timeout=60)
        listing = commands.run(gpg + ['--with-colons', '--list-keys'], env=env)
        fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        need(len(fingerprints) == 1 and re.fullmatch('[A-F0-9]{40}', fingerprints[0]), 'single actual TEST primary key')
        fingerprint = fingerprints[0]
        created = int(next(line.split(':')[5] for line in listing.splitlines() if line.startswith('pub:')))
        need(started <= created <= int(time.time()), 'actual-time TEST key creation')
        signature = temporary / 'package.pkg.tar.sig'
        commands.run(gpg + ['--local-user', fingerprint, '--digest-algo', 'SHA256', '--output', str(signature), '--detach-sign', str(archive)], env=env)
        verified = commands.run(gpg + ['--status-fd', '1', '--verify', str(signature), str(archive)], env=env)
        verify_status(verified, fingerprint)
        verification_log = commands.rows[-1]['log']
        certificate = temporary / 'TEST-public.gpg'
        commands.run(gpg + ['--output', str(certificate), '--export', fingerprint], env=env)
        alpm_gpg = ['/usr/bin/gpg', '--no-options', '--homedir', str(alpmhome), '--batch', '--yes']
        commands.run(alpm_gpg + ['--import', str(certificate)], env=env)
        ownertrust = temporary / 'TEST-ownertrust'; ownertrust.write_text(fingerprint + ':6:\n')
        commands.run(alpm_gpg + ['--import-ownertrust', str(ownertrust)], env=env)
        for path, name in ((signature, 'package.pkg.tar.sig'), (certificate, 'TEST-public.gpg')):
            publish(path, output, name, public)
        signing.update(fingerprint=fingerprint, key_created_epoch=created, verified_epoch=int(time.time()),
            archive=product['archive'], signature=pin(read(signature)), certificate=pin(read(certificate)),
            verification_log=verification_log, signature_verified_at_actual_time=True,
            alpm_local_signature_policy='Required TrustedOnly')
        hooks = temporary / 'disabled-hooks'; hooks.mkdir()
        for folder in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks', '/builder-disabled-hooks'):
            for path in Path(folder).glob('*.hook'):
                if not (hooks / path.name).is_symlink(): (hooks / path.name).symlink_to('/dev/null')
        config = temporary / 'pacman.conf'
        config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = ' + str(alpmhome) + '\nHookDir = ' + str(hooks) + '\n')
        pacman = ['/usr/bin/pacman', '--config', str(config), '--noconfirm', '--noscriptlet']
        homes = {}
        for profile in ('fresh', 'existing'):
            home = temporary / ('home-' + profile); home.mkdir(mode=0o700)
            sentinel = home / 'user-owned'; sentinel.write_bytes(b'original synthetic user bytes\x00\xff\n')
            os.chown(home, account.pw_uid, account.pw_gid); os.chown(sentinel, account.pw_uid, account.pw_gid)
            homes[profile] = dict(path=home, sentinel=pin(read(sentinel)), preserved={})

        def preserve():
            need(all(pin(read(Path(path))) == value for path, value in protected.items()), 'system pacman configuration preserved')
            for row in homes.values():
                need(pin(read(row['path'] / 'user-owned')) == row['sentinel'], 'synthetic user sentinel preserved')
                current = snapshot(row['path'])
                need(all(current.get(name) == value for name, value in row['preserved'].items()), 'prior user outputs preserved across transitions')

        def user(row, argv, expected=0):
            return commands.run(['/usr/bin/runuser', '-u', account.pw_name, '--', '/usr/bin/env', '-i',
                'PATH=/usr/bin:/bin', 'LC_ALL=C', 'LANG=C', 'HOME=' + str(row['path']), *argv], env=env,
                timeout=180, expected=expected)

        def observe(phase, profile, row):
            work = row['path'] / phase
            work.mkdir(mode=0o700); os.chown(work, account.pw_uid, account.pw_gid)
            collect_dir = work / 'collected'
            session = collect_dir / selected['cli_contract']['session_relative'] if 'session' not in fields['collect'] else work / 'session.json'
            values = dict(collect_dir=str(collect_dir), session=str(session), session_sha256='0' * 64,
                bundle_dir=str(work / 'bundle'), archive=str(work / 'bundle/support-bundle.tar'), archive_sha256='0' * 64,
                release_id='support-native-fixture', release_sha256='f' * 64, source_commit=source_sha)
            cli = '/usr/bin/' + selected['package']['name']
            start = len(commands.rows)
            user(row, [cli, *expand(selected['cli_contract']['collect'], values)])
            session_pin = pin(read(session)); values['session_sha256'] = session_pin['sha256']
            created = json.loads(user(row, [cli, *expand(selected['cli_contract']['create'], values)]))
            archive_path = Path(values['archive']); archive_pin = pin(read(archive_path))
            need(created.get('status') == 'CREATED' and created.get('sha256') == archive_pin['sha256']
                 and created.get('bytes') == archive_pin['bytes'], 'actual created bundle and receipt')
            values['archive_sha256'] = archive_pin['sha256']
            verified = json.loads(user(row, [cli, *expand(selected['cli_contract']['verify'], values)]))
            need(verified.get('status') == 'VERIFIED' and verified.get('sha256') == archive_pin['sha256'], 'actual verified bundle')
            relocated = work / 'relocated-support-bundle.tar'
            shutil.copyfile(archive_path, relocated); os.chown(relocated, account.pw_uid, account.pw_gid)
            relocated_values = dict(values, archive=str(relocated))
            need(json.loads(user(row, [cli, *expand(selected['cli_contract']['verify'], relocated_values)])).get('status') == 'VERIFIED', 'actual relocated bundle verification')
            malformed = work / 'malformed-session.json'; malformed.write_bytes(b'{"schema_version":1,"schema_version":1}')
            os.chown(malformed, account.pw_uid, account.pw_gid)
            bad = dict(values, session=str(malformed), session_sha256=pin(read(malformed))['sha256'], bundle_dir=str(work / 'must-not-exist'))
            user(row, [cli, *expand(selected['cli_contract']['create'], bad)], expected=2)
            need(not Path(bad['bundle_dir']).exists(), 'malformed refusal creates no output')
            tampered = work / 'tampered-support-bundle.tar'; raw = bytearray(read(archive_path))
            need(len(raw) > 1024, 'bounded actual support archive'); raw[1024] ^= 1; tampered.write_bytes(raw)
            os.chown(tampered, account.pw_uid, account.pw_gid)
            user(row, [cli, *expand(selected['cli_contract']['verify'], dict(values, archive=str(tampered)))], expected=2)
            prefix = 'observations/' + phase + '/' + profile + '/'
            publish(session, output, prefix + 'session.json', public)
            publish(archive_path, output, prefix + 'support-bundle.tar', public)
            preserve()
            row['preserved'] = snapshot(row['path'])
            return dict(profile=profile, collect_command=start, create_command=start + 1, verify_command=start + 2,
                relocation_command=start + 3, malformed_command=start + 4, tamper_command=start + 5,
                session=dict(path=prefix + 'session.json', **session_pin), archive=dict(path=prefix + 'support-bundle.tar', **archive_pin),
                preserved_files=row['preserved'], collect_create_verify='PASS', negative_refusals='PASS_EXPECTED_EXIT2')

        def installed(phase):
            current = inventory(commands)
            wanted = original + (selected['package']['name'] + ' ' + selected['package']['version'] + '\n').encode()
            wanted = b''.join(sorted(wanted.splitlines(keepends=True)))
            need(current == wanted, 'exact original341 plus selected one-package inventory')
            name = selected['package']['name']
            commands.run(['/usr/bin/pacman', '-Qkk', name], env=env)
            owned = commands.run(['/usr/bin/pacman', '-Qql', name], env=env).splitlines()
            need({path.lstrip('/') for path in owned if not path.endswith('/')} == set(selected['payload']), 'exact ALPM payload ownership')
            for name, expected in selected['payload'].items():
                path = Path('/') / name; info = path.lstat()
                need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                     and stat.S_IMODE(info.st_mode) == expected['mode'] and pin(read(path)) == {k: expected[k] for k in ('bytes', 'sha256')}, 'actual installed selected payload')
            preserve()
            observations = [observe(phase, profile, row) for profile, row in homes.items()]
            preserve()
            report['phases'].append(dict(phase=phase, status='PASS', inventory=pin(current), inventory_count=342,
                payload=selected['payload'], ownership_exact=True, observations=observations, prior_outputs_preserved=True))

        def absent(phase):
            current = inventory(commands)
            need(current == original, 'exact original341 restored after removal')
            need(all(not os.path.lexists(Path('/') / name) for name in selected['payload']), 'owned package files absent after remove')
            preserve()
            report['phases'].append(dict(phase=phase, status='PASS', inventory=pin(current), inventory_count=341,
                removed_payload_absent=True, prior_outputs_preserved=True))

        for phase in ('install', 'same-version'):
            commands.run([*pacman, '-U', str(archive)], env=env); installed(phase)
        commands.run([*pacman, '-R', selected['package']['name']], env=env); absent('remove')
        commands.run([*pacman, '-U', str(archive)], env=env); installed('reinstall')
        commands.run([*pacman, '-R', selected['package']['name']], env=env); absent('final-remove')
        report.update(status='PASS_SIGNED_DISPOSABLE_ALPM_LIFECYCLE', final_inventory=pin(inventory(commands)),
                      config_preserved=True, user_outputs_preserved=True, hook_masks=len(list(hooks.iterdir())))
    finally:
        # Dedicated cleanup budget within the owner's 1200-second role deadline.
        commands.deadline = time.monotonic() + 60
        try:
            for directory in (keyhome, alpmhome):
                commands.run(['/usr/bin/gpgconf', '--homedir', str(directory), '--kill', 'all'], env=env, timeout=15)
            shutil.rmtree(keyhome); shutil.rmtree(alpmhome)
            signing['private_key_removed'] = not keyhome.exists() and not alpmhome.exists()
        except BaseException as error:
            report['status'] = 'FAIL_PRIVATE_KEY_RETIREMENT'
            signing['retirement_error'] = type(error).__name__
            raise
        finally:
            report['signing'], report['commands'] = signing, commands.rows
            save(output / 'result.json', report)
            for path in (output, *output.rglob('*')):
                need(not path.is_symlink(), 'public output cannot contain aliases')
                os.chown(path, account.pw_uid, account.pw_gid)
                path.chmod(0o755 if path.is_dir() else 0o644)
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-map-sha256', required=True)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args()
    print(json.dumps(dict(status=run(Path('/source'), args.output, args.source_map_sha256, args.source_sha)['status'])))
