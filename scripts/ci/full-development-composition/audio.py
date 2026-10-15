#!/usr/bin/env python3
"""Six-package signed install/removal inside the existing offline ARM composition."""
import hashlib
from pathlib import Path
import stat

NAMES = {'asahi-audio', 'alsa-ucm-conf-asahi', 'speakersafetyd', 'bankstown', 'triforce-lv2', 'lsp-plugins-lv2'}
BASE = 'c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463'
EXPECTED = 'ff70e71ad067cb3cf261645b15173be315f02a3e91cd35e6bea5732125cce564'


def encoded(rows):
    return ''.join(k + ' ' + v + '\n' for k, v in sorted(rows.items())).encode()


def expected_inventory(source, before, rows, c):
    raw = (source / 'expected-audio.lock').read_bytes()
    c.need(hashlib.sha256(encoded(before)).hexdigest() == BASE and len(before) == 587 and not set(before) & NAMES, 'exact original587 audio checkpoint required')
    c.need(hashlib.sha256(raw).hexdigest() == EXPECTED, 'audio inventory pin differs')
    after = c.lock(raw.decode('ascii'))
    c.need(len(rows) == 6 and {r['name'] for r in rows} == NAMES and len(after) == 593 and after == before | {r['name']: r['version'] for r in rows}, 'audio inventory changes more than six additions')
    return after


def database(directory):
    """Retain bytes/types/modes of the original package records, excluding lock/logs."""
    rows = {}
    for path in sorted(directory.rglob('*')):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
            raise ValueError('unexpected local package database entry')
        rows[str(path.relative_to(directory))] = (info.st_mode, info.st_uid, info.st_gid,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
    return rows


def originals_preserved(before, directory, c, *, final=False):
    after = database(directory)
    c.need(all(after.get(k) == v for k, v in before.items()) and (not final or after == before), 'original587 package database changed')


def run(pacman, plan, before, source, work, c, payload_helper):
    c.guard()
    c.need(not Path('/dev/snd').exists() and not Path('/run/systemd/system').exists(), 'no audio devices or running systemd permitted')
    branch = plan['audio']; rows = branch['packages']
    c.need(branch['expected_inventory_sha256'] == EXPECTED, 'audio selection differs')
    after = expected_inventory(source, before, rows, c)
    c.need(c.inventory() == before, 'actual original587 inventory differs')
    db = Path('/var/lib/pacman/local'); saved = database(db)
    paths, directories, dependencies = [], {}, set()
    for row in rows:
        c.pin(source / row['filename'], row['sha256'], row['size'])
        c.pin(source / (row['filename'] + '.sig'), row['signature_sha256'], row['signature_size'])
        fields = c.archive_metadata(row, source)
        c.need(fields == row['metadata'], 'actual audio archive metadata differs')
        c.need(not any(fields.get(k) for k in ('conflict', 'replaces', 'backup')), 'audio changes existing package/config policy')
        dependencies.update(fields.get('depend', []))
        listing = c.run(['pacman', '-Qqlp', str(source / row['filename'])]).splitlines()
        c.need({p for p in listing if not p.endswith('/')} == {r['path'] for r in row['payload']}, 'actual audio payload list differs')
        for item in row['payload']:
            path = Path(item['path'])
            c.need(not path.exists() and not path.is_symlink(), 'audio would replace a pre-existing file')
            paths.append(path)
            for parent in path.parents:
                if parent.exists():
                    info = parent.lstat()
                    c.need(stat.S_ISDIR(info.st_mode), 'audio ancestor is not an ordinary directory')
                    directories[parent] = (info.st_mode, info.st_uid, info.st_gid)
    c.need(len(paths) == len(set(paths)), 'incoming audio file ownership collision')
    # Private trust already contains the exact upstream certificate and TEST signer.
    # Five new detached signatures use TEST; LSP keeps its pinned official signature.
    # Three ALPM mutations below retain implicit ldconfig (if present); its
    # return is ignored by ALPM. Cache/SONAME-link restoration is not asserted.
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-U', *[str(source / r['filename']) for r in rows]])
    c.need(c.inventory() == after, 'actual audio inventory differs from exact593')
    c.run(pacman + ['-Dk']); c.run(pacman + ['-T', *sorted(dependencies)])
    payload_helper.payloads(pacman, rows, c)
    originals_preserved(saved, db, c)
    # Remove the dependent first, then its five additions together. No -Rdd/-Rs.
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-R', 'asahi-audio'])
    c.need(c.inventory() == {k: v for k, v in after.items() if k != 'asahi-audio'}, 'dependent removal changed unrelated packages')
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-R', *sorted(NAMES - {'asahi-audio'})])
    c.need(c.inventory() == before, 'audio removal did not restore original587')
    c.run(pacman + ['-Dk'])
    originals_preserved(saved, db, c, final=True)
    c.need(all(not p.exists() and not p.is_symlink() for p in paths), 'audio package file remains after removal')
    for path, original in directories.items():
        info = path.lstat()
        c.need((info.st_mode, info.st_uid, info.st_gid) == original, 'pre-existing audio directory changed')
    payload_helper.payloads(pacman, plan['projects'], c)
    c.need(not Path('/dev/snd').exists() and not Path('/run/systemd/system').exists(), 'audio isolation changed')
    return {'status': 'PASS', 'installed_count': 593, 'installed_inventory_sha256': EXPECTED,
        'final_count': 587, 'final_inventory_sha256': BASE, 'dependencies': 'PASS-no-waivers',
        'payload_hashes_modes_ownership': 'PASS-six-additions-and-original-projects',
        'original587_database': 'PRESERVED', 'pre_existing_payload_directories': 'PRESERVED',
        'signatures': 'REQUIRED-five-TEST-one-pinned-ALARM', 'scriptlets': 'DISABLED', 'hooks': 'MASKED',
        'ALPM_auxiliary': 'three-eligible-ldconfig-calls; return-ignored; caches-links-unvalidated',
        'services': 'NOT RUN', 'audio': 'NOT RUN', 'hardware': 'NOT RUN', 'release': 'NOT ACCEPTED'}
