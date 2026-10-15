#!/usr/bin/env python3
"""Six-package signed install/removal inside the existing offline ARM composition."""
import hashlib
import json
from pathlib import Path
import re
import stat

NAMES = {'asahi-audio', 'alsa-ucm-conf-asahi', 'speakersafetyd', 'bankstown', 'triforce-lv2', 'lsp-plugins-lv2'}
BASE = 'c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463'
EXPECTED = '89d78d034a2ca1750157d93151719c360ee8c788bfe587c04c17740db072538d'
LD_HELPER = ('8794bf13f7a651963a219d8031fe04800d06ac6e44a29fbdfd81b64855b2bd98', 865664)
LD_CONF = '785c6c3614a27ae6115a27c1ca55bbf333654780997c4ba7e181172b021d1bf3'
LD_DIRS = ('/usr/lib', '/usr/lib64')
LD_FAKEROOT_CONF = '/usr/lib/ld.so.conf.d/fakeroot.conf'
LD_FAKEROOT_DIR = '/usr/lib/libfakeroot'
LD_FAKEROOT_NODE = {'type': 'file', 'mode': 0o644, 'uid': 0, 'gid': 0, 'size': 21,
                    'sha256': '564c4c4d369d005702d825d34edc5e5568cb1ab6ee1b19fa03d0d672fb8b3aee'}



class LdUnaccepted(ValueError): pass


def ld_need(ok, message):
    if not ok: raise LdUnaccepted(message)

def ld_node(path):
    try: info = path.lstat()
    except FileNotFoundError: return {'type': 'absent'}
    row = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    if stat.S_ISLNK(info.st_mode):
        row.update(type='link', target=str(path.readlink()))
    elif stat.S_ISDIR(info.st_mode): row['type'] = 'directory'
    elif stat.S_ISREG(info.st_mode):
        if info.st_size > 256 * 1024**2: raise LdUnaccepted('scan-file-size')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024**2), b''): digest.update(block)
        row.update(type='file', size=info.st_size, sha256=digest.hexdigest())
    else: raise LdUnaccepted('special-node')
    return row


def ld_entries(path, limit):
    entries = []
    for entry in path.iterdir():
        ld_need(len(entries) < limit, 'directory-entry-bound')
        entries.append(entry)
    return sorted(entries)


def ld_state(c, rows, root=Path('/')):
    """One finite read-only audio checkpoint; no config interpreter or regeneration."""
    at = lambda name: root / name.lstrip('/')
    helper = at('/usr/bin/ldconfig')
    c.pin(helper, *LD_HELPER)
    identity = ld_node(helper)
    ld_need(identity['type'] == 'file' and (identity['uid'], identity['gid'], identity['mode']) == (0, 0, 0o755), 'helper-identity')
    conf = at('/etc/ld.so.conf')
    ld_need(conf.is_file() and conf.stat().st_size <= 4096, 'main-config-size')
    configs = {'/etc/ld.so.conf': ld_node(conf)}
    ld_need(configs['/etc/ld.so.conf'].get('sha256') == LD_CONF, 'main-config-shape')
    for directory in ('/etc/ld.so.conf.d', '/usr/lib/ld.so.conf.d'):
        path = at(directory); configs[directory] = ld_node(path)
        ld_need(configs[directory]['type'] in ('absent', 'directory'), 'include-directory-shape')
        if not path.exists(): continue
        included = [p for p in ld_entries(path, 32) if not p.name.startswith('.') and p.name.endswith('.conf')]
        ld_need(len(included) <= 32, 'include-count')
        for path in included:
            name = '/' + str(path.relative_to(root))
            ld_need(path.lstat().st_size <= 4096, 'include-file-size ' + name)
            node = ld_node(path)
            ld_need(node['type'] == 'file' and node['size'] <= 4096, 'include-file-shape ' + name)
            if name == LD_FAKEROOT_CONF:
                ld_need(node == LD_FAKEROOT_NODE, 'fixed-fakeroot-config')
                configs[name] = node
                continue
            # Only audited literal standard dirs; no nested includes, flags or globs.
            for line in path.read_text(encoding='ascii').split('\n'):
                line = line.split('#', 1)[0].strip(' \t')
                ld_need(not line or line in LD_DIRS, 'unsupported-include ' + name)
            configs[name] = node
    ld_need(configs.get(LD_FAKEROOT_CONF) == LD_FAKEROOT_NODE, 'missing-fixed-fakeroot-config')
    ld_need(all(n['type'] == 'absent' or n['uid'] == n['gid'] == 0 and not n['mode'] & 0o022 for n in configs.values()), 'config-metadata')
    aliases, scan = {}, set()
    for name in LD_DIRS:
        path = at(name); aliases[name] = ld_node(path)
        if not path.exists():
            ld_need(aliases[name]['type'] == 'absent', 'dangling-scan-alias'); continue
        resolved = path.resolve(strict=True)
        ld_need(resolved in {at(n) for n in LD_DIRS} and resolved.is_dir(), 'scan-alias-shape')
        scan.add(resolved)
    path = at(LD_FAKEROOT_DIR); node = ld_node(path)
    ld_need(node == {'type': 'directory', 'mode': 0o755, 'uid': 0, 'gid': 0}
            and path.resolve(strict=True) == path, 'fixed-fakeroot-scan-directory')
    aliases[LD_FAKEROOT_DIR] = node
    scan.add(path)
    for path in tuple(scan):
        hwcaps = path / 'glibc-hwcaps'; name = '/' + str(hwcaps.relative_to(root)); aliases[name] = ld_node(hwcaps)
        ld_need(aliases[name]['type'] in ('absent', 'directory'), 'hwcaps-shape')
        if hwcaps.exists():
            children = [p for p in ld_entries(hwcaps, 32) if not p.name.startswith('.')]
            ld_need(len(children) <= 32, 'hwcaps-count')
            for child in children:
                node = ld_node(child)
                ld_need(re.fullmatch('[A-Za-z0-9_.-]{1,100}', child.name) and node['type'] == 'directory', 'hwcaps-child-shape')
                aliases['/' + str(child.relative_to(root))] = node
                scan.add(child)
    ld_need(not {at(str(Path(path).parent)).resolve() for row in rows for path in row['elf_paths']} & scan, 'audio-ELF-in-scan-directory')
    libraries, count, size = {}, 0, 0
    for directory in sorted(scan):
        for path in ld_entries(directory, 8192):
            count += 1; ld_need(count <= 8192, 'scan-entry-count')
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                size += info.st_size; ld_need(size <= 2 * 1024**3, 'scan-byte-budget')
            node = ld_node(path)
            if node['type'] == 'directory': continue
            name = '/' + str(path.relative_to(root)); libraries[name] = node
            info = path.lstat()
            node['identity'] = [info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns]
    cache_names = ('/etc/ld.so.cache', '/var/cache/ldconfig/aux-cache')
    for name in cache_names:
        ld_need(at(name).is_file() and at(name).stat().st_size <= 16 * 1024**2, 'missing-or-invalid-cache ' + name)
    caches = {name: ld_node(at(name)) for name in cache_names}
    for name, node in caches.items():
        ld_need(node['type'] == 'file' and node['size'] > 0 and node['uid'] == node['gid'] == 0, 'missing-or-invalid-cache ' + name)
        ld_need(ld_node(at(name + '~'))['type'] == 'absent', 'cache-temporary-leftover ' + name)
    caches['/var/cache/ldconfig'] = ld_node(at('/var/cache/ldconfig'))
    ld_need(caches['/var/cache/ldconfig']['type'] == 'directory' and caches['/var/cache/ldconfig']['uid'] == caches['/var/cache/ldconfig']['gid'] == 0, 'aux-directory-shape')
    # The pinned -p branch exits before scan/save. No normalizing call is made.
    printed = c.run([str(helper), '-p', '-C', str(at('/etc/ld.so.cache'))])
    ld_need(len(printed.encode()) <= 2 * 1024**2, 'printed-cache-bound')
    lines = printed.splitlines()
    header = re.fullmatch(r"([0-9]+) libs found in cache `" + re.escape(str(at('/etc/ld.so.cache'))) + "'", lines[0] if lines else '')
    ld_need(header and 0 < int(header[1]) <= 8192, 'printed-cache-header')
    number = int(header[1]); mapping = lines[1:1 + number]; tail = lines[1 + number:]
    ld_need(len(mapping) == number and (not tail or len(tail) == 1 and tail[0].startswith('Cache generated by: ')), 'printed-cache-shape')
    for line in mapping:
        match = re.fullmatch(r'\t([^\s]+) \(([^\r\n]+)\) => (/[^\s]+)', line)
        ld_need(match is not None, 'printed-cache-entry')
        path = Path(match[3]); target = at(str(path))
        ld_need('..' not in path.parts and target.parent.resolve() in scan and target.resolve().is_relative_to(root) and target.is_file() and libraries.get('/' + str(target.resolve().relative_to(root)), {}).get('type') == 'file', 'cache-target-shape ' + str(path)[:200])
    return {'helper': identity, 'configs': configs, 'aliases': aliases, 'scan': libraries,
            'caches': caches, 'mapping': mapping, 'generator': tail}


def ld_checkpoint(c, rows, work, label, baseline=None):
    try:
        state = ld_state(c, rows)
        raw = json.dumps(state, sort_keys=True).encode()
        ld_need(len(raw) <= 2 * 1024**2, 'checkpoint-size')
        (work / ('audio-ldconfig-' + label + '.json')).write_bytes(raw)
        changes = []
        if baseline is not None:
            aux = '/var/cache/ldconfig/aux-cache'
            ld_need(baseline['caches'][aux]['sha256'] == state['caches'][aux]['sha256'],
                    'aux-cache-byte-change ' + json.dumps({'before': baseline['caches'][aux], 'after': state['caches'][aux]}, sort_keys=True))
            for field in ('helper', 'configs', 'aliases', 'scan', 'mapping', 'generator', 'caches'):
                before, after = baseline[field], state[field]
                if field == 'caches':
                    before = {k: {a: v for a, v in n.items() if a != 'sha256' or k != '/etc/ld.so.cache'} for k, n in before.items()}
                    after = {k: {a: v for a, v in n.items() if a != 'sha256' or k != '/etc/ld.so.cache'} for k, n in after.items()}
                if before != after:
                    keys = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k)) if isinstance(before, dict) else ['ordered-records']
                    changes.append({'field': field, 'paths': keys[:12], 'before_sha256': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                                    'after_sha256': hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()})
        ld_need(not changes, 'changed-state ' + json.dumps(changes)[:1400])
        return state
    except Exception as error:
        raise ValueError('AUDIO_LDCONFIG_UNACCEPTED ' + label + ' ' + (str(error)[:1600] if isinstance(error, LdUnaccepted) else type(error).__name__)) from None


def ld_summary(states):
    return {'status': 'PASS-recorded-state-preserved', 'auxiliary_exit_status': 'NOT OBSERVED',
            'scope': 'four audio checkpoints; no extra regeneration; aux raw bytes equal',
            'checkpoints': [{'state_sha256': hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest(),
                             'main_sha256': s['caches']['/etc/ld.so.cache']['sha256'],
                             'aux_sha256': s['caches']['/var/cache/ldconfig/aux-cache']['sha256'],
                             'ordered_mappings': len(s['mapping']), 'scan_entries': len(s['scan'])} for s in states]}


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
    ld_states = [ld_checkpoint(c, rows, work, 'B0-587')]
    # Private trust already contains the exact upstream certificate and TEST signer.
    # Five new detached signatures use TEST; LSP keeps its pinned official signature.
    # Three ALPM mutations below retain implicit ldconfig (if present); its
    # return is ignored by ALPM. Four checkpoints compare the recorded state;
    # they do not observe the helper exit status or normalize a stale baseline.
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-U', *[str(source / r['filename']) for r in rows]])
    c.need(c.inventory() == after, 'actual audio inventory differs from exact593')
    ld_states.append(ld_checkpoint(c, rows, work, 'B1-593', ld_states[0]))
    c.run(pacman + ['-Dk']); c.run(pacman + ['-T', *sorted(dependencies)])
    payload_helper.payloads(pacman, rows, c)
    originals_preserved(saved, db, c)
    # Remove the dependent first, then its five additions together. No -Rdd/-Rs.
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-R', 'asahi-audio'])
    c.need(c.inventory() == {k: v for k, v in after.items() if k != 'asahi-audio'}, 'dependent removal changed unrelated packages')
    ld_states.append(ld_checkpoint(c, rows, work, 'B2-592', ld_states[0]))
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-R', *sorted(NAMES - {'asahi-audio'})])
    c.need(c.inventory() == before, 'audio removal did not restore original587')
    ld_states.append(ld_checkpoint(c, rows, work, 'B3-587', ld_states[0]))
    c.run(pacman + ['-Dk'])
    originals_preserved(saved, db, c, final=True)
    c.need(all(not p.exists() and not p.is_symlink() for p in paths), 'audio package file remains after removal')
    for path, original in directories.items():
        info = path.lstat()
        c.need((info.st_mode, info.st_uid, info.st_gid) == original, 'pre-existing audio directory changed')
    payload_helper.payloads(pacman, plan['projects'], c)
    c.need(not Path('/dev/snd').exists() and not Path('/run/systemd/system').exists(), 'audio isolation changed')
    return {'status': 'PASS', 'installed_count': 593, 'installed_inventory_sha256': EXPECTED, 'ldconfig_state': ld_summary(ld_states),
        'final_count': 587, 'final_inventory_sha256': BASE, 'dependencies': 'PASS-no-waivers',
        'payload_hashes_modes_ownership': 'PASS-six-additions-and-original-projects',
        'original587_database': 'PRESERVED', 'pre_existing_payload_directories': 'PRESERVED',
        'signatures': 'REQUIRED-five-TEST-one-pinned-ALARM', 'scriptlets': 'DISABLED', 'hooks': 'MASKED',
        'ALPM_auxiliary': 'three-eligible-ldconfig-calls; return-ignored; recorded-state-checked; exit-not-observed',
        'services': 'NOT RUN', 'audio': 'NOT RUN', 'hardware': 'NOT RUN', 'release': 'NOT ACCEPTED'}
