#!/usr/bin/env python3
"""Six-package signed install/removal inside the existing offline ARM composition."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

_spec = importlib.util.spec_from_file_location('audio_aux_order', Path(__file__).with_name('audio_aux.py'))
aux_order = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(aux_order)

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
LD_TARGET_PARENTS = ('/usr/lib/pkcs11', '/usr/lib/python3.14',
                     '/usr/lib/python3.14/site-packages', '/usr/lib/python3.14/site-packages/vapoursynth')
LD_TARGETS = {
    '/usr/lib/pkcs11/p11-kit-trust.so': (396568, 'd945af27e9e9d9ca7b2879cbfdf0d3fe17d8b94fc61dde4408f482793c0bffa7'),
    '/usr/lib/python3.14/site-packages/vapoursynth/libvapoursynth.so.4': (3284304, 'd946d71543f23536392e568268f59f5e1f83f7a2767bb2fc1bcbf7c192973111'),
    '/usr/lib/python3.14/site-packages/vapoursynth/libvsscript.so': (67816, '3ba72b1bc64942269cc29de3343a6250fcfb0a1b89f9a5d615d2f78973b3e65c'),
}
LD_AUX_NAME = '/var/cache/ldconfig/aux-cache'
LD_AUX_INPUT = Path(LD_AUX_NAME)
LD_AUX_OUTPUT = Path('/out')
LD_AUX_DIAGNOSTIC_LIMIT = 256 * 1024



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


def ld_target_chain(path, root, scan, libraries, targets):
    """Only observed root links may lead to one exact pinned off-scan file."""
    for _ in range(16):
        if '/' + str(path.relative_to(root)) in targets: return True
        if path.parent not in scan and path.parent not in {root / name.lstrip('/') for name in LD_DIRS}: return False
        parent = path.parent.resolve(strict=True)
        if parent not in scan: return False
        node = libraries.get('/' + str((parent / path.name).relative_to(root)), {})
        if node.get('type') != 'link': return False
        link = Path(node['target'])
        if '..' in link.parts: return False
        path = root / str(link).lstrip('/') if link.is_absolute() else parent / link
    return False


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
    # Observe only the three audited link targets; these parents are NOT scan roots.
    for name in LD_TARGET_PARENTS:
        path = at(name); node = ld_node(path)
        ld_need(node == {'type': 'directory', 'mode': 0o755, 'uid': 0, 'gid': 0}
                and path.resolve(strict=True) == path, 'fixed-target-parent ' + name)
        aliases[name] = node
    targets = {}
    for name, (expected_size, expected_sha) in LD_TARGETS.items():
        path = at(name); info = path.lstat()
        ld_need(stat.S_ISREG(info.st_mode) and info.st_size == expected_size, 'fixed-target-size-type ' + name)
        size += info.st_size; ld_need(size <= 2 * 1024**3, 'scan-byte-budget')
        count += 1; ld_need(count <= 8192, 'scan-entry-count')
        node = ld_node(path)
        ld_need(node == {'type': 'file', 'mode': 0o755, 'uid': 0, 'gid': 0,
                        'size': expected_size, 'sha256': expected_sha}, 'fixed-target-node ' + name)
        info = path.lstat()
        node['identity'] = [info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns]
        targets[name] = node
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
        message = 'cache-target-shape ' + str(path)[:200]
        ld_need('..' not in path.parts and target.parent.resolve() in scan, message)
        resolved = target.resolve()
        ld_need(resolved.is_relative_to(root) and target.is_file(), message)
        name = '/' + str(resolved.relative_to(root))
        observed = libraries.get(name, {}).get('type') == 'file'
        explicit = name in targets and ld_target_chain(target, root, scan, libraries, targets)
        ld_need(observed or explicit, message)
    return {'helper': identity, 'configs': configs, 'aliases': aliases, 'scan': libraries, 'targets': targets,
            'caches': caches, 'mapping': mapping, 'generator': tail}


def ld_aux_read(state):
    """Bounded stable descriptor read, joined to this checkpoint node/hash."""
    identity = lambda info: [info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                             info.st_uid, info.st_gid, info.st_size, info.st_ctime_ns, info.st_mtime_ns]
    descriptor = os.open(LD_AUX_INPUT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        ld_need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= LD_AUX_DIAGNOSTIC_LIMIT, 'aux-diagnostic-type-size')
        data = stream.read(before.st_size + 1)
        ld_need(identity(before) == identity(os.fstat(stream.fileno())) == identity(LD_AUX_INPUT.lstat()),
                'aux-diagnostic-read-drift')
    node = {'type': 'file', 'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid,
            'gid': before.st_gid, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    ld_need(len(data) == before.st_size and node == state['caches'][LD_AUX_NAME], 'aux-diagnostic-node-join')
    return data, node, identity(before)


def ld_aux_diagnostic(label, state, capture=None):
    """Two fixed diagnostic reads; never alter cache state or acceptance."""
    if label not in ('B0-587', 'B1-593'): return
    record = {'checkpoint': label, 'path': LD_AUX_NAME, 'status': 'UNAVAILABLE'}
    destination = LD_AUX_OUTPUT / ('audio-aux-' + label + '.bin')
    created = False
    try:
        data, node, read_identity = capture if capture is not None else ld_aux_read(state)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        created = True
        with os.fdopen(descriptor, 'wb') as stream:
            ld_need(stream.write(data) == len(data), 'aux-diagnostic-write')
            stream.flush(); os.fchmod(stream.fileno(), 0o644)
        record.update(status='CAPTURED', node=node, read_identity=read_identity,
                      helper_sha256=LD_HELPER[0], expected593_sha256=EXPECTED)
    except Exception as error:
        record['reason'] = str(error) if isinstance(error, LdUnaccepted) else type(error).__name__
        if created:
            try: destination.unlink()
            except OSError: record['partial_cleanup'] = 'FAILED'
    metadata_path = LD_AUX_OUTPUT / ('audio-aux-' + label + '.json')
    metadata_created = False
    try:
        encoded = json.dumps(record, sort_keys=True).encode() + b'\n'
        ld_need(len(encoded) <= 4096, 'aux-diagnostic-metadata-bound')
        descriptor = os.open(metadata_path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        metadata_created = True
        with os.fdopen(descriptor, 'wb') as stream:
            ld_need(stream.write(encoded) == len(encoded), 'aux-diagnostic-metadata-write')
            stream.flush(); os.fchmod(stream.fileno(), 0o644)
    except Exception as error:
        record['metadata_error'] = type(error).__name__
        if metadata_created:
            try: metadata_path.unlink()
            except OSError: record['metadata_cleanup'] = 'FAILED'
    try: print('AUDIO_AUX_DIAGNOSTIC ' + json.dumps(record, sort_keys=True), flush=True)
    except Exception: pass


def ld_checkpoint(c, rows, work, label, baseline=None, auxiliary=None):
    try:
        state = ld_state(c, rows)
        capture = None
        if auxiliary is not None:
            ld_need(LD_HELPER[0] == aux_order.HELPER_SHA256, 'aux-order-helper-pin')
            prior = {'B0-587': None, 'B1-593': 'B0-587', 'B2-592': 'B1-593', 'B3-587': 'B2-592'}
            ld_need(label in prior and auxiliary.get('label') == prior[label]
                    and (baseline is None) == (label == 'B0-587'), 'aux-order-checkpoint-sequence')
            capture = ld_aux_read(state)
        raw = json.dumps(state, sort_keys=True).encode()
        ld_need(len(raw) <= 2 * 1024**2, 'checkpoint-size')
        (work / ('audio-ldconfig-' + label + '.json')).write_bytes(raw)
        if capture is None: ld_aux_diagnostic(label, state)
        else: ld_aux_diagnostic(label, state, capture)
        transition = None
        if auxiliary is not None:
            transition = ({'kind': 'BASELINE'} if baseline is None
                          else aux_order.compare(auxiliary['data'], capture[0]))
        changes = []
        if baseline is not None:
            aux = '/var/cache/ldconfig/aux-cache'
            if auxiliary is None:
                ld_need(baseline['caches'][aux]['sha256'] == state['caches'][aux]['sha256'],
                        'aux-cache-byte-change ' + json.dumps({'before': baseline['caches'][aux], 'after': state['caches'][aux]}, sort_keys=True))
            for field in ('helper', 'configs', 'aliases', 'scan', 'targets', 'mapping', 'generator', 'caches'):
                before, after = baseline[field], state[field]
                if field == 'caches':
                    # Only the already-proved auxiliary transition may exempt its hash.
                    ignored_hashes = {'/etc/ld.so.cache'}
                    if auxiliary is not None: ignored_hashes.add(aux)
                    before = {k: {a: v for a, v in n.items() if a != 'sha256' or k not in ignored_hashes} for k, n in before.items()}
                    after = {k: {a: v for a, v in n.items() if a != 'sha256' or k not in ignored_hashes} for k, n in after.items()}
                if before != after:
                    keys = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k)) if isinstance(before, dict) else ['ordered-records']
                    changes.append({'field': field, 'paths': keys[:12], 'before_sha256': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                                    'after_sha256': hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()})
        ld_need(not changes, 'changed-state ' + json.dumps(changes)[:1400])
        if auxiliary is not None:
            auxiliary.update(label=label, data=capture[0])
            auxiliary.setdefault('transitions', []).append(dict(checkpoint=label, **transition))
        return state
    except Exception as error:
        raise ValueError('AUDIO_LDCONFIG_UNACCEPTED ' + label + ' ' + (str(error)[:1600] if isinstance(error, (LdUnaccepted, aux_order.Refused)) else type(error).__name__)) from None


def ld_summary(states, auxiliary=None):
    if auxiliary is not None:
        ld_need([row['checkpoint'] for row in auxiliary.get('transitions', [])]
                == ['B0-587', 'B1-593', 'B2-592', 'B3-587'], 'aux-order-incomplete-checkpoints')
    return {'status': 'PASS-recorded-state-preserved', 'auxiliary_exit_status': 'NOT OBSERVED',
            'scope': 'four audio checkpoints; no extra regeneration; aux raw-equal or exact prior load/save order; source-defined tail padding classified',
            'auxiliary_transitions': auxiliary['transitions'] if auxiliary is not None else [],
            'checkpoints': [{'state_sha256': hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest(),
                             'main_sha256': s['caches']['/etc/ld.so.cache']['sha256'],
                             'aux_sha256': s['caches']['/var/cache/ldconfig/aux-cache']['sha256'],
                             'ordered_mappings': len(s['mapping']), 'scan_entries': len(s['scan']),
                             'explicit_target_entries': len(s['targets'])} for s in states]}


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
    auxiliary = {}
    ld_states = [ld_checkpoint(c, rows, work, 'B0-587', auxiliary=auxiliary)]
    # Private trust already contains the exact upstream certificate and TEST signer.
    # Five new detached signatures use TEST; LSP keeps its pinned official signature.
    # Three ALPM mutations below retain implicit ldconfig (if present); its
    # return is ignored by ALPM. Four checkpoints compare the recorded state;
    # they do not observe the helper exit status or normalize a stale baseline.
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-U', *[str(source / r['filename']) for r in rows]])
    c.need(c.inventory() == after, 'actual audio inventory differs from exact593')
    ld_states.append(ld_checkpoint(c, rows, work, 'B1-593', ld_states[0], auxiliary=auxiliary))
    c.run(pacman + ['-Dk']); c.run(pacman + ['-T', *sorted(dependencies)])
    payload_helper.payloads(pacman, rows, c)
    originals_preserved(saved, db, c)
    # Remove the dependent first, then its five additions together. No -Rdd/-Rs.
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-R', 'asahi-audio'])
    c.need(c.inventory() == {k: v for k, v in after.items() if k != 'asahi-audio'}, 'dependent removal changed unrelated packages')
    ld_states.append(ld_checkpoint(c, rows, work, 'B2-592', ld_states[0], auxiliary=auxiliary))
    c.run(pacman + ['--noconfirm', '--noscriptlet', '-R', *sorted(NAMES - {'asahi-audio'})])
    c.need(c.inventory() == before, 'audio removal did not restore original587')
    ld_states.append(ld_checkpoint(c, rows, work, 'B3-587', ld_states[0], auxiliary=auxiliary))
    c.run(pacman + ['-Dk'])
    originals_preserved(saved, db, c, final=True)
    c.need(all(not p.exists() and not p.is_symlink() for p in paths), 'audio package file remains after removal')
    for path, original in directories.items():
        info = path.lstat()
        c.need((info.st_mode, info.st_uid, info.st_gid) == original, 'pre-existing audio directory changed')
    payload_helper.payloads(pacman, plan['projects'], c)
    c.need(not Path('/dev/snd').exists() and not Path('/run/systemd/system').exists(), 'audio isolation changed')
    return {'status': 'PASS', 'installed_count': 593, 'installed_inventory_sha256': EXPECTED, 'ldconfig_state': ld_summary(ld_states, auxiliary),
        'final_count': 587, 'final_inventory_sha256': BASE, 'dependencies': 'PASS-no-waivers',
        'payload_hashes_modes_ownership': 'PASS-six-additions-and-original-projects',
        'original587_database': 'PRESERVED', 'pre_existing_payload_directories': 'PRESERVED',
        'signatures': 'REQUIRED-five-TEST-one-pinned-ALARM', 'scriptlets': 'DISABLED', 'hooks': 'MASKED',
        'ALPM_auxiliary': 'three-eligible-ldconfig-calls; return-ignored; recorded-state-checked; exit-not-observed',
        'services': 'NOT RUN', 'audio': 'NOT RUN', 'hardware': 'NOT RUN', 'release': 'NOT ACCEPTED'}
