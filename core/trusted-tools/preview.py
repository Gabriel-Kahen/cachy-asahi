#!/usr/bin/env python3
"""Finite GENERIC ARM desktop proposal: private pacman print/deptest, never install."""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

NAME = re.compile(r'[a-z0-9][a-z0-9+_.-]*\Z')
REL = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9+_.-]*)(>=|<=|=|>|<)?([^\s]*)\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
FORMAT = '%n\t%v\t%r\t%a\t%s\t%h'
FIELDS = {'pkgname': 'NAME', 'pkgver': 'VERSION', 'arch': 'ARCH', 'depend': 'DEPENDS',
          'provides': 'PROVIDES', 'conflict': 'CONFLICTS', 'replaces': 'REPLACES',
          'license': 'LICENSE', 'url': 'URL', 'size': 'ISIZE', 'pkgdesc': 'DESC'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def pairs(items):
    d = {}
    for k, v in items:
        need(k not in d, 'duplicate JSON field')
        d[k] = v
    return d


def load(path, pin):
    need(HEX.fullmatch(pin) and digest(path) == pin, 'input hash mismatch')
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def desc(text):
    d, key = {}, None
    for line in text.splitlines():
        if line.startswith('%') and line.endswith('%'):
            key = line[1:-1]
            need(key not in d, 'duplicate metadata field')
            d[key] = []
        elif line and key:
            d[key].append(line)
    return d


def check(p):
    for k in ('NAME', 'VERSION', 'ARCH'):
        need(len(p.get(k, [])) == 1, 'missing singleton metadata')
    need(NAME.fullmatch(p['NAME'][0]), 'invalid package name')
    need(p['ARCH'][0] in ('aarch64', 'any'), 'wrong architecture')
    need(p['VERSION'][0] and not re.search(r'\s|/', p['VERSION'][0]), 'invalid version')
    for k in ('DEPENDS', 'PROVIDES', 'CONFLICTS', 'REPLACES'):
        for value in p.get(k, []):
            m = REL.fullmatch(value)
            need(m and bool(m[2]) == bool(m[3]), 'invalid version relation')
    return p


def databases(directory, records, diagnostics=None):
    packages = {}
    for r in records:
        need(r['name'] in ('core', 'extra'), 'unexpected repository')
        path = Path(directory) / (r['name'] + '.db')
        need(digest(path) == r['sha256'] and path.stat().st_size == r['size'], 'database pin mismatch')
        entries = {}
        with tarfile.open(path) as t:
            for member in t:
                if not member.name.endswith(('/desc', '/depends')):
                    continue
                need(member.isfile() and member.size <= 131072, 'unsafe metadata entry')
                fields = desc(t.extractfile(member).read().decode())
                group = entries.setdefault(member.name.rsplit('/', 1)[0], {})
                need(not set(group) & set(fields), 'duplicate database metadata field')
                group.update(fields)
        for entry, p in entries.items():
            # Explicitly known upstream malformed unselected entry; never select it.
            if len(p.get('NAME', [])) != 1:
                if diagnostics is not None:
                    diagnostics.append({'entry': r['name'] + '/' + entry, 'reason': 'missing/non-singleton NAME; unselectable'})
                continue
            try:
                check(p)
            except ValueError as e:
                p['_invalid'] = [str(e)]
            p['repo'] = r['name']
            packages.setdefault(p['NAME'][0], p)
    return packages


def local_inventory(cache, lock, installed):
    """Read only descriptor bytes; never unpack rootfs or package payloads."""
    records = {}
    root = Path(cache) / lock['rootfs']['filename']
    need(digest(root) == lock['rootfs']['sha256'], 'rootfs hash mismatch')
    with tarfile.open(root, 'r|gz') as t:
        for m in t:
            if m.name.lstrip('./').startswith('var/lib/pacman/local/') and m.name.endswith('/desc'):
                need(m.isfile() and m.size <= 131072, 'unsafe rootfs descriptor')
                p = check(desc(t.extractfile(m).read().decode()))
                need(p['NAME'][0] not in records, 'duplicate rootfs package')
                records[p['NAME'][0]] = p
    need(len(records) == len(lock['rootfs_packages']), 'rootfs inventory mismatch')
    for p in lock['packages']:
        path = Path(cache) / p['filename']
        need(path.name == p['filename'] and digest(path) == p['sha256'], 'archive pin mismatch')
        with tarfile.open(path) as t:
            m = t.getmember('.PKGINFO')
            need(m.isfile() and m.size <= 131072, 'unsafe package descriptor')
            meta = {}
            for line in t.extractfile(m).read().decode().splitlines():
                if line.startswith('#') or ' = ' not in line:
                    continue
                k, v = line.split(' = ', 1)
                if k in FIELDS:
                    meta.setdefault(FIELDS[k], []).append(v)
            check(meta)
            need(meta['NAME'] == [p['name']] and meta['VERSION'] == [p['version']], 'archive identity mismatch')
            meta.update({'FILENAME': [p['filename']], 'SHA256SUM': [p['sha256']], 'repo': 'retained-generic-builder'})
            records[p['name']] = meta
    observed = ''.join(f'{n} {p["VERSION"][0]}\n' for n, p in sorted(records.items()))
    need(observed == Path(installed).read_text(), 'exact installed inventory mismatch')
    need(len(records) == 341, 'expected exact 341-package generic builder')
    return records


def write_local(directory, records):
    directory.mkdir(parents=True)
    (directory / 'ALPM_DB_VERSION').write_text('9\n')
    for name, p in sorted(records.items()):
        out = directory / (name + '-' + p['VERSION'][0])
        out.mkdir()
        (out / 'desc').write_text(''.join('%' + k + '%\n' + '\n'.join(v) + '\n\n'
                                        for k, v in p.items() if k != 'repo' and not k.startswith('_')))
        (out / 'files').write_text('%FILES%\n\n')


def command(work, operation, targets):
    base = ['/usr/bin/pacman', '--config', str(work / 'pacman.conf'), '--root', str(work / 'root'),
            '--dbpath', str(work / 'db'), '--cachedir', str(work / 'cache'),
            '--gpgdir', str(work / 'gpg'), '--hookdir', str(work / 'hooks'),
            '--logfile', str(work / 'pacman.log'), '--arch', 'aarch64', '--color', 'never']
    if operation == 'preview':
        return base + ['--sync', '--print', '--needed', '--noconfirm', '--print-format', FORMAT] + targets
    need(operation == 'deps', 'operation refused')
    return base + ['--deptest'] + targets


def guard(argv, work, operation, targets):
    need(work.is_absolute() and work.is_relative_to(Path('/tmp')) and work.name.startswith('cachy-port-'),
         'host context refused')
    need(argv == command(work, operation, targets), 'non-print/mutating/custom pacman argument refused')
    need(work.is_dir() and not work.is_symlink(), 'unsafe temporary context')
    for name in ('root', 'db', 'cache', 'gpg', 'hooks'):
        need((work / name).is_dir() and not (work / name).is_symlink(), 'unsafe private context')
    need((work / 'pacman.conf').is_file() and not (work / 'pacman.conf').is_symlink(), 'unsafe config')
    text = (work / 'pacman.conf').read_text()
    allowed = {'[options]', 'Architecture = aarch64', 'SigLevel = Required DatabaseOptional',
               '[core]', '[extra]', 'Server = https://metadata.invalid/core', 'Server = https://metadata.invalid/extra'}
    need(all(line in allowed for line in text.splitlines()) and
         text.startswith('[options]\nArchitecture = aarch64\nSigLevel = Required DatabaseOptional\n'),
         'host/external configuration refused')
    need(all(isinstance(t, str) and REL.fullmatch(t) for t in targets), 'unsafe target')


def run(work, operation, targets):
    argv = command(work, operation, targets)
    guard(argv, work, operation, targets)
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
                          env={'PATH': '/usr/bin', 'HOME': str(work), 'LC_ALL': 'C'})


def setup(work, dbdir, snapshots, records):
    for name in ('root', 'cache', 'gpg', 'hooks', 'db/sync'):
        (work / name).mkdir(parents=True)
    write_local(work / 'db/local', records)
    for r in snapshots:
        shutil.copyfile(Path(dbdir) / (r['name'] + '.db'), work / 'db/sync' / (r['name'] + '.db'))
    # No Include, host mirrorlist, DownloadUser, external helper or host trust state.
    (work / 'pacman.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required DatabaseOptional\n'
                                    + ''.join(f'[{r["name"]}]\nServer = https://metadata.invalid/{r["name"]}\n'
                                              for r in snapshots))


def proposal_check(p, packages):
    need(set(p) == {'schema', 'scope', 'builder_lock_sha256', 'builder_inventory_sha256', 'snapshots',
                    'roots', 'provider_constraints', 'optional_roots', 'baseline_editors', 'limitations'},
         'unexpected proposal fields')
    need(p['schema'] == 1 and p['scope'] == 'GENERIC-builder-metadata-preview', 'proposal scope refused')
    need([r['name'] for r in p['snapshots']] == ['core', 'extra'], 'finite core/extra snapshots required')
    for r in p['snapshots']:
        need(set(r) == {'name', 'sha256', 'signed', 'size', 'url'} and r['signed'] is False and
             isinstance(r['size'], int) and 0 < r['size'] <= 20000000 and HEX.fullmatch(r['sha256']) and
             r['url'] == 'https://ca.us.mirror.archlinuxarm.org/aarch64/' + r['name'] + '/' + r['name'] + '.db',
             'snapshot scope refused')

    roots = p['roots']
    need(isinstance(roots, list) and 1 <= len(roots) <= 100, 'nonfinite roots')
    seen = set()
    for r in roots + p['provider_constraints']:
        need(set(r) == {'name', 'version'}, 'unexpected root fields')
        need(r['name'] in packages and r['name'] not in seen, 'missing/duplicate root or provider')
        need(not packages[r['name']].get('_invalid'), 'malformed selected metadata')
        need(packages[r['name']]['VERSION'] == [r['version']], 'root version pin mismatch')
        seen.add(r['name'])
    return [r['name'] + '=' + r['version'] for r in roots + p['provider_constraints']]


def alpm_audit(work, records):
    """Use real libalpm dependency/provider comparison against selected final metadata."""
    class List(ctypes.Structure):
        pass
    Ptr = ctypes.POINTER(List)
    List._fields_ = [('data', ctypes.c_void_p), ('prev', Ptr), ('next', Ptr)]
    lib = ctypes.CDLL(ctypes.util.find_library('alpm'))
    def bind(name, result, args):
        f = getattr(lib, name); f.restype = result; f.argtypes = args; return f
    initialize = bind('alpm_initialize', ctypes.c_void_p, [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)])
    local = bind('alpm_get_localdb', ctypes.c_void_p, [ctypes.c_void_p])
    cache = bind('alpm_db_get_pkgcache', Ptr, [ctypes.c_void_p])
    satisfier = bind('alpm_find_satisfier', ctypes.c_void_p, [Ptr, ctypes.c_char_p])
    name = bind('alpm_pkg_get_name', ctypes.c_char_p, [ctypes.c_void_p])
    release = bind('alpm_release', ctypes.c_int, [ctypes.c_void_p])
    err = ctypes.c_int()
    handle = initialize(os.fsencode(work / 'root'), os.fsencode(work / 'db'), ctypes.byref(err))
    need(handle, 'libalpm private metadata load failed')
    try:
        entries = cache(local(handle))
        relationships, conflicts = [], []
        for n, p in sorted(records.items()):
            for dep in p.get('DEPENDS', []):
                found = satisfier(entries, dep.encode())
                relationships.append({'package': n, 'relation': dep, 'provider': name(found).decode() if found else None})
        class Conflict(ctypes.Structure):
            _fields_ = [('package1', ctypes.c_void_p), ('package2', ctypes.c_void_p), ('reason', ctypes.c_void_p)]
        checkconflicts = bind('alpm_checkconflicts', Ptr, [ctypes.c_void_p, Ptr])
        freeconflict = bind('alpm_conflict_free', None, [ctypes.c_void_p])
        freelist = bind('alpm_list_free', None, [Ptr])
        results = checkconflicts(handle, entries)
        item = results
        while item:
            c = ctypes.cast(item.contents.data, ctypes.POINTER(Conflict)).contents
            conflicts.append({'package': name(c.package1).decode(), 'with': name(c.package2).decode(),
                              'comparison': 'native libalpm_checkconflicts'})
            freeconflict(item.contents.data)
            item = item.contents.next
        freelist(results)
        return relationships, conflicts
    finally:
        release(handle)


def public_record(p):
    return {k: p.get(field, []) for k, field in {
        'name': 'NAME', 'version': 'VERSION', 'arch': 'ARCH', 'depends': 'DEPENDS',
        'provides': 'PROVIDES', 'conflicts': 'CONFLICTS', 'replaces': 'REPLACES',
        'license_metadata': 'LICENSE', 'upstream_url': 'URL',
        'archive_filename': 'FILENAME', 'archive_sha256': 'SHA256SUM'}.items()} | {
            'repository': p.get('repo', 'retained-generic-builder'),
            'maintenance_owner_class': 'maintained-upstream-ALARM; project compatibility owner unassigned',
            'archive_authentication': 'NOT RUN by this preview; metadata hash is not archive authentication',
            'source_recipe_and_license_text_audit': 'outstanding; license_metadata is repository/package declaration'}


def preview(proposal, lock, dbdir, cache, installed):
    diagnostics = []
    packages = databases(dbdir, proposal['snapshots'], diagnostics)
    targets = proposal_check(proposal, packages)
    initial = local_inventory(cache, lock, installed)
    receipt = {'schema': 1, 'scope': proposal['scope'], 'status': 'FAIL', 'target_Asahi_transaction': 'NOT RUN',
               'install': 'NOT RUN', 'downloads': 'NOT RUN', 'hardware': 'NOT RUN',
               'execution': 'host pacman/libalpm reading private generic-aarch64 metadata, not native ARM execution',
               'preview_source_sha256': digest(__file__),
               'pacman_binary_sha256': digest('/usr/bin/pacman'),
               'pacman_version': subprocess.run(['/usr/bin/pacman', '--version'], capture_output=True, text=True, check=True).stdout.strip(),
               'snapshots': proposal['snapshots'], 'builder_lock_sha256': proposal['builder_lock_sha256'],
               'builder_inventory_sha256': proposal['builder_inventory_sha256'], 'initial_count': len(initial),
               'roots': [r | {'current_builder_version': initial.get(r['name'], {}).get('VERSION', [None])[0]} for r in proposal['roots']], 'optional_roots_not_selected': proposal['optional_roots'],
               'provider_constraints': proposal['provider_constraints'], 'signature_claim': 'unsigned DB metadata only; no package signatures checked',
               'database_entry_diagnostics': diagnostics,
               'malformed_unselected_metadata': [{'name': n, 'reason': p['_invalid']} for n,p in packages.items() if '_invalid' in p]}
    with tempfile.TemporaryDirectory(prefix='cachy-port-', dir='/tmp') as tmp:
        work = Path(tmp)
        setup(work, dbdir, proposal['snapshots'], initial)
        result = run(work, 'preview', targets)
        # Public stderr is package metadata diagnostic only, never raw input/root trees.
        receipt['pacman_exit'] = result.returncode
        receipt['diagnostic'] = result.stderr.replace(str(work), '<temporary-context>')
        changes, final = [], dict(initial)
        for line in result.stdout.splitlines():
            parts = line.split('\t')
            if len(parts) != 6:
                continue
            n, version, repo, arch, size, hash_ = parts
            need(n in packages and packages[n]['VERSION'] == [version] and packages[n]['repo'] == repo,
                 'pacman result not bound to snapshot')
            need(packages[n]['ARCH'] == [arch] and packages[n]['SHA256SUM'] == [hash_], 'pacman identity mismatch')
            changes.append({'name': n, 'old_version': initial.get(n, {}).get('VERSION', [None])[0],
                            'version': version, 'download_bytes': int(size), 'kind': 'change' if n in initial else 'add'})
            need(not packages[n].get('_invalid'), 'malformed selected dependency metadata')
            final[n] = packages[n]
        need(len({c['name'] for c in changes}) == len(changes), 'duplicate print result')
        if result.returncode == 0:
            for r in proposal['roots'] + proposal['provider_constraints']:
                need(final.get(r['name'], {}).get('VERSION') == [r['version']], 'selected root/provider missing from candidate')
        shutil.rmtree(work / 'db/local')
        write_local(work / 'db/local', final)
        relationships, conflicts = alpm_audit(work, final)
        missing = [r for r in relationships if not r['provider']]
        deps = sorted({r['relation'] for r in relationships})
        deptest = run(work, 'deps', deps)
        receipt.update({'changes': sorted(changes, key=lambda c: c['name']), 'remove': [],
                        'removal_check': 'none; all initial packages retained unchanged and native final conflict audit empty; no transaction commit',
                        'file_hook_and_signed_archive_checks': 'NOT RUN; package metadata preview cannot establish installed file/hook compatibility or signature authentication',
                        'final_count': len(final), 'download_bytes': sum(c['download_bytes'] for c in changes),
                        'dependency_relationships': relationships, 'unsatisfied': missing, 'conflicts': conflicts,
                        'deptest_exit': deptest.returncode, 'deptest_missing': deptest.stdout.splitlines(),
                        'full_candidate_inventory': [public_record(p) for _, p in sorted(final.items())]})
        receipt['status'] = 'PASS-generic-metadata-preview' if not (result.returncode or missing or conflicts or deptest.returncode) else 'FAIL'
        receipt['closure_meaning'] = 'selected final generic builder metadata; includes existing base and build-only packages; not a minimal fresh-install closure'
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('proposal', 'proposal-sha256', 'builder-lock', 'database-dir', 'archive-cache', 'installed-lock', 'output'):
        parser.add_argument('--' + field, required=True)
    args = parser.parse_args()
    try:
        p = load(args.proposal, args.proposal_sha256)
        lock = load(args.builder_lock, p['builder_lock_sha256'])
        need(digest(args.installed_lock) == p['builder_inventory_sha256'], 'installed inventory pin mismatch')
        out = Path(args.output)
        need(not out.exists(), 'output exists')
        result = preview(p, lock, args.database_dir, args.archive_cache, args.installed_lock)
        out.mkdir(parents=True)
        (out / 'proposal.json').write_text(json.dumps(p, indent=2, sort_keys=True) + '\n')
        (out / 'receipt.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(result['status'])
        return 0 if result['status'].startswith('PASS') else 1
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.SubprocessError):
        print('REFUSED: invalid/pin-mismatched input or unavailable preview prerequisite')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
