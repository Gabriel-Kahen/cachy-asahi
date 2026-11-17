#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy/read back a closed public Qt pair packet. No actors or acceptance authority."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES, MAX_FILES, MAX_JSON = 128 * 1024**2, 4096, 8 * 1024**2
BASIS_SHA256 = '3fa1f4351629a84825e85f89b6b0ee33e9de606dd99a3ea3f918da64fd07ae0b'
ATTEMPTS = ('build-1', 'build-2')
FLAGS = ('normal_comparator', 'archive_bytes', 'payload', 'pkginfo', 'buildinfo',
         'own_check_each', 'stage_each', 'notices_each')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def decode(raw):
    need(len(raw) <= MAX_JSON, 'JSON byte cap')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: need(False, 'nonfinite JSON'))
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        need(depth <= 20 and count <= 250000, 'JSON structure cap')
        need(type(item) is not float or math.isfinite(item), 'nonfinite JSON number')
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    need(type(value) is dict, 'JSON object required')
    return value


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def member(name):
    need(type(name) is str and len(name) <= 255 and 1 <= len(name.split('/')) <= 8
         and all((p == '.SRCINFO' or re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]*', p)) and p not in ('.', '..')
                 for p in name.split('/')), 'safe finite member required')
    return name


def descriptor(row, mode=True):
    keys = {'bytes', 'sha256', 'mode'} if mode else {'bytes', 'sha256'}
    need(type(row) is dict and set(row) == keys and type(row['bytes']) is int
         and (0 < row['bytes'] <= MAX_BYTES if mode else 0 <= row['bytes'] <= 2 * 1024**3)
         and digest(row['sha256'])
         and (not mode or type(row['mode']) is int and row['mode'] == 0o644), 'whole public file descriptor')
    return row


def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid',
                                       'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path))
         and all(not p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path required')
    return path


class Tree:
    """Exact namespace, retained directory descriptors, no links or special files."""
    def __init__(self, root, names):
        self.root, self.dirs, self.files = ordinary(root), {}, {}
        self.names = set(names)
        need(0 < len(self.names) <= MAX_FILES, 'file count cap')
        for name in self.names: member(name)
        expected_dirs = {str(p) for name in self.names for p in Path(name).parents if str(p) != '.'}
        try:
            self._directory('', None, expected_dirs)
            need(set(self.files) == self.names, 'missing transport members')
            need(sum(row[6] for row in self.files.values()) <= MAX_BYTES, 'namespace total byte cap')
        except BaseException:
            self.close()
            raise

    def _directory(self, name, parent_fd, expected_dirs):
        target = self.root if not name else name.rsplit('/', 1)[-1]
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent_fd)
        before = os.fstat(fd)
        self.dirs[name] = fd, identity(before)
        need(before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o022, 'unsafe directory')
        with os.scandir(fd) as entries:
            for entry in entries:
                rel = name + '/' + entry.name if name else entry.name
                need(len(self.files) + len(self.dirs) <= 2 * MAX_FILES, 'namespace cap')
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    need(rel in expected_dirs, 'unexpected directory')
                    self._directory(rel, fd, expected_dirs)
                else:
                    need(rel in self.names and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                         and info.st_uid in (0, os.geteuid()) and stat.S_IMODE(info.st_mode) == 0o644,
                         'unexpected, linked, private or special file')
                    need(0 < info.st_size <= MAX_BYTES, 'file size cap')
                    self.files[rel] = identity(info)
        self.stable()

    def stable(self):
        for name, (fd, previous) in self.dirs.items():
            need(identity(os.fstat(fd)) == previous and identity((self.root / name).lstat()) == previous,
                 'directory replaced or changed')
        need(all(identity((self.root / name).lstat()) == previous for name, previous in self.files.items()),
             'input leaf replaced or changed')

    def stream(self, name, expected=None, collect=False, target=None):
        self.stable()
        parent, _, leaf = name.rpartition('/')
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=self.dirs[parent][0])
        try:
            before = os.fstat(fd)
            need(identity(before) == self.files[name], 'file replaced before read')
            need(expected is None or before.st_size == expected['bytes'], 'size differs before read')
            cap = MAX_JSON if collect else MAX_BYTES
            need(before.st_size <= cap, 'read byte cap')
            h, size, parts = hashlib.sha256(), 0, []
            while block := os.read(fd, min(1024**2, before.st_size + 1 - size)):
                size += len(block); need(size <= before.st_size, 'file grew')
                h.update(block)
                if collect: parts.append(block)
                if target is not None: target.write(block)
            row = {'bytes': size, 'sha256': h.hexdigest(), 'mode': stat.S_IMODE(before.st_mode)}
            need(size == before.st_size and identity(os.fstat(fd)) == self.files[name]
                 and identity((self.root / name).lstat()) == self.files[name], 'file changed during read')
            need(expected is None or row == expected, 'whole file pin mismatch')
            return b''.join(parts) if collect else row
        finally:
            os.close(fd)

    def close(self):
        for fd, _ in self.dirs.values(): os.close(fd)
        self.dirs.clear()


class Export:
    """Fresh output anchored to owned directory descriptors; never overwrite a leaf."""
    def __init__(self, root, expected_parent):
        self.root, self.dirs = root, {}
        self.parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.parent_id = self.directory_id(os.fstat(self.parent))
        try:
            need(self.parent_id == expected_parent, 'export parent changed before creation')
            os.mkdir(root.name, 0o700, dir_fd=self.parent)
            fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            self.dirs[''] = fd, self.directory_id(os.fstat(fd))
            self.stable()
        except BaseException:
            self.close(); raise

    @staticmethod
    def directory_id(s):
        return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'))

    def stable(self):
        need(self.directory_id(os.fstat(self.parent)) == self.parent_id
             == self.directory_id(self.root.parent.lstat()), 'export parent replaced')
        for name, (fd, previous) in self.dirs.items():
            need(self.directory_id(os.fstat(fd)) == previous
                 == self.directory_id((self.root / name).lstat()), 'export directory replaced')

    def directory(self, name):
        if name in self.dirs: return self.dirs[name][0]
        parent, _, leaf = name.rpartition('/')
        parent_fd = self.directory(parent)
        self.stable(); os.mkdir(leaf, 0o700, dir_fd=parent_fd)
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        self.dirs[name] = fd, self.directory_id(os.fstat(fd))
        return fd

    def put(self, name, raw=None, source=None, expected=None):
        member(name); self.stable(); parent, _, leaf = name.rpartition('/')
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o644, dir_fd=self.directory(parent))
        with os.fdopen(fd, 'wb') as target:
            os.fchmod(target.fileno(), 0o644)
            if raw is not None: target.write(raw)
            else: source.stream(name, expected, target=target)
            target.flush(); before = identity(os.fstat(target.fileno()))
        self.stable()
        need(before == identity((self.root / name).lstat()), 'export leaf replaced during copy')

    def close(self):
        for fd, _ in self.dirs.values(): os.close(fd)
        self.dirs.clear()
        os.close(self.parent)


def read_one(path, expected_sha):
    path = ordinary(path)
    need(digest(expected_sha), 'external whole SHA256 required')
    # A receipt may live beside unrelated C files; anchor only its parent and leaf.
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent = identity(os.fstat(fd))
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o644
                 and before.st_uid in (0, os.geteuid()) and 0 < before.st_size <= MAX_JSON, 'ordinary public receipt')
            raw = bytearray()
            while block := os.read(leaf, min(1024**2, before.st_size + 1 - len(raw))):
                raw.extend(block); need(len(raw) <= before.st_size, 'receipt grew')
            need(len(raw) == before.st_size and sha(raw) == expected_sha
                 and identity(before) == identity(os.fstat(leaf)) == identity(path.lstat())
                 and parent == identity(os.fstat(fd)) == identity(path.parent.lstat()), 'receipt changed or pin mismatch')
            return bytes(raw)
        finally: os.close(leaf)
    finally: os.close(fd)


def basis():
    return decode(read_one(Path(__file__).with_name('basis.json'), BASIS_SHA256))


def payload_names(b):
    return {f'{a}/{n}' for a in ATTEMPTS for n in ('artifacts/' + b['filename'], 'provenance.json',
            'validation.json', 'stage-contract.json', 'check-receipt.json', 'license-receipt.json')} | {
            'pair/comparison.json', 'pair/qt-pair-finisher.json'}


def receipt_contract(r, b):
    need(set(r) == {'schema', 'kind', 'recipe_commit', 'recipe_contract_sha256', 'producer', 'run',
                   'files', 'provenance_operands', 'external_retention', 'pair_checks', 'Root_acceptance'}
         and type(r['schema']) is int and r['schema'] == 1
         and r['kind'] == 'QT612_REFERENCE_PAIR_TRANSPORT_RECEIPT_V1'
         and r['recipe_commit'] == b['recipe_commit']
         and r['recipe_contract_sha256'] == b['recipe_contract_sha256'] and r['Root_acceptance'] is None,
         'new F69a-bound C producer contract receipt required')
    need(type(r['producer']) is dict and set(r['producer']) == {
        'source_commit', 'source_map_sha256', 'program_sha256', 'finisher_sha256', 'contract_sha256'}
        and re.fullmatch('[0-9a-f]{40}', r['producer']['source_commit'])
        and all(digest(v) for k, v in r['producer'].items() if k != 'source_commit'), 'pinned C producer contract')
    need(type(r['run']) is dict and set(r['run']) == {'repository', 'head_sha', 'run_id', 'run_attempt', 'job_id'}
         and r['run']['repository'] == 'Gabriel-Kahen/cachy-asahi'
         and re.fullmatch('[0-9a-f]{40}', r['run']['head_sha'])
         and all(type(r['run'][k]) is str and re.fullmatch('[1-9][0-9]{0,19}', r['run'][k])
                 for k in ('run_id', 'run_attempt', 'job_id')), 'finite actual run binding')
    need(type(r['files']) is dict and set(r['files']) == payload_names(b), 'exact14 public payload roles')
    for row in r['files'].values(): descriptor(row)
    need(sum(row['bytes'] for row in r['files'].values()) < MAX_BYTES, 'payload total byte cap')
    need(type(r['pair_checks']) is dict and set(r['pair_checks']) == set(FLAGS)
         and all(v is True for v in r['pair_checks'].values()), 'all C pair checks required')
    need(type(r['provenance_operands']) is dict and set(r['provenance_operands']) == set(ATTEMPTS),
         'both provenance operand closures required')
    need(type(r['external_retention']) is dict and set(r['external_retention']) == {'store_id', 'receipt_sha256'}
         and digest(r['external_retention']['receipt_sha256'])
         and type(r['external_retention']['store_id']) is str
         and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,127}', r['external_retention']['store_id']),
         'Root-accessible external retention receipt binding required')


def validate(tree, r, b):
    """Check byte bindings and finite C assertions, without executing a comparator/payload."""
    receipt_contract(r, b)
    for name, row in r['files'].items(): tree.stream(name, row)
    def doc(name): return decode(tree.stream(name, r['files'][name], collect=True))
    comp = doc('pair/comparison.json')
    need(set(comp) == {'status', 'errors', 'packages', 'hardware_status', 'independence_limit'}
         and comp['hardware_status'] == 'NOT RUN'
         and comp['independence_limit'] == 'Distinct recorded container runs; independent machine execution is not attested.'
         and comp.get('status') == 'contents-reproduced' and comp.get('errors') == []
         and set(comp.get('packages', {})) == {b['filename']}, 'normal pair comparison required')
    need(set(comp['packages'][b['filename']]) == {'installed_contents_equal', 'pkginfo_equal', 'bytes_equal', 'buildinfo_equal'}
         and all(v is True for v in comp['packages'][b['filename']].values()), 'strict four-way pair equality required')
    finisher = doc('pair/qt-pair-finisher.json')
    need(set(finisher) == {'schema', 'kind', 'status', 'recipe_commit', 'recipe_contract_sha256',
                          'comparison_sha256', 'attempts'}
         and type(finisher['schema']) is int and finisher['schema'] == 1
         and finisher['kind'] == 'QT612_REFERENCE_PAIR_FINISHER_V1'
         and finisher['status'] == 'PASS_QT612_REFERENCE_PAIR_ONLY'
         and finisher['recipe_commit'] == b['recipe_commit']
         and finisher['recipe_contract_sha256'] == b['recipe_contract_sha256']
         and finisher['comparison_sha256'] == r['files']['pair/comparison.json']['sha256']
         and set(finisher['attempts']) == set(ATTEMPTS), 'new bound Qt pair finisher required')
    provenance, external = [], 0
    for a in ATTEMPTS:
        archive = r['files'][f'{a}/artifacts/{b["filename"]}']
        p = doc(f'{a}/provenance.json'); provenance.append(p)
        need(p.get('status') == 'built-package-static-pass' and p.get('mode') == 'native'
             and p.get('network') == 'none' and type(p.get('exit_code')) is int and p['exit_code'] == 0
             and p.get('builder_host_arch') in ('arm64', 'aarch64')
             and p.get('recipe_inputs') == b['recipe_inputs']
             and p.get('artifacts') == {b['filename']: archive['sha256']}, 'exact native F69a provenance assertion')
        need(type(p.get('image')) is str and re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[0-9a-f]{64}', p['image'])
             and type(p.get('image_id')) is str and re.fullmatch('sha256:[0-9a-f]{64}', p['image_id'])
             and digest(p.get('expected_packages_sha256')) and digest(p.get('entry_script_sha256'))
             and type(p.get('source_date_epoch')) is int and p['source_date_epoch'] >= 0
             and p.get('recipe_metadata') == b['recipe_metadata']
             and type(p.get('source_material')) is dict and bool(p['source_material']), 'finite pinned native build inputs')
        required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                    'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                    'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
        need(type(p.get('files')) is dict and required <= set(p['files']), 'normal comparator operand closure missing')
        operands = {}
        for group in ('files', 'artifacts', 'recipe_inputs'):
            need(type(p.get(group)) is dict and 0 < len(p[group]) <= MAX_FILES, 'finite complete provenance maps')
            for name, checksum in p[group].items():
                name = ('' if group == 'files' else 'artifacts/' if group == 'artifacts' else 'inputs/') + member(name)
                need(digest(checksum) and (name not in operands or operands[name] == checksum), 'conflicting provenance aliases')
                operands[name] = checksum
        partition = r['provenance_operands'][a]
        need(type(partition) is dict and set(partition) == set(operands) and len(partition) <= MAX_FILES,
             'exact included/external provenance partition required')
        for name, checksum in operands.items():
            row = partition[name]; need(type(row) is dict, 'operand descriptor required')
            descriptor({k: row[k] for k in ('bytes', 'sha256')}, mode=False)
            need(row['sha256'] == checksum, 'operand hash differs from unchanged provenance')
            aliases = {a + '/' + name}
            for original, exported in (('artifacts/qt612-stage-contract.json', 'stage-contract.json'),
                                       ('artifacts/qt612-check-receipt.json', 'check-receipt.json'),
                                       ('artifacts/qt612-license-receipt.json', 'license-receipt.json')):
                if name == original: aliases.add(a + '/' + exported)
            if row.get('disposition') == 'included':
                need(set(row) == {'bytes', 'sha256', 'disposition', 'transport_path'}
                     and row['transport_path'] in aliases and row['transport_path'] in r['files']
                     and {k: row[k] for k in ('bytes', 'sha256')} == {
                         k: r['files'][row['transport_path']][k] for k in ('bytes', 'sha256')}, 'included operand alias/pin mismatch')
            else:
                need(set(row) == {'bytes', 'sha256', 'disposition', 'external_store_key'}
                     and row['disposition'] == 'external_retained' and digest(row['external_store_key']),
                     'explicit externally retained operand required')
                need(not aliases.intersection(r['files']), 'included operand cannot be hidden externally')
                external += 1
        validation = doc(f'{a}/validation.json')
        need(validation.get('errors') == [] and type(validation.get('artifacts')) is list
             and len(validation['artifacts']) == 1
             and validation['artifacts'][0].get('sha256') == archive['sha256']
             and validation['artifacts'][0].get('errors') == [], 'bound package validation required')
        stage = doc(f'{a}/stage-contract.json')
        need(set(stage) == {'status', 'architecture', 'evidence_scope', 'files', 'symlinks', 'directories',
                            'elf', 'payload_bytes', 'native_execution', 'installation', 'hardware'}
             and stage['native_execution'] == 'NOT_ESTABLISHED' and stage['installation'] == 'NOT_RUN'
             and stage['hardware'] == 'NOT_RUN'
             and all(type(stage[k]) is dict for k in ('files', 'symlinks', 'directories', 'elf'))
             and type(stage['payload_bytes']) is int and 0 < stage['payload_bytes'] <= 1024**3
             and stage.get('status') == 'PASS_QT612_DESTDIR_CONTRACT_ONLY' and stage.get('architecture') == 'aarch64'
             and stage.get('evidence_scope') == 'STAGED_AARCH64_ELF_ONLY', 'AArch64 stage receipt required')
        check = doc(f'{a}/check-receipt.json')
        check_operand = 'artifacts/' + b['filename'].removesuffix('.pkg.tar.xz') + '-check.log'
        need(check_operand in p['files'] and partition[check_operand]['bytes'] > 0, 'original normal check log binding required')
        check_log = {'operand': check_operand, 'bytes': partition[check_operand]['bytes'],
                     'sha256': p['files'][check_operand]}
        need(type(check.get('schema')) is int and check.get('normal_makepkg_check') is True
             and check == {'schema': 1, 'status': 'PASS_QT612_OFFSCREEN_API_SMOKE_ONLY', 'normal_makepkg_check': True,
                       'recipe_commit': b['recipe_commit'], 'archive_sha256': archive['sha256'], 'check_log': check_log}
             and encoded(check['check_log']) == encoded(check_log), 'own normal check receipt required')
        license_receipt = doc(f'{a}/license-receipt.json')
        need(license_receipt == {'status': 'PASS_QT612_SOURCE_NOTICES_ONLY', 'notices': 173, 'bytes': 636122,
                                'notice_policy_sha256': b['notice_policy_sha256'], 'archive_sha256': archive['sha256']},
             'pinned notice-policy/archive receipt required')
        expected = {'archive': {k: archive[k] for k in ('bytes', 'sha256')},
                    'provenance_sha256': r['files'][f'{a}/provenance.json']['sha256'],
                    'stage_canonical_sha256': sha(encoded(stage)),
                    'check_receipt_sha256': r['files'][f'{a}/check-receipt.json']['sha256'],
                    'license_receipt_sha256': r['files'][f'{a}/license-receipt.json']['sha256']}
        need(encoded(finisher['attempts'][a]) == encoded(expected), 'Qt finisher binding differs from transported bytes')
    need(all(type(p.get('clean_environment_id')) is str and re.fullmatch(
                 '[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', p['clean_environment_id']) for p in provenance)
         and provenance[0]['clean_environment_id'] != provenance[1]['clean_environment_id'], 'distinct clean attempts required')
    for key in ('image', 'image_id', 'source_date_epoch', 'expected_packages_sha256', 'entry_script_sha256',
                'recipe_metadata', 'source_material'):
        need(key in provenance[0] and key in provenance[1] and provenance[0][key] == provenance[1][key],
             'pair input binding differs: ' + key)
    need(r['files'][f'build-1/artifacts/{b["filename"]}'] == r['files'][f'build-2/artifacts/{b["filename"]}'],
         'actual archive whole pins differ')
    tree.stable()
    return external


def manifest_for(r, receipt_raw, external):
    return {'schema': 1, 'kind': 'QT612_REFERENCE_TRANSPORT_MANIFEST_V1', 'recipe_commit': r['recipe_commit'],
            'run': r['run'], 'files': dict(r['files'], **{'producer-receipt.json': {
                'bytes': len(receipt_raw), 'sha256': sha(receipt_raw), 'mode': 0o644}}),
            'external_operands': external, 'external_readback_required': bool(external),
            'offline_comparison_complete': False, 'Root_acceptance': None, 'native_acceptance': False}


def collect(source, receipt, receipt_sha256, output):
    raw = read_one(receipt, receipt_sha256); r = decode(raw); b = basis(); receipt_contract(r, b)
    source, output, receipt = ordinary(source), ordinary(output), ordinary(receipt)
    need(not output.exists() and not output.is_relative_to(source) and not source.is_relative_to(output)
         and not receipt.is_relative_to(output) and output.parent.is_dir(), 'fresh disjoint export required')
    tree = Tree(source, r['files'])
    try:
        parent_id = Export.directory_id(output.parent.lstat())
        need(parent_id[:2] not in {Export.directory_id(os.fstat(fd))[:2] for fd, _ in tree.dirs.values()},
             'export parent aliases source directory')
        external = validate(tree, r, b)
        manifest = manifest_for(r, raw, external); mr = encoded(manifest)
        need(len(r['files']) + 2 <= MAX_FILES and sum(v['bytes'] for v in r['files'].values())
             + len(raw) + len(mr) <= MAX_BYTES and len(mr) <= MAX_JSON, 'complete transport budget exceeded')
        writer = Export(output, parent_id)
        try:
            for name, row in r['files'].items(): writer.put(name, source=tree, expected=row)
            writer.put('producer-receipt.json', raw=raw)
            # Manifest is a completion marker, written after all byte copies/readback succeed.
            copied = Tree(output, manifest['files'])
            try:
                for name, row in manifest['files'].items(): copied.stream(name, row)
            finally: copied.close()
            tree.stable(); writer.put('transport-manifest.json', raw=mr)
        finally: writer.close()
        return verify(output, sha(mr), receipt_sha256)
    finally: tree.close()


def verify(root, manifest_sha256, receipt_sha256):
    root = ordinary(root); raw = read_one(root / 'transport-manifest.json', manifest_sha256)
    manifest = decode(raw); receipt_raw = read_one(root / 'producer-receipt.json', receipt_sha256)
    r, b = decode(receipt_raw), basis(); receipt_contract(r, b)
    need(len(r['files']) + 2 <= MAX_FILES, 'file count cap')
    tree = Tree(root, set(r['files']) | {'producer-receipt.json', 'transport-manifest.json'})
    try:
        need(sum((root / name).lstat().st_size for name in tree.files) <= MAX_BYTES, 'whole directory byte cap')
        external = validate(tree, r, b)
        need(raw == encoded(manifest_for(r, receipt_raw, external)), 'exact canonical manifest required')
        tree.stream('producer-receipt.json', manifest['files']['producer-receipt.json'])
        tree.stream('transport-manifest.json', {'bytes': len(raw), 'sha256': manifest_sha256, 'mode': 0o644})
        tree.stable()
        return {'status': 'PASS_TRANSPORT_BYTES_ONLY', 'manifest_sha256': manifest_sha256,
                'receipt_sha256': receipt_sha256, 'files': len(tree.files),
                'external_operands': external, 'external_readback_required': bool(external),
                'offline_comparison_complete': False, 'native_acceptance': False, 'Root_acceptance': None}
    finally: tree.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='command', required=True)
    c = sub.add_parser('collect'); c.add_argument('--source', type=Path, required=True)
    c.add_argument('--receipt', type=Path, required=True); c.add_argument('--output', type=Path, required=True)
    v = sub.add_parser('verify'); v.add_argument('--root', type=Path, required=True)
    v.add_argument('--manifest-sha256', required=True)
    for p in (c, v): p.add_argument('--receipt-sha256', required=True)
    args = vars(parser.parse_args()); command = args.pop('command')
    try:
        result = collect(**args) if command == 'collect' else verify(**args)
        print(json.dumps(result, sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError, MemoryError) as error:
        print(json.dumps({'status': 'HOLD_TRANSPORT_INCOMPLETE', 'reason': str(error),
                          'native_acceptance': False, 'Root_acceptance': None}, sort_keys=True)); return 1


if __name__ == '__main__': sys.exit(main())
