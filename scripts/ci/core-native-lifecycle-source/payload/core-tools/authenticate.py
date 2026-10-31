#!/usr/bin/env python3
"""Authenticate a finite generic proposal's archives as data; never install."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
import native_arm as native
import preview

SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
CACHE = Path('/tmp/cachy-asahi-port-auth-cache')
MAX_BYTES = 300_000_000
KEY_FIELDS = {'filename', 'sha256', 'size', 'url'}
ARCHIVE_FIELDS = {'name', 'version', 'arch', 'filename', 'sha256', 'size', 'url',
                  'signature_sha256', 'signature_size', 'license', 'depends', 'provides',
                  'conflicts', 'replaces', 'source_url', 'repo', 'isize'}


def validate(lock):
    preview.need(set(lock) == {'schema', 'scope', 'signer_fingerprint', 'keyring_files', 'packages',
                             'proposal_sha256', 'preview_receipt_sha256', 'builder_lock_sha256',
                             'repository_databases'}, 'unknown archive-lock field')
    preview.need(lock['schema'] == 1 and lock['scope'] == 'GENERIC-desktop-data-authentication' and
                 lock['signer_fingerprint'] == SIGNER, 'scope/signer refused')
    for k in ('proposal_sha256', 'preview_receipt_sha256', 'builder_lock_sha256'):
        native.check_pin(lock[k])
    preview.need([r['name'] for r in lock['repository_databases']] == ['core', 'extra'], 'snapshot set refused')
    preview.need(len(lock['packages']) == 233, 'exact 233 added archive set required')
    total, names = 0, set()
    for item in lock['packages']:
        preview.need(set(item) == ARCHIVE_FIELDS and item['repo'] in ('core', 'extra'), 'archive record scope refused')
        preview.need(preview.NAME.fullmatch(item['name']) and item['arch'] in ('aarch64', 'any') and
                     item['filename'] == f'{item["name"]}-{item["version"]}-{item["arch"]}.pkg.tar.xz', 'archive identity refused')
        expected = f'https://ca.us.mirror.archlinuxarm.org/aarch64/{item["repo"]}/{item["filename"]}'
        preview.need(item['url'] == expected, 'nonofficial archive URL refused')
        preview.need(item['filename'] not in names, 'duplicate archive')
        names.add(item['filename'])
        for k in ('sha256', 'signature_sha256'):
            native.check_pin(item[k])
        preview.need(isinstance(item['size'], int) and 0 < item['size'] <= MAX_BYTES and
                     isinstance(item['signature_size'], int) and 0 < item['signature_size'] <= 65536 and
                     isinstance(item['isize'], int) and 0 <= item['isize'] <= 2**31, 'archive bound refused')
        total += item['size'] + item['signature_size']
    preview.need(total <= MAX_BYTES, 'total download bound refused')
    preview.need(len(lock['keyring_files']) == 3, 'key file set refused')
    for k in lock['keyring_files']:
        preview.need(set(k) == KEY_FIELDS and k['filename'] in
                     {'archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked'}, 'key file refused')
        native.check_pin(k['sha256'])
    preview.need(len({k['filename'] for k in lock['keyring_files']}) == 3, 'duplicate key file')
    return total


def fetch(item, cache):
    # Keep the audited streaming pin/size implementation, add official redirect boundary.
    original = native.urllib.request.urlopen
    def official(request, *args, **kwargs):
        response = original(request, *args, **kwargs)
        url = urllib.parse.urlsplit(response.url)
        if url.scheme != 'https' or url.hostname != 'ca.us.mirror.archlinuxarm.org' or url.query or url.fragment:
            response.close()
            raise ValueError('nonofficial archive redirect refused')
        return response
    # A local opener avoids changing shared urllib state across worker threads.
    target = cache / item['filename']
    if target.exists() or target.is_symlink():
        preview.need(not target.is_symlink() and target.is_file() and target.stat().st_size == item['size'] and
                     native.sha(target) == item['sha256'], 'cached archive pin mismatch')
        return target
    fd, tmp = tempfile.mkstemp(prefix='archive-', suffix='.partial', dir=cache)
    temporary = Path(tmp)
    try:
        with os.fdopen(fd, 'wb') as out, official(item['url'], timeout=60) as response:
            size = 0
            while b := response.read(1024**2):
                size += len(b)
                preview.need(size <= item['size'], 'download exceeded pinned size')
                out.write(b)
        preview.need(temporary.stat().st_size == item['size'] and native.sha(temporary) == item['sha256'],
                     'download SHA256/size mismatch')
        temporary.rename(target)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def observe(path, expected):
    metadata, buildinfo, paths, links, elf, hooks, licenses, seen = None, None, [], [], [], [], [], set()
    size = 0
    with tarfile.open(path, 'r|xz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            preview.need(name and not name.startswith('/') and '..' not in Path(name).parts and
                         name not in seen and len(seen) < 400000, 'unsafe/duplicate archive path')
            seen.add(name)
            preview.need(member.isdir() or member.isfile() or member.issym() or member.islnk(), 'special archive node refused')
            if name not in ('.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL'):
                paths.append(name)
            if member.issym() or member.islnk():
                # Observations only, no link or tree materialization.
                preview.need(not member.islnk() or not member.linkname.startswith('/') and '..' not in Path(member.linkname).parts,
                             'unsafe hardlink archive target')
                links.append({'path': name, 'target': member.linkname, 'type': 'symlink' if member.issym() else 'hardlink'})
            is_hook = name == '.INSTALL' or name.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) and not member.isdir()
            if name in ('.PKGINFO', '.BUILDINFO') or is_hook:
                preview.need(member.isfile() and member.size <= 1024**2, 'unsafe/oversized metadata/scriptlet/hook')
                data = archive.extractfile(member).read()
                if name == '.PKGINFO':
                    metadata = native.pkginfo(data.decode())
                elif name == '.BUILDINFO':
                    buildinfo = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                                 'fields': native.pkginfo(data.decode())}
                else:
                    hooks.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                                  'kind': 'install-scriptlet' if name == '.INSTALL' else 'ALPM-hook', 'executed': False})
            elif member.isfile() and name.startswith('usr/share/licenses/'):
                preview.need(member.size <= 1024**2, 'oversized license notice')
                data = archive.extractfile(member).read()
                licenses.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                                 'legal_clearance': 'NOT ESTABLISHED; retained notice observation'})
            elif member.isfile():
                size += member.size
                preview.need(size <= 2**31, 'unbounded uncompressed archive')
                data = archive.extractfile(member).read(64)
                if data.startswith(b'\x7fELF'):
                    preview.need(len(data) >= 20 and data[4] in (1, 2) and data[5] in (1, 2), 'malformed ELF header')
                    endian = '<' if data[5] == 1 else '>'
                    machine = struct.unpack(endian+'H', data[18:20])[0]
                    elf.append({'path': name, 'class': 32 if data[4] == 1 else 64, 'machine': machine,
                                'endianness': 'little' if data[5] == 1 else 'big', 'runtime': 'NOT RUN', '16K_load': 'NOT RUN'})
    preview.need(metadata is not None, 'missing PKGINFO')
    for field, key in [('pkgname','name'), ('pkgver','version'), ('arch','arch'), ('depend','depends'),
                       ('provides','provides'), ('conflict','conflicts'), ('replaces','replaces'), ('license','license')]:
        expected_values = expected[key] if isinstance(expected[key], list) else [expected[key]]
        preview.need(sorted(metadata.get(field, [])) == sorted(expected_values), f'PKGINFO mismatch: {field}')
    return {'metadata': metadata, 'buildinfo': buildinfo, 'installed_paths': paths, 'path_count': len(paths),
            'links': links, 'ELF': elf, 'hooks_and_scriptlets': hooks, 'license_notice_files': licenses,
            'license_declaration': metadata.get('license', []),
            'complete_corresponding_source_license_closure': 'NOT ESTABLISHED; declared package metadata only',
            'package_execution': 'NOT RUN'}


def status(result):
    preview.need(result.returncode == 0, 'GPG verification nonzero exit')
    native.valid_signature(result.stdout, SIGNER)
    preview.need(not any(re.search(r'^\[GNUPG:\] '+marker+r'\b', result.stdout, re.M)
                         for marker in ('FAILURE','ERROR','NODATA','BADARMOR')), 'bad GPG status')


def authenticate(lock, cache, keydir, output, lock_sha256):
    total = validate(lock)
    preview.need(cache == CACHE and not cache.is_symlink(), 'private cache path refused')
    cache.mkdir(mode=0o700, exist_ok=True)
    preview.need(cache.stat().st_uid == os.getuid() and cache.stat().st_mode & 0o077 == 0, 'private cache ownership/mode refused')
    record = {'schema': 1, 'scope': lock['scope'], 'status': 'FAIL', 'source_sha256': native.sha(Path(__file__)),
              'archive_lock_sha256': lock_sha256, 'builder_lock_sha256': lock['builder_lock_sha256'],
              'native_helper_sha256': native.sha(Path(native.__file__)), 'package_count': 233, 'bounded_bytes': total,
              'signer_fingerprint': SIGNER, 'proposal_sha256': lock['proposal_sha256'],
              'preview_receipt_sha256': lock['preview_receipt_sha256'], 'repository_databases': lock['repository_databases'],
              'download': 'read-only HTTPS archives/signatures into private cache', 'installation': 'NOT RUN',
              'target_Asahi_transaction': 'NOT RUN', 'hardware': 'NOT RUN', 'packages': [], 'failures': []}
    def save():
        native.save(output / 'authentication-receipt.json', record)
    output.mkdir(parents=True)
    (output / 'observations').mkdir()
    save()
    for k in lock['keyring_files']:
        path = keydir / k['filename']
        preview.need(path.is_file() and not path.is_symlink() and path.stat().st_size == k['size'] and
                     native.sha(path) == k['sha256'], 'official public key file pin mismatch')
    with tempfile.TemporaryDirectory(prefix='cachy-port-public-gpg-', dir='/tmp') as tmp:
        home = Path(tmp)
        gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve', '--no-autostart']
        imported = subprocess.run(gpg + ['--import', str(keydir/'archlinuxarm.gpg')], capture_output=True, text=True, timeout=60)
        preview.need(imported.returncode == 0, 'public key import failed')
        record['keyring_files'] = lock['keyring_files']
        record['key_import'] = {'exit': imported.returncode, 'secret_keys_generated': False, 'ownertrust_modified': False}
        record['gpg_version'] = subprocess.run(['/usr/bin/gpg', '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
        def download(item):
            try:
                fetch(item, cache); fetch(native.signature_item(item), cache)
                return item['name'], None
            except Exception as e:
                return item['name'], {'phase':'download', 'kind':type(e).__name__,
                    'diagnostic': str(e).replace(str(cache), '<private-cache>')[:1000]}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = dict(pool.map(download, lock['packages']))
        for item in lock['packages']:
            failure = results[item['name']]
            result = {'name':item['name'], 'version':item['version'], 'archive_sha256':item['sha256'],
                      'signature_sha256':item['signature_sha256'], 'status':'FAIL'}
            if failure:
                result['failure'] = failure
            else:
                try:
                    verify = subprocess.run(gpg + ['--status-fd','1','--verify',str(cache/(item['filename']+'.sig')),
                                                        str(cache/item['filename'])], capture_output=True,text=True,timeout=60)
                    result['gpg'] = {'exit':verify.returncode, 'status':verify.stdout,
                        'diagnostic':verify.stderr.replace(str(cache), '<private-cache>').replace(str(home), '<public-only-gpg-home>')}
                    status(verify)
                    observations = observe(cache/item['filename'], item)
                    observation_file = output / 'observations' / (item['name'] + '.json')
                    native.save(observation_file, observations)
                    result['archive_observations'] = {'file': 'observations/' + item['name'] + '.json',
                        'sha256': native.sha(observation_file), 'path_count': observations['path_count'],
                        'ELF_count': len(observations['ELF']), 'hook_scriptlet_count': len(observations['hooks_and_scriptlets']),
                        'package_execution': 'NOT RUN'}
                    result['status'] = 'PASS-authenticated-data'
                except Exception as e:
                    result['failure'] = {'phase':'signature-or-inspection','kind':type(e).__name__,
                                         'diagnostic':str(e).replace(str(cache), '<private-cache>').replace(str(home), '<public-only-gpg-home>')[:1000]}
            record['packages'].append(result)
            if result['status'] != 'PASS-authenticated-data':
                record['failures'].append({'name':item['name'], 'failure':result['failure']})
            save()
        record['verified_count'] = sum(r['status']=='PASS-authenticated-data' for r in record['packages'])
        record['status'] = 'PASS-233-authenticated-generic-archives' if record['verified_count']==233 else 'FAIL-incomplete-archive-authentication'
        save()
    record['public_only_gpg_home_removed'] = True
    save()
    return record


def bind(lock, proposal, receipt, builder):
    preview.need(lock['repository_databases']==proposal['snapshots']==receipt['snapshots'] and
                 lock['keyring_files']==builder['keyring_files'] and builder['signer_fingerprint']==SIGNER,
                 'source/key binding mismatch')
    preview.need(receipt['status']=='PASS-generic-metadata-preview' and
                 {(p['name'],p['version']) for p in lock['packages']} ==
                 {(p['name'],p['version']) for p in receipt['changes']} and len(receipt['changes'])==233 and
                 all(p['kind']=='add' for p in receipt['changes']), 'resolved addition binding mismatch')
    candidate={r['name'][0]:r for r in receipt['full_candidate_inventory']}
    sizes={r['name']:r['download_bytes'] for r in receipt['changes']}
    for item in lock['packages']:
        r=candidate[item['name']]
        for key,field in [('name','name'),('version','version'),('arch','arch'),('filename','archive_filename'),
                          ('sha256','archive_sha256'),('license','license_metadata'),('depends','depends'),
                          ('provides','provides'),('conflicts','conflicts'),('replaces','replaces'),('source_url','upstream_url')]:
            values=item[key] if isinstance(item[key],list) else [item[key]]
            preview.need(sorted(values)==sorted(r[field]), 'archive metadata/preview binding mismatch: '+key)
        preview.need(item['size']==sizes[item['name']] and item['repo']==r['repository'], 'archive size/repository binding mismatch')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ('lock','lock-sha256','proposal','preview-receipt','builder-lock','public-key-directory','output'):
        parser.add_argument('--'+field, required=True, type=Path if field != 'lock-sha256' else str)
    a=parser.parse_args()
    try:
        lock=preview.load(a.lock,a.lock_sha256)
        validate(lock)
        proposal=preview.load(a.proposal,lock['proposal_sha256'])
        receipt=preview.load(a.preview_receipt,lock['preview_receipt_sha256'])
        builder=preview.load(a.builder_lock,lock['builder_lock_sha256'])
        bind(lock,proposal,receipt,builder)
        preview.need(not a.output.exists() and not a.output.is_symlink(), 'output must be new')
        record=authenticate(lock,CACHE,a.public_key_directory,a.output,a.lock_sha256)
        print(record['status'])
        return 0 if record['status'].startswith('PASS') else 1
    except (ValueError,OSError,KeyError,subprocess.SubprocessError):
        print('REFUSED: source/key/input pin or prerequisite failure; no authentication acceptance')
        return 2


if __name__=='__main__':raise SystemExit(main())
