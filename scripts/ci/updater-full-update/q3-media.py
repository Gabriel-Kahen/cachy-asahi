# SPDX-License-Identifier: MIT
"""Verify and seal the media for one unissued offline Q3 updater trial."""

import argparse
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import tarfile
import tempfile
import time
from types import SimpleNamespace
from uuid import UUID

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
REQUEST = 'UPDATER_Q3_SIGNED_MEDIA_REQUEST_V1'
PREPARATION = 'UPDATER_Q3_PREPARATION_UNISSUED'
MEDIA = 'UPDATER_Q3_MEDIA_V1'
GUEST = 'cachy-asahi-updater16k-disposable-v1'
CASES = frozenset(('update', 'signature-refusal'))
ENTRIES = ('fixture.db', 'fixture.db.sig')
SHA = re.compile('[a-f0-9]{64}')
FINGERPRINT = re.compile('[0-9A-F]{40}')
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
DISK_BYTES, DISK_LABEL = 128 << 20, 'UPDATER16K'
MAX_DB_TAR = 64 << 10


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(data):
    return {'bytes': len(data), 'sha256': sha(data)}


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def document(raw):
    def unique(pairs):
        value = dict(pairs)
        need(len(value) == len(pairs), 'duplicate JSON key')
        return value
    def invalid(_value):
        raise ValueError('non-finite JSON value')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read_pins(client, root, pins, limits):
    need(type(pins) is dict and pins.keys() == limits.keys(), 'exact media pin set required')
    fd = client['directory'](root)
    try:
        result = {}
        for name, limit in limits.items():
            expected = pins[name]
            need(type(expected) is dict and set(expected) == {'bytes', 'sha256'}
                 and type(expected['bytes']) is int and 0 < expected['bytes'] <= limit
                 and type(expected['sha256']) is str and SHA.fullmatch(expected['sha256']),
                 'bounded media pin required')
            body = client['read_member'](fd, name, limit)
            need(pin(body) == expected, 'media member differs: ' + name)
            result[name] = body
        return result
    finally:
        os.close(fd)


def document_at(client, path, expected_sha):
    need(type(expected_sha) is str and SHA.fullmatch(expected_sha), 'external document pin required')
    raw = client['read_path'](path, 64 << 10)
    need(sha(raw) == expected_sha, 'external document pin differs')
    value = document(raw)
    need(type(value) is dict, 'JSON object required')
    return value


def request_selection(value, prep, prep_sha, now):
    need(set(value) == {'kind', 'case', 'preparation_sha256', 'valid_from', 'expires', 'signer', 'files'}
         and value['kind'] == REQUEST and value['preparation_sha256'] == prep_sha
         and type(value['case']) is str and value['case'] in CASES and value['case'] == prep.get('case')
         and type(value['signer']) is str and FINGERPRINT.fullmatch(value['signer'])
         and type(value['valid_from']) is type(value['expires']) is int
         and 0 < value['valid_from'] <= now < value['expires']
         and value['expires'] - value['valid_from'] <= 86400,
         'exact current signed-media request required')
    config = prep.get('input_ext4')
    need(prep.get('kind') == PREPARATION and 'authority' in prep and prep['authority'] is None
         and prep.get('base_inventory') == 356 and prep.get('target_inventory') == 362
         and type(prep.get('nonce')) is str and re.fullmatch(r'[0-9a-f]{32}', prep['nonce'])
         and type(config) is dict and set(config) == {'bytes', 'label', 'uuid'}
         and type(config['bytes']) is int and config['bytes'] == DISK_BYTES
         and config['label'] == DISK_LABEL and type(config['uuid']) is str
         and str(UUID(config['uuid'])) == config['uuid'], 'exact unissued Q3 media geometry required')
    return config['uuid']


def limits(guest, runtime):
    old, new = guest['OLD_ARCHIVE'], guest['REPO'][2]
    unsigned = {'q3.lock': 16384, 'before.lock': 16384, 'hooks.list': 8192,
                old: 1 << 20, 'repo/' + new: 1 << 20}
    fixed = {}
    for name, _url, expected in runtime['runtime_files']():
        if not name.startswith('xdg-utils-'):
            fixed['vendor/' + name] = {'bytes': expected[0], 'sha256': expected[1]}
    key_size, key_sha = runtime['KEYRING_PIN']
    fixed['vendor/' + runtime['KEYRING']] = {'bytes': key_size, 'sha256': key_sha}
    unsigned.update({name: ref['bytes'] for name, ref in fixed.items()})
    signed = {'TEST-public.gpg': 8192, 'updater.pkg': 64 << 20, 'updater.pkg.sig': 16384,
              old + '.sig': 16384, 'repo/' + new + '.sig': 16384,
              'repo/' + ENTRIES[0]: 1 << 20, 'repo/' + ENTRIES[1]: 16384,
              **{name: 1 << 20 for name in guest['POLICIES']}}
    need(set(unsigned) | set(signed) == guest['FILES'] | set(fixed) | {'TEST-public.gpg'},
         'guest and sealer fixture shapes differ')
    return unsigned, fixed, signed


def descriptor(raw, member_name):
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
        body = handle.read(MAX_DB_TAR + 1)
    need(len(body) <= MAX_DB_TAR, 'repository database tar exceeds bound')
    fields = None
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:') as archive:
        need(not archive.pax_headers, 'unexpected repository pax headers')
        for row in archive:
            name = row.name.removeprefix('./')
            need(name not in seen and not row.pax_headers and row.sparse is None,
                 'duplicate or extended repository database member')
            seen.add(name)
            if name == member_name.rsplit('/', 1)[0] and row.isdir() and row.size == 0:
                continue
            need(name == member_name and row.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                 and 0 < row.size <= 16384 and fields is None, 'unexpected repository database member')
            with archive.extractfile(row) as stream:
                data = stream.read(16385)
            need(len(data) == row.size, 'truncated repository descriptor')
            fields = data.decode('utf-8')
        need(not archive.pax_headers and not any(body[archive.offset:]), 'extended or trailing repository data')
    need(fields is not None and fields.endswith('\n\n'), 'missing or malformed repository descriptor')
    result = {}
    for block in fields[:-2].split('\n\n'):
        header, *values = block.split('\n')
        need(re.fullmatch(r'%[A-Z0-9_]+%', header) and header not in result
             and len(values) == 1 and len(values[0]) > 0, 'ambiguous repository descriptor field')
        result[header] = values[0]
    return result


def verify_repository(guest, data, case):
    new = guest['REPO'][2]
    archive = data['repo/' + new]
    signed = data['repo/' + new + '.sig']
    old_signature = data[guest['OLD_ARCHIVE'] + '.sig']
    need((signed == old_signature) == (case == 'signature-refusal'), 'case signature relationship differs')
    fields = descriptor(data['repo/fixture.db'], f"{guest['NAME']}-{guest['NEW']}/desc")
    expected = {'%NAME%': guest['NAME'], '%VERSION%': guest['NEW'], '%ARCH%': 'any', '%FILENAME%': new,
                '%SHA256SUM%': sha(archive), '%PGPSIG%': base64.b64encode(signed).decode()}
    optional = {'%BASE%': guest['NAME'], '%CSIZE%': str(len(archive)),
                '%ISIZE%': str(len(guest['fixture_payload'](guest['NEW']))),
                '%MD5SUM%': hashlib.md5(archive, usedforsecurity=False).hexdigest(),
                '%DESC%': 'Disposable update-check test data', '%URL%': 'https://test.invalid/',
                '%LICENSE%': 'MIT', '%BUILDDATE%': '1', '%PACKAGER%': 'TEST ONLY'}
    need(all(fields.get(name) == val for name, val in expected.items())
         and all(name in expected or optional.get(name) == val for name, val in fields.items()),
         'repository differs from the sole inert signed candidate')


def verify_policy(policy, data):
    accepted, pre, post, protected, observed = (
        document(data[name]) for name in ('policy.json', 'pre.json', 'post.json',
                                          'protected-policy.json', 'protected-pre.json'))
    need(accepted['release_id'] == protected['release_id'] == 'synthetic-test-only',
         'disposable synthetic policy required')
    evaluate = policy['evaluate']
    for operation in ('repository-update', 'orphan-removal', 'package-cache-removal'):
        need(evaluate(accepted, pre, action='transaction', operation=operation)['decision']
             == 'transaction-allowed', 'generic operation must pass policy')
    need(evaluate(accepted, post, action='kernel')['decision'] == 'no-kernel-change',
         'generic observation must preserve the kernel')
    refusal = evaluate(protected, observed, action='transaction', operation='repository-update')
    need(refusal['decision'] == 'coordination-required' and refusal['reason'] == 'protected-platform-changed'
         and refusal['protected_changes'] == ['asahi-audio'], 'exact protected-audio refusal required')


def command(args, home):
    result = subprocess.run(args, cwd=home, env=ENV | {'HOME': str(home), 'GNUPGHOME': str(home)},
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    need(len(result.stdout) + len(result.stderr) <= 64 << 10, 'GPG diagnostic exceeds bound')
    return result


def expected_bad_signature(result, signer):
    status = [row for line in result.stdout.decode('utf-8').splitlines()
              if line.startswith('[GNUPG:] ') and len(row := line.split()) >= 2]
    bad = [row for row in status if len(row) >= 3 and row[1] == 'BADSIG']
    excluded = {'GOODSIG', 'VALIDSIG', 'ERRSIG', 'NO_PUBKEY', 'NODATA', 'KEYEXPIRED', 'SIGEXPIRED',
                'EXPKEYSIG', 'EXPSIG', 'REVKEYSIG', 'KEYREVOKED', 'BADARMOR'}
    return (result.returncode != 0 and len(bad) == 1 and re.fullmatch('[0-9A-F]{16}', bad[0][2])
            and signer.endswith(bad[0][2]) and sum(row[1] == 'NEWSIG' for row in status) == 1
            and not any(row[1] in excluded for row in status))


def verify_signatures(client, setup, guest, stage, home, request, now):
    signer = request['signer']
    need(signer != setup['OFFICIAL'], 'TEST signer must differ from official signer')
    args = setup['gpg'](home)
    public = stage / 'TEST-public.gpg'
    result = command((*args, '--with-colons', '--fingerprint', '--show-keys', str(public)), home)
    records = result.stdout.decode('utf-8')
    need(result.returncode == 0 and setup['selected_test_key'](records, signer, now),
         'one current public TEST primary required')
    primary, = [line.split(':') for line in records.splitlines() if line.startswith('pub:')]
    need(int(primary[5]) <= request['valid_from'] and request['expires'] <= int(primary[6]),
         'media validity must fit the TEST key lifetime')
    need(command((*args, '--import', str(public)), home).returncode == 0, 'TEST public import refused')
    instant = datetime.fromtimestamp(now, timezone.utc)
    new = 'repo/' + guest['REPO'][2]
    for name in ('updater.pkg', guest['OLD_ARCHIVE'], 'repo/fixture.db', new):
        result = command((*args, '--status-fd', '1', '--verify', '--',
                          str(stage / (name + '.sig')), str(stage / name)), home)
        if name == new and request['case'] == 'signature-refusal':
            need(expected_bad_signature(result, signer), 'intentional NEW signature mismatch was not observed')
        else:
            need(result.returncode == 0 and
                 client['signature_status'](result.stdout, signer, instant)['signing_fingerprint'] == signer,
                 'detached signature differs: ' + name)


def verify_image(reader, image, uuid, expected):
    with reader(image, max_nodes=64, max_file_bytes=64 << 20) as fs:
        nodes = fs.inventory()['nodes']
        need(fs.size == DISK_BYTES and fs.uuid == uuid
             and fs.read(1024 + 120, 16).rstrip(b'\0') == DISK_LABEL.encode(), 'sealed media geometry differs')
    folders = {'.', 'repo', 'vendor', 'lost+found'}
    need(set(nodes) == folders | expected.keys(), 'unexpected sealed media members')
    for name in folders:
        row = nodes[name]
        need(row['type'] == 'directory' and row['mode'] == (0o700 if name == 'lost+found' else 0o755)
             and row['uid'] == row['gid'] == 0 and not row['xattrs'], 'sealed media directory differs')
    for name, info in expected.items():
        row = nodes[name]
        need(row['type'] == 'file' and row['mode'] == 0o444 and row['links'] == 1
             and row['uid'] == row['gid'] == 0 and not row['xattrs']
             and {'bytes': row['size'], 'sha256': row['sha256']} == info, 'sealed media file differs: ' + name)


def pack(params, reader, tools, parent, stage, image, uuid, expected):
    with image.open('xb') as stream:
        stream.truncate(DISK_BYTES)
    tools.run('mke2fs', ['-q', '-F', '-t', 'ext4', '-b', '4096', '-m', '0', '-L', DISK_LABEL, '-U', uuid,
                         '-O', '^orphan_file', '-E', 'lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0',
                         '-d', stage, image], parent)
    # mke2fs preserves source ownership for copied leaves. Set guest uid/gid
    # in our new image without requiring privileged host file operations.
    edits = parent / 'media.debugfs'
    edits.write_text(''.join(f'set_inode_field /{name} {field} 0\n'
                             for name in ('repo', 'vendor', *sorted(expected)) for field in ('uid', 'gid')))
    tools.run('debugfs', ['-w', '-f', edits, image], parent)
    tools.run('e2fsck', ['-fn', image], parent)
    verify_image(reader, image, uuid, expected)
    image.chmod(0o444)
    return params['observe'](image, DISK_BYTES)[1]


def select(args, modules, now):
    client, guest, setup, runtime = (modules[name] for name in ('client', 'guest', 'setup', 'runtime'))
    prep = document_at(client, args.packet / 'PLAN.UNISSUED.json', args.preparation_sha256)
    req = document_at(client, args.signed / 'request.json', args.signed_sha256)
    uuid = request_selection(req, prep, args.preparation_sha256, now)
    unsigned, fixed, signed = limits(guest, runtime)
    unsigned_pins = prep.get('unsigned_media')
    need(type(unsigned_pins) is dict and all(unsigned_pins.get(name) == value for name, value in fixed.items()),
         'retained vendor pairs differ')
    repos = {name.removeprefix('repo/') for name in signed if name.startswith('repo/')}
    repo = args.signed / 'repo'
    need(not repo.is_symlink() and repo.is_dir()
         and {path.name for path in args.signed.iterdir()}
         == {name for name in signed if '/' not in name} | {'repo', 'request.json'}
         and {path.name for path in repo.iterdir()} == repos,
         'signed selection contains unrelated material')
    data = read_pins(client, args.packet / 'unsigned-media', unsigned_pins, unsigned)
    data.update(read_pins(client, args.signed, req['files'], signed))
    need(sha(data['updater.pkg']) == guest['UPDATER'] and sha(data['q3.lock']) == guest['Q3_LOCK']
         and sha(data['before.lock']) == setup['BEFORE_SHA'], 'qualified package or Q3 lock differs')
    guest['expected_inventories'](data['q3.lock'], data['before.lock'])
    guest['verify_fixture_archive'](data[guest['OLD_ARCHIVE']], guest['OLD'])
    guest['verify_fixture_archive'](data['repo/' + guest['REPO'][2]], guest['NEW'])
    hooks = data['hooks.list']
    need(pin(hooks) == {'bytes': modules['prep']['HOOKS'][0], 'sha256': modules['prep']['HOOKS'][1]},
         'exact Q3 hook list required')
    verify_policy(modules['policy'], data)
    verify_repository(guest, data, req['case'])
    plan = {name: req[name] for name in ('case', 'valid_from', 'expires', 'signer')}
    plan.update(kind=GUEST, files={name: sha(data[name]) for name in sorted(guest['FILES'])})
    return data | {'plan.json': json_bytes(plan)}, req, uuid


def seal(args, modules):
    output = args.output
    parent = output.parent
    need(all(path.is_absolute() and path.resolve() == path for path in (args.packet, args.signed, output))
         and all(root.is_dir() and not output.is_relative_to(root) and not root.is_relative_to(output)
                 for root in (args.packet, args.signed))
         and parent.stat().st_uid == os.geteuid() and not parent.stat().st_mode & 0o022
         and not os.path.lexists(output), 'fresh output disjoint from inputs under an owned parent required')
    now = int(time.time())
    data, request, uuid = select(args, modules, now)
    with tempfile.TemporaryDirectory(prefix='.updater-q3-media-', dir=parent) as tmp:
        work = Path(tmp)
        tree, home, published = (work / name for name in ('tree', 'gnupg', 'published'))
        for folder in (tree, home, published, tree / 'repo', tree / 'vendor'):
            folder.mkdir(mode=0o700)
        for name, body in data.items():
            modules['params']['new'](tree / name, body)
        verify_signatures(modules['client'], modules['setup'], modules['guest'], tree, home, request, now)
        for folder in (tree, tree / 'repo', tree / 'vendor'):
            folder.chmod(0o755)
        expected = {name: pin(body) for name, body in data.items()}
        media = pack(modules['params'], modules['reader'], modules['tools'](), work, tree,
                     published / 'media.raw', uuid, expected)
        need(int(time.time()) < request['expires'], 'signed-media request expired during packing')
        receipt = {'kind': MEDIA, 'preparation_sha256': args.preparation_sha256, 'case': request['case'],
                   'plan': expected['plan.json'], 'media': media}
        modules['params']['new'](published / 'media.json', json_bytes(receipt))
        modules['params']['new'](published / 'plan.json', data['plan.json'])
        need(not os.path.lexists(output), 'output appeared during packing')
        published.rename(output)
    return receipt


def dependencies():
    qt = REPO / 'scripts/integration/qt612_gui_16k_link_checkpoint'
    prep = runpy.run_path(str(HERE / 'prepare_q3.py'))
    def tools():
        formatting = runpy.run_path(str(qt / 'prepare.py'))['Formatting']
        capsule = SimpleNamespace(**runpy.run_path(str(qt / 'gui_capsule.py')))
        return formatting(capsule, {name: {'path': f'/usr/bin/{name}', 'bytes': size, 'sha256': digest}
                                    for name, (size, digest) in prep['TOOLS'].items()})
    return {'guest': runpy.run_path(str(HERE / 'guest.py')), 'setup': runpy.run_path(str(HERE / 'q3-setup.py')),
            'client': runpy.run_path(str(REPO / 'scripts/client/client.py')),
            'policy': runpy.run_path(str(REPO / 'packages/tools/cachy-asahi-update/asahi-policy.py')),
            'params': runpy.run_path(str(REPO / 'scripts/integration/qt612_md4c_compile/prepare.py')),
            'runtime': runpy.run_path(str(REPO / 'scripts/port/updater-native-stage/runtime_intake.py')),
            'reader': runpy.run_path(str(REPO / 'scripts/integration/arm16k_perl5423_vm/frozen/independent_readback.py'))['Ext4Reader'],
            'prep': prep, 'tools': tools}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ('packet', 'signed', 'output'):
        parser.add_argument('--' + role, type=Path, required=True)
    for role in ('preparation-sha256', 'signed-sha256'):
        parser.add_argument('--' + role, required=True)
    result = seal(parser.parse_args(), dependencies())
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
