# SPDX-License-Identifier: MIT
"""Separately versioned Root-local identity; never invents a GitHub run."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C

LANE = 'scripts/ci/platform-namespace-vm-probe-v1'
CODE = {LANE + '/' + n for n in ('common.py', 'controller.py', 'guest.py', 'probe_exec.py', 'inside.py',
        'local.py', 'local_operator.py', 'dependencies.json', 'input-policy.json', 'local-input-policy.json')}
CODE |= {'scripts/virtual/generic16k/fixture.py', 'scripts/virtual/generic16k/build_kernel.py',
         'scripts/ci/glibc-owned-runtime/runner.py', '.github/workflows/platform-namespace-vm-probe-v1-data.yml'}


def defaults():
    value = C.defaults()
    value.update(schema=2, status='UNBOUND_ROOT_LOCAL_INPUTS_NOT_EXECUTABLE', local_id=None, nonce=None,
                 provider_manifest=None, input_provenance=None)
    return value


def selection(value):
    C.need(set(value) == set(defaults()) and type(value['schema']) is int and value['schema'] == 2 and
           value['operation'] == C.OPERATION and value['bounds'] == C.BOUNDS and
           all(type(x) is int for x in value['bounds'].values()), 'exact version2 local contract/caps')
    C.need(value['status'] == 'ROOT_BOUND_LOCAL_GENERIC16K_NAMESPACE_PROBE_INPUTS' and value['issuer'] == 'Root' and
           value['input_reviewed'] is True and value['native_permission'] is False, 'UNBOUND Root-local inputs')
    C.need(value['actual_run'] is None and re.fullmatch('[0-9a-f]{40}', value['actual_source'] or '') and
           re.fullmatch('codex/[A-Za-z0-9._/-]+', value['actual_ref'] or ''), 'local run has no GitHub run ID')
    C.relative(value['actual_ref'])
    C.need(re.fullmatch('Root-local-[A-Za-z0-9_-]{1,100}', value['local_id'] or '') and
           re.fullmatch('[0-9a-f]{32}', value['nonce'] or ''), 'explicit independently issued local identity/nonce')
    C.need(set(value['kernel']) == {'Image', 'config', 'qualification', 'release', 'source', 'run'} and
           set(value['rootfs']) == {'archive', 'manifest', 'qualification', 'source', 'run'} and
           re.fullmatch('[A-Za-z0-9_.+-]{1,128}', value['kernel']['release'] or ''), 'exact local input roles')
    # Local DATA assembly has no invented GitHub source/run; independent Root provenance is mandatory.
    C.need(set(value['input_provenance']) == {'kernel', 'rootfs', 'provider'}, 'all local input provenance roles')
    for role in ('kernel', 'rootfs'):
        row = value[role]
        C.need(row['source'] is None or re.fullmatch('[0-9a-f]{40}', row['source']), 'literal existing input source or NULL')
        C.need(row['run'] is None or type(row['run']) is int and row['run'] > 0, 'genuine input run or NULL')
    return value


def reference(row, cap):
    C.need(set(row) == {'path', 'bytes', 'sha256'}, 'exact externally pinned local DATA reference')
    return C.pinned(Path(row['path']), {k: row[k] for k in ('bytes', 'sha256')}, cap)


def tree_id(rows):
    root = {}
    for name, row in rows.items():
        C.relative(name)
        C.need(row['mode'] in ('100644', '100755', '120000') and re.fullmatch('[0-9a-f]{40}', row['oid']), 'Git DATA map row')
        at = root
        parts = name.split('/')
        for part in parts[:-1]:
            at = at.setdefault(part, {})
        at[parts[-1]] = (row['mode'], row['oid'])
    def descend(at):
        chunks = []
        for name, item in at.items():
            mode, oid = ('40000', descend(item)) if type(item) is dict else item
            chunks.append((name.encode() + (b'/' if mode == '40000' else b''),
                           mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)))
        raw = b''.join(value for _, value in sorted(chunks))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return descend(root)


def code(root, proof, value):
    C.need(root.is_absolute() and root == root.resolve() and Path(__file__).resolve().parent == root / LANE,
           'run only exact maintained local operator/code root')
    C.need(set(proof) == {'source', 'ref', 'tree', 'raw_commit', 'full_map', 'files'} and
           proof['source'] == value['actual_source'] and proof['ref'] == value['actual_ref'] and
           set(proof['files']) == CODE, 'exact maintained Git code closure')
    raw = reference(proof['raw_commit'], 1048576)
    C.need(hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == proof['source'], 'actual raw Git source')
    header = raw.split(b'\n\n', 1)[0].splitlines()
    C.need([x[5:].decode() for x in header if x.startswith(b'tree ')] == [proof['tree']], 'actual code Git tree')
    rows = C.decode(reference(proof['full_map'], 16 * 1048576))
    C.need(type(rows) is dict and len(rows) <= 30000 and tree_id(rows) == proof['tree'], 'whole Git map/tree join')
    for name, row in proof['files'].items():
        C.need(set(row) == {'bytes', 'sha256', 'mode', 'oid'} and row['mode'] == '100644' and
               rows[name] == {k: row[k] for k in ('mode', 'oid')}, 'exact Git code mode/object')
        body = C.pinned(root / name, {k: row[k] for k in ('bytes', 'sha256')}, 1048576)
        C.need(hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == row['oid'], 'actual code bytes/Git blob')
    expected_lane = {n for n in rows if n.startswith(LANE + '/')}
    actual_lane = {p.relative_to(root).as_posix() for p in (root / LANE).rglob('*')
                   if p.is_file() or p.is_symlink()}
    C.need(actual_lane == expected_lane, 'closed maintained lane; no untracked import candidates')
    return proof['files']


def provider(root, manifest, binary, expected, environment):
    C.need(root.is_absolute() and root == root.resolve() and root.is_dir() and root.stat().st_uid == os.geteuid() and
           stat.S_IMODE(root.stat().st_mode) == 0o700, 'owned0700 private provider root')
    C.need(set(manifest) == {'schema', 'status', 'host_machine', 'binary', 'files', 'host_libraries'} and
           type(manifest['schema']) is int and manifest['schema'] == 1 and manifest['status'] == 'ROOT_REVIEWED_PRIVATE_QEMU_PROVIDER' and
           manifest['host_machine'] == os.uname().machine, 'Root reviewed exact host provider')
    C.need(binary == root / C.relative(manifest['binary']) and 1 <= len(manifest['files']) <= 8192,
           'same actual private QEMU binary/root')
    total = 0
    for name, row in manifest['files'].items():
        C.relative(name)
        C.need(set(row) == {'bytes', 'sha256', 'mode'} and type(row['mode']) is int and row['mode'] in (0o600, 0o644, 0o755),
               'ordinary reviewed provider modes')
        raw = C.pinned(root / name, {k: row[k] for k in ('bytes', 'sha256')}, 128 * 1048576)
        C.need(stat.S_IMODE((root / name).stat().st_mode) == row['mode'], 'actual private provider mode')
        total += len(raw)
        C.need(total <= 256 * 1048576, 'private provider byte cap')
    C.need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()} == set(manifest['files']),
           'closed private provider namespace')
    C.need(len(manifest['host_libraries']) <= 256, 'bounded reviewed host library closure')
    for name, row in manifest['host_libraries'].items():
        C.pinned(Path(name), row, 128 * 1048576)
    raw = C.pinned(binary, expected, 128 * 1048576)
    C.need(raw[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', raw, 18)[0] == 62 and
           stat.S_IMODE(binary.stat().st_mode) == 0o755, 'actual x86_64 ELF QEMU, no implicit wrapper/daemon')
    allowed = {'LD_LIBRARY_PATH': str(root / 'usr/lib'), 'QEMU_MODULE_DIR': str(root / 'usr/lib/qemu')}
    C.need(environment == allowed, 'only exact reviewed same-process private loader/module paths')
    C.need(all((root / name).is_dir() and (root / name) == (root / name).resolve()
               for name in ('usr/lib', 'usr/lib/qemu', 'usr/share/qemu')), 'explicit private library/module/data directories')
    return dict(C.ENV, **allowed)


def authorize(args):
    raw = C.read(args.selection)
    C.need(C.pin(raw)['sha256'] == args.selection_sha256, 'external local selection pin')
    value = selection(C.decode(raw))
    authority_raw = C.read(args.local_authority)
    C.need(C.pin(authority_raw)['sha256'] == args.local_authority_sha256, 'external Root local authority pin')
    authority = C.decode(authority_raw)
    required = {'schema', 'issuer', 'status', 'approved', 'operation', 'selection', 'local_id', 'nonce',
                'host', 'bounds', 'code', 'provider_root', 'environment', 'paths', 'lease', 'reviews', 'issued_at', 'expires_at'}
    C.need(set(authority) == required and type(authority['schema']) is int and authority['schema'] == 1 and
           authority['issuer'] == 'Root' and authority['approved'] is True and
           authority['status'] == 'ROOT_ISSUED_EXCLUSIVE_LOCAL_EMULATED16K_NAMESPACE_PROBE' and
           authority['operation'] == C.OPERATION and authority['selection'] == C.pin(raw) and
           authority['local_id'] == value['local_id'] and authority['nonce'] == value['nonce'] and
           authority['bounds'] == C.BOUNDS, 'exact independent Root local resource/identity authority')
    C.need(all(type(v) is int for v in authority['bounds'].values()), 'typed Root local caps')
    now = datetime.now(timezone.utc)
    issued, expires = [datetime.fromisoformat(authority[k]) for k in ('issued_at', 'expires_at')]
    C.need(issued.tzinfo is not None and expires.tzinfo is not None and issued <= now <= expires and
           0 < (expires - issued).total_seconds() <= 3600, 'fresh bounded Root local authority')
    host = dict(sysname=os.uname().sysname, machine=os.uname().machine,
                boot_id_sha256=C.pin(Path('/proc/sys/kernel/random/boot_id').read_bytes())['sha256'])
    C.need(authority['host'] == host and host['sysname'] == 'Linux' and host['machine'] == 'x86_64', 'exact actual local Linux host')
    C.need(authority['paths'] == {'work': str(args.work), 'output': str(args.output)} and
           not args.output.exists(), 'fixed fresh one-trial output, not a reusable GitHub run identity')
    reviews = {'exact_Git_code_and_DATA_CI', 'kernel_rootfs_provider_authentication_and_closure',
               'local_host_resources_exclusively_reserved', 'independent_of_hosted_A9_no_native_waiver',
               'physical_kernel_signer_serialization_preserved'}
    C.need(set(authority['reviews']) == reviews and all(v is True for v in authority['reviews'].values()), 'Root reviews, never self-issued')
    files = code(args.source_root, authority['code'], value)
    for role in ('kernel', 'rootfs', 'provider'):
        reference(value['input_provenance'][role], 4 * 1048576)
    manifest = C.decode(reference(value['provider_manifest'], 8 * 1048576))
    environment = provider(Path(authority['provider_root']), manifest, args.qemu, value['QEMU'], authority['environment'])
    return dict(selection=value, authority=authority, authority_pin=C.pin(authority_raw), files=files, environment=environment,
                firmware_dir=Path(authority['provider_root']) / 'usr/share/qemu')


def revalidate(local, args):
    """Last DATA/lease freshness join immediately before the single QEMU actor."""
    C.need(C.pin(C.read(args.local_authority)) == local['authority_pin'], 'same independent Root authority at launch')
    authority = local['authority']
    now = datetime.now(timezone.utc)
    C.need(datetime.fromisoformat(authority['issued_at']) <= now <= datetime.fromisoformat(authority['expires_at']),
           'Root local authority still fresh at launch')
    lease = authority['lease']
    actual = os.fstat(local['lease_fd'])
    path = Path(lease['path']).lstat()
    C.need((actual.st_dev, actual.st_ino, actual.st_uid) == (path.st_dev, path.st_ino, path.st_uid) ==
           (lease['device'], lease['inode'], lease['uid']), 'same held local lease descriptor/path')
    code(args.source_root, authority['code'], local['selection'])
