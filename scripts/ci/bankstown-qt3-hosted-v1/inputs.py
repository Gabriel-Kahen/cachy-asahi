# SPDX-License-Identifier: MIT
"""Finite audio hosted input transport; no acquisition or authority issuance.

The hosted validator checks semantic DATA and returns the complete file list.
The maintained launcher must still stream every selected reference before
privilege. Assembly verifies actual bodies; no actual operands are supplied here.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

API = 'BANKSTOWN_QT3_HOSTED_INPUTS_V1'
KIND = 'ROOT_STAGED_BANKSTOWN_QT3_INPUTS_V1'
OPERATION = 'bankstown-qt3-native-private-test-v1'
MEMBER = 'scripts/ci/bankstown-qt3-native-source/inputs.py'
AUDIO_PIN = dict(bytes=9376, sha256='b605524811535fd9f108a2797ada7f135c2beed91c0ab99c73e28b76046e270d')
REF_KEYS = {'path', 'bytes', 'sha256'}
PRIVATE_PARTS = {'.gnupg', '.ssh', '.aws', '.config'}


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(len(raw) <= 4 * 1024**2, 'FINITE_AUDIO_INPUT_BYTES')
    return raw


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def owner_inputs_pin(owner_inputs):
    return pin(encoded(owner_inputs))


def ordinary(value):
    need(type(value) is str and 0 < len(value) <= 4096 and '\x00' not in value
         and all(ord(c) >= 32 and ord(c) != 127 for c in value), 'ORDINARY_AUDIO_DATA_PATH')
    p = Path(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts
         and not any(x.is_symlink() for x in (p, *p.parents)), 'UNALIASED_AUDIO_DATA_PATH')
    need(not PRIVATE_PARTS.intersection(p.parts), 'NO_PRIVATE_CREDENTIAL_DOMAIN')
    return p


def descriptor(row, cap=8 * 1024**3, *, empty=True):
    need(type(row) is dict and set(row) == REF_KEYS and type(row['bytes']) is int
         and (0 if empty else 1) <= row['bytes'] <= cap
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'WHOLE_AUDIO_FILE_REFERENCE')
    ordinary(row['path'])
    return row


def references(value):
    rows, visited = {}, 0
    def visit(item, depth=0):
        nonlocal visited
        visited += 1
        need(depth <= 32 and visited <= 4096, 'FINITE_AUDIO_REFERENCE_TREE')
        if type(item) is dict:
            if set(item).intersection(REF_KEYS):
                descriptor(item)
                path = item['path']
                need(path not in rows or rows[path] == item, 'CONFLICTING_AUDIO_REFERENCE')
                rows[path] = dict(item)
            else:
                for child in item.values():
                    visit(child, depth + 1)
        elif type(item) is list:
            for child in item:
                visit(child, depth + 1)
    visit(value)
    need(0 < len(rows) <= 1024 and sum(r['bytes'] for r in rows.values()) <= 32 * 1024**3,
         'FINITE_COMPLETE_AUDIO_REFERENCES')
    return [rows[p] for p in sorted(rows)]


def read_reference(row, cap, *, collect=True):
    descriptor(row, cap)
    path = ordinary(row['path'])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022
             and before.st_size == row['bytes'], 'ORDINARY_AUDIO_INPUT_FILE')
        h, size, chunks, tail = hashlib.sha256(), 0, [], b''
        while part := os.read(fd, 1024**2):
            size += len(part)
            need(size <= row['bytes'], 'AUDIO_INPUT_GREW')
            need(not re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----', tail + part),
                 'PRIVATE_KEY_MATERIAL_REFUSED')
            tail = part[-128:]
            h.update(part)
            if collect:
                chunks.append(part)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        identity = lambda s: tuple(getattr(s, n) for n in fields)
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and dict(bytes=size, sha256=h.hexdigest()) == {k: row[k] for k in ('bytes', 'sha256')},
             'STABLE_WHOLE_AUDIO_INPUT')
        return b''.join(chunks) if collect else None
    finally:
        os.close(fd)


def source_inputs(source_root, delegation):
    root = ordinary(str(source_root))
    need(type(delegation) is dict and type(delegation.get('schema')) is int and delegation['schema'] == 1
         and delegation.get('kind') == 'ROOT_DELEGATED_BANKSTOWN_QT3_PRIVATE_TEST_V1'
         and delegation.get('stage') == 'qt3'
         and delegation.get('capability', {}).get('operation') == OPERATION,
         'EXACT_AUDIO_DELEGATION_DATA')
    expected = delegation['binding']['source_lock']
    need(type(expected) is dict and set(expected) == {'bytes', 'sha256'}, 'SOURCE_MAP_PIN_REQUIRED')
    for name in ('source-map.json', 'source.lock.json'):
        path = ordinary(str(root / name))
        need(stat.S_IMODE(path.lstat().st_mode) == 0o644, 'EXACT_SOURCE_MAP_ALIAS_MODE')
    raw = read_reference(dict(path=str(root / 'source-map.json'), **expected), 1024**2)
    alias = read_reference(dict(path=str(root / 'source.lock.json'), **expected), 1024**2)
    need(raw == alias, 'SOURCE_MAP_ALIAS_DIFFERS')
    mapping = json.loads(raw)
    need(type(mapping.get('schema')) is int and mapping['schema'] == 1
         and mapping.get('kind') == 'BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1'
         and mapping.get('operation') == OPERATION and type(mapping.get('files')) is dict
         and len(mapping['files']) + 2 <= 256 and type(mapping.get('actual')) is dict and mapping['actual']
         and all(v is None for v in mapping['actual'].values()), 'CLOSED_UNISSUED_AUDIO_SOURCE_MAP')
    code_row = mapping['files'][MEMBER]
    need(code_row == dict(AUDIO_PIN, mode=0o644), 'EXACT_MAINTAINED_AUDIO_INPUTS_PIN')
    path = root / MEMBER
    body = read_reference(dict(path=str(path), **AUDIO_PIN), 128 * 1024)
    spec = importlib.util.spec_from_file_location('hosted_exact_audio_inputs', path)
    I = importlib.util.module_from_spec(spec)
    exec(compile(body, str(path), 'exec'), I.__dict__)
    return I, mapping['files']


def _owner_plan(inputs, delegation, source_root, *, verify_archives):
    refs = references(inputs)  # Reject private/aliased paths before metadata reads.
    I, rows = source_inputs(source_root, delegation)
    need(type(inputs) is dict and set(inputs) == I.REQUEST_KEYS, 'EXACT_NINE_AUDIO_OWNER_INPUTS')
    need(owner_inputs_pin(inputs) == delegation['inputs_pin'], 'ROOT_SELECTED_AUDIO_OWNER_INPUTS_PIN')
    trust = inputs['official_trust']
    need(type(trust) is dict and set(trust) == {'Root_admission', 'public_key', 'fingerprint'},
         'EXACT_OFFICIAL_PUBLIC_TRUST_REFERENCES')
    descriptor(trust['Root_admission'], 2 * 1024**2, empty=False)
    descriptor(trust['public_key'], 65536, empty=False)
    need(type(trust['fingerprint']) is str and re.fullmatch('[0-9A-F]{40}', trust['fingerprint']),
         'EXPLICIT_OFFICIAL_PRIMARY_FINGERPRINT')
    plan = I.plan_inputs(source_root=source_root, source_rows=rows, request=inputs,
                         verify_archives=verify_archives)
    need(trust['fingerprint'] == plan['base']['signer_fingerprint'], 'SAME_BASE_OFFICIAL_PRIMARY')
    need({k: inputs['baseline_inventory'][k] for k in ('bytes', 'sha256')}
         == {k: plan['base_fields']['baseline_inventory'][k] for k in ('bytes', 'sha256')},
         'EXACT_PROTECTED349_REFERENCE')
    need(len(plan['base_rows']) == 257 and len(plan['additions']) == 128
         and len(plan['baseline']) == 349 and len(plan['expected']) == 477, 'COMPLETE773_FIXED_SELECTION')
    return refs, plan


def validate_owner_inputs(*, inputs, delegation, source_root):
    refs, _ = _owner_plan(inputs, delegation, source_root, verify_archives=False)
    return {'valid': True, 'required_refs': refs}


def validate_hosted_inputs_v3(*, inputs, delegation, source_root):
    need(type(inputs) is dict and set(inputs) == {'schema', 'kind', 'owner_inputs', 'staged_refs'}
         and type(inputs['schema']) is int and inputs['schema'] == 1 and inputs['kind'] == KIND
         and type(inputs['staged_refs']) is list, 'EXACT_AUDIO_HOSTED_ENVELOPE')
    result = validate_owner_inputs(inputs=inputs['owner_inputs'], delegation=delegation, source_root=source_root)
    need(inputs['staged_refs'] == result['required_refs'], 'EXACT_ALL_SELECTED_STAGED_REFERENCES')
    return result


def assemble_inputs(*, complete_reference_result, baseline_inventory, candidate_materials, catalog,
                    official_trust, source_root, delegation, output=None):
    """Join the actual complete517 provider and explicit four audio operands.

    Every selected body is verified, with no cache search, copy, acquisition or
    approval. output, when explicit, selects one fresh private wrapper file.
    """
    I, _ = source_inputs(source_root, delegation)
    owner = dict(I.provider_fields(complete_reference_result, source_root=source_root),
                 baseline_inventory=baseline_inventory, candidate_materials=candidate_materials,
                 catalog=catalog, official_trust=official_trust)
    owner = json.loads(encoded(owner))
    refs, _ = _owner_plan(owner, delegation, source_root, verify_archives=True)
    for ref in refs:
        read_reference(ref, 8 * 1024**3, collect=False)
    value = dict(schema=1, kind=KIND, owner_inputs=owner, staged_refs=refs)
    if output is not None:
        path = ordinary(str(output))
        need(not path.exists() and not path.is_relative_to(Path(source_root))
             and path.parent.is_dir() and path.parent.stat().st_uid == os.getuid()
             and stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'FRESH_PRIVATE_AUDIO_WRAPPER_OUTPUT')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded(value))
    return value
