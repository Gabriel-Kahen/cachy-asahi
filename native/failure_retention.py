# SPDX-License-Identifier: MIT
"""Fixed public bootstrap failure DATA retention; no producer execution."""
import builtins
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MIB = 1024 ** 2
CAP = 32 * MIB
NAMES = ('acquisition.json', 'key-import.log', 'bootstrap.log', 'signatures.json')
PRODUCER = '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'
INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
GENERIC = 'transport, cache or pinned-byte validation failed'
LABEL = 'org.cachy-asahi.native-developer'
EXCEPTIONS = {n for n, v in vars(builtins).items() if isinstance(v, type) and issubclass(v, Exception)} | {'URLError', 'HTTPError', 'ContentTooShortError', 'SubprocessError', 'CalledProcessError', 'TimeoutExpired'}
PRIVATE = re.compile(r'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)


class Guard(ValueError):
    pass


def _need(value, code):
    if not value:
        raise Guard(code)


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _directory(path):
    path = Path(path)
    _need(path.is_absolute() and '..' not in path.parts, 'PATH_GUARD')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(path, cap):
    fd = _directory(path.parent)
    try:
        before = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'FILE_GUARD')
        _need(before.st_size <= cap, 'SIZE_GUARD')
        filefd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            _need(_identity(os.fstat(filefd)) == _identity(before), 'RACE_GUARD')
            with os.fdopen(filefd, 'rb', closefd=False) as stream:
                body = stream.read(cap + 1)
            _need(len(body) <= cap and len(body) == before.st_size, 'SIZE_GUARD')
            _need(_identity(before) == _identity(os.fstat(filefd)) == _identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'RACE_GUARD')
            current = _directory(path.parent)
            try:
                old, new = os.fstat(fd), os.fstat(current)
                _need((old.st_dev, old.st_ino, old.st_mode) == (new.st_dev, new.st_ino, new.st_mode), 'RACE_GUARD')
            finally:
                os.close(current)
            return body, stat.S_IMODE(before.st_mode)
        finally:
            os.close(filefd)
    finally:
        os.close(fd)


def _json(body):
    def pairs(rows):
        result = {}
        for key, value in rows:
            _need(key not in result, 'JSON_GUARD'); result[key] = value
        return result
    try:
        return json.loads(body.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Guard('JSON_GUARD')))
    except (ValueError, RecursionError):
        raise Guard('JSON_GUARD') from None


def _public(body):
    text = body.decode('utf-8')
    _need(not PRIVATE.search(text) and not any(ord(c) < 32 and c not in '\t\r\n' for c in text), 'PRIVACY_GUARD')


def _items(original):
    rows = list(original['keyring_files'])
    for row in [original['rootfs']] + original['packages']:
        rows += [row, dict(filename=row['filename'] + '.sig', size=row['signature_size'], sha256=row['signature_sha256'])]
    _need(len(rows) == 501 and len({r['filename'] for r in rows}) == 501, 'INPUT_GUARD')
    return {r['filename']: {'expected_bytes': r['size'], 'expected_sha256': r['sha256']} for r in rows}


def _acquisition(body, expected):
    data = _json(body)
    _need(type(data) is dict and set(data) == {'schema_version', 'acquisition', 'signature_authentication', 'inputs', 'counts'}, 'SCHEMA_GUARD')
    _need(type(data['schema_version']) is int and data['schema_version'] == 1 and data['signature_authentication'] == 'NOT RUN', 'SCHEMA_GUARD')
    _need(type(data['inputs']) is dict and set(data['inputs']) == set(expected), 'INPUT_GUARD')
    counts = dict(total=501, **{'pass': 0, 'fail': 0, 'pending': 0})
    for name, row in data['inputs'].items():
        _need(type(row) is dict and row.get('status') in ('PENDING', 'PASS', 'FAIL'), 'SCHEMA_GUARD')
        status = row['status']; keys = {'status', 'expected_bytes', 'expected_sha256'}
        if status == 'FAIL':
            keys |= {'error_type', 'error'}
            if row.get('error_type') == 'AcquisitionError':
                keys.add('http_status'); code = row.get('http_status')
                _need(row.get('error') in ('HTTP failure', 'HTTPS transport failure') and (code is None or type(code) is int and 100 <= code <= 599), 'ERROR_GUARD')
                _need(row['error'] != 'HTTPS transport failure' or code is None, 'ERROR_GUARD')
            else:
                _need(row.get('error_type') in EXCEPTIONS and row.get('error') == GENERIC, 'ERROR_GUARD')
        _need(set(row) == keys and type(row['expected_bytes']) is int and {k: row[k] for k in expected[name]} == expected[name], 'INPUT_GUARD')
        counts[status.lower()] += 1
    _need(type(data['counts']) is dict and set(data['counts']) == set(counts) and all(type(v) is int for v in data['counts'].values()) and data['counts'] == counts, 'COUNT_GUARD')
    _need(data['acquisition'] in ('IN_PROGRESS', 'PASS', 'FAIL'), 'SCHEMA_GUARD')
    if data['acquisition'] != 'IN_PROGRESS':
        _need(counts['pending'] == 0 and data['acquisition'] == ('FAIL' if counts['fail'] else 'PASS'), 'COUNT_GUARD')


def _gpg(work):
    return ['gpg', '--batch', '--no-options', '--homedir', str(work / 'bootstrap/gpg'), '--no-auto-key-retrieve']


def _signatures(body, original, work, cache):
    rows = _json(body); names = [r['filename'] for r in [original['rootfs']] + original['packages']]
    _need(type(rows) is dict and 1 <= len(rows) <= len(names) and set(rows) == set(names[:len(rows)]), 'SCHEMA_GUARD')
    for name, row in rows.items():
        _need(type(row) is dict and set(row) == {'command', 'exit_code', 'status', 'diagnostic'}, 'SCHEMA_GUARD')
        _need(row['command'] == _gpg(work) + ['--status-fd', '1', '--verify', str(cache / (name + '.sig')), str(cache / name)], 'COMMAND_GUARD')
        _need(type(row['exit_code']) is int and -64 <= row['exit_code'] <= 255 and type(row['status']) is str and type(row['diagnostic']) is str, 'SCHEMA_GUARD')
        _need(name == names[len(rows)-1] or row['exit_code'] == 0, 'SCHEMA_GUARD')
        _public(row['status'].encode()); _public(row['diagnostic'].encode())


def _stream(name, body, work, cache, binding, actors):
    path = str(work / 'bootstrap' / name)
    rows = [r for r in actors if type(r) is dict and r.get('log') == path]
    _need(len(rows) == 1, 'ACTOR_GUARD')
    if name == 'key-import.log':
        command = _gpg(work) + ['--import', str(cache / 'archlinuxarm.gpg')]
    else:
        token, source = binding['token'], binding['source']
        _need(type(token) is str and re.fullmatch('[0-9a-f]{24}', token) and type(source) is str and re.fullmatch('[0-9a-f]{40}', source), 'BINDING_GUARD')
        command = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'build', '--no-cache', '--tag', 'native-developer-base:' + token,
                   '--label', LABEL + '=' + token, '--label', LABEL + '.source=' + source,
                   '--network=none', '--pull=false', '--platform=linux/arm64', '--iidfile', str(work / 'bootstrap/image-id'), str(work / 'bootstrap/context')]
    _need(rows[0].get('argv') == command, 'COMMAND_GUARD'); _public(body)


def _usage(fd, counts, depth=0):
    _need(depth <= 128, 'PUBLIC_BOUND_GUARD')
    total = 0
    for name in os.listdir(fd):
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            counts[1] += 1; _need(counts[1] <= 3000, 'PUBLIC_BOUND_GUARD')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try: total += _usage(child, counts, depth+1)
            finally: os.close(child)
        else:
            counts[0] += 1; _need(counts[0] <= 3001, 'PUBLIC_BOUND_GUARD')
            if stat.S_ISLNK(st.st_mode): total += len(os.readlink(name, dir_fd=fd).encode())
            else:
                _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'PUBLIC_BOUND_GUARD'); total += st.st_size
        _need(total <= CAP, 'PUBLIC_BOUND_GUARD')
    return total


def _publish(output, name, body):
    rootfd = _directory(output)
    try:
        counts = [0, 1]; used = _usage(rootfd, counts)
        _need(used + len(body) <= CAP and counts[0] < 3001, 'PUBLIC_BOUND_GUARD')
        try:
            os.stat('bootstrap-proof', dir_fd=rootfd, follow_symlinks=False)
        except FileNotFoundError:
            _need(counts[1] < 3000, 'PUBLIC_BOUND_GUARD')
        try: os.mkdir('bootstrap-proof', mode=0o700, dir_fd=rootfd)
        except FileExistsError: pass
        proof = os.open('bootstrap-proof', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
        try:
            target = 'bootstrap-' + name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=proof)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, 'wb', closefd=False) as stream: stream.write(body)
            finally: os.close(fd)
        finally: os.close(proof)
    finally: os.close(rootfd)


def retain(source_root, work, cache, output, original_inputs, binding, actor_rows):
    """Expected guard refusals return fixed codes and never replace a primary error."""
    root, work, cache, output = map(Path, (source_root, work, cache, output))
    receipt = dict(schema=1, status='PASS_BOUNDED_BOOTSTRAP_FAILURE_DATA', guard_code='PUBLIC_SOURCE_VALIDATED', binding=binding, files={}, blocked_actor_logs=[])
    prerequisite = None
    try:
        producer, _ = _read(root / 'bootstrap/scripts/ci/native_arm.py', MIB)
        inputs, _ = _read(root / 'bootstrap/scripts/ci/inputs.lock.json', MIB)
        _need(hashlib.sha256(producer).hexdigest() == PRODUCER and hashlib.sha256(inputs).hexdigest() == INPUTS, 'SOURCE_GUARD')
        _need(json.dumps(original_inputs, sort_keys=True, allow_nan=False) == json.dumps(_json(inputs), sort_keys=True, allow_nan=False), 'INPUT_GUARD'); expected = _items(original_inputs)
        for path in (work, cache, output):
            fd = _directory(path); os.close(fd)
        _need(type(actor_rows) is list and type(binding) is dict, 'SCHEMA_GUARD')
        _need(set(binding) == {'source', 'ref', 'run', 'attempt', 'token'} and type(binding['attempt']) is int and binding['attempt'] == 1
              and type(binding['source']) is str and re.fullmatch('[0-9a-f]{40}', binding['source'])
              and type(binding['ref']) is str and binding['ref'].startswith('refs/heads/codex/')
              and type(binding['run']) is str and re.fullmatch('[1-9][0-9]*', binding['run'])
              and binding['token'] == hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24], 'BINDING_GUARD')
    except (Guard, OSError, ValueError, TypeError, KeyError, OverflowError) as error:
        prerequisite = str(error) if type(error) is Guard else 'SOURCE_IO_GUARD'
        receipt.update(status='FAIL_BOUNDED_BOOTSTRAP_FAILURE_DATA_GUARD', guard_code=prerequisite)
        receipt['files'] = {name: dict(status='REFUSED', code=prerequisite) for name in NAMES}
        receipt['blocked_actor_logs'] = [str(work / 'bootstrap' / name) for name in NAMES if name.endswith('.log')]
        return receipt
    for name in NAMES:
        path = work / 'bootstrap' / name
        try:
            body, mode = _read(path, MIB if name == 'acquisition.json' else 16 * MIB)
        except FileNotFoundError:
            receipt['files'][name] = dict(status='ABSENT', code='NOT_PRESENT'); continue
        except (Guard, OSError, ValueError, TypeError) as error:
            code = str(error) if type(error) is Guard else 'FILE_IO_GUARD'
        else:
            try:
                _need(prerequisite is None, prerequisite or 'SOURCE_GUARD')
                _need(mode <= 0o777, 'FILE_GUARD')
                if name == 'acquisition.json': _acquisition(body, expected)
                elif name == 'signatures.json': _signatures(body, original_inputs, work, cache)
                else: _stream(name, body, work, cache, binding, actor_rows)
                _publish(output, name, body)
                receipt['files'][name] = dict(status='RETAINED', code='PUBLIC_DATA_VALIDATED', public_path='bootstrap-proof/bootstrap-' + name,
                    kind='file', mode=0o600, source_mode=mode, bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
                continue
            except (Guard, OSError, ValueError, TypeError, KeyError, OverflowError) as error:
                code = str(error) if type(error) is Guard else 'DATA_IO_GUARD'
        receipt['files'][name] = dict(status='REFUSED', code=code)
        receipt['status'] = 'FAIL_BOUNDED_BOOTSTRAP_FAILURE_DATA_GUARD'
        if name.endswith('.log'): receipt['blocked_actor_logs'].append(str(path))
    return receipt
