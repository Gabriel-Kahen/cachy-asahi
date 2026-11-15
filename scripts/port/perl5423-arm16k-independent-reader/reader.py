#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit, bounded retained-DATA reader. Never imports controller/artifact code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


HERE = Path(__file__).resolve().parent
OP = 'arm16k-perl5423-system-runtime-v1'
MAX_FILE = 32 * 1024**2
MAX_TOTAL = 256 * 1024**2
MAX_FILES = 512
MAX_SECONDS = 60


def need(ok, message):
    if not ok:
        error = ValueError(message)
        error.reader_check = message
        raise error


def digest(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def parse(raw):
    def pairs(rows):
        value = {}
        for k, v in rows:
            need(k not in value, 'duplicate JSON key')
            value[k] = v
        return value
    def nonfinite(_):
        raise ValueError('nonfinite JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def keys(value, names, message):
    need(type(value) is dict and set(value) == set(names), message)


def pin_shape(value):
    keys(value, ('bytes', 'sha256'), 'exact DATA pin')
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= MAX_FILE
         and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'bounded DATA pin')


def relative(name):
    need(type(name) is str and 0 < len(name) <= 256 and not name.startswith('/')
         and all(p not in ('', '.', '..') for p in name.split('/'))
         and re.fullmatch('[A-Za-z0-9_.+/-]+', name), 'contained literal DATA name')
    return name


def ordinary(value, directory=False):
    need(type(value) in (str, Path) or isinstance(value, Path), 'literal path')
    p = Path(value)
    need(p.is_absolute() and str(p) == str(value) and '..' not in p.parts, 'canonical absolute path')
    for q in (*reversed(p.parents), p):
        s = q.lstat()
        need(not stat.S_ISLNK(s.st_mode), 'path alias forbidden')
    if directory:
        need(p.is_dir(), 'ordinary directory')
    return p


class Inputs:
    """Whole-byte, same-descriptor checks with finite cumulative work and recheck."""
    def __init__(self):
        self.end = time.monotonic() + MAX_SECONDS
        self.total = 0
        self.rows = {}

    def read(self, path, pin=None, mode=None):
        need(time.monotonic() < self.end, 'reader time bound')
        p = ordinary(path)
        need(p.suffix not in ('.raw', '.qcow2', '.xz', '.zst', '.zip', '.gz')
             and 'credential' not in p.name.lower(), 'raw/archive/credential reads forbidden')
        if pin is not None:
            pin_shape(pin)
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as f:
            before = os.fstat(f.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and not before.st_mode & 0o022 and before.st_size <= MAX_FILE, 'bounded ordinary single-link DATA')
            if mode is not None:
                need(stat.S_IMODE(before.st_mode) == mode, 'exact DATA mode')
            need(self.total + before.st_size <= MAX_TOTAL and len(self.rows) < MAX_FILES, 'complete reader work bound')
            raw = f.read(MAX_FILE + 1)
            after = os.fstat(f.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(after) == identity(p.lstat()), 'DATA changed during read')
        observed = digest(raw)
        need(pin is None or observed == pin, 'selected whole DATA pin mismatch')
        if str(p) in self.rows:
            need(self.rows[str(p)] == (observed, identity(before)), 'selected DATA changed')
        self.rows[str(p)] = observed, identity(before)
        self.total += len(raw)
        return raw

    def operand(self, row):
        keys(row, ('path', 'pin'), 'explicit selected DATA operand')
        return self.read(row['path'], row['pin'])

    def recheck(self):
        # Every byte is re-read; only the admission pass counts toward caps.
        rows = dict(self.rows)
        self.total = 0
        self.rows = {}
        for p, (pin, identity) in rows.items():
            self.read(p, pin)
            need(self.rows[p][1] == identity, 'input changed before completion')


def tree(inputs, root, manifest, exact=True):
    root = ordinary(root, True)
    need(type(manifest) is dict and 0 < len(manifest) <= 128, 'bounded selected tree')
    data = {}
    for name, row in manifest.items():
        relative(name)
        keys(row, ('bytes', 'sha256', 'mode'), 'tree pin and mode')
        need(type(row['mode']) is int and row['mode'] in (0o600, 0o644, 0o700, 0o755), 'ordinary reviewed tree mode')
        data[name] = inputs.read(root / name, {k: row[k] for k in ('bytes', 'sha256')}, row['mode'])
    if exact:
        found = set()
        directory_count = 0
        for current, dirs, files in os.walk(root, followlinks=False):
            directory_count += 1
            need(len(found) <= 128 and directory_count <= 128 and time.monotonic() < inputs.end, 'tree membership/time bound')
            for name in dirs:
                need(not (Path(current) / name).is_symlink(), 'tree directory alias')
            found.update((Path(current) / n).relative_to(root).as_posix() for n in files)
        need(found == set(manifest), 'complete tree membership')
    return data


def local_module(inputs):
    # Only this reader's reviewed, locally locked code is executable.
    import types
    lock = parse(inputs.read(HERE / 'source.lock.json'))
    row = lock['files']['joins.py']
    raw = inputs.read(HERE / 'joins.py', {n: row[n] for n in ('bytes', 'sha256')}, row['mode'])
    module = types.ModuleType('perl16k_independent_joins')
    exec(compile(raw, str(HERE / 'joins.py'), 'exec'), module.__dict__)
    return module


def closed_reader(inputs):
    raw = inputs.read(HERE / 'source.lock.json')
    lock = parse(raw)
    keys(lock, ('schema', 'kind', 'files', 'actual'), 'reader lock fields')
    need(lock['schema'] == 1 and lock['kind'] == 'PERL5423_ARM16K_PASSIVE_READER_SOURCE_V1'
         and lock['actual'] == dict(issued_by=None, decision_time=None, runtime_acceptance=None), 'closed unissued reader Source')
    manifest = dict(lock['files'])
    manifest['source.lock.json'] = dict(digest(raw), mode=0o644)
    tree(inputs, HERE, manifest)
    return digest(raw)


def authority(request_raw, request, grant, reader_pin, output, now, uid):
    keys(request, ('schema', 'kind', 'operation', 'nonce', 'source', 'packet', 'prepared', 'prepare_report',
                   'prepare_provider_observation', 'native_pair', 'prepare_outer', 'boot_outer', 'boot_authority', 'boot', 'receipts', 'actual'), 'request fields')
    need(request['schema'] == 1 and request['kind'] == 'PERL5423_ARM16K_PASSIVE_REQUEST_V1'
         and request['operation'] == OP and re.fullmatch('[0-9a-f]{32}', request['nonce'] or '')
         and request['actual'] == dict(issued_by=None, decision_time=None, runtime_acceptance=None), 'unissued exact reader request')
    keys(grant, ('schema', 'kind', 'issued_by', 'allow_passive_read', 'operation', 'request', 'reader_source',
                 'uid', 'created_utc', 'expires_utc', 'output', 'controller_source_reviewed'), 'grant fields')
    need(grant['schema'] == 1 and grant['kind'] == 'ROOT_PERL5423_ARM16K_PASSIVE_GRANT_V1'
         and grant['issued_by'] == 'Root' and grant['allow_passive_read'] is True
         and grant['controller_source_reviewed'] is True and grant['operation'] == OP
         and grant['request'] == digest(request_raw) and grant['reader_source'] == reader_pin
         and type(grant['uid']) is int and grant['uid'] == uid != 0 and grant['output'] == str(output), 'genuine exact Root passive grant required')
    need(type(grant['created_utc']) is type(grant['expires_utc']) is int
         and 0 <= now - grant['created_utc'] <= 3600 and now < grant['expires_utc'] <= grant['created_utc'] + 3600, 'finite fresh Root grant')


def review(inputs, request):
    J = local_module(inputs)
    source = request['source']
    keys(source, ('directory', 'lock'), 'explicit controller Source')
    lock_raw = inputs.read(Path(source['directory']) / 'source.lock.json', source['lock'])
    lock = parse(lock_raw)
    need(lock.get('kind') == 'ARM16K_PERL5423_CASE_SOURCE_LOCK_V1' and lock.get('operation') == OP
         and lock.get('actual') and all(v is None for v in lock['actual'].values()), 'closed Perl controller Source')
    source_files = tree(inputs, source['directory'], dict(lock['files'], **{'source.lock.json': dict(digest(lock_raw), mode=0o644)}))
    packet = request['packet']
    keys(packet, ('directory', 'pin'), 'explicit packet')
    packet_raw = inputs.read(Path(packet['directory']) / 'case-packet.json', packet['pin'])
    p = parse(packet_raw)
    packet_files = tree(inputs, packet['directory'], dict(p['files'], **{'case-packet.json': dict(digest(packet_raw), mode=0o644)}))
    context = J.case_context(p, packet_files, source_files, source['lock'], request['nonce'], parse, digest)
    context.update(source_pin=source['lock'], packet_pin=packet['pin'], prepared_pin=request['prepared']['pin'])
    prepared = parse(inputs.operand(request['prepared']))
    prepare_report = parse(inputs.operand(request['prepare_report']))
    native_raw = inputs.operand(request['native_pair'])
    native = parse(native_raw)
    context['native_pair_pin'] = digest(native_raw)
    observation = parse(inputs.operand(request['prepare_provider_observation']))
    J.lineage(context, p, packet['pin'], prepared, prepare_report, native, observation,
              parse(inputs.operand(request['prepare_outer'])), digest)
    result = dict(status='HOLD_MISSING_BOOT_EVIDENCE', checks=['SOURCE_PACKET_CERTIFICATE_NATIVE_PREPARE_JOINS'], missing=[],
                  scope='RETAINED_DATA_CONSISTENCY_ONLY', issued_by=None, decision_time=None,
                  runtime_acceptance=None, Root_acceptance=None, VM_acceptance=None,
                  actual_installed_ELF=None, expected_provider_projection=True,
                  native16K='NOT_RUN', M2='NOT_RUN', external_XS='NOT_QUALIFIED', performance='NOT_MEASURED', release='NOT_ADMITTED')
    if request['boot'] is None or request['boot_outer'] is None or request['boot_authority'] is None:
        result['missing'] = ['complete Root-selected boot outputs and outer custody receipt']
        return result
    keys(request['boot'], ('directory', 'files'), 'selected boot DATA')
    J.boot_names(request['boot']['files'])
    boot = tree(inputs, request['boot']['directory'], request['boot']['files'], exact=False)
    context['boot_authority'] = parse(inputs.operand(request['boot_authority']))
    context['boot_authority_pin'] = request['boot_authority']['pin']
    context['boot_directory'] = request['boot']['directory']
    context['source_directory'] = request['source']['directory']
    context['packet_directory'] = request['packet']['directory']
    context['prepared_directory'] = str(Path(request['prepared']['path']).parent)
    J.retained_manifest(context, p, boot, request['boot']['files'], parse, digest)
    boot_summary = J.boot(context, p, packet_files, prepared, boot,
                          parse(inputs.operand(request['boot_outer'])), parse, digest)
    result.update(boot_summary)
    result['checks'].append('INDEPENDENT_SERIAL_PAM_RTC_OUTPUT_ELF_QEMU_CID_CUSTODY_JOINS')
    if request['receipts'] is None:
        result.update(status='HOLD_MISSING_SELECTED_PRESERVATION_RECEIPTS',
                      missing=['Root-selected ordinary D/receipts DATA; no raw extraction performed'])
        return result
    keys(request['receipts'], ('directory', 'files'), 'selected transaction receipts')
    J.receipt_names(request['receipts']['files'])
    receipts = tree(inputs, request['receipts']['directory'], request['receipts']['files'], exact=False)
    J.selected_receipts(context, request['receipts']['files'], receipts, digest)
    result['restoration'] = J.restoration(context, packet_files, receipts, parse(boot['preservation.json']), digest)
    result['preservation_scope'] = 'SELECTED_NORMAL_ALPM_AND_PRESERVATION_RECEIPTS_JOINED; NO_RAW_REQUALIFICATION'
    result['checks'].append('INDEPENDENT_NORMAL_ALPM_AND_PRESERVATION_RECEIPT_JOINS')
    result['status'] = 'PASS_PASSIVE_RETAINED_PERL5423_ARM16K_DATA_CONSISTENCY_ONLY'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-passive-reader', action='store_true')
    for n in ('request', 'grant', 'output'):
        parser.add_argument('--' + n, type=Path, required=True)
    for n in ('request-sha256', 'grant-sha256'):
        parser.add_argument('--' + n, required=True)
    a = parser.parse_args()
    need(a.execute_passive_reader and sys.flags.isolated and sys.dont_write_bytecode and __debug__
         and os.getuid() == os.geteuid() != 0, 'explicit ordinary isolated passive reader entry')
    inputs = Inputs()
    reader_pin = closed_reader(inputs)
    request_raw, grant_raw = inputs.read(a.request), inputs.read(a.grant)
    need(digest(request_raw)['sha256'] == a.request_sha256 and digest(grant_raw)['sha256'] == a.grant_sha256, 'external exact request/grant SHA256')
    request, grant = parse(request_raw), parse(grant_raw)
    output = a.output
    parent = ordinary(output.parent, True)
    need(not output.exists() and not output.is_symlink() and parent.stat().st_uid == os.getuid()
         and not parent.stat().st_mode & 0o022, 'fresh private owned report output')
    authority(request_raw, request, grant, reader_pin, output, int(time.time()), os.getuid())
    for group in ('source', 'packet', 'boot', 'receipts'):
        if request[group] is not None:
            root = Path(request[group]['directory'])
            need(root != output and root not in output.parents and output not in root.parents, 'report disjoint from selected trees')
    try:
        result = review(inputs, request)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, IndexError, OverflowError, RecursionError) as error:
        # No artifact text, passwords, account data or file bodies in diagnostics.
        result = dict(status='HOLD_INVALID_OR_INCOMPLETE_EVIDENCE', failure_category=type(error).__name__,
                      failure_check=getattr(error, 'reader_check', 'input parsing/schema/ordinary-file read failure'),
                      issued_by=None, decision_time=None, runtime_acceptance=None, Root_acceptance=None)
    inputs.recheck()
    result.update(schema=1, reader_source=reader_pin, request=digest(request_raw), grant=digest(grant_raw),
                  selected_files=len(inputs.rows), selected_bytes=inputs.total)
    with output.open('xb') as stream:
        os.chmod(output, 0o600)
        stream.write(canonical(result))
    print(json.dumps(dict(status=result['status'], report=digest(canonical(result))), sort_keys=True))
    return 0 if result['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
