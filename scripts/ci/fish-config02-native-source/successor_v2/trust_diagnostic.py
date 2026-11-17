# SPDX-License-Identifier: MIT
"""Read-only public reference evidence, NEVER an APT trust/admission decision.

No action on import, subprocess, environment dump, configuration evaluation or
arbitrary path following. Caller retains the returned projection before running
the unchanged prerequisite guard. No raw source/configuration/key bytes escape.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

TARGET = 'usr/share/keyrings/ubuntu-pro-esm-apps.gpg'
LIMITS = dict(seconds=5, nodes=256, file_bytes=2*1024**2,
              total_bytes=16*1024**2, output_bytes=128*1024)
PUBLIC_KEY = re.compile(r'(?:usr/share/keyrings|etc/apt/keyrings|etc/apt/trusted\.gpg\.d)/[A-Za-z0-9_.+-]{1,120}\.(?:gpg|asc)\Z')
NAME = re.compile(r'[A-Za-z0-9_.-]{1,120}\Z')


class Refusal(ValueError):
    """Only fixed reason codes; never attach exception text or input values."""


class UnsafePublic(Refusal):
    def __init__(self, info):
        super().__init__('UNSAFE_PUBLIC_FILE')
        self.info = info


def need(ok, code):
    if not ok:
        raise Refusal(code)


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode',
                 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def safe_file(info, uid):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == uid and
            not info.st_mode & 0o022 and info.st_nlink == 1 and
            0 <= info.st_size <= LIMITS['file_bytes'])


def file_row(name, info):
    return dict(path=name, reason='UNSAFE_PUBLIC_FILE',
                metadata=dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                              gid=info.st_gid, links=info.st_nlink, bytes=info.st_size))


class PublicInputs:
    def __init__(self, root, uid, deadline):
        self.root, self.uid, self.deadline = Path(root), uid, deadline
        need(self.root.is_absolute() and self.root == self.root.resolve(), 'EXPLICIT_UNALIASED_ROOT_REQUIRED')
        self.nodes = self.total = 0

    def tick(self):
        need(time.monotonic() < self.deadline, 'DIAGNOSTIC_DEADLINE')

    def open(self, name, directory=False):
        """Walk from an explicit root descriptor, refusing every alias/ancestor."""
        self.tick()
        need(self.nodes < LIMITS['nodes'], 'DIAGNOSTIC_NODE_LIMIT')
        self.nodes += 1
        parts = name.split('/')
        need(all(p not in ('', '.', '..') for p in parts), 'NONPUBLIC_PATH')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for index, part in enumerate(parts):
                info = os.fstat(fd)
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and
                     not info.st_mode & 0o022, 'UNSAFE_PUBLIC_ANCESTOR')
                before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                need(not stat.S_ISLNK(before.st_mode), 'PUBLIC_PATH_ALIAS')
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if index < len(parts)-1 or directory:
                    need(stat.S_ISDIR(before.st_mode) and before.st_uid == self.uid and
                         not before.st_mode & 0o022, 'UNSAFE_PUBLIC_ANCESTOR')
                    flags |= os.O_DIRECTORY
                elif not safe_file(before, self.uid):
                    raise UnsafePublic(before)  # Never open a device/FIFO/unsafe key.
                child = os.open(part, flags, dir_fd=fd)
                if identity(before) != identity(os.fstat(child)):
                    os.close(child)
                    raise Refusal('PUBLIC_PATH_CHANGED')
                os.close(fd)
                fd = child
            result, fd = fd, None
            return result
        finally:
            if fd is not None:
                os.close(fd)

    def observe(self, name, contents=False):
        try:
            fd = self.open(name)
        except FileNotFoundError:
            return dict(path=name, reason='ABSENT'), None
        except UnsafePublic as error:
            return file_row(name, error.info), None
        except Refusal as error:
            if error.args[0] not in ('UNSAFE_PUBLIC_ANCESTOR', 'PUBLIC_PATH_ALIAS', 'PUBLIC_PATH_CHANGED', 'NONPUBLIC_PATH'):
                raise
            return dict(path=name, reason='UNSAFE_OR_UNREADABLE_PUBLIC_PATH'), None
        except OSError:
            return dict(path=name, reason='UNSAFE_OR_UNREADABLE_PUBLIC_PATH'), None
        try:
            before = os.fstat(fd)
            row = file_row(name, before)
            if not safe_file(before, self.uid):
                return row, None  # In particular NEVER read/hash the 0777 key.
            row['reason'] = 'SAFE_PUBLIC_FILE'
            need(before.st_size <= LIMITS['total_bytes'] - self.total, 'DIAGNOSTIC_TOTAL_LIMIT')
            raw = bytearray()
            while len(raw) < before.st_size:
                self.tick()
                chunk = os.read(fd, min(65536, before.st_size - len(raw)))
                need(bool(chunk), 'PUBLIC_FILE_CHANGED')
                raw.extend(chunk)
                self.total += len(chunk)
            need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)),
                 'PUBLIC_FILE_CHANGED')
            row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            return row, bytes(raw) if contents else None
        finally:
            os.close(fd)

    def names(self, name, suffixes):
        try:
            fd = self.open(name, directory=True)
        except FileNotFoundError:
            return []
        try:
            info = os.fstat(fd)
            need(info.st_uid == self.uid and not info.st_mode & 0o022, 'UNSAFE_PUBLIC_DIRECTORY')
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.tick()
                    need(self.nodes < LIMITS['nodes'], 'DIAGNOSTIC_NODE_LIMIT')
                    self.nodes += 1
                    if NAME.fullmatch(entry.name) and any(entry.name.endswith(s) for s in suffixes):
                        names.append(name + '/' + entry.name)
            need(identity(info) == identity(os.fstat(fd)), 'PUBLIC_DIRECTORY_CHANGED')
            return sorted(names)
        finally:
            os.close(fd)


def signed_by(value, disabled=False, tick=lambda: None):
    """Reference hints only. Parsing does not validate or enable a repository."""
    if '-----BEGIN PGP PUBLIC KEY BLOCK-----' in value:
        return [dict(reason='EMBEDDED_KEY_UNRESOLVED', path=None)]
    rows = []
    for match in re.finditer(r'[^\s,]+', value):
        tick()
        if len(rows) >= LIMITS['nodes']:
            return [dict(reason='SOURCE_HINT_PARSE_LIMIT', path=None)]
        token = match[0]
        if token.startswith('/'):
            name = token[1:]
            if name == 'etc/apt/trusted.gpg' or PUBLIC_KEY.fullmatch(name):
                rows.append(dict(reason='DISABLED_SIGNED_BY_HINT' if disabled else 'SIGNED_BY_PATH_HINT', path=name))
            else:
                rows.append(dict(reason='NONPUBLIC_OR_UNSUPPORTED_SIGNED_BY', path=None))
        elif re.fullmatch(r'[A-Fa-f0-9]{40}!?', token):
            rows.append(dict(reason='FINGERPRINT_GLOBAL_FALLBACK_UNRESOLVED', path=None))
        else:
            rows.append(dict(reason='MALFORMED_SIGNED_BY', path=None))
    return rows or [dict(reason='MALFORMED_SIGNED_BY', path=None)]


def source_hints(raw, deb822, tick=lambda: None):
    """Recognize explicit references; never claim completeness or unused keys."""
    if len(raw) > 65536:
        return [dict(reason='SOURCE_HINT_PARSE_LIMIT', path=None)]
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return [dict(reason='MALFORMED_SOURCE', path=None)]
    lines = text.splitlines()
    if len(lines) > 1024 or any(len(line) > 4096 for line in lines):
        return [dict(reason='SOURCE_HINT_PARSE_LIMIT', path=None)]
    if not deb822:
        rows = []
        for line in lines:
            tick()
            if len(rows) >= LIMITS['nodes']:
                return [dict(reason='SOURCE_HINT_PARSE_LIMIT', path=None)]
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            match = re.fullmatch(r'deb(?:-src)?\s+(?:\[([^\[\]]*)\]\s+)?([^\s]+)\s+([^\s]+)(?:\s+[^\[\]]+)?', line)
            if not match:
                rows.append(dict(reason='MALFORMED_SOURCE', path=None)); continue
            options = (match[1] or '').split()
            selected = [v.split('=', 1)[1] for v in options if v.startswith('signed-by=')]
            if len(selected) > 1 or any(v.startswith('signed-by') and not v.startswith('signed-by=') for v in options):
                rows.append(dict(reason='MALFORMED_SIGNED_BY', path=None))
            elif selected:
                hints = signed_by(selected[0], tick=tick)
                if len(rows) + len(hints) > LIMITS['nodes']:
                    return [dict(reason='SOURCE_HINT_PARSE_LIMIT', path=None)]
                rows.extend(hints)
            else:
                rows.append(dict(reason='GLOBAL_TRUST_FALLBACK_UNRESOLVED', path=None))
        return rows
    rows = []
    for stanza in re.split(r'\n\s*\n', text):
        tick()
        if len(rows) >= LIMITS['nodes']:
            return [dict(reason='SOURCE_HINT_PARSE_LIMIT', path=None)]
        fields, previous, bad = {}, None, False
        for line in stanza.splitlines():
            tick()
            if line.startswith('#') or not line.strip():
                continue
            if line[0].isspace() and previous:
                fields[previous] += '\n' + line.strip(); continue
            match = re.fullmatch(r'([A-Za-z][A-Za-z0-9-]*):\s*(.*)', line)
            if not match or match[1].lower() in fields:
                bad = True; continue
            previous = match[1].lower(); fields[previous] = match[2]
        if bad or (fields and not {'types', 'uris', 'suites'} <= fields.keys()):
            rows.append(dict(reason='MALFORMED_SOURCE', path=None)); continue
        if not fields:
            continue
        disabled = fields.get('enabled', 'yes') == 'no'
        if fields.get('enabled', 'yes') not in ('yes', 'no'):
            rows.append(dict(reason='MALFORMED_SOURCE', path=None)); continue
        if 'signed-by' in fields:
            hints = signed_by(fields['signed-by'], disabled, tick)
            if len(rows) + len(hints) > LIMITS['nodes']:
                return [dict(reason='SOURCE_HINT_PARSE_LIMIT', path=None)]
            rows.extend(hints)
        elif not disabled:
            rows.append(dict(reason='GLOBAL_TRUST_FALLBACK_UNRESOLVED', path=None))
    return rows


def diagnose(root=Path('/'), uid=0, *, apt_config_present, deadline):
    """Caller supplies actual-child APT_CONFIG presence, not its private value.

    Always HOLD. Even an apparently unreferenced target is NOT proven unused.
    Intended as a pre-guard public projection in a separately reviewed successor.
    """
    need(type(apt_config_present) is bool, 'EXPLICIT_CHILD_ENVIRONMENT_REQUIRED')
    end = min(deadline, time.monotonic() + LIMITS['seconds'])
    inputs = PublicInputs(root, uid, end)
    result = dict(kind='FISH_APT_PUBLIC_REFERENCE_DIAGNOSTIC_V3', status='HOLD',
                  effective_closure='UNKNOWN', exclusion_authorized=False,
                  Root_acceptance=None, actual_source=None, actual_grants=None,
                  reason_codes=['EFFECTIVE_APT_CONFIGURATION_UNRESOLVED'],
                  inputs=[], references=[], target=None)
    if apt_config_present:
        result['reason_codes'].append('APT_CONFIG_PRESENT_NOT_FOLLOWED')
    try:
        names = ['etc/apt/sources.list', 'etc/apt/apt.conf', 'etc/apt/trusted.gpg']
        names += inputs.names('etc/apt/sources.list.d', ('.list', '.sources'))
        names += inputs.names('etc/apt/apt.conf.d', ('',))
        names += inputs.names('etc/apt/trusted.gpg.d', ('.gpg', '.asc'))
        keys = {TARGET}
        for name in names:
            row, raw = inputs.observe(name, contents=True)
            result['inputs'].append(row)
            if raw is None:
                continue
            if name == 'etc/apt/apt.conf' or name.startswith('etc/apt/apt.conf.d/'):
                if raw.strip():
                    result['reason_codes'].append('CONFIGURATION_SEMANTICS_NOT_EVALUATED')
                continue
            if name == 'etc/apt/sources.list' or name.startswith('etc/apt/sources.list.d/'):
                hints = source_hints(raw, name.endswith('.sources'), inputs.tick)
                for hint in hints:
                    hint['source'] = name
                    if hint['path'] and hint['reason'] == 'SIGNED_BY_PATH_HINT':
                        keys.add(hint['path'])
                result['references'].extend(hints)
                need(len(result['references']) <= LIMITS['nodes'], 'DIAGNOSTIC_REFERENCE_LIMIT')
        for key in sorted(keys):
            row, _ = inputs.observe(key)
            result['inputs'].append(row)
            if key == TARGET:
                result['target'] = dict(row, reference_evidence='EXPLICIT_PATH_HINT' if any(
                    r['path'] == TARGET and r['reason'] == 'SIGNED_BY_PATH_HINT'
                    for r in result['references']) else 'NOT_FOUND_IN_SCANNED_DEFAULT_SOURCES')
        inputs.tick()
    except (OSError, Refusal):
        # No str(exception): a malicious filename/URL/env value must not escape.
        result['reason_codes'].append('PUBLIC_SCAN_REFUSED_OR_LIMIT_REACHED')
    result['reason_codes'] = sorted(set(result['reason_codes']))
    result['observed_counts'] = dict(nodes=inputs.nodes, bytes=inputs.total)
    if len(json.dumps(result).encode()) > LIMITS['output_bytes']:
        result.update(inputs=[], references=[], target=None,
                      reason_codes=['DIAGNOSTIC_OUTPUT_LIMIT', 'EFFECTIVE_APT_CONFIGURATION_UNRESOLVED'])
    return result
