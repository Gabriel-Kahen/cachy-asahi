# SPDX-License-Identifier: MIT
"""Exact local-DB reference comparison; only INSTALLDATE may vary.

The reference must come from a successful Required/Required install of the same
signed archive on the same target libalpm, then be frozen before interruption.
This parser does not authenticate a reference or establish source correspondence.
"""
from dataclasses import dataclass
import base64
import copy
import hashlib
import re

from security_recovery_state import NAME, NEW, _expected

DESC_CAP = 65536
LEAF_CAP = 1024**2


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def window(value):
    need(type(value) is dict and set(value) == {'started_epoch', 'finished_epoch'},
         'exact owned-command wall interval')
    start, finish = value['started_epoch'], value['finished_epoch']
    need(type(start) is int and type(finish) is int and 0 < start <= finish < 2**63
         and finish - start <= 185, '180s command plus at most 5s owned retirement interval')
    return start, finish


def normalize_desc(raw, install_window):
    """Return unchanged raw bytes except the single INSTALLDATE decimal value."""
    need(type(raw) is bytes and 0 < len(raw) <= DESC_CAP and raw.endswith(b'\n\n')
         and b'\x00' not in raw and b'\r' not in raw, 'bounded exact LF local desc')
    start, finish = window(install_window)
    lines, position, offset, fields, date_span = raw.splitlines(keepends=True), 0, 0, {}, None
    while position < len(lines):
        header = lines[position]
        match = re.fullmatch(rb'%([A-Z0-9_]+)%\n', header)
        need(match is not None, 'exact local desc section header')
        field = match[1].decode('ascii')
        need(field not in fields, 'duplicate local desc field')
        offset += len(header); position += 1
        values, value_start = [], offset
        while position < len(lines) and lines[position] != b'\n':
            need(lines[position].endswith(b'\n'), 'complete local desc value line')
            values.append(lines[position][:-1])
            offset += len(lines[position]); position += 1
        need(position < len(lines), 'section blank terminator')
        value_end = offset
        offset += 1; position += 1
        fields[field] = tuple(values)
        if field == 'INSTALLDATE':
            need(len(values) == 1 and re.fullmatch(rb'[1-9][0-9]{0,18}', values[0]),
                 'one decimal INSTALLDATE value')
            date = int(values[0]); need(start <= date <= finish, 'INSTALLDATE outside owned install')
            date_span = value_start, value_end, date
    need(fields.get('NAME') == (NAME.encode(),) and fields.get('VERSION') == (b'0.1.0-2',),
         'exact candidate name and version')
    need(date_span is not None and offset == len(raw), 'single complete INSTALLDATE section')
    left, right, date = date_span
    return raw[:left] + b'<OWNED_INSTALLDATE>\n' + raw[right:], date


@dataclass(frozen=True)
class MetadataReference:
    """Pinned raw candidate DB captured before the interrupted episode."""
    raw_files: dict
    expected_db: dict
    install_window: dict
    authority: dict

    def validate(self):
        need(type(self.raw_files) is dict and type(self.expected_db) is dict
             and NEW in self.expected_db and len(self.expected_db) <= 64,
             'finite exact candidate reference')
        for value in self.expected_db.values():
            _expected(value)
        need(type(self.authority) is dict and set(self.authority) ==
             {'archive', 'signature', 'config', 'keyring', 'signer', 'binding'},
             'reference signed-input and actual-binding authority')
        for name in ('archive', 'signature', 'config', 'keyring'):
            value = self.authority[name]
            need(type(value) is dict and set(value) == {'bytes', 'sha256'}
                 and type(value['bytes']) is int and 0 < value['bytes'] <= LEAF_CAP
                 and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']),
                 'exact reference input pin')
        need(type(self.authority['signer']) is str
             and re.fullmatch('[0-9A-F]{40}', self.authority['signer'])
             and type(self.authority['binding']) is dict, 'reference signer and binding')
        need(all(type(n) is str and len(n) <= 512 and n.split('/')[0] == NEW
                 and all(re.fullmatch('[A-Za-z0-9_.:+@-]+', s) and s not in ('.', '..')
                         for s in n.split('/')) for n in self.expected_db),
             'candidate-only reference namespace')
        need(sum(len(b) for b in self.raw_files.values() if type(b) is bytes) <= 4 * 1024**2,
             'reference aggregate bytes')
        expected_files = {n for n, r in self.expected_db.items() if r.get('kind') == 'file'}
        need(set(self.raw_files) == expected_files and NEW + '/desc' in expected_files
             and NEW + '/files' in expected_files, 'complete reference desc/files namespace')
        for name, raw in self.raw_files.items():
            need(type(name) is str and name.startswith(NEW + '/')
                 and type(raw) is bytes and len(raw) <= LEAF_CAP,
                 'bounded candidate reference file')
            need(pin(raw) == {k: self.expected_db[name][k] for k in ('bytes', 'sha256')},
                 'raw reference matches preauthorized content pin')
        normalize_desc(self.raw_files[NEW + '/desc'], self.install_window)
        return self

    def record(self):
        self.validate()
        return dict(protocol='security-candidate-db-reference-v1',
                    files={n: dict(pin(raw), base64=base64.b64encode(raw).decode('ascii'))
                           for n, raw in self.raw_files.items()},
                    expected_db=copy.deepcopy(self.expected_db),
                    install_window=dict(self.install_window), authority=copy.deepcopy(self.authority))

    @classmethod
    def from_record(cls, value):
        need(type(value) is dict and set(value) ==
             {'protocol', 'files', 'expected_db', 'install_window', 'authority'}
             and value['protocol'] == 'security-candidate-db-reference-v1', 'reference record schema')
        need(type(value['files']) is dict and len(value['files']) <= 64, 'reference file count')
        files = {}
        for name, row in value['files'].items():
            need(type(row) is dict and set(row) == {'bytes', 'sha256', 'base64'}
                 and type(row['bytes']) is int and 0 <= row['bytes'] <= LEAF_CAP
                 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
                 and type(row['base64']) is str and len(row['base64']) <= 1400000,
                 'bounded encoded reference')
            raw = base64.b64decode(row['base64'], validate=True)
            need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}
                 and base64.b64encode(raw).decode('ascii') == row['base64'], 'canonical reference bytes')
            files[name] = raw
        return cls(files, copy.deepcopy(value['expected_db']), dict(value['install_window']),
                   copy.deepcopy(value['authority'])).validate()


class MetadataNormalizer:
    def __init__(self, reference):
        need(type(reference) is MetadataReference, 'exact reference object')
        self.reference = copy.deepcopy(reference).validate()

    def normalize(self, root_fd, recovered, expected_db, policy, install_window):
        import security_recovery_fs as fs
        ref = self.reference.validate()
        need(all(ref.authority['binding'].get(k) == v for k, v in policy.binding().items()),
             'same actual recovery reference binding')
        need(expected_db == ref.expected_db, 'reference expectations were changed')
        need(type(recovered) is dict and type(recovered.get('db')) is dict,
             'actual recovered snapshot')
        out = copy.deepcopy(expected_db)
        evidence = dict(field='INSTALLDATE', reference_window=dict(ref.install_window),
                        recovered_window=dict(install_window), file_evidence={},
                        authority=copy.deepcopy(ref.authority))
        for name, original in ref.raw_files.items():
            relative = 'var/lib/pacman/local/' + name
            raw, entry = fs.read_regular(root_fd, relative)
            need(name in recovered['db'] and entry == recovered['db'][name],
                 'post-install snapshot and descriptor bytes join')
            if name.endswith('/desc'):
                before, reference_date = normalize_desc(original, ref.install_window)
                after, actual_date = normalize_desc(raw, install_window)
                need(before == after, 'candidate DB differs outside INSTALLDATE')
                out[name].update(pin(raw))
                evidence['file_evidence'][name] = dict(reference=pin(original), actual=pin(raw),
                    normalized=pin(after), reference_installdate=reference_date,
                    actual_installdate=actual_date)
            else:
                need(raw == original, 'non-desc candidate DB bytes changed')
        need(len(evidence['file_evidence']) == 1, 'only the candidate desc is normalized')
        return out, evidence
