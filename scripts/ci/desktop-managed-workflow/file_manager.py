# SPDX-License-Identifier: MIT
"""Exact file-manager inputs and fail-closed introspection/window gates."""
import xml.etree.ElementTree as ET
import hashlib
import json
import os
import stat
MAX_REPORT = 256 * 1024

def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, cap=MAX_REPORT):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size <= cap,
         'unsafe or oversized workflow file')
    with path.open('rb') as stream:
        data = stream.read(cap + 1)
    need(len(data) <= cap, 'workflow read byte limit')
    return data


def publish(path, value):
    need(not os.path.lexists(path), 'fresh workflow result required')
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    need(len(raw) <= MAX_REPORT, 'workflow result byte limit')
    partial = path.with_name(path.name + '.partial')
    with partial.open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    partial.chmod(0o600)
    os.rename(partial, path)


def snapshot(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        need(len(result) < 128, 'configuration entry limit')
        info = path.lstat()
        row = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        if stat.S_ISLNK(info.st_mode):
            row.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            row.update(kind='file', sha256=sha(read(path, 1024**2)))
        else:
            need(stat.S_ISDIR(info.st_mode), 'special configuration node')
            row.update(kind='directory')
        result[str(path.relative_to(directory))] = row
    return result


CONTENT = 'Cachy Asahi file workflow — café / λ = 42\n'.encode()
BUS = 'org.xfce.FileManager'
OBJECT = '/org/xfce/FileManager'
METHODS = {
    'DisplayFolder': [('uri', 's'), ('display', 's'), ('startup_id', 's')],
    'CopyTo': [('working_directory', 's'), ('source_filenames', 'as'),
               ('target_filenames', 'as'), ('display', 's'), ('startup_id', 's')],
    'LaunchFiles': [('working_directory', 's'), ('filenames', 'as'),
                    ('display', 's'), ('startup_id', 's')],
}


def introspection(raw):
    need(len(raw) <= 256 * 1024, 'introspection byte limit')
    root = ET.fromstring(raw)
    interfaces = [i for i in root.findall('interface') if i.get('name') == BUS]
    need(len(interfaces) == 1, 'exact Thunar interface required')
    for name, expected in METHODS.items():
        rows = [m for m in interfaces[0].findall('method') if m.get('name') == name]
        need(len(rows) == 1, 'missing/duplicate Thunar method: ' + name)
        actual = [(a.get('name'), a.get('type')) for a in rows[0].findall('arg')
                  if a.get('direction', 'in') == 'in']
        need(actual == expected, 'Thunar method signature differs: ' + name)
    return {name: expected for name, expected in METHODS.items()}


def window(clients, pid, directory):
    need(type(clients) is list and all(type(c) is dict for c in clients), 'invalid clients')
    rows = [c for c in clients if c.get('pid') == pid and c.get('mapped') is True]
    need(len(rows) <= 1, 'ambiguous Thunar windows')
    if not rows or rows[0].get('visible') is not True:return None
    row = rows[0]
    need(row.get('class') in ('thunar', 'Thunar', 'org.xfce.Thunar') and
         row.get('hidden') is False and row.get('xwayland') is False and
         directory in row.get('title', ''), 'Thunar window identity differs')
    at, size = row.get('at'), row.get('size')
    need(type(at) is list and type(size) is list and len(at) == len(size) == 2 and
         all(type(v) is int for v in at + size), 'Thunar geometry differs')
    need(min(at) >= 0 and size[0] >= 500 and size[1] >= 300 and
         at[0] + size[0] <= 1024 and at[1] + size[1] <= 768, 'Thunar clipped/too small')
    return row


def validate(proof, stage, pid):
    need(proof.get('status') == 'PASS_THUNAR_DBUS_COPY_LAUNCH_GIO_RENAME' and
         proof.get('stage') == stage and proof.get('thunar_pid') == pid and
         type(pid) is int and pid > 0 and proof.get('bus_owner_pid') == pid,
         'Thunar proof identity differs')
    need(proof.get('content_sha256') == sha(CONTENT) and proof.get('bytes') == len(CONTENT)
         and proof.get('original_preserved') is True and proof.get('outside_preserved') is True,
         'file content/preservation proof differs')
    need(proof.get('copy') == 'Thunar org.xfce.FileManager.CopyTo' and
         proof.get('rename') == 'GIO move; Thunar rename UI NOT_RUN' and
         proof.get('open') == 'Thunar LaunchFiles to private text handler; editor UI NOT_RUN',
         'operation attribution differs')
    handler = proof.get('handler', {})
    need(handler.get('path') == proof.get('renamed_path') and
         handler.get('sha256') == sha(CONTENT) and handler.get('bytes') == len(CONTENT)
         and handler.get('nonce') == proof.get('nonce') and handler.get('uid') == 23001,
         'launched handler/content identity differs')
