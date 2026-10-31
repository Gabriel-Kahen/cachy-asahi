# SPDX-License-Identifier: MIT
"""Exact synthetic inputs and data gates for the private generic ARM workflow."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat

TITLE = 'Cachy Asahi terminal workflow'
APP_ID = 'cachy-asahi-terminal'
SEED = b'#include <stdio.h>\nint main(void) { printf("UNEDITED: %d\\n", 0); return 0; }\n'
EDITED = SEED.replace(b'UNEDITED', b'Cachy Asahi native C').replace(b', 0);', b', 6 * 7);')
OUTPUT = b'Cachy Asahi native C: 42\n'
CLIPBOARD = 'Cachy Asahi — café / Ελληνικά / λ = 42\n'.encode()
MIME = 'text/plain;charset=utf-8'
MAX_REPORT = 256 * 1024
ALACRITTY = '''[window]
opacity = 1.0
dynamic_title = false
padding = { x = 12, y = 12 }
[font]
size = 12.0
[colors.primary]
background = "#20242c"
foreground = "#eceff4"
'''


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.b64encode(data).decode()


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


def window(clients, pid):
    need(type(clients) is list and all(type(c) is dict for c in clients), 'invalid clients reply')
    found = [c for c in clients if type(c.get('pid')) is int and c['pid'] == pid]
    need(len(found) <= 1, 'ambiguous owned terminal')
    if not found:
        return None
    row = found[0]
    if row.get('mapped') is not True or row.get('visible') is not True:
        return None
    need(row.get('hidden') is False and row.get('xwayland') is False and
         row.get('class') == APP_ID and row.get('title') == TITLE, 'terminal identity/visibility differs')
    size, at = row.get('size'), row.get('at')
    need(type(size) is list and type(at) is list and len(size) == len(at) == 2 and
         all(type(v) is int for v in [*size, *at]), 'invalid terminal geometry')
    need(size[0] >= 640 and size[1] >= 400 and at[0] >= 0 and at[1] >= 0 and
         at[0] + size[0] <= 1024 and at[1] + size[1] <= 768, 'terminal clipped or too small')
    return row


def elf(data):
    need(len(data) >= 20 and data[:6] == b'\x7fELF\x02\x01' and
         int.from_bytes(data[18:20], 'little') == 183, 'compiled output is not AArch64 ELF')


def validate_result(result, stage, nonce, terminal_pid):
    need(result.get('status') == 'PASS_TERMINAL_EDITOR_NATIVE_C_CLIPBOARD' and
         result.get('stage') == stage and result.get('nonce') == nonce and
         result.get('terminal_pid') == terminal_pid and type(result.get('worker_pid')) is int and
         result['worker_pid'] > 0 and result.get('architecture') == 'aarch64', 'workflow identity/result differs')
    need(type(terminal_pid) is int and terminal_pid > 0 and result.get('terminal_isatty') is True and
         type(result.get('pty')) is str and result['pty'].startswith('/dev/pts/'), 'owned terminal PTY proof absent')
    for field, expected in (('source_before', SEED), ('source_after', EDITED),
                             ('native_stdout', OUTPUT), ('clipboard', CLIPBOARD)):
        value = result[field]
        need(value['base64'] == b64(expected) and value['sha256'] == sha(expected) and
             value['bytes'] == len(expected), field + ' proof differs')
    elf(base64.b64decode(result['executable']['header_base64'], validate=True))
    for name in ('vim-edit', 'compile', 'native-run', 'paste', 'clipboard-owner'):
        found = [r for r in result['processes'] if r.get('name') == name]
        need(len(found) == 1 and found[0]['returncode'] == 0, 'required workflow process failed/absent: ' + name)
    need(result.get('editor_mode') == 'Vim Ex, no user configuration' and
         result.get('clipboard_processes') == 'separate wl-copy/wl-paste', 'workflow method differs')


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
