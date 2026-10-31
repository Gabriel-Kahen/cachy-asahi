#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only selected desktop integration audit of an explicit quiescent staged root.

No subprocess, host PATH lookup, desktop activation or command execution occurs.
All logical absolute paths and absolute symlink targets are relative to root.
"""
import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import sys

TEXT_CAP = 256 * 1024
FILE_CAP = 64 * 1024 * 1024
ENTRY_CAP = 10000
RESERVED = set("\t\n\r'\\><~|&;$*?#()`")
ESCAPES = {'s': ' ', 'n': '\n', 't': '\t', 'r': '\r', '\\': '\\'}


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def absolute(value):
    if not isinstance(value, str) or not value.startswith('/') or '\0' in value:
        raise ValueError('absolute staged path required: ' + repr(value))
    parts = []
    for part in value.split('/'):
        if part == '..':
            if not parts:
                raise ValueError('path escapes staged root: ' + value)
            parts.pop()
        elif part not in ('', '.'):
            parts.append(part)
    return '/' + '/'.join(parts)


class Stage:
    """Descriptor-relative reads; symlinks are interpreted in the staged namespace.

    The root and its ancestry are caller-trusted. Contents must be quiescent;
    the audit is not a transactional snapshot of concurrently changing files.
    """
    def __init__(self, root):
        self.root = str(Path(root).absolute())
        if self.root == '/':
            raise ValueError('supply a staged root, not the active host /')
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened, host = os.fstat(self.fd), os.stat('/')
        if (opened.st_dev, opened.st_ino) == (host.st_dev, host.st_ino):
            os.close(self.fd)
            raise ValueError('supply a staged root, not an alias of the active host /')
        self.pins = {}
        self.open_attempts = self.bytes_read = self.entry_visits = 0

    def close(self):
        os.close(self.fd)

    def open(self, path, directory=False):
        self.open_attempts += 1
        if self.open_attempts > 100000:
            raise ValueError('staged open-attempt budget exhausted')
        if not isinstance(path, str) or not path.startswith('/') or '\0' in path:
            raise ValueError('absolute staged path required')
        pending = [x for x in path.split('/') if x not in ('', '.')]
        done, links = [], []
        fd = os.dup(self.fd)
        try:
            while pending:
                name = pending.pop(0)
                if name == '..':
                    if not done:
                        raise ValueError('path escapes staged root: ' + path)
                    pending = done[:-1] + pending
                    done = []
                    os.close(fd)
                    fd = os.dup(self.fd)
                    continue
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    if len(links) >= 40:
                        raise ValueError('symlink loop/limit: ' + path)
                    target = os.readlink(name, dir_fd=fd)
                    links.append({'path': '/' + '/'.join(done + [name]), 'target': target})
                    pending = [x for x in target.split('/') if x not in ('', '.')] + pending
                    if target.startswith('/'):
                        done = []
                        os.close(fd)
                        fd = os.dup(self.fd)
                    continue
                last = not pending
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if not last or directory:
                    flags |= os.O_DIRECTORY
                elif not stat.S_ISREG(info.st_mode):
                    raise ValueError('not a regular staged file: ' + path)
                new = os.open(name, flags, dir_fd=fd)
                os.close(fd)
                fd = new
                done.append(name)
            info = os.fstat(fd)
            if not directory and not stat.S_ISREG(info.st_mode):
                raise ValueError('not a regular staged file: ' + path)
            return fd, {'path': path, 'resolved': '/' + '/'.join(done),
                        'mode': oct(stat.S_IMODE(info.st_mode)), 'symlinks': links}
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, cap=TEXT_CAP):
        fd, record = self.open(path)
        try:
            chunks, count = [], 0
            while True:
                raw = os.read(fd, min(1024 * 1024, cap + 1 - count))
                if not raw:
                    break
                count += len(raw)
                self.bytes_read += len(raw)
                if self.bytes_read > 512 * 1024 * 1024:
                    raise ValueError('total staged byte-read budget exhausted')
                if count > cap:
                    raise ValueError('staged file exceeds read cap: ' + path)
                chunks.append(raw)
            raw = b''.join(chunks)
            record.update(pin(raw))
            self.pins[path] = record
            return raw, record
        finally:
            os.close(fd)

    def optional(self, path):
        try:
            return self.read(path)
        except FileNotFoundError:
            return None

    def entries(self, path):
        """Bounded application traversal; directory symlinks are not traversed."""
        results = []
        def walk(current, depth):
            if depth > 16:
                raise ValueError('application directory depth cap: ' + current)
            try:
                fd, _ = self.open(current, directory=True)
            except FileNotFoundError:
                return
            try:
                with os.scandir(fd) as items:
                    names = []
                    for item in items:
                        self.entry_visits += 1
                        if self.entry_visits > ENTRY_CAP:
                            raise ValueError('application directory entry cap')
                        names.append((item.name, item.is_dir(follow_symlinks=False)))
                for name, is_dir in sorted(names):
                    child = current + '/' + name
                    if is_dir:
                        walk(child, depth + 1)
                    elif name.endswith('.desktop'):
                        results.append(child)
            finally:
                os.close(fd)
        walk(path, 0)
        return results


def ini(raw):
    parser = configparser.ConfigParser(interpolation=None, strict=True,
                                       delimiters=('=',), comment_prefixes=('#',),
                                       inline_comment_prefixes=None, empty_lines_in_values=False)
    parser.optionxform = str
    parser.read_string(raw.decode('utf-8'))
    return parser


def unescape(value):
    def replace(match):
        if match[1] not in ESCAPES:
            raise ValueError('invalid string escape: \\' + match[1])
        return ESCAPES[match[1]]
    if len(value) - len(value.rstrip('\\')) & 1:
        raise ValueError('trailing string escape')
    return re.sub(r'\\(.)', replace, value)


def values(value):
    result, current, i = [], '', 0
    while i < len(value):
        char = value[i]
        if char == '\\':
            i += 1
            if i == len(value) or value[i] not in set(ESCAPES) | {';'}:
                raise ValueError('invalid list escape')
            current += ';' if value[i] == ';' else ESCAPES[value[i]]
        elif char == ';':
            if current:
                result.append(current)
            current = ''
        else:
            current += char
        i += 1
    if current:
        result.append(current)
    return result


def boolean(entry, key):
    value = entry.get(key, 'false')
    if value not in ('true', 'false'):
        raise ValueError('invalid boolean ' + key)
    return value == 'true'


def exec_argv(raw, name='', icon='', location=''):
    """Parse both Exec escaping layers and expand fields with no file input.

    Quoted field codes are undefined by the specification and are refused.
    This builds an inspection value only; the argv is never executed.
    """
    value = unescape(raw)
    words, i = [], 0
    while i < len(value):
        if value[i] in ' \t':
            i += 1
            continue
        quoted = value[i] == '"'
        if quoted:
            i += 1
        word, closed = '', not quoted
        while i < len(value):
            char = value[i]
            if quoted and char == '"':
                i += 1
                closed = True
                if i < len(value) and value[i] not in ' \t':
                    raise ValueError('quoting must enclose a whole argument')
                break
            if not quoted and char in ' \t':
                break
            if char == '\\':
                i += 1
                if not quoted or i == len(value) or value[i] not in '"`$\\':
                    raise ValueError('invalid Exec quoting escape')
                char = value[i]
            elif (quoted and char in '`$') or (not quoted and (char in RESERVED or char == '"')):
                raise ValueError('unescaped reserved Exec character: ' + char)
            if ord(char) < 32:
                raise ValueError('control character in Exec')
            word += char
            i += 1
        if not closed:
            raise ValueError('unterminated Exec quote')
        words.append((word, quoted))
    if not words or not words[0][0] or '=' in words[0][0]:
        raise ValueError('invalid/missing Exec executable')
    output, codes, files = [], [], 0
    for index, (word, quoted) in enumerate(words):
        expanded, j, drop = '', 0, False
        while j < len(word):
            if word[j] != '%':
                expanded += word[j]
                j += 1
                continue
            j += 1
            if j == len(word) or word[j] not in '%fFuUickdDnNvm':
                raise ValueError('unknown/trailing Exec field code')
            code = word[j]
            j += 1
            if code == '%':
                expanded += '%'
                continue
            if index == 0:
                raise ValueError('field code in executable')
            if quoted:
                raise ValueError('field code inside quoted argument is undefined')
            codes.append('%' + code)
            if code in 'fFuU':
                files += 1
            if code in 'FUi' and word != '%' + code:
                raise ValueError('multi-argument field code must stand alone')
            if code == 'i':
                if icon:
                    output.extend(['--icon', icon])
                drop = True
            elif code == 'c':
                expanded += name
            elif code == 'k':
                expanded += location
            elif word == '%' + code:
                drop = True
        if not drop:
            output.append(expanded)
    if files > 1 or not output or not output[0]:
        raise ValueError('invalid executable field code or repeated file field')
    return {'argv_without_file_inputs': output, 'field_codes': codes}


def environment(value):
    required = ('HOME', 'XDG_DATA_HOME', 'XDG_DATA_DIRS', 'XDG_CONFIG_HOME',
                'XDG_CONFIG_DIRS', 'XDG_CURRENT_DESKTOP', 'PATH', 'icon_theme',
                'icon_size', 'icon_scale', 'terminal_argv', 'locale')
    if not isinstance(value, dict) or any(k not in value for k in required):
        raise ValueError('explicit environment requires: ' + ', '.join(required))
    if any(isinstance(x, str) and len(x) > 4096 for x in value.values()):
        raise ValueError('environment string length cap')
    result = dict(value)
    for key in ('HOME', 'XDG_DATA_HOME', 'XDG_CONFIG_HOME'):
        result[key] = absolute(value[key])
    for key in ('XDG_DATA_DIRS', 'XDG_CONFIG_DIRS', 'PATH'):
        if not isinstance(value[key], str) or not value[key]:
            raise ValueError('nonempty absolute path list required: ' + key)
        if len(value[key].split(':')) > 32:
            raise ValueError('environment path-list count cap: ' + key)
        result[key] = ':'.join(absolute(x) for x in value[key].split(':'))
    if not isinstance(value['XDG_CURRENT_DESKTOP'], str) or any(
            not re.fullmatch(r'[A-Za-z0-9_-]+', x) for x in value['XDG_CURRENT_DESKTOP'].split(':')):
        raise ValueError('explicit desktop name(s) required')
    if not isinstance(value['icon_theme'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', value['icon_theme']):
        raise ValueError('invalid icon theme')
    if any(type(value[k]) is not int or not 1 <= value[k] <= 1024 for k in ('icon_size', 'icon_scale')):
        raise ValueError('positive bounded icon size/scale required')
    terminal = value['terminal_argv']
    if not isinstance(terminal, list) or len(terminal) > 128 or any(not isinstance(x, str) or not x or len(x) > 4096 or '\0' in x for x in terminal):
        raise ValueError('terminal_argv must be explicit array (empty means unconfigured)')
    if not isinstance(value['locale'], str) or not re.fullmatch(r'[A-Za-z0-9_.@-]+', value['locale']):
        raise ValueError('explicit locale required')
    return result


def command_ok(value):
    if not value or 'error' in value:
        return False
    return all(command_ok(value[key]) for key in ('interpreter', 'env_target') if key in value)


def elf_interpreter(raw):
    if len(raw) < 52 or raw[4] not in (1, 2) or raw[5] not in (1, 2):
        raise ValueError('invalid ELF class/encoding/header')
    endian = '<' if raw[5] == 1 else '>'
    if raw[4] == 2:
        if len(raw) < 64:
            raise ValueError('truncated ELF64 header')
        offset = struct.unpack_from(endian + 'Q', raw, 32)[0]
        size, count = struct.unpack_from(endian + 'HH', raw, 54)
        minimum = 56
    else:
        offset = struct.unpack_from(endian + 'I', raw, 28)[0]
        size, count = struct.unpack_from(endian + 'HH', raw, 42)
        minimum = 32
    if count == 0xffff or count > 4096 or (count and size < minimum) or offset + size * count > len(raw):
        raise ValueError('invalid/unsupported ELF program header table')
    found = []
    for i in range(count):
        pos = offset + i * size
        if struct.unpack_from(endian + 'I', raw, pos)[0] != 3:
            continue
        if raw[4] == 2:
            start = struct.unpack_from(endian + 'Q', raw, pos + 8)[0]
            length = struct.unpack_from(endian + 'Q', raw, pos + 32)[0]
        else:
            start = struct.unpack_from(endian + 'I', raw, pos + 4)[0]
            length = struct.unpack_from(endian + 'I', raw, pos + 16)[0]
        data = raw[start:start + length]
        if not 1 < length <= 4096 or len(data) != length or data[-1:] != b'\0' or b'\0' in data[:-1]:
            raise ValueError('invalid ELF PT_INTERP')
        found.append(absolute(data[:-1].decode('utf-8')))
    if len(found) > 1:
        raise ValueError('multiple ELF interpreters')
    return found[0] if found else None


class Audit:
    def __init__(self, root, env):
        self.env = environment(env)
        self.stage = Stage(root)
        self.issues, self.catalog, self.cache = [], {}, {}
        self.data = [self.env['XDG_DATA_HOME']] + self.env['XDG_DATA_DIRS'].split(':')
        try:
            for rank, base in enumerate(self.data):
                local = {}
                for path in self.stage.entries(base + '/applications'):
                    ident = path[len(base + '/applications/'):].replace('/', '-')
                    if ident in local:
                        raise ValueError('ambiguous desktop ID in one data directory: ' + ident)
                    local[ident] = path
                    self.catalog.setdefault(ident, []).append({'path': path, 'rank': rank,
                        'origin': 'user_override' if rank == 0 else 'system_data'})
        except BaseException:
            self.stage.close()
            raise

    def issue(self, code, path, detail, severity='error'):
        row = {'code': code, 'path': path, 'detail': detail, 'severity': severity}
        if row not in self.issues:
            self.issues.append(row)

    def executable(self, name, path=None, ancestry=()):
        if not name or '=' in name or ('/' in name and not name.startswith('/')):
            raise ValueError('executable must be basename or absolute: ' + repr(name))
        candidates = [name] if name.startswith('/') else [x + '/' + name for x in (path or self.env['PATH']).split(':')]
        attempts = []
        for candidate in candidates:
            try:
                raw, record = self.stage.read(candidate, FILE_CAP)
            except FileNotFoundError:
                attempts.append({'path': candidate, 'reason': 'missing'})
                continue
            if not int(record['mode'], 8) & 0o111:
                attempts.append({'path': candidate, 'reason': 'no_execute_mode_bit'})
                continue
            result = {'requested': name, 'file': record, 'search_misses': attempts}
            if record['resolved'] in ancestry or len(ancestry) >= 8:
                result['error'] = 'interpreter cycle/depth cap'
                return result
            chain = ancestry + (record['resolved'],)
            interpreter = None
            if raw.startswith(b'#!'):
                line = raw.split(b'\n', 1)[0][2:]
                if len(line) > 253:
                    result['error'] = 'shebang exceeds conservative Linux limit'
                    return result
                fields = line.decode('utf-8').strip().split(None, 1)
                if not fields or not fields[0].startswith('/'):
                    result['error'] = 'invalid absolute shebang interpreter'
                    return result
                interpreter = fields[0]
                result['format'] = 'shebang'
                result['shebang_arguments'] = fields[1:]
                if interpreter.rsplit('/', 1)[-1] == 'env' and len(fields) == 2:
                    # Linux passes the entire optional argument as ONE string.
                    if fields[1].startswith('-S '):
                        args = shlex.split(fields[1][3:])
                    elif any(x.isspace() for x in fields[1]):
                        result['error'] = 'env shebang needs -S for multiple arguments'
                        return result
                    else:
                        args = [fields[1]]
                    result['env_target'] = self.env_target(args, chain)
            elif raw.startswith(b'\x7fELF'):
                result['format'] = 'ELF'
                interpreter = elf_interpreter(raw)
                result['elf_machine'] = struct.unpack_from('<H' if raw[5] == 1 else '>H', raw, 18)[0]
            else:
                result['format'] = 'unknown'
                result['error'] = 'executable format is neither ELF nor shebang'
            if interpreter:
                result['interpreter'] = self.executable(interpreter, ancestry=chain)
            return result
        return {'requested': name, 'error': 'executable unavailable', 'search_misses': attempts}

    def env_target(self, args, ancestry=()):
        tool_path, i, options = self.env['PATH'], 0, True
        while i < len(args):
            arg = args[i]
            if options and arg in ('-i', '--ignore-environment'):
                tool_path = None
                i += 1
            elif options and arg == '--':
                options = False
                i += 1
            elif options and arg in ('-u', '--unset') and i + 1 < len(args):
                if args[i + 1] == 'PATH':
                    tool_path = None
                i += 2
            elif options and arg.startswith('-'):
                return {'error': 'unsupported env option; nested command unresolved: ' + arg}
            elif '=' in arg:
                key, value = arg.split('=', 1)
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                    return {'error': 'invalid env assignment'}
                if key == 'PATH':
                    tool_path = ':'.join(absolute(x) for x in value.split(':'))
                i += 1
            else:
                break
        if i == len(args):
            return {'error': 'env has no application command'}
        if tool_path is None and not args[i].startswith('/'):
            return {'error': 'env PATH unset; platform default search is not inferred'}
        result = self.executable(args[i], path=tool_path, ancestry=ancestry)
        if args[i].rsplit('/', 1)[-1] == 'env':
            result['error'] = 'nested env wrappers unresolved'
        if args[i].rsplit('/', 1)[-1] in ('sh', 'bash', 'zsh', 'fish') and '-c' in args[i + 1:]:
            result['error'] = 'shell -c payload is dynamic and NOT_AUDITED'
        return result

    def command(self, argv):
        result = self.executable(argv[0])
        if argv[0].rsplit('/', 1)[-1] == 'env':
            result['env_target'] = self.env_target(argv[1:])
        if argv[0].rsplit('/', 1)[-1] in ('sh', 'bash', 'zsh', 'fish') and '-c' in argv[1:]:
            result['error'] = 'shell -c payload is dynamic and NOT_AUDITED'
        return result

    def entry(self, ident):
        if ident in self.cache:
            return self.cache[ident]
        row = {'id': ident}
        self.cache[ident] = row
        sources = self.catalog.get(ident, [])
        if not sources:
            row['error'] = 'desktop ID not installed'
            return row
        row.update(sources[0])
        row['shadowed'] = sources[1:]
        try:
            raw, row['file'] = self.stage.read(row['path'])
            entry = ini(raw)['Desktop Entry']
            row['hidden'] = boolean(entry, 'Hidden')
            if row['hidden']:
                row['visibility'] = 'HIDDEN_TOMBSTONE'
                return row
            if entry.get('Type') != 'Application':
                raise ValueError('selected entry Type must be Application')
            name = entry.get('Name', '')
            locale, _, modifier = self.env['locale'].partition('@')
            locale = locale.split('.', 1)[0]
            language = locale.split('_', 1)[0]
            choices = ([locale + '@' + modifier] if modifier else []) + [locale]
            if modifier:
                choices.append(language + '@' + modifier)
            for choice in choices + [language]:
                if 'Name[' + choice + ']' in entry:
                    name = entry['Name[' + choice + ']']
                    break
            row['name'] = unescape(name)
            if not row['name']:
                raise ValueError('missing Name')
            only, exclude = values(entry.get('OnlyShowIn', '')), values(entry.get('NotShowIn', ''))
            if only and exclude:
                raise ValueError('OnlyShowIn and NotShowIn are mutually exclusive')
            desktop = self.env['XDG_CURRENT_DESKTOP'].split(':')
            row['desktop_eligible'] = (not only or any(x in only for x in desktop)) and not any(x in exclude for x in desktop)
            row['no_display'] = boolean(entry, 'NoDisplay')
            row['visibility'] = ('DESKTOP_EXCLUDED' if not row['desktop_eligible'] else
                                 'NO_DISPLAY_HANDLER' if row['no_display'] else 'MENU_CANDIDATE')
            row['mime_types'] = values(entry.get('MimeType', ''))
            row['terminal'] = boolean(entry, 'Terminal')
            row['dbus_activatable'] = boolean(entry, 'DBusActivatable')
            if row['dbus_activatable']:
                row['activation'] = 'DBUS_ACTIVATION_NOT_RUN; Exec is fallback only'
                self.issue('dbus_activation_unverified', row['path'], row['activation'], 'warning')
            if 'TryExec' in entry:
                row['try_exec'] = self.executable(unescape(entry['TryExec']))
            if 'Exec' in entry:
                icon = unescape(entry.get('Icon', ''))
                row['exec'] = exec_argv(entry['Exec'], row['name'], icon, row['path'])
                row['exec']['resolution'] = self.command(row['exec']['argv_without_file_inputs'])
            elif not row['dbus_activatable']:
                raise ValueError('missing Exec')
            if entry.get('Path'):
                working = absolute(unescape(entry['Path']))
                fd, row['working_directory'] = self.stage.open(working, directory=True)
                os.close(fd)
            row['icon'] = self.icon(unescape(entry.get('Icon', '')))
            if row['terminal']:
                row['terminal_command'] = self.command(self.env['terminal_argv']) if self.env['terminal_argv'] else {'error': 'terminal command unconfigured'}
        except (ValueError, OSError, KeyError, configparser.Error, UnicodeError, struct.error) as error:
            row['error'] = str(error)
        return row

    def icon(self, name):
        if not name:
            return {'status': 'UNSPECIFIED'}
        if name.startswith('/'):
            _, record = self.stage.read(name, FILE_CAP)
            return {'status': 'FOUND_ABSOLUTE', 'file': record}
        if '/' in name:
            raise ValueError('icon name must be basename or absolute path')
        bases = [self.env['HOME'] + '/.icons', self.env['XDG_DATA_HOME'] + '/icons'] + [x + '/icons' for x in self.env['XDG_DATA_DIRS'].split(':')]
        seen, indexes = set(), []
        def theme_lookup(theme):
            if theme in seen:
                return None
            if len(seen) >= 32 or not re.fullmatch(r'[A-Za-z0-9_.-]+', theme):
                raise ValueError('icon theme inheritance cap/invalid name')
            seen.add(theme)
            index = None
            for base in bases:
                found = self.stage.optional(base + '/' + theme + '/index.theme')
                if found:
                    raw, receipt = found
                    indexes.append(receipt)
                    index = ini(raw)
                    break
            if index is None:
                return None
            main = index['Icon Theme']
            directories = [x for x in (main.get('Directories', '') + ',' + main.get('ScaledDirectories', '')).split(',') if x]
            if len(directories) > 1024:
                raise ValueError('icon theme directory count cap')
            candidates = []
            for order, sub in enumerate(dict.fromkeys(directories)):
                if sub.startswith('/') or '..' in sub.split('/'):
                    raise ValueError('unsafe icon theme directory')
                group = index[sub]
                size, scale = int(group['Size']), int(group.get('Scale', '1'))
                kind = group.get('Type', 'Threshold')
                if size < 1 or scale < 1:
                    raise ValueError('invalid icon directory size/scale')
                low = int(group.get('MinSize', str(size))) if kind == 'Scalable' else size - int(group.get('Threshold', '2')) if kind == 'Threshold' else size
                high = int(group.get('MaxSize', str(size))) if kind == 'Scalable' else size + int(group.get('Threshold', '2')) if kind == 'Threshold' else size
                if kind not in ('Fixed', 'Scalable', 'Threshold') or low > high:
                    raise ValueError('invalid icon directory type/range')
                wanted = self.env['icon_size'] * self.env['icon_scale']
                distance = max(low * scale - wanted, wanted - high * scale, 0)
                exact = scale == self.env['icon_scale'] and low <= self.env['icon_size'] <= high
                for base in bases:
                    for ext in ('.png', '.svg', '.xpm'):
                        found = self.stage.optional(base + '/' + theme + '/' + sub + '/' + name + ext)
                        if found:
                            _, receipt = found
                            candidates.append((not exact, distance, order, receipt))
            if candidates:
                # Stable sort preserves base-directory then extension precedence.
                return sorted(candidates, key=lambda x: x[:3])[0][3]
            for parent in main.get('Inherits', '').split(','):
                if parent and parent != 'hicolor':
                    found = theme_lookup(parent)
                    if found:
                        return found
            return None
        record = theme_lookup(self.env['icon_theme']) or theme_lookup('hicolor')
        if not record:
            for base in bases + ['/usr/share/pixmaps']:
                for ext in ('.png', '.svg', '.xpm'):
                    found = self.stage.optional(base + '/' + name + ext)
                    if found:
                        _, record = found
                        break
                if record:
                    break
        return {'status': 'FOUND' if record else 'MISSING', 'name': name,
                'file': record, 'theme_indexes': indexes, 'themes_checked': sorted(seen),
                'rendering': 'NOT_RUN (SVG support assumed for selection)'}

    def mime_files(self):
        result = []
        config = [self.env['XDG_CONFIG_HOME']] + self.env['XDG_CONFIG_DIRS'].split(':')
        for base, rank in [(x, -1) for x in config] + [(x + '/applications', i) for i, x in enumerate(self.data)]:
            for desktop in [x.lower() + '-' for x in self.env['XDG_CURRENT_DESKTOP'].split(':')] + ['']:
                path = base + '/' + desktop + 'mimeapps.list'
                found = self.stage.optional(path)
                if found:
                    raw, receipt = found
                    parsed = ini(raw)
                    if desktop and any(x in parsed for x in ('Added Associations', 'Removed Associations')):
                        raise ValueError('desktop-specific mimeapps cannot change associations: ' + path)
                    result.append({'path': path, 'rank': rank, 'desktop_specific': bool(desktop),
                                   'file': receipt, 'parsed': parsed})
        return result

    def mime(self, mime, files):
        references, candidates = [], []
        def associated(ident, app):
            if app.get('hidden') or 'error' in app:
                return False
            for source in files:
                if source['desktop_specific'] or (source['rank'] >= 0 and source['rank'] > app['rank']):
                    continue
                parser = source['parsed']
                added = values(parser.get('Added Associations', mime, fallback=''))
                removed = values(parser.get('Removed Associations', mime, fallback=''))
                if ident in added and ident in removed:
                    raise ValueError('conflicting MIME association: ' + source['path'])
                if ident in added:
                    return True
                if ident in removed:
                    return False
            return mime in app.get('mime_types', [])
        effective = None
        for source in files:
            parser = source['parsed']
            for section in ('Default Applications', 'Added Associations', 'Removed Associations'):
                for ident in values(parser.get(section, mime, fallback='')):
                    if not re.fullmatch(r'[^/\s]+\.desktop', ident):
                        raise ValueError('invalid desktop ID in MIME reference: ' + source['path'])
                    app = self.entry(ident)
                    linked = associated(ident, app)
                    references.append({'path': source['path'], 'section': section,
                                       'id': ident, 'associated': linked,
                                       'entry_path': app.get('path'), 'entry_error': app.get('error'),
                                       'hidden': app.get('hidden', False)})
                    if section != 'Removed Associations' and ('error' in app or app.get('hidden')):
                        self.issue('mime_reference_unavailable', source['path'], mime + ': ' + ident, 'warning')
                    if section == 'Default Applications':
                        usable = linked and command_ok(app.get('exec', {}).get('resolution')) and (
                            not app.get('try_exec') or command_ok(app['try_exec']))
                        if app.get('terminal'):
                            usable = usable and command_ok(app.get('terminal_command'))
                        candidates.append({'id': ident, 'source': source['path'], 'usable_exec_fallback': bool(usable)})
                        if effective is None and usable:
                            effective = ident
        return {'mime_type': mime, 'references': references, 'default_candidates': candidates,
                'effective_explicit_exec_fallback': effective,
                'implicit_fallback_and_subclasses': 'NOT_INFERRED'}

    def run(self, selected, mime_types=()):
        if not selected or len(selected) > 128 or any(not re.fullmatch(r'[^/\s]+\.desktop', x) for x in selected):
            raise ValueError('select 1..128 desktop IDs')
        apps = [self.entry(x) for x in dict.fromkeys(selected)]
        for app in apps:
            path = app.get('path', app['id'])
            if app.get('error'):
                self.issue('desktop_entry_broken', path, app['error'])
            elif app.get('hidden'):
                self.issue('selected_hidden', path, 'tombstone suppresses lower-precedence entries')
            else:
                if not app['desktop_eligible']:
                    self.issue('selected_desktop_excluded', path, 'entry excludes chosen XDG_CURRENT_DESKTOP')
                for key, value in [('Exec', app.get('exec', {}).get('resolution')),
                                   ('TryExec', app.get('try_exec')), ('Terminal', app.get('terminal_command'))]:
                    if value is not None and not command_ok(value):
                        self.issue('command_unavailable', path, key + ': ' + json.dumps(value, sort_keys=True))
                if app.get('icon', {}).get('status') == 'MISSING':
                    self.issue('icon_missing', path, app['icon']['name'])
        files = self.mime_files()
        types = sorted(set(mime_types) | {m for app in apps for m in app.get('mime_types', [])})
        if len(types) > 512:
            raise ValueError('MIME selection cap')
        mime_rows = [self.mime(x, files) for x in types]
        for row in mime_rows:
            if row['mime_type'] in mime_types and not row['effective_explicit_exec_fallback']:
                self.issue('required_mime_default_unresolved', row['mime_type'], 'no available explicit Exec fallback; implicit fallback not inferred')
        return {'schema': 1, 'scope': 'STAGED_DESKTOP_INTEGRATION_ONLY',
                'status': 'FAIL_STAGED_CHECKS' if any(x['severity'] == 'error' for x in self.issues) else 'PASS_STAGED_CHECKS',
                'root': self.stage.root, 'environment': self.env, 'applications': apps,
                'mime': mime_rows, 'mime_files': [{k: v for k, v in x.items() if k != 'parsed'} for x in files],
                'issues': self.issues, 'pins': self.stage.pins,
                'budget_used': {'open_attempts': self.stage.open_attempts, 'bytes_read': self.stage.bytes_read,
                                'application_entries_visited': self.stage.entry_visits},
                'limits': ['no commands launched; executable mode bits are not credential/mount access proof',
                           'ELF dependencies, arbitrary interpreter arguments, application behavior NOT_AUDITED',
                           'D-Bus activation, icon rendering, MIME subtype/implicit ranking NOT_RUN',
                           'native ARM, Wayland UI, physical M2, performance, release acceptance NOT_RUN']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--environment', required=True, type=Path, help='explicit JSON environment, never sourced')
    parser.add_argument('--select', action='append', required=True, help='selected desktop ID; repeatable')
    parser.add_argument('--mime', action='append', default=[], help='require explicit available default for this MIME type')
    args = parser.parse_args(argv)
    audit = None
    try:
        with args.environment.open('rb') as stream:
            raw = stream.read(TEXT_CAP + 1)
        if len(raw) > TEXT_CAP:
            raise ValueError('environment input exceeds cap')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate environment key: ' + key)
                result[key] = value
            return result
        audit = Audit(args.root, json.loads(raw, object_pairs_hook=unique))
        report = audit.run(args.select, args.mime)
        report['environment_input'] = dict(path=str(args.environment.absolute()), **pin(raw))
        print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
        return 0 if report['status'] == 'PASS_STAGED_CHECKS' else 1
    except (ValueError, OSError, configparser.Error, UnicodeError, KeyError, TypeError, struct.error) as error:
        print(json.dumps({'schema': 1, 'status': 'REFUSED', 'error': str(error)}, sort_keys=True))
        return 2
    finally:
        if audit is not None:
            audit.stage.close()


if __name__ == '__main__':
    sys.exit(main())
