#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare declared literal PKGBUILD/.SRCINFO metadata without evaluating shell."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 1024**2
SCALARS = {'pkgbase', 'pkgname', 'pkgver', 'pkgrel', 'epoch'}
RELATIONS = {'depends', 'makedepends', 'checkdepends', 'optdepends',
             'provides', 'conflicts', 'replaces'}
CHECKSUMS = {'md5sums': 32, 'sha1sums': 40, 'sha224sums': 56,
             'sha256sums': 64, 'sha384sums': 96, 'sha512sums': 128, 'b2sums': 128}
GROUPS = RELATIONS | set(CHECKSUMS) | {'source'}
FUNCTION = re.compile(r'(prepare|build|check|package)\(\)\s*\{\s*(?:#.*)?$')
ASSIGNMENT = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
RELATION = re.compile(r'([A-Za-z0-9@_+][A-Za-z0-9@._+-]*)(?:(>=|<=|=|>|<)'
                      r'((?:[0-9]+:)?[A-Za-z0-9_+.~]+(?:-[0-9]+(?:\.[0-9]+)?)?))?$')


class Unsupported(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Unsupported(reason)


def group(key):
    for base in sorted(GROUPS, key=len, reverse=True):
        if key == base:
            return base, ''
        if key.startswith(base + '_'):
            suffix = key[len(base) + 1:]
            require(re.fullmatch(r'[a-z][a-z0-9_]*', suffix), 'unsupported architecture suffix: ' + key)
            return base, suffix
    return key, ''


def words(raw):
    """Complete separate literal shell words; no concatenation, escapes or expansion."""
    result, at = [], 0
    while at < len(raw):
        if raw[at].isspace():
            at += 1
            continue
        if raw[at] == '#':
            end = raw.find('\n', at)
            at = len(raw) if end < 0 else end + 1
            continue
        if raw[at] in "'\"":
            quote = raw[at]
            end = raw.find(quote, at + 1)
            require(end >= 0, 'unterminated quoted literal')
            item = raw[at + 1:end]
            require(all(32 <= ord(c) <= 126 for c in item), 'single-line ASCII literal required')
            if quote == '"':
                require(not any(c in item for c in '$`\\'), 'dynamic or escaped double-quoted word')
            at = end + 1
            require(at == len(raw) or raw[at].isspace(), 'compound literal word or assignment tail')
        else:
            end = at
            while end < len(raw) and not raw[end].isspace():
                end += 1
            item, at = raw[at:end], end
            require(re.fullmatch(r'[A-Za-z0-9_@%+:,./~!?=-]+', item),
                    'unquoted shell syntax or expansion')
        result.append(item)
    return result


def array_end(raw, quote=None):
    comment = False
    for at, char in enumerate(raw):
        if comment:
            comment = char != '\n'
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == '#' and (at == 0 or raw[at - 1].isspace()):
            comment = True
        elif char == ')':
            return at, quote
    return None, quote


def pkgbuild(text):
    values, functions = {}, []
    lines = text.splitlines()
    at = 0
    while at < len(lines):
        line = lines[at]
        at += 1
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        function = FUNCTION.fullmatch(line)
        if function:
            name = function[1]
            require(name not in functions, 'duplicate stage function: ' + name)
            functions.append(name)
            while at < len(lines) and lines[at].strip() != '}':
                require(not lines[at] or lines[at][0].isspace() or lines[at].startswith('#'),
                        'stage bodies must be indented; unsupported shell layout')
                at += 1
            require(at < len(lines) and lines[at] == '}', 'unsupported stage function boundary')
            at += 1
            continue
        match = ASSIGNMENT.fullmatch(line)
        require(match, 'unsupported top-level shell, dynamic function or assignment')
        key, raw = match.groups()
        require(key not in values, 'duplicate or amended assignment: ' + key)
        if raw.startswith('('):
            raw = raw[1:]
            parts = []
            end, quote = array_end(raw)
            while end is None and at < len(lines):
                parts.append(raw)
                raw = lines[at]
                at += 1
                end, quote = array_end(raw, quote)
            require(end is not None, 'unterminated literal array: ' + key)
            tail = raw[end + 1:].strip()
            require(not tail or tail.startswith('#'), 'nonliteral array assignment tail: ' + key)
            raw = '\n'.join([*parts, raw[:end]])
        values[key] = words(raw)
    return values, functions


def srcinfo(text):
    values = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*', line)
        require(match, 'unsupported .SRCINFO line')
        key, value = match.groups()
        require(value and all(32 <= ord(c) <= 126 for c in value), 'nonempty ASCII .SRCINFO value required')
        values.setdefault(key, []).append(value)
    return values


def normalize(values):
    result, ignored = {}, []
    for key, items in values.items():
        base, suffix = group(key)
        if base not in SCALARS | GROUPS | {'arch'}:
            ignored.append(key)
            continue
        if base in SCALARS:
            require(len(items) == 1 and items[0], 'single literal ' + key + ' required; split packages unsupported')
        if base in RELATIONS:
            for item in items:
                relation = item.partition(': ')[0] if base == 'optdepends' else item
                match = RELATION.fullmatch(relation)
                require(match and (base != 'provides' or match[2] in (None, '=')), 'unsupported relation: ' + key)
        if base in CHECKSUMS:
            require(all(x == 'SKIP' or re.fullmatch('[0-9a-fA-F]{' + str(CHECKSUMS[base]) + '}', x)
                        for x in items), 'unsupported checksum literal: ' + key)
            items = [x if x == 'SKIP' else x.lower() for x in items]
        if base == 'source':
            require(all(x and all(32 <= ord(c) <= 126 for c in x) for x in items), 'nonempty ASCII source literal required')
        result[key] = sorted(set(items)) if base in RELATIONS | {'arch'} else list(items)
    for key in ('pkgname', 'pkgver', 'pkgrel', 'arch'):
        require(result.get(key), 'missing literal field: ' + key)
    require(re.fullmatch(r'[A-Za-z0-9@_+][A-Za-z0-9@._+-]*', result['pkgname'][0]), 'unsupported package name')
    require(re.fullmatch(r'[A-Za-z0-9_+.~]+', result['pkgver'][0]), 'unsupported package version')
    require(re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', result['pkgrel'][0]), 'unsupported package release')
    result.setdefault('pkgbase', list(result['pkgname']))
    require(result['pkgbase'] == result['pkgname'], 'separate package base or split package unsupported')
    epoch = result.setdefault('epoch', ['0'])
    require(len(epoch[0]) <= 20 and re.fullmatch(r'[0-9]+', epoch[0]), 'unsupported epoch (maximum20 digits)')
    result['epoch'] = [str(int(epoch[0]))]
    require(all(re.fullmatch(r'[a-z][a-z0-9_]*', x) for x in result['arch']), 'unsupported architecture literal')
    for key, items in result.items():
        base, suffix = group(key)
        if suffix:
            require(suffix in result['arch'] and 'any' not in result['arch'], 'architecture-qualified field outside declared architecture: ' + key)
        if base in CHECKSUMS:
            source = 'source' + ('_' + suffix if suffix else '')
            require(len(items) == len(result.get(source, [])), 'source/checksum count differs: ' + key)
        if base == 'source' and items:
            require(any(group(k)[0] in CHECKSUMS and group(k)[1] == suffix for k in result), 'source group lacks modeled checksums: ' + key)
    return result, sorted(ignored)


def compare(recipe, info):
    report = dict(schema=1, status='UNSUPPORTED', mismatches=[], unsupported=[], compared_fields=[],
                  ignored_fields={}, opaque_stage_functions=[], shell_evaluation=False,
                  qualification='DECLARED_LITERAL_METADATA_ONLY_NOT_RECIPE_SAFETY_OR_SOURCE_AUTHENTICITY')
    parsed = {}
    for role, text in (('PKGBUILD', recipe), ('.SRCINFO', info)):
        try:
            if role == 'PKGBUILD':
                values, report['opaque_stage_functions'] = pkgbuild(text)
            else:
                values = srcinfo(text)
            parsed[role], report['ignored_fields'][role] = normalize(values)
        except Unsupported as error:
            report['unsupported'].append(dict(input=role, reason=str(error)))
    if len(parsed) != 2:
        return report
    left, right = parsed['PKGBUILD'], parsed['.SRCINFO']
    report['compared_fields'] = sorted(set(left) | set(right))
    for key in report['compared_fields']:
        if left.get(key, []) != right.get(key, []):
            report['mismatches'].append(dict(field=key, PKGBUILD=left.get(key, []), SRCINFO=right.get(key, [])))
    report['status'] = 'MISMATCH' if report['mismatches'] else 'MATCH_MODELED_LITERAL_DECLARATIONS'
    return report


def read(path):
    path = Path(path).absolute()
    require(path == path.resolve(), 'canonical input path required; aliases refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= MAX_BYTES,
                'ordinary single-link input <=1MiB required')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_uid,
                              s.st_gid, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
                'input changed while reading')
        require(b'\0' not in raw, 'NUL input refused')
        return raw.decode('utf-8'), dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('recipe', type=Path)
    parser.add_argument('--srcinfo', type=Path)
    args = parser.parse_args(argv)
    try:
        require(sys.version_info >= (3, 12), 'Python >=3.12 required; standard library only')
        recipe, rp = read(args.recipe)
        info, ip = read(args.srcinfo or args.recipe.parent / '.SRCINFO')
        report = compare(recipe, info)
        report['inputs'] = dict(PKGBUILD=rp, SRCINFO=ip)
    except (OSError, UnicodeError, Unsupported) as error:
        report = dict(schema=1, status='INPUT_ERROR', error=str(error), shell_evaluation=False)
    print(json.dumps(report, sort_keys=True, indent=2))
    return {'MATCH_MODELED_LITERAL_DECLARATIONS': 0, 'MISMATCH': 1}.get(report['status'], 2)


if __name__ == '__main__':
    raise SystemExit(main())
