# SPDX-License-Identifier: MIT
"""Finite local source/package contract for the Setup8 real-shell trial."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

DELIVERY_SHA = 'e07fd35837b5d1b7239fdd42313e11f72e0133d7ac8359a528c019c0c57bd7d2'
SETUP_SHA = '8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47'
PACKAGES = {
 'fish': 'packages/shells/cachy-asahi-fish-config',
 'zsh': 'packages/shells/cachy-asahi-zsh-config',
 'fish-bang-bang': 'packages/shells/cachy-asahi-fish-bang-bang',
 'fish-autopair': 'packages/tools/cachy-asahi-fish-autopair',
 'fish-done': 'packages/tools/cachy-asahi-fish-done',
 'zsh-autosuggestions': 'packages/shells/cachy-asahi-zsh-autosuggestions',
 'zsh-syntax-highlighting': 'packages/tools/cachy-asahi-zsh-syntax-highlighting',
 'zsh-history-substring-search': 'packages/tools/cachy-asahi-zsh-history-substring-search',
}
COMPONENTS = tuple(PACKAGES)


def need(ok, why):
    if not ok: raise ValueError(why)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(path): return sha(path.read_bytes())
def encode(value): return (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()
def save(path, value): path.write_bytes(encode(value))


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path required')
    return path


def tree(root):
    result = {}; total = 0
    for path in sorted(root.rglob('*')):
        need(len(result) < 4096, 'finite tree node cap')
        item = path.lstat()
        need(stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode), 'ordinary tree nodes required')
        if path.is_file():
            total += item.st_size
            need(item.st_size <= 2*1024**2 and total <= 24*1024**2, 'finite tree byte cap')
        result[str(path.relative_to(root))] = dict(kind='file' if path.is_file() else 'directory',
            mode=stat.S_IMODE(item.st_mode), uid=item.st_uid, gid=item.st_gid,
            sha256=digest(path) if path.is_file() else None,
            xattrs={n:sha(os.getxattr(path,n)) for n in os.listxattr(path)})
    return result


def payload_tree(root):
    return {n:{k:v for k,v in row.items() if k not in ('uid','gid')} for n,row in tree(root).items()}


def command(argv, *, env=None, cwd=None, expected=0, timeout=20):
    result = subprocess.run(list(map(str, argv)), env=env, cwd=cwd, capture_output=True, timeout=timeout)
    need(len(result.stdout)+len(result.stderr) < 2*1024**2, 'command output cap')
    need(result.returncode == expected, 'command failed '+str(argv[:3])+': '+result.stderr.decode(errors='replace')[:1000])
    return result


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify_context(root):
    ordinary(root)
    record = json.loads((root/'context.json').read_bytes())
    need(digest(root/'setup-source/test_delivery.py') == DELIVERY_SHA,'accepted delivery driver differs')
    need(record['schema_version'] == 1 and record['components'] == list(COMPONENTS), 'finite context schema/components differ')
    need(record['setup_archive_sha256'] == SETUP_SHA and digest(root/'setup8.pkg.tar.xz') == SETUP_SHA, 'accepted Setup8 archive differs')
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    need(actual == set(record['files']) | {'context.json'}, 'complete context file registry differs')
    for name, row in record['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe context relative leaf required')
        path = ordinary(root/name)
        need(path.is_file() and path.stat().st_size == row['bytes'] and digest(path) == row['sha256'], 'context bytes differ: '+name)
    need(payload_tree(root/'stage') == record['stage_tree'], 'staged package payload/mode/owner differs')
    return record
