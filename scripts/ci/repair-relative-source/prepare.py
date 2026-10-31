# SPDX-License-Identifier: MIT
"""Reproduce exact public245 from closed public242; source-only, no actors."""
import argparse
import ast
import base64
import hashlib
import json
import os
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE_PIN = {'bytes': 98855, 'sha256': '09224a91d4cf71f34c8e3110422cd8de69ca654cf830fba3e6147df09eea6f9e'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)),
         'absolute normalized path required')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'aliased path refused')
    return path


def read(path, cap=8 * 1024**2):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= cap, 'bounded ordinary single-link file')
        raw = bytearray()
        while part := os.read(fd, min(65536, before.st_size + 1 - len(raw))):
            raw.extend(part)
            need(len(raw) <= before.st_size, 'file growth refused')
        identity = lambda s: tuple(getattr(s, k) for k in (
            'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
            'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(path.lstat()), 'file changed during read')
        return bytes(raw)
    finally:
        os.close(fd)


def tree(root):
    root = ordinary(root)
    need(root.is_dir(), 'complete source directory required')
    values, directories = {}, set()
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        need(not path.is_symlink() and
             (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
             'ordinary source namespace required')
        name = path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            directories.add(name)
        else:
            values[name] = read(path)
    need(directories == {p.as_posix() for n in values for p in Path(n).parents
                         if p.as_posix() != '.'}, 'foreign empty directory refused')
    return values


"""One private FRESH_QUERY installer dependency; complete242 inverse."""
import ast,json
A='scripts/ci/apps7-full574-repair16k/adapter.py';SELECT='apps16-repair/selection.py';SUCCESSOR='apps16-repair/successor.json';HELPER='apps16-repair/relative_query.py';GUARD='apps16-repair/relative_source.py';PROFILE='apps16-repair/relative-profile.json'
MANIFESTS=('scripts/ci/apps7-full574-repair-native/source-manifest.json','scripts/ci/apps7-full574-repair16k/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json')
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-apps7-full574-repair16k.yml')
OLDHOOK=" load(root/'apps16-repair/inspect1200_source.py','_apps16_inspect1200_source').prove(root)\n";NEWHOOK=" load(root/'apps16-repair/relative_source.py','_apps16_private_relative_source').prove(root)\n"
def one(raw,a,b):
 need(raw.count(a)==1,'one exact private relative seam');out=raw.replace(a,b,1);need(out.replace(b,a,1)==raw,'entire private relative inverse');return out

def fresh(before,helper):
 old=" facade=types.SimpleNamespace(**vars(roots));facade._mount_id=helper._mount600(roots._mount_id)\n facade.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=facade._mount_id))"
 new=" installer=_relative_query.bind_installer(root,roots.installer,read)\n facade=types.SimpleNamespace(**dict(vars(roots),installer=installer));facade._mount_id=helper._mount600(roots._mount_id)\n facade.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=facade._mount_id,installer=installer))"
 out=one(before,old,new);anchor='def query_api(root,roots,read):\n';setup="_relative_query=types.ModuleType('_private_repair_relative')\nexec(compile("+repr(helper.decode())+",'<private-repair-relative>','exec'),vars(_relative_query))\n"
 out=one(out,anchor,setup+anchor);need(out.replace(setup,'',1).replace(new,old,1)==before,'whole fresh query before body');return out

def transformed(old,helper,guard,profile):
 need(len(old)==242,'entire242 source required');out=dict(old);raw=old[A];node=next(n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='FRESH_QUERY'for t in n.targets));before=ast.literal_eval(node.value);literal=ast.get_source_segment(raw.decode(),node.value);out[A]=one(raw,literal.encode(),repr(fresh(before,helper)).encode());out[SELECT]=one(old[SELECT],OLDHOOK.encode(),NEWHOOK.encode());out.update({HELPER:helper,GUARD:guard,PROFILE:profile})
 s=json.loads(old[SUCCESSOR]);s['after']={n:pin(b)for n,b in sorted(out.items())if n not in s['excluded_seals']};out[SUCCESSOR]=enc(s)
 for name in MANIFESTS:
  m=json.loads(old[name]);m['files']={n:pin(out[n])for n in sorted(set(m['files'])|{HELPER,GUARD,PROFILE})};out[name]=enc(m)
 for name in WORKFLOWS:out[name]=one(old[name],pin(old[MANIFESTS[-1]])['sha256'].encode(),pin(out[MANIFESTS[-1]])['sha256'].encode())
 need(len(out)==245 and set(out)-set(old)=={HELPER,GUARD,PROFILE},'closed245 private relative source');return out


def compose(source):
    source = ordinary(source)
    raw_profile = read(HERE / 'profile.json')
    need(pin(raw_profile) == PROFILE_PIN, 'whole fixed portable profile')
    p = json.loads(raw_profile)
    before = tree(source)
    need({n: pin(b) for n, b in before.items()} == p['parent']['files'],
         'complete exact exported public242 source required')
    payloads = {n: read(HERE / n) for n in p['payloads']}
    need({n: pin(b) for n, b in payloads.items()} == p['payloads'],
         'whole readable245 source payloads')
    values = transformed(before, payloads['relative_query.py.in'],
                         payloads['relative_source.py.in'],
                         payloads['relative-profile.json.in'])
    need({n: pin(b) for n, b in values.items()} == p['result']['files'],
         'complete exact public245 output namespace and bytes')
    need(all(values[n] == before[n] for n in p['held']) and
         {n for n in before if values[n] != before[n]} == set(p['changed']) and
         set(values) - set(before) == set(p['added']), '234 held/8 changed/3 added')
    need(tree(source) == before and read(HERE / 'profile.json') == raw_profile and
         all(read(HERE / n) == raw for n, raw in payloads.items()),
         'late source/profile/payload drift before writes')
    return values, p


def emit(source, output, context):
    source, output = ordinary(source), ordinary(output)
    need(context in ('known', 'null'), 'explicit known or NULL source-only context')
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'actual namespace is not a source destination')
    for root in (source, HERE):
        need(not output.is_relative_to(root) and not root.is_relative_to(output),
             'input/factory/output must be disjoint')
    values, p = compose(source)
    need(not os.path.lexists(output), 'late output collision refused')
    output.mkdir(mode=0o700)
    for name, raw in values.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    need(tree(output) == values, 'all245 emitted bytes verified')
    identity = p['result'] if context == 'known' else dict(source=None, ref=None)
    return dict(status='SOURCE_ONLY_EXACT_PUBLIC245_NOT_NATIVE_ACCEPTANCE', files=245,
                source=identity['source'], ref=identity['ref'], actual=None,
                native_acceptance=False, old600fit='NOT_ESTABLISHED',
                new1200fit='NOT_ESTABLISHED', M2_performance='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--context', choices=('known', 'null'), required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.source, args.output, args.context), sort_keys=True))
