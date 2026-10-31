# SPDX-License-Identifier: MIT
"""Reproduce exact public242 from closed public239; source-only, no actors."""
import argparse
import base64
import hashlib
import json
import os
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE_PIN = {'bytes': 126915, 'sha256': 'd761f8222cd215f5768d2e9269b27d5efe7d052ad06a8a2702bc67172f56e3b2'}


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


# The counted transform below is the exact published242 finite source transform.
A='scripts/ci/apps7-full574-repair16k/adapter.py';VM='scripts/ci/apps7-full574-repair16k/vm.py';JOB='scripts/ci/apps7-full574-repair16k/job.py';SELECT='apps16-repair/selection.py';SUCCESSOR='apps16-repair/successor.json';HELPER='apps16-repair/inspect_validation.py';GUARD='apps16-repair/inspect1200_source.py';PROFILE='apps16-repair/inspect1200-profile.json'
MANIFESTS=('scripts/ci/apps7-full574-repair-native/source-manifest.json','scripts/ci/apps7-full574-repair16k/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json')
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-apps7-full574-repair16k.yml')
OLDHOOK=" load(root/'apps16-repair/separated_source.py','_apps16_separated_input_source').prove(root)\n"
NEWHOOK=" load(root/'apps16-repair/inspect1200_source.py','_apps16_inspect1200_source').prove(root)\n"
WRAPPERS='''
# Explicit opt-in source profile. Every default method retains exact239 output.
def _inspect_profile_helper():
 import types
 m=types.ModuleType('_source_owned_inspect_profile');exec(compile(_INSPECT_VALIDATION_SOURCE,'<source-owned-inspect-profile>','exec'),vars(m));return m

def rendered_backend(source,*,inspect_profile=False):
 raw,ledger=_rendered_backend_original(source)
 if not inspect_profile:return raw,ledger
 m=_inspect_profile_helper();out=m.backend(raw,_INSPECT_VALIDATION_SOURCE);ledger=dict(ledger,owned_inspect_validation=dict(profile=m.PROFILE,backend_seconds=1200,caller_seconds=1210,parent_backend=pin(raw),derived_backend=pin(out),default_backend_seconds=600,default_caller_seconds=610,scope='EXACT_OWNED_COPY_INSPECT_ARGV_ONLY',old600_fit='NOT_ESTABLISHED',M2_performance='NOT_RUN'))
 return out,ledger

def lifecycle(raw,*,inspect_profile=False):
 out=_lifecycle_original(raw)
 return _inspect_profile_helper().lifecycle(out,_INSPECT_VALIDATION_SOURCE)if inspect_profile else out
'''
def one(raw,before,after):
 need(raw.count(before)==1,'one finite exact source seam: '+str(before)[:80]);out=raw.replace(before,after,1);need(out.replace(after,before,1)==raw,'whole finite source inverse');return out

def transformed(old,helper,guard,profile):
 need(len(old)==239,'entire exact239 parent');out=dict(old)
 a=one(old[A],b'def rendered_backend(source):',b'def _rendered_backend_original(source):');a=one(a,b'def lifecycle(raw):',b'def _lifecycle_original(raw):');a=one(a,b'def execution(source,output,manifest):',b'def execution(source,output,manifest,*,inspect_profile=False):');a=one(a,b'rendered,derivation=rendered_backend(source)',b'rendered,derivation=rendered_backend(source,inspect_profile=inspect_profile)');a=one(a,b"unchanged_functions='ALL_NATIVE_RENDERED_BACKEND_FUNCTIONS_EXCEPT_ENVIRONMENT_AND_EXPLICIT_READONLY_INVENTORY_BINDING'",b"unchanged_functions=('ALL_PARENT_RUNTIME_BODIES_HELD_EXCEPT_TYPED_INSPECT_PARSER_AND_SELECTED_BUDGET_WRAPPER'if inspect_profile else'ALL_NATIVE_RENDERED_BACKEND_FUNCTIONS_EXCEPT_ENVIRONMENT_AND_EXPLICIT_READONLY_INVENTORY_BINDING')")
 out[A]=a+b'\n_INSPECT_VALIDATION_SOURCE='+repr(helper.decode()).encode()+b'\n'+WRAPPERS.encode()
 out[VM]=one(old[VM],b'adaptation=adapter.execution(root,execution,manifest)',b'adaptation=adapter.execution(root,execution,manifest,inspect_profile=True)');out[VM]=one(out[VM],b'derived=adapter.lifecycle(raw)',b'derived=adapter.lifecycle(raw,inspect_profile=True)');out[VM]=one(out[VM],b"case_body='UNCHANGED'",b"case_body='UNCHANGED',owned_inspect_validation=dict(profile='REPAIR_GENERIC16K_OWNED_INSPECT_VALIDATION_1200_V1',backend_seconds=1200,caller_seconds=1210,added_function='_tcg_owned_inspect_call',default_route_retained=True)")
 # The selected export changes one exact routing seam after whole native retain
 # derivation. Its original body and all other packet references stay accessible.
 out[JOB]=one(old[JOB],b' J=native_job(args.source,native);original=J.derived\n',b" J=native_job(args.source,native);original=J.derived\n J.H._inspect_validation=C.load('selected_inspect_validation',args.source/'apps16-repair/inspect_validation.py')\n")
 out[JOB]=one(out[JOB],b"parts['actor']=actor_body(parts['actor']);return parts",b"parts['actor']=actor_body(parts['actor']);parts['retain']=J.H._inspect_validation.retention(parts['retain'],selected=True);return parts")
 out[SELECT]=one(old[SELECT],OLDHOOK.encode(),NEWHOOK.encode());out[HELPER]=helper;out[GUARD]=guard;out[PROFILE]=profile
 s=json.loads(old[SUCCESSOR])
 for n in(VM,JOB):
  need(n not in s['before_bodies']and pin(old[n])==s['before'][n],'previously held original235 operand');s['before_bodies'][n]=base64.b64encode(old[n]).decode()
 s['after']={n:pin(v)for n,v in sorted(out.items())if n not in s['excluded_seals']};out[SUCCESSOR]=enc(s)
 for name in MANIFESTS:
  m=json.loads(old[name]);m['files']={n:pin(out[n])for n in sorted(set(m['files'])|{HELPER,GUARD,PROFILE})};out[name]=enc(m)
 before=pin(old[MANIFESTS[-1]])['sha256'].encode();after=pin(out[MANIFESTS[-1]])['sha256'].encode()
 for name in WORKFLOWS:out[name]=one(old[name],before,after)
 need(set(out)-set(old)=={HELPER,GUARD,PROFILE}and len(out)==242,'honest complete242 source namespace')
 return out


def compose(source):
    source = ordinary(source)
    raw_profile = read(HERE / 'profile.json')
    need(pin(raw_profile) == PROFILE_PIN, 'whole fixed portable profile')
    p = json.loads(raw_profile)
    before = tree(source)
    need({n: pin(b) for n, b in before.items()} == p['parent']['files'],
         'complete exact exported public239 source required')
    payloads = {n: read(HERE / n) for n in p['payloads']}
    need({n: pin(b) for n, b in payloads.items()} == p['payloads'],
         'whole readable242 source payloads')
    values = transformed(before, payloads['inspect_validation.py.in'],
                         payloads['inspect1200_source.py.in'],
                         payloads['inspect1200-profile.json.in'])
    need({n: pin(b) for n, b in values.items()} == p['result']['files'],
         'complete exact public242 output namespace and bytes')
    need(all(values[n] == before[n] for n in p['held']) and
         {n for n in before if values[n] != before[n]} == set(p['changed']) and
         set(values) - set(before) == set(p['added']), '229 held/10 changed/3 added')
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
    need(tree(output) == values, 'all242 emitted bytes verified')
    identity = p['result'] if context == 'known' else dict(source=None, ref=None)
    return dict(status='SOURCE_ONLY_EXACT_PUBLIC242_NOT_NATIVE_ACCEPTANCE', files=242,
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
