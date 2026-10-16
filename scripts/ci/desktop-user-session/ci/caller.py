#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin/stage one managed VM trial and retain only declared bounded evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

LANE = 'scripts/ci/desktop-user-session'
PASS = 'PASS_MANAGED_USER_GENERIC_ARM_SESSION'
ENTRY = "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_path(sys.path[0]+'/desktop574_runtime.py',run_name='__main__')"
TEXT = {
    'base-build.log': 256*1024, 'managed-runtime.log': 256*1024, 'base-cleanup.log': 64*1024,
    'base/seed-report.json': 256*1024, 'base/report.json': 256*1024,
    'base/installed-packages.lock': 64*1024,
    'runtime/runtime.json': 2*1024**2, 'runtime/events.log': 2*1024**2,
    'runtime/guest.log': 512*1024, 'runtime/configuration.log': 128*1024,
    'runtime/package-build.log': 128*1024, 'runtime/package/build.log': 128*1024,
    'runtime/package/provenance.json': 256*1024, 'runtime/package/validation.json': 512*1024,
    'runtime/package/expected-packages.lock': 64*1024,
    'runtime/base-reference.log': 128*1024, 'runtime/runtime-image.log': 128*1024,
    'runtime/fixture.log': 128*1024, 'runtime/config/desktop/desktop.json': 512*1024,
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data): return hashlib.sha256(data).hexdigest()
def encoded(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path required')
    return path


def read(path, limit):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
             'bounded ordinary single-link file required: ' + path.name)
        with os.fdopen(fd, 'rb', closefd=False) as stream: data = stream.read(limit + 1)
        after = os.fstat(fd)
        identity = lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(data) == before.st_size <= limit and identity(before) == identity(after)
             == identity(path.lstat()), 'file changed while reading')
        return data
    finally:
        os.close(fd)


def load(path):
    spec = importlib.util.spec_from_file_location('managed_caller_' + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(source, manifest, pin):
    source = ordinary(source)
    raw = read(manifest, 128*1024)
    need(re.fullmatch('[0-9a-f]{64}', pin) and sha(raw) == pin, 'exact caller manifest required')
    value = json.loads(raw)
    need(type(value) is dict and set(value) == {'schema_version','lane','base_accepted_source',
         'retained_public_source','source_files','derived_files'} and value['schema_version'] == 1
         and value['lane'] == LANE, 'exact managed CI manifest schema required')
    files = value['source_files']
    need(type(files) is dict and 1 <= len(files) <= 128, 'finite source closure required')
    for name, row in files.items():
        p = PurePosixPath(name)
        need(not p.is_absolute() and p.as_posix() == name and not {'.','..'} & set(p.parts)
             and type(row) is dict and set(row) == {'bytes','sha256'}, 'source row shape')
        data = read(source / name, 2*1024**2)
        need(len(data) == row['bytes'] and sha(data) == row['sha256'], 'source bytes differ: ' + name)
    return value


def runner_check(trial, manifest):
    runner = ordinary(trial / 'runner')
    expected = manifest['derived_files']
    need(type(expected) is dict and set(p.name for p in runner.iterdir()) == set(expected) | {'profile.json'},
         'exact generated runner membership required')
    profile = json.loads(read(runner / 'profile.json', 64*1024))
    need(profile['profile'] == 'OPT_IN_MANAGED_USER_VM' and profile['files'] == expected, 'runner receipt differs')
    for name,pin in expected.items():
        need(Path(name).name == name and sha(read(runner/name,2*1024**2)) == pin, 'derived runner bytes differ')
    return runner


def prepare(source, trial, manifest, source_commit):
    need(type(source_commit) is str and re.fullmatch('[0-9a-f]{40}', source_commit),
         'exact Root-selected source commit required')
    trial = ordinary(trial)
    trial.mkdir(mode=0o700)
    load(source/LANE/'prepare.py').prepare(source,trial/'runner')
    runner_check(trial,manifest)
    token = os.urandom(8).hex()
    (trial/'job-token').write_text(token+'\n')
    report = dict(status='READY_NOT_RUN',source_commit=source_commit,job_token=token,
        profile='OPT_IN_MANAGED_USER_VM',base_builder='accepted-exact574-with-owned-token',hardware='NOT RUN')
    (trial/'preparation.json').write_bytes(encoded(report))
    return report


def runtime_argv(source, trial, base, manifest):
    runner = runner_check(trial,manifest)
    need(not (trial/'runtime').exists(), 'fresh managed runtime output required')
    return [sys.executable,'-I','-B','-c',ENTRY,str(runner),'--source',str(source),
            '--base-dir',str(base),'--output',str(trial/'runtime')]


def ppm(data):
    match = re.match(rb'P6\s+1024\s+768\s+255\s',data)
    need(match is not None and len(data)-match.end() == 1024*768*3, 'complete1024x768 PPM required')
    pixels = data[match.end():]
    need(any(pixels[i:i+3] != pixels[:3] for i in range(0,len(pixels),3)), 'uniform frame refused')
    return dict(width=1024,height=768,sha256=sha(data))


def native_gate(source, base, trial, frames):
    original = json.loads(read(base/'report.json',256*1024))
    runtime = json.loads(read(trial/'runtime/runtime.json',2*1024**2))
    need(original['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['packages'] == 574,
         'exact574 native base did not pass')
    inputs = json.loads(read(source/'scripts/ci/maintained-desktop574-inputs.json',2*1024**2))
    rows = inputs['packages']
    expected = ''.join(f"{r['name']} {r['version']}\n" for r in sorted(rows,key=lambda r:r['name'])).encode()
    need(len(rows) == 574 and read(base/'installed-packages.lock',64*1024) == expected,
         'actual installed574 lock differs')
    need(runtime['status'] == PASS and runtime['runtime_package_count'] == 591
         and runtime['base_image'] == original['image'], 'managed VM/runtime identity did not pass')
    load(source/LANE/'managed_contract.py').verify_result(runtime['events'])
    need(runtime['managed_session']['status'] == 'PASS' and runtime['base_reference_cleanup']['ok'] is True
         and runtime['cleanup'] and all((r.get('exit') == 0 if 'exit' in r else r.get('guest_disk_removed') is True)
                                      for r in runtime['cleanup'])
         and any(r.get('guest_disk_removed') is True for r in runtime['cleanup']), 'VM cleanup did not pass')
    cleanup = original['owned_cleanup']
    need(cleanup['status'] == 'PASS' and cleanup['image']['id'] == original['image']
         and cleanup['image']['absence_verified'] is True and cleanup['probe']['absence_verified'] is True,
         'owned base cleanup did not pass')
    need(set(frames) == {'minimal','overlay'} and frames == runtime['frames'], 'retained pixels differ from runtime')


def retain(source, trial, base):
    """Fixed public leaves only; no recursive caches, disks, homes or packages."""
    public = ordinary(trial/'public'); public.mkdir(mode=0o700)
    receipt = dict(status='BOUNDED_EVIDENCE_RETAINED',native_gate='FAIL',files={},frames={},
                   visual_review='ROOT REQUIRED',hardware='NOT RUN')
    for name,cap in TEXT.items():
        origin = (base/name.removeprefix('base/')) if name.startswith('base/') else (trial/name)
        if not os.path.lexists(origin):
            receipt['files'][name] = {'status':'MISSING'}
            continue
        data = read(origin,16*1024**2)
        truncated = len(data)>cap
        target = public/(name+'.tail' if truncated else name)
        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        target.write_bytes(data[-cap:])
        receipt['files'][name] = dict(status='RETAINED',source_bytes=len(data),source_sha256=sha(data),
            retained_bytes=min(len(data),cap),truncated=truncated,output=target.relative_to(public).as_posix())
    for stage in ('minimal','overlay'):
        origin = trial/'runtime/frames'/(stage+'.ppm')
        if not os.path.lexists(origin): continue
        data = read(origin,3*1024**2)
        receipt['frames'][stage] = ppm(data)
        target = public/'frames'/(stage+'.ppm');target.parent.mkdir(mode=0o700,exist_ok=True)
        target.write_bytes(data)
    try:
        native_gate(source,base,trial,receipt['frames'])
        receipt['native_gate'] = 'PASS'
    except (OSError,ValueError,KeyError,TypeError) as error:
        receipt['gate_error'] = type(error).__name__ + ': ' + str(error)[:256]
    total = sum(p.stat().st_size for p in public.rglob('*') if p.is_file())
    need(total < 16*1024**2,'total retained evidence exceeds16MiB')
    receipt['retained_bytes_before_receipt'] = total
    (public/'retention.json').write_bytes(encoded(receipt))
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('verify','prepare','runtime','retain'))
    for name in ('source','manifest','trial','base'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--source-commit')
    args=parser.parse_args()
    source,trial,base=(ordinary(p) for p in (args.source,args.trial,args.base))
    manifest=verify(source,args.manifest,args.manifest_sha256)
    if args.phase=='verify': result={'status':'PINNED_SOURCE_PASS'}
    elif args.phase=='prepare': result=prepare(source,trial,manifest,args.source_commit)
    elif args.phase=='runtime':
        argv=runtime_argv(source,trial,base,manifest)
        os.execve(sys.executable,argv,{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
        raise AssertionError('exec returned')
    else: result=retain(source,trial,base)
    print(json.dumps(result,sort_keys=True))
    return int(args.phase=='retain' and result['native_gate']!='PASS')


if __name__=='__main__':raise SystemExit(main())
