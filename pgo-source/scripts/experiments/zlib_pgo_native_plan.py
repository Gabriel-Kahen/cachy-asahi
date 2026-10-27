#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline construction plan; never launches Docker, compilation or training."""
import argparse,hashlib,json,re,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
for p in ('scripts/build','scripts/checks'):sys.path.insert(0,str(ROOT/p))
import source_materials as M
from package_checks import recipe
RECIPE='packages/experiments/cachy-asahi-zlib-pgo-v1'
CATALOG='50979bf81eda4d1f5b23fbe05aec5fabd7827b270fe3edda22b7189944004c43'
ARCHIVE='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'


def need(ok,message):
    if not ok:raise ValueError(message)


def raw(path,cap=16*1024**2):
    path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary path required')
    info=path.stat();need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_size<=cap,'bounded single-link file')
    return path.read_bytes()


def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def save(path,value):
    with path.open('x')as f:f.write(json.dumps(value,indent=2,sort_keys=True)+'\n')


def verify_source(root=ROOT):
    root=Path(root).absolute();manifest=json.loads(raw(root/'PGO-SOURCE.json'))
    need(manifest['schema']==1 and manifest['actual']is None,'source-only NULL selection')
    files=manifest['files'];paths=list(root.rglob('*'))
    need(not any(p.is_symlink()for p in paths),'source aliases refused')
    need({p.relative_to(root).as_posix()for p in paths if not p.is_dir()}==set(files)|{'PGO-SOURCE.json'},'closed complete PGO source')
    for name,row in files.items():
        p=root/name;need(not Path(name).is_absolute()and '..'not in Path(name).parts,'source relative name')
        need(dict(**pin(raw(p)),mode=stat.S_IMODE(p.stat().st_mode))==row,'source pin differs: '+name)
    return manifest


def seed_cache(root,destination):
    """Copy existing verified source DATA into a fresh private cache; no acquisition."""
    seed=root/'inputs/cache-seed';destination.mkdir(mode=0o700)
    for name in('objects','receipts','.partial'):(destination/name).mkdir(mode=0o700)
    for p in seed.rglob('*'):
        if not p.is_file():continue
        target=destination/p.relative_to(seed);data=raw(p)
        with target.open('xb')as f:f.write(data)
        target.chmod(0o600)
    return destination


def prepare(output,image,expected_packages,cache=None,root=ROOT):
    root=Path(root).absolute();verify_source(root)
    need(re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[0-9a-f]{64}',image or''),'explicit immutable Root image identity')
    lock=Path(expected_packages).absolute();lockbytes=raw(lock,1024**2);lines=lockbytes.decode().splitlines(keepends=True)
    need(lines and lines==sorted(lines)and all(re.fullmatch(r'[^\s]+ [^\s]+\n',line)for line in lines),'sorted complete newline package lock')
    need(len({line.split()[0]for line in lines})==len(lines),'unique package inventory')
    output=Path(output).absolute();need('..'not in output.parts and not any(p.is_symlink()for p in(output,*output.parents)),'ordinary output')
    need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(root)and not root.is_relative_to(output),'fresh disjoint preparation output')
    report=recipe(root/RECIPE/'PKGBUILD');need(not report['errors'],'static recipe errors: '+str(report['errors']))
    output.mkdir(mode=0o700)
    cache=Path(cache).absolute()if cache else seed_cache(root,output/'seed-cache')
    catalog=root/'inputs/source-inputs.json';need(pin(raw(catalog))['sha256']==CATALOG,'pinned source catalog')
    plan=dict(schema_version=1,purpose='offline-build-sources',recipe_inputs=report['input_sha256'],catalog_sha256=CATALOG,
        sources=[dict(source='https://zlib.net/zlib-1.3.2.tar.gz',id='zlib-1.3.2',revision='zlib-1.3.2 release archive; exact archive SHA256 pinned')])
    save(output/'source-plan.json',plan);save(output/'reviewed-inputs.json',report['input_sha256'])
    plan_sha=pin(raw(output/'source-plan.json'))['sha256']
    prepared=M.prepare(report,output/'source-plan.json',plan_sha,catalog,cache)
    selection=M.stage(prepared,output/'source-material')
    archive=raw(output/'source-material/srcdest/zlib-1.3.2.tar.gz')
    need(pin(archive)==dict(bytes=1502830,sha256=ARCHIVE),'whole offline pinned real zlib')
    (output/'expected-packages.lock').write_bytes(lockbytes)
    command=[sys.executable,'-B',str(root/'scripts/build/build_v2.py'),str(root/RECIPE),'--image',image,'--output',str(output/'native-build'),
        '--mode','native','--source-date-epoch','1791748800','--network','none','--timeout','1800',
        '--expected-packages',str(output/'expected-packages.lock'),'--reviewed-inputs',str(output/'reviewed-inputs.json'),
        '--source-plan',str(output/'source-plan.json'),'--source-plan-sha256',plan_sha,'--source-catalog',str(catalog),'--source-cache',str(cache)]
    result=dict(schema=1,status='OFFLINE_NATIVE_CONSTRUCTION_READY_NOT_EXECUTED',command=command,source_plan_sha256=plan_sha,
        expected_packages=pin(lockbytes),source_selection=selection,source_archive=pin(archive),actual=None,
        training='NOT RUN',optimized_builds='NOT RUN',generic16k='NOT RUN',hardware='NOT RUN',performance='NOT GRANTED',release='NOT_ADMITTED')
    save(output/'native-command.json',result);return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--image',required=True);parser.add_argument('--expected-packages',required=True,type=Path);parser.add_argument('--cache',type=Path)
    args=parser.parse_args()
    try:print(json.dumps(prepare(args.output,args.image,args.expected_packages,args.cache),indent=2,sort_keys=True))
    except(OSError,ValueError,KeyError,TypeError)as e:print(str(e),file=sys.stderr);raise SystemExit(1)
