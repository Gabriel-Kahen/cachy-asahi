# SPDX-License-Identifier: MIT
"""Finite current-Fish Source, admission and builder projections; no actor on import."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/fish-config02-native-source'
WORKFLOW='.github/workflows/native-arm-fish-config02-source.yml'
BUILD_EDITS=(
 ("        name = 'cachy-asahi-' + os.urandom(8).hex()", "        name = 'cachy-fish02-' + os.environ['CACHY_FISH02_NONCE'] + '-' + os.environ['CACHY_FISH02_ATTEMPT']\n        if not re.fullmatch(r'cachy-fish02-[0-9a-f]{32}-[12]', name):\n            raise ValueError('fixed Fish02 build identity required')"),
 ("                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',", "                   '--label', 'org.cachy-asahi.fish02.nonce=' + os.environ['CACHY_FISH02_NONCE'],\n                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',"),
 ("'--memory', '4g', '--cpus', '4'", "'--memory', '4g', '--memory-swap', '4g', '--cpus', '4'"),
)

def need(value,why):
    if not value:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path=Path(path)
    need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)), 'ordinary absolute path required')
    return path


def read(path,cap=2*1024**2,empty=False):
    path=ordinary(path);s=path.lstat()
    need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid in(0,os.getuid())and not s.st_mode&0o022 and (0 if empty else 1)<=s.st_size<=cap,'bounded owned ordinary DATA required')
    raw=path.read_bytes();need(len(raw)==s.st_size and path.lstat()==s,'DATA changed during read');return raw


def load(path,cap=2*1024**2):return json.loads(read(path,cap))


def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def projected_build(raw):
    text=raw.decode()
    for old,new in BUILD_EDITS:
        need(text.count(old)==1,'exact finite builder projection anchor');text=text.replace(old,new)
    inverse=text
    for old,new in reversed(BUILD_EDITS):
        need(inverse.count(new)==1,'exact builder inverse anchor');inverse=inverse.replace(new,old)
    need(inverse.encode()==raw,'whole unchanged builder inverse');return text.encode()


def audit_adapter(native,raw):
    """Keep host command pre-exec/supervision on the main thread; same audit DATA."""
    text=raw.decode();node,=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='audit']
    original=ast.get_source_segment(text,node)
    before="    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:\n        values = list(pool.map(lambda item: inspect_package(cache / item['filename'], item), inputs['packages']))"
    after="    values = [inspect_package(cache / item['filename'], item) for item in inputs['packages']]"
    need(original.count(before)==1,'exact package-metadata scheduling anchor')
    projected=original.replace(before,after);need(projected.replace(after,before)==original,'complete unchanged audit inverse')
    exec(compile(projected,'<Fish02-serial-metadata-audit>','exec'),native.__dict__)
    return projected


def verify_source(root,expected):
    root=ordinary(root);path=root/PREFIX/'source-map.json';raw=read(path)
    need(re.fullmatch('[0-9a-f]{64}',expected or '')and pin(raw)['sha256']==expected,'independent complete Source map SHA-256 required')
    value=json.loads(raw);need(value['kind']=='FISH02_MINIMAL_HOSTED_SOURCE_MAP_V1'and 20<len(value['files'])<64,'finite Fish02 Source closure')
    actual={str(p.relative_to(root))for p in root.rglob('*')if p.relative_to(root).parts[0]!='.git'and(p.is_file()or p.is_symlink())}
    need(actual==set(value['files'])|{str(path.relative_to(root))},'complete closed Source namespace')
    need(all(v is None for v in value['actual'].values()),'prospective Source actuals remain null')
    for name,row in value['files'].items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts,'relative Source leaf')
        path=root/name;need(dict(pin(read(path)),mode=stat.S_IMODE(path.stat().st_mode))==row,'whole Source byte/mode pin: '+name)
    return value


def admitted(admission,runtime,source_map,env,profile,now=None):
    now=int(time.time())if now is None else now
    for value,kind in((admission,'ROOT_FISH02_HOSTED_ADMISSION_V1'),(runtime,'ROOT_FISH02_HOSTED_RUNTIME_V1')):
        need(value['kind']==kind and value['issued_by']=='Root'and value['accepted']is True,'separate genuine Root issuer/admission required')
        need(re.fullmatch('[0-9a-f]{40}',value['source']or'')and value['source']==env.get('GITHUB_SHA')and value['ref']==env.get('GITHUB_REF')and value['ref'].startswith('refs/heads/'),'exact actual dispatch Source/ref')
        need(value['source_map_sha256']==source_map and value['resources']==profile['resources'],'exact reviewed Source/resources')
        need(type(value['created_utc'])is int and type(value['expires_utc'])is int and value['created_utc']<=now<value['expires_utc']and value['expires_utc']-value['created_utc']<=3600,'fresh bounded Root admission')
        need(re.fullmatch('[0-9a-f]{32}',value['nonce']or''),'fresh operation nonce')
    need(admission['nonce']==runtime['nonce'],'same fresh runtime/admission nonce')
    need(env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and env.get('GITHUB_RUN_ATTEMPT')=='1'and re.fullmatch('[1-9][0-9]{1,19}',env.get('GITHUB_RUN_ID','')),'one fresh real hosted dispatch attempt')
    need(type(runtime['bootstrap_resource_domain'])is dict and type(runtime['external_supervision'])is dict and all(re.fullmatch('[0-9a-f]{64}',v.get('sha256',''))for v in(runtime['bootstrap_resource_domain'],runtime['external_supervision'])),'external Root bootstrap resource/custody receipt pins required')
    return admission['nonce']


def plans(here,output,image):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image),'actual immutable fresh bootstrap image')
    common=['--image',image,'--mode','native','--network','none','--source-date-epoch','1791748800','--timeout','300','--expected-packages',str(here/'expected349.lock'),'--reviewed-inputs',str(here/'reviewed-inputs.json')]
    builds=[['/usr/bin/python3','-I','-B',str(here/'runtime/scripts/build/build_fish02.py'),str(here/'recipe'),*common,'--output',str(output/('build-'+str(i)))]for i in(1,2)]
    compare=['/usr/bin/python3','-I','-B',str(here/'runtime/scripts/build/compare_v2.py'),str(output/'build-1'),str(output/'build-2'),'--require-bytes']
    return builds,compare
