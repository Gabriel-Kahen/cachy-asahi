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
PREFIX='scripts/ci/llhttp-minimal-builder-source/base'
WORKFLOW='.github/workflows/native-arm-llhttp-minimal-builder-source.yml'
BUILD_EDITS=(
 ("        name = 'cachy-asahi-' + os.urandom(8).hex()", "        name = 'cachy-llhttp-minimal-builder-' + os.environ['CACHY_LLHTTP_MINIMAL_BUILDER_NONCE'] + '-' + os.environ['CACHY_LLHTTP_MINIMAL_BUILDER_ATTEMPT']\n        if not re.fullmatch(r'cachy-llhttp-minimal-builder-[0-9a-f]{32}-[12]', name):\n            raise ValueError('fixed llhttp reference build identity required')"),
 ("                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',", "                   '--label', 'org.cachy-asahi.llhttp-minimal-builder.nonce=' + os.environ['CACHY_LLHTTP_MINIMAL_BUILDER_NONCE'],\n                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',"),
 ("'--memory', '4g', '--cpus', '4'", "'--memory', '4g', '--memory-swap', '4g', '--cpus', '4'"),
 ("        paths = sorted(p for p in artifacts.glob('*.pkg.tar.*') if not p.name.endswith('.sig'))", "        paths = sorted(p for p in artifacts.glob('*.pkg.tar.*') if not p.name.endswith('.sig'))\n        if len(paths) != 1 or not paths[0].name.endswith('.pkg.tar.xz'):\n            raise ValueError('fixed llhttp XZ-only archive required before package inspection')"),
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
    identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_nlink,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    raw=path.read_bytes();need(len(raw)==s.st_size and identity(path.lstat())==identity(s),'DATA changed during read');return raw


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
    exec(compile(projected,'<llhttp reference-serial-metadata-audit>','exec'),native.__dict__)
    return projected


def verify_source(root,expected):
    root=ordinary(root);path=root/PREFIX/'source-map.json';raw=read(path)
    need(re.fullmatch('[0-9a-f]{64}',expected or '')and pin(raw)['sha256']==expected,'independent complete Source map SHA-256 required')
    value=json.loads(raw);need(value['kind']=='LLHTTP_MINIMAL206_BUILD_ONLY_MINIMAL_HOSTED_SOURCE_MAP_V1'and 20<len(value['files'])<64,'finite llhttp reference Source closure')
    actual={str(p.relative_to(root))for p in root.rglob('*')if p.relative_to(root).parts[0]!='.git'and(p.is_file()or p.is_symlink())}
    need(actual==set(value['files'])|{str(path.relative_to(root))},'complete closed Source namespace')
    need(all(v is None for v in value['actual'].values()),'prospective Source actuals remain null')
    for name,row in value['files'].items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts,'relative Source leaf')
        path=root/name;need(dict(pin(read(path)),mode=stat.S_IMODE(path.stat().st_mode))==row,'whole Source byte/mode pin: '+name)
    return value



def seed_minimal_public_signatures(cache,inputs,profile):
    import base64
    need(pin(json.dumps(profile['minimal_public_signatures'],indent=2,sort_keys=True).encode()+b'\n')==profile['minimal_builder']['public_signature_seed'],'whole pinned public signature payload map')
    cache=ordinary(cache);need(cache.is_dir()and cache.stat().st_uid==os.getuid()and stat.S_IMODE(cache.stat().st_mode)==0o700,'exact owned private builder cache')
    rows={r['filename']+'.sig':r for r in inputs['packages']};need(len(rows)==206 and set(rows)==set(profile['minimal_public_signatures']),'complete public206 signature namespace')
    total=0
    for name,row in rows.items():
        need('/'not in name and row['signature_size']<=4096,'finite literal public signature file')
        raw=base64.b64decode(profile['minimal_public_signatures'][name],validate=True);total+=len(raw);need(total<=256*1024 and pin(raw)==dict(bytes=row['signature_size'],sha256=row['signature_sha256']),'exact public signature bytes')
        path=cache/name
        if path.exists()or path.is_symlink():need(pin(read(path,4096))==pin(raw),'existing public signature differs')
        else:
            with path.open('xb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw)
    return dict(files=len(rows),bytes=total,authentication='NOT RUN; unchanged ordinary native audit required')

def minimal_inputs(admission,runtime,profile):
    value = admission.get('builder_input_authentication')
    need(type(value) is dict and value == runtime.get('builder_input_authentication'),
         'separate same whole Root input authentication projection required')
    need(set(value) == set(('Root_native_authority', 'accepted', 'all_verifiers_naturally_retired', 'builder_lock', 'current_official_trust_reviewed', 'issuer', 'kind', 'original_adoption', 'signatures', 'signer_fingerprint', 'status')),
         'closed public authentication projection schema')
    need(type(value['signatures']) is dict and set(value['signatures']) == {'bytes', 'sha256'},
         'path-free public signature transcript pin')
    need(profile['minimal_builder']['package_count'] == 206 and profile['minimal_builder']['target'] == 'llhttp'
         and profile['minimal_builder']['scope'] == 'BUILD_ONLY'
         and value['builder_lock'] == profile['minimal_builder']['builder_lock']
         and value['signer_fingerprint'] == profile['minimal_builder']['signer_fingerprint'],
         'exact llhttp BUILD_ONLY profile and unchanged trust commitments')
    for candidate in (value, runtime['builder_input_authentication']):
        need(pin((json.dumps(candidate, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()) == {'bytes': 762, 'sha256': '99cb2fafb8dd8e4a86fb88109fb1db014be39eec9d8e7ed39c97be9b0a38fca7'},
             'exact path-free projection of Root-adopted minimal206 input authentication r2')
    return value


def admitted(admission,runtime,source_map,env,profile,now=None):
    now=int(time.time())if now is None else now
    for value,kind in((admission,'ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_HOSTED_ADMISSION_V1'),(runtime,'ROOT_LLHTTP_MINIMAL206_BUILD_ONLY_HOSTED_RUNTIME_V1')):
        need(value['kind']==kind and value['issued_by']=='Root'and value['accepted']is True,'separate genuine Root issuer/admission required')
        need(re.fullmatch('[0-9a-f]{40}',value['source']or'')and value['source']==env.get('GITHUB_SHA')and value['ref']==env.get('GITHUB_REF')and value['ref'].startswith('refs/heads/'),'exact actual dispatch Source/ref')
        need(value['source_map_sha256']==source_map and value['resources']==profile['resources'],'exact reviewed Source/resources')
        need(type(value['created_utc'])is int and type(value['expires_utc'])is int and value['created_utc']<=now<value['expires_utc']and value['expires_utc']-value['created_utc']<=3600,'fresh bounded Root admission')
        need(re.fullmatch('[0-9a-f]{32}',value['nonce']or''),'fresh operation nonce')
    need(admission['nonce']==runtime['nonce'],'same fresh runtime/admission nonce')
    need(env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and env.get('GITHUB_RUN_ATTEMPT')=='1'and re.fullmatch('[1-9][0-9]{1,19}',env.get('GITHUB_RUN_ID','')),'one fresh real hosted dispatch attempt')
    need(type(runtime['bootstrap_resource_domain'])is dict and type(runtime['external_supervision'])is dict and all(re.fullmatch('[0-9a-f]{64}',v.get('sha256',''))for v in(runtime['bootstrap_resource_domain'],runtime['external_supervision'])),'external Root bootstrap resource/custody receipt pins required')
    minimal_inputs(admission,runtime,profile)
    return admission['nonce']


def plans(here,output,image):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image),'actual immutable fresh bootstrap image')
    common=['--image',image,'--mode','native','--network','none','--source-date-epoch','1791748800','--timeout','300','--expected-packages',str(here/'expected206.lock'),'--reviewed-inputs',str(here/'reviewed-inputs.json')]
    builds=[['/usr/bin/python3','-I','-B',str(here/'runtime/scripts/build/build_llhttp-reference.py'),str(here/'recipe'),*common,'--output',str(output/('build-'+str(i)))]for i in(1,2)]
    compare=['/usr/bin/python3','-I','-B',str(here/'runtime/scripts/build/compare_llhttp.py'),str(output/'build-1'),str(output/'build-2'),'--require-bytes']
    return builds,compare


COMPARE_BEFORE="    actual = {p.name for p in (path / 'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')}"
COMPARE_AFTER=COMPARE_BEFORE+"\n    if len(actual) != 1 or any(not name.endswith('.pkg.tar.xz') for name in actual):\n        raise ValueError('fixed llhttp XZ-only archive required before comparison inspection')"

def projected_compare(raw):
    text=raw.decode();need(text.count(COMPARE_BEFORE)==1 and COMPARE_AFTER not in text,'one finite XZ-only comparator gate')
    text=text.replace(COMPARE_BEFORE,COMPARE_AFTER)
    need(text.replace(COMPARE_AFTER,COMPARE_BEFORE).encode()==raw,'whole unchanged comparator inverse')
    return text.encode()
