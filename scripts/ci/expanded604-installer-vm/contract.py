# SPDX-License-Identifier: MIT
"""Separate fresh604 authority gate; existing composition and installer APIs stay held."""
import importlib.util
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[2]
TARGET_SHA=AFTER='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'
LEGACY='b6b17e5f6b322f160f7eeb22c8a01380a3c854cd'
CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source')
DECISIONS=('fresh600_decisions','native604_decisions')


def _shared():
    path=HERE.parent/'expanded604-composition/contract.py'
    spec=importlib.util.spec_from_file_location('_fresh604_composition_contract',path)
    value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;spec.loader.exec_module(value)
    return value


COMPOSITION=_shared()
need,read,sha,encoded=COMPOSITION.need,COMPOSITION.read,COMPOSITION.sha,COMPOSITION.encoded
safe,checked,ref,load=COMPOSITION.safe,COMPOSITION.checked,COMPOSITION.ref,COMPOSITION.load
revision,scoped_load=COMPOSITION.revision,COMPOSITION.scoped_load


def legacy(root,*,git=True):
    return load('_fresh604_accepted600_contract',HERE.parent/'expanded600-installer-vm/contract.py').legacy(root,git=git)


def policy(*,bound=True):
    value=read(HERE/'input-policy.json')
    need(value.get('schema_version')==1 and value.get('expected604_sha256')==TARGET_SHA,
         'fixed separate604 installer policy required')
    prior=value.get('fresh600',{})
    need(prior==dict(source_sha='3cbd856315adb30ba7a1b9246739a520c19c9728',run_id='38965999704',
         carrier_source='fd42f51b6c32a1cca69df5699760ed2a9e39329f',decision=dict(path='payload/fresh600.json',
         bytes=3332,sha256='bea4b56374ef779756ffdc3e0aba680e3c74fac7316257c2433eb14417f210ef')),
         'exact accepted signed600 installer predecessor required')
    if bound:
        native=value.get('native604',{})
        need(value.get('status')=='ROOT_BOUND_NATIVE604_ACCEPTANCE' and
             all(re.fullmatch('[0-9a-f]{40}',native.get(k) or '') for k in ('source_sha','carrier_source')) and
             re.fullmatch('[1-9][0-9]{0,19}',native.get('run_id') or '') and
             all(re.fullmatch('[0-9a-f]{64}',native.get(k) or '') for k in ('source_manifest_sha256','input_policy_sha256')),
             'native604 Root acceptance remains UNBOUND; no secrets or actors allowed')
        ref(native.get('decision'),4*1024**2)
    return value


def locks():
    raw=(HERE/'expected604.lock').read_bytes()
    need(__import__('hashlib').sha256(raw).hexdigest()==TARGET_SHA,'fixed604 installer lock differs')
    before,after=COMPOSITION.locks()
    need(COMPOSITION.lock(raw,604)==after,'installer/composition604 locks differ')
    return before,after


def verify_source(source):
    policy()  # Never let a source-only fixture authorize an actor.
    need(source==SOURCE,'exact implementation root required')
    value=read(HERE/'source-manifest.json')
    need(value.get('schema_version')==1 and value.get('status')=='FROZEN_ROOT_FINAL_SOURCE' and
         1<=len(value.get('files',{}))<=512,'Root final604 installer source remains UNBOUND')
    locks();COMPOSITION.verify_source(source)
    for name,row in value['files'].items():checked(source,dict(path=name,**row),16*1024**2)
    manifest=str((HERE/'source-manifest.json').relative_to(source))
    __import__('subprocess').run(['git','-C',str(source),'diff','--exit-code','HEAD','--',*value['files'],manifest],
         check=True,capture_output=True,timeout=15)
    return value


def decisions(fresh_root,native_root,value):
    for root,key in ((fresh_root,'fresh600'),(native_root,'native604')):
        need(revision(root)==value[key]['carrier_source'],'exact Root decision carrier required')
    prior=read(checked(fresh_root,value['fresh600']['decision'],4*1024**2))
    need(prior.get('status')=='ROOT_ACCEPTED_SIGNED_EXPANDED600_FRESH_INSTALLER' and prior.get('package_count')==600 and
         prior.get('source_sha')==value['fresh600']['source_sha'] and prior.get('run_id')==value['fresh600']['run_id'] and
         prior.get('expected600_sha256')==COMPOSITION.OLD600 and
         all(prior.get(k)=='PASS' for k in ('ordinary_parent_retired','independent_root_readback','cleanup')) and
         prior.get('hardware')=='NOT_RUN' and prior.get('release')=='NOT_ADMITTED',
         'accepted actual signed600 fresh installer decision differs')
    bound=value['native604'];native=read(checked(native_root,bound['decision'],4*1024**2))
    need(native.get('status')=='ROOT_ACCEPTED_NATIVE_EXPANDED604_COMPOSITION' and native.get('package_count')==604 and
         native.get('expected604_sha256')==TARGET_SHA and
         all(native.get(k)==bound[k] for k in ('source_sha','run_id','source_manifest_sha256','input_policy_sha256')) and
         all(native.get(k)=='PASS' for k in ('installed_lifecycle','installed_six_modules','cleanup')) and
         native.get('hardware')=='NOT_RUN' and native.get('release')=='NOT_ADMITTED',
         'accepted actual native604 lifecycle/coexistence/cleanup decision differs')
    directory=HERE.parent/'expanded604-composition'
    need(sha(directory/'source-manifest.json')==bound['source_manifest_sha256'] and
         sha(directory/'input-policy.json')==bound['input_policy_sha256'],
         'installer must consume exact Root accepted604 composition source/input closure')
    return dict(fresh600=prior,native604=native)


def inputs(args,value):
    need(value==policy(),'current Root604 installer policy required')
    accepted=decisions(args.fresh600_decisions,args.native604_decisions,value)
    comp=COMPOSITION.policy();summary=COMPOSITION.inputs(args,comp)
    return comp,summary,accepted


def freeze(source):
    """Root explicitly binds authority first, then freezes adopted bytes without actors."""
    source=safe(source.absolute());policy();need(source==SOURCE,'freeze only adopted canonical lane')
    locks();COMPOSITION.verify_source(source)
    names=set(read(HERE.parent/'expanded604-composition/source-manifest.json')['files'])
    names.add('scripts/ci/expanded604-composition/source-manifest.json')
    names|={'scripts/ci/expanded600-installer-vm/'+name for name in
        ('contract.py','adapter.py','adapter-rules.json','call-rules.json','legacy-pins.json','observer600.py')}
    names|={p.relative_to(source).as_posix() for p in HERE.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    need(1<=len(names)<=512,'finite604 installer source closure required')
    files={}
    for name in sorted(names):
        path=safe(source/name);info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=16*1024**2,'ordinary bounded source required')
        files[name]=dict(bytes=info.st_size,sha256=sha(path))
    manifest=HERE/'source-manifest.json'
    manifest.write_bytes(encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,
         scope='PRIVATE_SIGNED604_FRESH_INSTALLER',native='NOT_RUN',hardware='NOT_RUN')))
    workflow=source/'.github/workflows/native-arm-expanded604-installer-vm.yml';text=workflow.read_text()
    for marker,path in (('@OWNER_SHA256@',HERE/'ci.py'),('@MANIFEST_SHA256@',manifest)):
        need(text.count(marker)==1,'Root must explicitly refresh604 installer workflow digest markers')
        text=text.replace(marker,sha(path))
    workflow.write_text(text)
    return dict(status='FROZEN_SOURCE_ONLY',files=len(files),manifest_sha256=sha(manifest),native='NOT_RUN',hardware='NOT_RUN')
