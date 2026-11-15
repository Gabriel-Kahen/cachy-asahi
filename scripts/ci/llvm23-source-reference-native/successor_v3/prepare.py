#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact v2 alias-correction Source DATA. No actor, acquisition, lease or replay."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE=Path(__file__).resolve().parent
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
path=HERE.parent/'filesystem.py'
if hashlib.sha256(path.read_bytes()).hexdigest()!=FS_SHA:raise ValueError('frozen DATA filesystem helper changed')
spec=importlib.util.spec_from_file_location('llvm_alias_frozen_filesystem',path)
fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs)
fs.MAX_FILES=320;fs.MAX_TOTAL=96*1024**2
PARENT=dict(source='6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0',files=251,bytes=40807998,
    map_sha256='809f57839dfd574b7abf0c65535321aeac08c58608d4f9597f936a7af78fb3a2',tree='87f5aa3537474c2dd33a02c50e869ea5fb25e7b4')
OP='llvm23-source-reference-native-v2';INNER='llvm23-source-reference-native-v1'
ACTUAL=dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-llvm23-source-reference-v2.yml')
OLD_ALIAS='.github/workflows/native-arm-llvm23-source-reference-v1.yml'
SAVED_MAP='previous-v2/source-map.json';META='successor-v3.json'
FROZEN_PYTHON=('actor/container_mode.py','actor/entry.py','actor/runtime.py','actor/work_check.py')


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def replace(raw,old,new):
    fs.need(raw.count(old)==1 and new not in raw,'one exact reviewed alias/hash seam')
    result=raw.replace(old,new);fs.need(result.count(new)==1 and result.replace(new,old)==raw,'exact seam inverse')
    return result


def validate_parent(rows):
    fs.need(len(rows)==PARENT['files'] and sum(len(raw) for raw,_ in rows.values())==PARENT['bytes']
            and fs.tree(rows)==PARENT['tree'],'complete exact251 parent bytes/modes/tree')
    raw,mode=rows['source-map.json'];m=fs.decode(raw)
    fs.need(mode==0o644 and fs.pin(raw)['sha256']==PARENT['map_sha256'] and m['actual']==ACTUAL
            and m['files']==fs.descriptors({n:v for n,v in rows.items() if n!='source-map.json'}),'whole parent map/membership/NULL join')
    fs.need(OLD_ALIAS not in rows and rows[ALIASES[0]]==rows[ALIASES[1]],'actual v2 alias pair')
    return rows


def parent(directory):return validate_parent(fs.snapshot(directory))


def render(previous):
    before=validate_parent(previous);files=dict(before);files.pop('source-map.json')
    fs.need(SAVED_MAP not in files and META not in files,'new independent correction namespace')
    raw,mode=before['hosted/common.py'];fixed=replace(raw,OLD_ALIAS.encode(),ALIASES[1].encode())
    files['hosted/common.py']=(fixed,mode)
    old_hash=hashlib.sha256(raw).hexdigest().encode();new_hash=hashlib.sha256(fixed).hexdigest().encode()
    changes={'hosted/common.py':dict(old=OLD_ALIAS,new=ALIASES[1],count=1)}
    for name in ALIASES:
        body,mode=before[name];files[name]=(replace(body,old_hash,new_hash),mode)
        changes[name]=dict(old=old_hash.decode(),new=new_hash.decode(),count=1)
    fs.need(files[ALIASES[0]]==files[ALIASES[1]],'identical corrected workflow aliases')
    frozen={n:v for n,v in before.items() if n.startswith(('actor/','packages/','original/')) or n in
        ('hosted/entry.py','policy.json','root-admission.TEMPLATE.json','contract.json','candidate-map.json','successor-v2.json')}
    fs.need(all(files[n]==row for n,row in frozen.items()),'frozen actor/candidate/original/policy/entry/v2 lineage changed')
    fs.need(all(n in frozen for n in FROZEN_PYTHON),'all four current Python actor leaves frozen')
    files[SAVED_MAP]=before['source-map.json']
    changed={n:dict(before=fs.descriptors({n:before[n]})[n],after=fs.descriptors({n:files[n]})[n],inverse=changes[n]) for n in sorted(changes)}
    observed=fs.decode(fs.read(HERE/'observed-failure.json')[0])
    inverse=dict(schema=1,scope='HOSTED_ALIAS_CORRECTION_SOURCE_ONLY_NOT_REPLAY',parent=PARENT,
        outer_operation=OP,inner_operation=INNER,changed=changed,saved_parent_map=SAVED_MAP,
        frozen_python=fs.descriptors({n:before[n] for n in FROZEN_PYTHON}),
        frozen_entry=fs.descriptors({'hosted/entry.py':before['hosted/entry.py']})['hosted/entry.py'],
        candidate_original_actor_policy_unchanged=True,closed_failure=observed,actual=ACTUAL)
    files[META]=(encode(inverse),0o644)
    files['source-map.json']=(encode(dict(schema=1,scope='LLVM23_NATIVE_V2_ALIAS_CORRECTION_SOURCE_PACKET_ONLY',
        actual=ACTUAL,files=fs.descriptors(files))),0o644)
    fs.need(undo(files)==before,'complete self-contained251 inverse')
    fs.need(len(files)==253 and sum(len(raw) for raw,_ in files.values())<=96*1024**2,'exact finite253 correction')
    return files


def undo(files):
    """Restore every v2 parent body/mode using only the successor's retained DATA."""
    result=dict(files);map_raw,map_mode=result.pop('source-map.json');m=fs.decode(map_raw)
    fs.need(map_mode==0o644 and m['actual']==ACTUAL and m['files']==fs.descriptors(result),'successor closed map/body/mode join')
    raw,mode=result.pop(META);meta=fs.decode(raw)
    fs.need(mode==0o644 and meta['parent']==PARENT and meta['actual']==ACTUAL and meta['outer_operation']==OP
            and meta['inner_operation']==INNER and meta['saved_parent_map']==SAVED_MAP,'exact unadmitted correction lineage')
    saved=result.pop(SAVED_MAP);fs.need(saved[1]==0o644 and fs.pin(saved[0])['sha256']==PARENT['map_sha256'],'retained actual parent map')
    fs.need(set(meta['changed'])=={'hosted/common.py',*ALIASES},'exact three corrected existing leaves')
    for name,row in meta['changed'].items():
        current=result[name];fs.need(fs.descriptors({name:current})[name]==row['after'],'inverse after body/mode: '+name)
        seam=row['inverse'];fs.need(seam['count']==1,'one finite inverse seam')
        restored=replace(current[0],seam['new'].encode(),seam['old'].encode())
        candidate=(restored,row['before']['mode'])
        fs.need(fs.descriptors({name:candidate})[name]==row['before'],'inverse original body/mode: '+name)
        result[name]=candidate
    result['source-map.json']=saved
    validate_parent(result)
    fs.need(meta['frozen_python']==fs.descriptors({n:result[n] for n in FROZEN_PYTHON})
            and meta['frozen_entry']==fs.descriptors({'hosted/entry.py':result['hosted/entry.py']})['hosted/entry.py'],
            'unchanged actual Python actor/hosted entry identities')
    return result


def constructor_files():
    names=('prepare.py','observed-failure.json','README.md','test_constructor.py','test_hosted_guard.py')
    return fs.descriptors({n:fs.read(HERE/n) for n in names})


def verify_profile(expected):
    raw=fs.read(HERE/'constructor-profile.json',1024**2)[0]
    fs.need(fs.pin(raw)['sha256']==expected,'external exact correction profile SHA required')
    profile=fs.decode(raw)
    fs.need(profile['parent']==PARENT and profile['outer_operation']==OP and profile['inner_operation']==INNER
            and profile['actual']==ACTUAL and profile['constructor_files']==constructor_files(),'whole correction constructor/profile DATA join')
    return profile


def construct(source,output,profile_sha):
    source,output=fs.absolute(source),fs.absolute(output)
    fs.need(not source.is_relative_to(output) and not output.is_relative_to(source)
            and not output.is_relative_to(HERE) and not HERE.is_relative_to(output),'fresh disjoint correction output')
    profile=verify_profile(profile_sha);files=render(parent(source))
    fs.need(len(files)==profile['expected_files'] and sum(len(raw) for raw,_ in files.values())==profile['expected_bytes']
            and fs.pin(files['source-map.json'][0])==profile['expected_map'] and fs.tree(files)==profile['expected_tree'],
            'exact count/bytes/map/tree correction profile')
    fs.publish(files,output)
    return dict(status='CONSTRUCTED_ALIAS_CORRECTION_DATA_ONLY',files=len(files),bytes=profile['expected_bytes'],
        map=profile['expected_map'],tree=profile['expected_tree'],parent=PARENT,outer_operation=OP,inner_operation=INNER,
        actual=ACTUAL,native_acceptance=False,publication='NOT_PERFORMED_BY_CONSTRUCTOR')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent-source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--profile-sha256',required=True);a=p.parse_args()
    print(json.dumps(construct(a.parent_source,a.output,a.profile_sha256),sort_keys=True))
