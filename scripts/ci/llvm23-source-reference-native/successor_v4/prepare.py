#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact Docker capability-spelling Source DATA; no actor, acquisition or replay."""
import argparse,hashlib,importlib.util,json,resource
from pathlib import Path
HERE=Path(__file__).resolve().parent
path=HERE.parent/'filesystem.py'
if hashlib.sha256(path.read_bytes()).hexdigest()!='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':raise ValueError('frozen filesystem helper')
spec=importlib.util.spec_from_file_location('llvm_cap_frozen_filesystem',path);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs)
fs.MAX_FILES=320;fs.MAX_TOTAL=96*1024**2
PARENT=dict(source=None,ref=None,files=253,bytes=40862047,map_sha256='5c19a2699856e081712d159c551ce496919938bd456f2182c0c905f03cbd2ef0',tree='2f90eaaaa532d14574c0ce1f1c93b02310f44d91')
OP='llvm23-source-reference-native-v2';INNER='llvm23-source-reference-native-v1'
ACTUAL=dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))
VOLUME='hosted/volume.py';SAVED_VOLUME='previous-v3/hosted-volume.py';SAVED_MAP='previous-v3/source-map.json';META='successor-v4.json'
OLD="h['CapAdd']==['CHOWN']";NEW="h['CapAdd']in(['CHOWN'],['CAP_CHOWN'])"
OLD_VOLUME=dict(bytes=5818,sha256='5403e74515cf11aacb05fbd719d5e129549aa565b913b84d86d2b1ed608426bd',mode=0o644)

def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def descriptor(row):return dict(**fs.pin(row[0]),mode=row[1])
def closed(rows):
 raw,mode=rows['source-map.json'];m=fs.decode(raw)
 fs.need(mode==0o644 and set(m)=={'schema','scope','actual','files'}and type(m['schema'])is int and m['schema']==1 and m['actual']==ACTUAL and m['files']==fs.descriptors({n:v for n,v in rows.items()if n!='source-map.json'}),'closed map/body/mode/NULL join')
def validate_parent(rows):
 closed(rows);fs.need(len(rows)==PARENT['files']and sum(len(b)for b,_ in rows.values())==PARENT['bytes']and fs.tree(rows)==PARENT['tree']and fs.pin(rows['source-map.json'][0])['sha256']==PARENT['map_sha256'],'complete exact unpublished253 parent DATA')
 fs.need(descriptor(rows[VOLUME])==OLD_VOLUME,'exact old volume body/mode');return rows
def parent(directory):return validate_parent(fs.snapshot(directory))
def corrected(raw):
 fs.need(raw.count(OLD.encode())==1 and NEW.encode()not in raw,'one exact initializer capability spelling seam')
 result=raw.replace(OLD.encode(),NEW.encode());fs.need(result.replace(NEW.encode(),OLD.encode())==raw,'whole exact volume inverse');return result

def render(previous):
 before=validate_parent(previous);files=dict(before);files.pop('source-map.json')
 fs.need(not{SAVED_MAP,SAVED_VOLUME,META}&set(files),'fresh capability-correction namespace')
 files[VOLUME]=(corrected(before[VOLUME][0]),before[VOLUME][1]);files[SAVED_VOLUME]=before[VOLUME];files[SAVED_MAP]=before['source-map.json']
 meta=dict(schema=1,scope='INITIALIZER_CAPABILITY_SPELLING_SOURCE_ONLY_NOT_REPLAY',parent=PARENT,outer_operation=OP,inner_operation=INNER,changed={VOLUME:dict(before=descriptor(before[VOLUME]),after=descriptor(files[VOLUME]),inverse=dict(old=OLD,new=NEW,count=1))},saved_parent_map=SAVED_MAP,saved_parent_volume=SAVED_VOLUME,all_other_parent_leaves_unchanged=True,actual=ACTUAL)
 files[META]=(encode(meta),0o644)
 files['source-map.json']=(encode(dict(schema=1,scope='LLVM23_NATIVE_V2_CAPABILITY_SPELLING_SOURCE_PACKET_ONLY',actual=ACTUAL,files=fs.descriptors(files))),0o644)
 fs.need(undo(files)==before and len(files)==256,'complete self-contained253 inverse and finite256 correction')
 fs.need(all(files[n]==v for n,v in before.items()if n not in(VOLUME,'source-map.json')),'all actor/compiledcode/policy/common/workflow and other parent leaves frozen')
 return files

def undo(files):
 closed(files);result=dict(files);result.pop('source-map.json');raw,mode=result.pop(META);meta=fs.decode(raw)
 fs.need(mode==0o644 and set(meta)=={'schema','scope','parent','outer_operation','inner_operation','changed','saved_parent_map','saved_parent_volume','all_other_parent_leaves_unchanged','actual'}and meta['schema']==1 and meta['scope']=='INITIALIZER_CAPABILITY_SPELLING_SOURCE_ONLY_NOT_REPLAY'and meta['parent']==PARENT and meta['outer_operation']==OP and meta['inner_operation']==INNER and meta['actual']==ACTUAL and meta['all_other_parent_leaves_unchanged']is True and meta['saved_parent_map']==SAVED_MAP and meta['saved_parent_volume']==SAVED_VOLUME and set(meta['changed'])=={VOLUME},'exact unadmitted capability correction lineage')
 saved=result.pop(SAVED_VOLUME);saved_map=result.pop(SAVED_MAP);row=meta['changed'][VOLUME]
 fs.need(descriptor(saved)==OLD_VOLUME and saved_map[1]==0o644 and fs.pin(saved_map[0])['sha256']==PARENT['map_sha256'],'retained whole253 volume/map')
 fs.need(row==dict(before=OLD_VOLUME,after=descriptor(result[VOLUME]),inverse=dict(old=OLD,new=NEW,count=1))and result[VOLUME]==(corrected(saved[0]),saved[1]),'only exact raw-list capability spelling predicate changed')
 result[VOLUME]=saved;result['source-map.json']=saved_map
 return validate_parent(result)

def constructor_files():return fs.descriptors({n:fs.read(HERE/n)for n in('prepare.py','README.md','test_constructor.py','test_volume_guard.py','fixtures/volume-guard.DATA.json')})
def verify_profile(expected):
 raw=fs.read(HERE/'constructor-profile.json')[0];fs.need(fs.pin(raw)['sha256']==expected,'external exact capability constructor profile required');p=fs.decode(raw)
 fs.need(p['parent']==PARENT and p['actual']==ACTUAL and p['outer_operation']==OP and p['inner_operation']==INNER and p['constructor_files']==constructor_files(),'whole capability constructor/profile DATA join');return p

def construct(source,output,profile_sha):
 source,output=fs.absolute(source),fs.absolute(output)
 fs.need(not source.is_relative_to(output)and not output.is_relative_to(source)and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh disjoint correction output')
 p=verify_profile(profile_sha);files=render(parent(source))
 fs.need(len(files)==p['expected_files']and sum(len(b)for b,_ in files.values())==p['expected_bytes']and fs.pin(files['source-map.json'][0])==p['expected_map']and fs.tree(files)==p['expected_tree'],'exact count/bytes/map/tree capability correction profile')
 fs.publish(files,output)
 return dict(status='CONSTRUCTED_CAPABILITY_SPELLING_DATA_ONLY',files=len(files),bytes=p['expected_bytes'],map=p['expected_map'],tree=p['expected_tree'],parent=PARENT,outer_operation=OP,inner_operation=INNER,actual=ACTUAL,native_acceptance=False,publication='NOT_PERFORMED_BY_CONSTRUCTOR')
if __name__=='__main__':
 resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--parent-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent_source,a.output,a.profile_sha256),sort_keys=True))
