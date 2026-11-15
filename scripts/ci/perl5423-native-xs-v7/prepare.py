#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Additive XS v7 Source326 with exact321 inverse; no operational entry points."""
import argparse,ast,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
OLD=REPO/'scripts/port/perl5423-xs-consumer/native_adapter/hosted_source_v6/prepare.py'
if hashlib.sha256(OLD.read_bytes()).hexdigest()!='dfa2f1eed62b926dd8de8728a8911445569086a81a39a8d895355b3bdea5141b':raise ValueError('frozen v6 constructor pin')
s=importlib.util.spec_from_file_location('held_v6_constructor',OLD);V6=importlib.util.module_from_spec(s);s.loader.exec_module(V6);atomic=V6.atomic
ACTUAL=V6.ACTUAL;PARENT='898554db64007b7b6071e7d94cfcbbb06d906145';PARENT_MAP='2a32e63ca3eef8147ef0200cafdcaef27bc6d9653e791f727dcfbc35d878db22';PARENT_TREE='23eb609e638450cab16e13666c433cca198520b6';PARENT_BYTES=87959648
OPERATION='perl5423-native-xs-v7';GENERIC=V6.GENERIC;OLD_ALIAS='.github/workflows/native-arm-perl5423-xs-v6.yml';NEW_ALIAS='.github/workflows/native-arm-perl5423-xs-v7.yml'
ARCHIVE_MAP={'consumer/native_adapter/native.py':'previous-v6/native.py','xs/entry.py':'previous-v6/entry.py',GENERIC:'previous-v6/workflow.yml','xs-provenance.json':'previous-v6/provenance.json','source-map.json':'previous-v6/source-map.json'}
def encode(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def previous(path):
 files=atomic.snapshot(path);atomic.need(len(files)==321 and sum(len(b)for b,_ in files.values())==PARENT_BYTES and atomic.tree(files)==PARENT_TREE and atomic.pin(files['source-map.json'][0])==dict(bytes=62358,sha256=PARENT_MAP),'whole exact321 Source bytes/modes/map/tree')
 m=atomic.decode(files['source-map.json'][0]);atomic.need(m['actual']==ACTUAL and m['files']==atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'})and files[OLD_ALIAS]==files[GENERIC],'closed321 namespace/NULL declarations/aliases');return files

def profile(expected):
 raw,mode=atomic.read(HERE/'profile.json');atomic.need(mode==0o644 and atomic.pin(raw)['sha256']==expected,'whole external v7 profile');p=atomic.decode(raw)
 atomic.need(p['schema']==1 and p['actual']==ACTUAL and p['operation']==OPERATION and p['parent_source']==PARENT and p['delegated_consumer_operation']==V6.INNER and p['delegated_image_seal_operation']==V6.IMAGE_OPERATION and p['global_path_guard']=='UNCHANGED'and p['runner']==p['preflight']=='BYTE_IDENTICAL'and p['budget_increase_seconds']==0 and p['actor_revision']=='EXACT_PATH_OBJECT_TO_STRING_AT_RUNNER_SANDBOX_ARGUMENT_ONLY','v7 narrow correction, unissued scope and frozen policy')
 atomic.need(p['runtime_manifest']==V6.MODE_PIN and p['accepted_archive']==V6.PACKAGE_PIN and p['compiler_manifest']==V6.COMPILER_PIN and set(p['payload'])==V6.PAYLOAD,'same runtime/compiler/accepted input and exactly two payloads');return p

def native_delta(old,new,p):
 before=p['before'].encode();after=p['after'].encode();atomic.need(before==b"runner.execute('/inputs/xs-plan.json', a['plan_sha256'], sandbox_path,"and after==b"runner.execute('/inputs/xs-plan.json', a['plan_sha256'], str(sandbox_path),",'fixed exact call seam')
 atomic.need(old.count(before)==new.count(after)==1 and new.replace(after,before)==old,'whole native body exact one-seam inverse; global guards unchanged')
 a,b=V6.functions(old),V6.functions(new);atomic.need(a.keys()==b.keys()and all(a[n]==b[n]for n in a if n!='actor'),'all other native function bodies byte-identical')
 return dict(kind=p['actor_revision'],before=atomic.pin(a['actor']),after=atomic.pin(b['actor']),before_literal=p['before'],after_literal=p['after'],global_path_guard='UNCHANGED',runner='BYTE_IDENTICAL',preflight='BYTE_IDENTICAL')

def workflow(old,old_sha,new_sha):
 text=old
 for a,b,count in [(b'native-arm-perl5423-xs-v6',b'native-arm-perl5423-xs-v7',2),(b'perl5423-native-xs-v6',OPERATION.encode(),4),(old_sha.encode(),new_sha.encode(),1)]:
  atomic.need(text.count(a)==count and b not in text,'exact counted workflow literal');changed=text.replace(a,b);atomic.need(changed.replace(b,a)==text,'literal inverse');text=changed
 return text

def inverse(files):
 old=dict(files)
 for name,saved in ARCHIVE_MAP.items():atomic.need(saved in old,'all five exact v6 archive leaves');old[name]=old.pop(saved)
 atomic.need(NEW_ALIAS in old and OLD_ALIAS not in old,'v7 active alias only');del old[NEW_ALIAS];old[OLD_ALIAS]=old[GENERIC]
 atomic.need(len(old)==321 and sum(len(b)for b,_ in old.values())==PARENT_BYTES and atomic.tree(old)==PARENT_TREE and atomic.pin(old['source-map.json'][0])['sha256']==PARENT_MAP,'whole exact321 inverse')
 atomic.need(atomic.decode(old['source-map.json'][0])['files']==atomic.descriptors({n:r for n,r in old.items()if n!='source-map.json'}),'complete inverse membership');return old

def render(parent,profile_sha):
 p=profile(profile_sha);before=previous(parent);files=dict(before)
 for name,saved in ARCHIVE_MAP.items():atomic.need(saved not in files,'fresh archived v6 namespace');files[saved]=before[name]
 for name,row in p['payload'].items():
  body,mode=atomic.read(HERE/'payload'/name);atomic.need(dict(**atomic.pin(body),mode=mode)==row,'exact v7 payload pin');files[name]=(body,mode)
 native='consumer/native_adapter/native.py';revision=native_delta(before[native][0],files[native][0],p)
 oldentry=before['xs/entry.py'][0];newentry=files['xs/entry.py'][0];native_sha=atomic.pin(files[native][0])['sha256'];old_native_sha=atomic.pin(before[native][0])['sha256']
 atomic.need(oldentry.count(b'native-arm-perl5423-xs-v6')==newentry.count(b'native-arm-perl5423-xs-v7')==1 and oldentry.count(b'perl5423-native-xs-v6')==newentry.count(OPERATION.encode())==1,'exact hosted outer alias/operation literals')
 restored=newentry.replace(native_sha.encode(),old_native_sha.encode()).replace(b'native-arm-perl5423-xs-v7',b'native-arm-perl5423-xs-v6').replace(OPERATION.encode(),b'perl5423-native-xs-v6');atomic.need(restored==oldentry and newentry.count(native_sha.encode())==1,'whole hosted-entry literal/hash inverse')
 for prefix in('held/','accepted/'):
  atomic.need({n:r for n,r in files.items()if n.startswith(prefix)}=={n:r for n,r in before.items()if n.startswith(prefix)},'complete unchanged held/accepted inputs')
 atomic.need(sum(files[n]==r for n,r in before.items()if n.startswith('consumer/'))==12 and files['consumer/preflight.py']==before['consumer/preflight.py']and files['consumer/runner/run.py']==before['consumer/runner/run.py'],'12of13 unchanged including global guard and runner')
 wf=workflow(before[GENERIC][0],atomic.pin(oldentry)['sha256'],atomic.pin(newentry)['sha256']);del files[OLD_ALIAS];files[NEW_ALIAS]=files[GENERIC]=(wf,0o644)
 files['xs-provenance.json']=(encode(dict(schema=1,actual=ACTUAL,operation=OPERATION,delegated_consumer_operation=V6.INNER,delegated_image_seal_operation=V6.IMAGE_OPERATION,parent_source=PARENT,parent_map_sha256=PARENT_MAP,parent_tree=PARENT_TREE,constructor_profile_sha256=profile_sha,closed_failed_run='43753943999',closed_failed_job='132933814476',closed_failed_artifact='14178075955',closed_failure='PATH_OBJECT_PASSED_TO_STRING_ONLY_RUNNER_SANDBOX_OPERAND_CHECK_REPRODUCED',native_adapter_revision=dict(path=native,old_body=atomic.pin(before[native][0]),new_body=atomic.pin(files[native][0]),archived_body=ARCHIVE_MAP[native],consumer_files=13,unchanged_consumer_files=12),actor_revision=revision,runtime_manifest=V6.MODE_PIN,compiler_manifest=V6.COMPILER_PIN,accepted_archive=V6.PACKAGE_PIN,work_volume_policy=atomic.decode(before['xs-provenance.json'][0])['work_volume_policy'],cap_add_raw_encodings=[['CHOWN'],['CAP_CHOWN']],native_acceptance=False,XS_acceptance=False)),0o644)
 files['source-map.json']=(encode(dict(schema=1,actual=ACTUAL,scope='PROPOSED_SEPARATE_NATIVE_XS_V7_TYPED_SANDBOX_CALL_ARGUMENT_ONLY',files=atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'}))),0o644)
 atomic.need(len(files)==326 and sum(len(b)for b,_ in files.values())<=96*1024**2 and inverse(files)==before,'finite326 Source with whole321 inverse')
 # Reuse the previous finite inverse after restoring321 to prove the entire lineage.
 atomic.need(len(V6.inverse(before))==316,'preserved whole321→316 inverse');return files

def construct(parent,profile_sha,output):
 parent,output=map(atomic.absolute,(parent,output));atomic.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in(REPO,parent)),'fresh disjoint Source output')
 files=render(parent,profile_sha);atomic.publish(files,output);return dict(status='CONSTRUCTED_XS_V7_SOURCE_DATA_ONLY',actual=ACTUAL,files=len(files),bytes=sum(len(b)for b,_ in files.values()),map=atomic.pin(files['source-map.json'][0]),prospective_tree=atomic.tree(files),parent_source=PARENT,native_acceptance=False,XS_acceptance=False)
if __name__=='__main__':
 atomic.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Source constructor');p=argparse.ArgumentParser(description=__doc__)
 for n in('previous-xs-source','profile-sha256','output'):p.add_argument('--'+n,required=True)
 a=p.parse_args();print(json.dumps(construct(Path(a.previous_xs_source),a.profile_sha256,Path(a.output)),sort_keys=True))
