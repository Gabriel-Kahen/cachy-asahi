#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure exact-parent Source successor; never initializes volumes or launches actors."""
import argparse,hashlib,importlib.util,json,resource
from pathlib import Path
HERE=Path(__file__).resolve().parent
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
path=HERE.parent/'filesystem.py'
if hashlib.sha256(path.read_bytes()).hexdigest()!=FS_SHA:raise ValueError('frozen DATA filesystem helper changed')
spec=importlib.util.spec_from_file_location('llvm_v2_frozen_filesystem',path);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs)
PARENT=dict(source='4ceaa1c6958349451197b19acdb084a2a5be216b',files=248,bytes=40788233,map_sha256='b462bebb24a5dcf18aaecb5843b75cba0f6c3f89b920c313263abff91f7e7e33',tree='b6d4f3bcbfb7454b1760c3ff9f9910d734d8bece')
OP='llvm23-source-reference-native-v2';INNER='llvm23-source-reference-native-v1'
ACTUAL=dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))

def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def replace(raw,old,new,count=1):
 fs.need(raw.count(old)==count,'exact reviewed literal count: '+str(old));result=raw.replace(old,new);fs.need(result.replace(new,old)==raw,'exact literal inverse');return result

def parent(directory):
 fs.MAX_FILES=320;rows=fs.snapshot(directory);raw,mode=rows['source-map.json'];fs.need(mode==0o644 and fs.pin(raw)['sha256']==PARENT['map_sha256'],'exact prior248 Source map')
 fs.need(len(rows)==PARENT['files']and sum(len(b)for b,_ in rows.values())==PARENT['bytes']and fs.tree(rows)==PARENT['tree'],'complete prior248 bytes/modes/tree')
 fs.need(fs.descriptors({n:v for n,v in rows.items()if n!='source-map.json'})==json.loads(raw)['files'],'closed parent map joins actual files');return rows

def render(previous):
 before=dict(previous);fs.need(len(before)==248 and fs.tree(before)==PARENT['tree'],'only exact retained parent')
 files={n:v for n,v in before.items()if n!='source-map.json'}
 for path in sorted((HERE/'payload').rglob('*')):
  if path.is_file():files[path.relative_to(HERE/'payload').as_posix()]=fs.read(path)
 files['hosted/entry.py']=(replace(files['hosted/entry.py'][0],b'llvm23-native-v1',b'llvm23-native-v2'),0o644)
 files['hosted/common.py']=(replace(files['hosted/common.py'][0],INNER.encode(),OP.encode()),0o644)
 shell=before['actor/entry.sh'][0];line=b'exec /usr/bin/python3 -I -B /inputs/actor/entry.py\n'
 files['actor/entry.sh']=(replace(shell,line,b'/usr/bin/python3 -I -B /inputs/actor/work_check.py\n'+line),before['actor/entry.sh'][1])
 contract=json.loads(before['contract.json'][0]);contract['actor_files']=fs.descriptors({n.removeprefix('actor/'):v for n,v in files.items()if n.startswith('actor/')});contract['outer_delegation']=dict(operation=OP,inner_operation=INNER,frozen_python_actor=True,volume_preentry='EXACT_NONMUTATING_WORK_ROOT_CHECK');files['contract.json']=(encode(contract),0o644)
 policy=json.loads(before['policy.json'][0]);policy['native_seconds']=19920;policy['work_volume_initialization']=dict(seconds=120,cpus=1,memory_bytes=536870912,swap_bytes=0,pids=64,user='0:0',cap_add=['CHOWN'],network='none',mounts='ONLY_EXACT_OWNED_WORK_VOLUME_NOCOPY',recursive=False)
 files['policy.json']=(encode(policy),0o644);admission=json.loads(before['root-admission.TEMPLATE.json'][0]);admission.update(operation=OP,resources=policy);files['root-admission.TEMPLATE.json']=(encode(admission),0o644)
 workflow=before['.github/workflows/native-arm-build.yml'][0]
 workflow=replace(workflow,b'native-arm-llvm23-source-reference-v1',b'native-arm-llvm23-source-reference-v2',2)
 workflow=replace(workflow,INNER.encode(),OP.encode(),2)
 workflow=replace(workflow,b'llvm23-native-v1',b'llvm23-native-v2',2)
 workflow=replace(workflow,b'timeout-minutes: 330',b'timeout-minutes: 332')
 workflow=replace(workflow,b'19500s python3',b'19620s python3')
 workflow=replace(workflow,hashlib.sha256(before['hosted/common.py'][0]).hexdigest().encode(),hashlib.sha256(files['hosted/common.py'][0]).hexdigest().encode())
 workflow=replace(workflow,hashlib.sha256(before['hosted/entry.py'][0]).hexdigest().encode(),hashlib.sha256(files['hosted/entry.py'][0]).hexdigest().encode())
 # Preserve all old retention operands and add only the new initialization DATA.
 anchor=b'            ${{ runner.temp }}/llvm23-hosted/llvm-build/actor-inspect.json\n'
 extra=b''.join(b'            ${{ runner.temp }}/llvm23-hosted/llvm-build/'+n+b'\n'for n in (b'volume-before.json',b'initializer-before.json',b'initializer-after.json',b'volume-initialization.json',b'inputs/volume-admission.json',b'inputs/volume-initialization.json'))
 workflow=replace(workflow,anchor,anchor+extra)
 files.pop('.github/workflows/native-arm-llvm23-source-reference-v1.yml')
 for name in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-llvm23-source-reference-v2.yml'):files[name]=(workflow,0o644)
 frozen=['actor/entry.py','actor/runtime.py','actor/container_mode.py','actor/runtime-derivation.json']
 fs.need(all(files[n]==before[n]for n in frozen),'frozen v1 Python actor/runtime altered')
 candidate={n:v for n,v in before.items()if n.startswith('packages/')or n=='candidate-map.json'};fs.need({n:v for n,v in files.items()if n.startswith('packages/')or n=='candidate-map.json'}==candidate,'private candidate is unchanged')
 changed={n for n in set(before)|set(files)if n!='source-map.json'and before.get(n)!=files.get(n)}
 inverse=dict(schema=1,parent=PARENT,outer_operation=OP,inner_operation=INNER,changed={n:dict(before=fs.descriptors({n:before[n]})[n]if n in before else None,after=fs.descriptors({n:files[n]})[n]if n in files else None)for n in sorted(changed)},frozen_python=fs.descriptors({n:before[n]for n in frozen}),candidate_unchanged=True,actual=ACTUAL,scope='SOURCE_SUCCESSOR_ONLY_NO_VOLUME_BUILD_NATIVE_OR_READER_RUN')
 files['successor-v2.json']=(encode(inverse),0o644)
 files['source-map.json']=(encode(dict(schema=1,scope='LLVM23_NATIVE_V2_SOURCE_PACKET_ONLY',actual=ACTUAL,files=fs.descriptors(files))),0o644)
 restored=undo(files,before,inverse);fs.need(restored==before and fs.tree(restored)==PARENT['tree'],'full byte/mode parent inverse')
 fs.need(len(files)<=320 and sum(len(b)for b,_ in files.values())<=96*1024**2,'finite standalone successor')
 return files

def undo(files,before,inverse):
 result=dict(files);result.pop('successor-v2.json',None);result.pop('source-map.json',None)
 for n,row in inverse['changed'].items():
  fs.need((fs.descriptors({n:result[n]})[n]if n in result else None)==row['after'],'inverse after operand differs: '+n)
  fs.need((fs.descriptors({n:before[n]})[n]if n in before else None)==row['before'],'inverse parent operand differs: '+n)
  if n in before:result[n]=before[n]
  else:result.pop(n,None)
 result['source-map.json']=before['source-map.json']
 fs.need(result==before,'inverse unchanged namespace differs')
 return result

def verify_profile(expected):
 raw=fs.read(HERE/'constructor-profile.json')[0];fs.need(fs.pin(raw)['sha256']==expected,'exact reviewed v2 constructor profile');p=json.loads(raw)
 for n,row in p['constructor_files'].items():fs.need(fs.descriptors({n:fs.read(HERE/n)})[n]==row,'constructor input changed: '+n)
 fs.need(p['parent']==PARENT,'profile exact parent');return p

def construct(source,output,profile_sha):
 source,output=fs.absolute(source),fs.absolute(output);fs.need(not output.is_relative_to(source)and not source.is_relative_to(output)and not output.is_relative_to(HERE),'fresh disjoint output')
 profile=verify_profile(profile_sha);files=render(parent(source));fs.need(fs.pin(files['source-map.json'][0])['sha256']==profile['expected_source_map_sha256']and fs.tree(files)==profile['expected_tree'],'exact constructed successor profile')
 fs.MAX_FILES=320;fs.publish(files,output);return dict(status='CONSTRUCTED_V2_DATA_ONLY_NO_ACTORS',files=len(files),bytes=sum(len(b)for b,_ in files.values()),map=fs.pin(files['source-map.json'][0]),tree=fs.tree(files),parent=PARENT,actual=ACTUAL,native_acceptance=False)

if __name__=='__main__':
 resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent_source,a.output,a.profile_sha256),sort_keys=True))
