#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite XS v6 Source DATA/inverse; no Source actor, Docker, compiler or publication."""
import argparse,ast,hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[4]
HELPER=Path(os.environ.get('CACHY_XS_V6_ATOMIC_HELPER',REPO/'scripts/ci/native-build-namespace-preflight/prepare.py'))
if hashlib.sha256(HELPER.read_bytes()).hexdigest()!='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':raise ValueError('held atomic DATA helper differs')
spec=importlib.util.spec_from_file_location('xs_v6_atomic',HELPER);atomic=importlib.util.module_from_spec(spec);spec.loader.exec_module(atomic)
atomic.MAX_FILES=384;atomic.MAX_TOTAL=96*1024**2
ACTUAL=dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))
PARENT='ac06bdbe5093e73fe7c67ad75cd830255f897c3b';PARENT_MAP='465a227c13249c72bc298266a18e5720721a89de49b01e4bbe7d336ecf127111';PARENT_TREE='d11f4f8cbe708f10d590e127cb316bb68e548d94'
OPERATION='perl5423-native-xs-v6';INNER='perl5423-native-xs-v1';IMAGE_OPERATION='perl5423-native-xs-v4'
GENERIC='.github/workflows/native-arm-build.yml';OLD_ALIAS='.github/workflows/native-arm-perl5423-xs-v5.yml';NEW_ALIAS='.github/workflows/native-arm-perl5423-xs-v6.yml'
ARCHIVE_MAP={'consumer/native_adapter/native.py':'previous-v5/native.py','xs/entry.py':'previous-v5/entry.py',GENERIC:'previous-v5/workflow.yml','xs-provenance.json':'previous-v5/provenance.json','source-map.json':'previous-v5/source-map.json'}
PAYLOAD={'consumer/native_adapter/native.py','xs/entry.py'}
MODE_PIN=dict(bytes=349767,sha256='7004309f83344b49f0f8ca598d8cefcffbc078450944824849ab9c575f1c0cd2');PACKAGE_PIN=dict(bytes=22071176,sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22');COMPILER_PIN=dict(bytes=11025,sha256='fa613490865d94362d4d9efe6c5860904158c09733439a9f6c5709168f88d23c')
FROZEN_FUNCTIONS=('operation','inputs','bundle_check','daemon_join')

def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def previous(path):
 files=atomic.snapshot(path)
 atomic.need(len(files)==316 and sum(len(b)for b,_ in files.values())==87801470 and atomic.tree(files)==PARENT_TREE and atomic.pin(files['source-map.json'][0])==dict(bytes=61529,sha256=PARENT_MAP),'exact full316 v5 Source bytes/modes/map/tree')
 m=atomic.decode(files['source-map.json'][0]);atomic.need(m['actual']==ACTUAL and m['files']==atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'})and files[OLD_ALIAS]==files[GENERIC],'complete316 namespace/NULL declarations/aliases')
 atomic.need(not any(n in files for n in ARCHIVE_MAP.values()),'fresh previous-v5 archive namespace');return files

def profile(expected):
 raw,mode=atomic.read(HERE/'profile.json');atomic.need(mode==0o644 and atomic.pin(raw)['sha256']==expected,'whole externally reviewed v6 profile pin');p=atomic.decode(raw)
 atomic.need(p['schema']==1 and p['actual']==ACTUAL and p['operation']==OPERATION and p['delegated_consumer_operation']==INNER and p['delegated_image_seal_operation']==IMAGE_OPERATION and p['parent_source']==PARENT and p['runtime_manifest']==MODE_PIN and p['accepted_archive']==PACKAGE_PIN and p['compiler_manifest']==COMPILER_PIN,'new v6 scope, exact parent/runtime/compiler inputs')
 atomic.need(p['derived_default_argv']==dict(Entrypoint=['/usr/bin/false'],Cmd=['/usr/bin/false'])and p['captured_config_fields']==['AttachStderr','AttachStdout','Hostname','Image']and set(p['payload'])==PAYLOAD,'unchanged refusal-image contract and exact two-payload revision')
 atomic.need(p['actor_revision']=='EXPLICIT_FIXED_ROOT_INVENTORY_BOUND_ALPM_DESC_READER_NOT_BYTE_IDENTICAL'and p['primary_error_policy']=='PRESERVE_PRIMARY_WITH_BOUNDED_SECONDARY_NOTE_NO_EARLY_SUCCESS'and p['global_path_guard']=='UNCHANGED'and set(p['actor_inventory_delta'])=={'actor-inventory-before.txt','actor-inventory-after.txt'},'explicit actor/primary-error seam and unchanged global path guard')
 return p

def functions(raw):
 text=raw.decode();tree=ast.parse(text);return{n.name:ast.get_source_segment(text,n).encode()for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def validate_native_delta(old,new,p):
 before,after=functions(old),functions(new)
 atomic.need(set(after)==set(before)|{'alpm_inventory','read_alpm_desc'},'only two new fixed-root DATA helpers')
 atomic.need(all(before[n]==after[n]for n in before if n not in('actor','actor_dispatch')),'all other native functions/probes/budgets/caps/work guards unchanged')
 rows={}
 for n,row in p['actor_inventory_delta'].items():
  body,mode=atomic.read(HERE/n);atomic.need(atomic.pin(body)==row and mode==0o644,'exact actor inventory DATA seam');rows[n]=body
 a,b=rows['actor-inventory-before.txt'],rows['actor-inventory-after.txt']
 atomic.need(before['actor'].count(a)==after['actor'].count(b)==1 and after['actor'].replace(b,a)==before['actor'],'explicit exactly invertible actor inventory seam')
 old_comment=b'code = actor(admission_sha)  # Original actor/probe/JSON implementation is byte-identical.'
 new_comment=b'code = actor(admission_sha)  # Explicit v6 ALPM-read seam; other runtime probes/JSON are unchanged.'
 old_error=b'                raise failure from error'
 new_error=b"                failure.add_note('XS v6 preentry receipt unavailable: ' + type(error).__name__ + ': ' + str(error)[:512])\n                raise failure from None"
 atomic.need(after['actor_dispatch'].count(new_comment)==after['actor_dispatch'].count(new_error)==1 and after['actor_dispatch'].replace(new_comment,old_comment).replace(new_error,old_error)==before['actor_dispatch'],'primary error preserved; only finite dispatch diagnostic seam')
 start=new.index(b'def alpm_inventory(');end=new.index(b'def actor(admission_sha):',start)
 restored=(new[:start]+new[end:]).replace(b,a).replace(new_comment,old_comment).replace(new_error,old_error)
 atomic.need(restored==old,'whole native body inverse; imports/constants/top-level policy unchanged')

def workflow(raw,old_sha,new_sha):
 text=raw
 for old,new,count in [(b'native-arm-perl5423-xs-v5',b'native-arm-perl5423-xs-v6',2),(b'perl5423-native-xs-v5',OPERATION.encode(),4),(old_sha.encode(),new_sha.encode(),1)]:
  atomic.need(text.count(old)==count and new not in text,'exact counted v4 workflow seam');changed=text.replace(old,new);atomic.need(changed.replace(new,old)==text,'whole workflow literal inverse');text=changed
 atomic.need(b'group: native-arm-build\n  cancel-in-progress: false\n  queue: max'in text and text.count(b'            ${{ runner.temp }}/perl-hosted/compiler-image*.json\n')==1,'existing canonical lane and image evidence retained')
 return text

def inverse(files):
 before=dict(files)
 for name,saved in ARCHIVE_MAP.items():atomic.need(saved in before,'all five exact archived v5 bodies required');before[name]=before.pop(saved)
 atomic.need(NEW_ALIAS in before and OLD_ALIAS not in before,'distinct v6 alias, no old active alias');del before[NEW_ALIAS];before[OLD_ALIAS]=before[GENERIC]
 atomic.need(len(before)==316 and sum(len(b)for b,_ in before.values())==87801470 and atomic.tree(before)==PARENT_TREE and atomic.pin(before['source-map.json'][0])==dict(bytes=61529,sha256=PARENT_MAP),'full exact316 inverse bytes/modes/map/tree')
 m=atomic.decode(before['source-map.json'][0]);atomic.need(m['files']==atomic.descriptors({n:r for n,r in before.items()if n!='source-map.json'})and m['actual']==ACTUAL,'inverse closed declared namespace');return before

def render(parent,profile_sha):
 p=profile(profile_sha);before=previous(parent);files=dict(before)
 for name,saved in ARCHIVE_MAP.items():files[saved]=before[name]
 for name,row in p['payload'].items():
  body,mode=atomic.read(HERE/'payload'/name);atomic.need(dict(**atomic.pin(body),mode=mode)==row,'whole reviewed v6 payload: '+name);files[name]=(body,mode)
 native='consumer/native_adapter/native.py';old_functions,new_functions=functions(before[native][0]),functions(files[native][0])
 atomic.need(all(old_functions[n]==new_functions[n]for n in FROZEN_FUNCTIONS),'existing Perl/runtime/input policies unchanged')
 validate_native_delta(before[native][0],files[native][0],p)
 preserved={n:r for n,r in before.items()if n not in {*ARCHIVE_MAP,OLD_ALIAS}}
 atomic.need(all(files[n]==r for n,r in preserved.items()),'all old held272/accepted/image/preparation and other12 consumer bodies/modes unchanged')
 consumers=[n for n in before if n.startswith('consumer/')];atomic.need(len(consumers)==13 and sum(files[n]==before[n]for n in consumers)==12 and files[native]!=before[native],'explicit exactly-one-of13 native-adapter revision')
 native_sha=atomic.pin(files[native][0])['sha256'];entry_tree=ast.parse(files['xs/entry.py'][0]);values=[n.value.value for n in entry_tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='NATIVE_SHA'for t in n.targets)and isinstance(n.value,ast.Constant)]
 atomic.need(values==[native_sha],'hosted entry must authorize exact revised native adapter')
 wf=workflow(before[GENERIC][0],atomic.pin(before['xs/entry.py'][0])['sha256'],atomic.pin(files['xs/entry.py'][0])['sha256']);del files[OLD_ALIAS];files[NEW_ALIAS]=files[GENERIC]=(wf,0o644)
 revision=dict(path=native,old_body=atomic.pin(before[native][0]),new_body=atomic.pin(files[native][0]),archived_body=ARCHIVE_MAP[native],consumer_files=13,unchanged_consumer_files=12,frozen_functions={n:atomic.pin(old_functions[n])for n in FROZEN_FUNCTIONS})
 files['xs-provenance.json']=(encode(dict(schema=1,actual=ACTUAL,operation=OPERATION,delegated_consumer_operation=INNER,delegated_image_seal_operation=IMAGE_OPERATION,parent_source=PARENT,parent_map_sha256=PARENT_MAP,parent_tree=PARENT_TREE,closed_failed_run='43733645464',closed_failed_job='132871372912',closed_failed_artifact='14168654559',closed_failure='GLOBAL_ORDINARY_PATH_GUARD_REJECTED_UNLOGGED_ALPM_DESC_OPERAND_EPOCH_COLON_CAUSE_INFERRED',constructor_profile_sha256=profile_sha,runtime_manifest=MODE_PIN,compiler_manifest=COMPILER_PIN,accepted_archive=PACKAGE_PIN,native_adapter_revision=revision,actor_revision=dict(kind=p['actor_revision'],before=atomic.pin(old_functions['actor']),after=atomic.pin(new_functions['actor']),inventory_delta=p['actor_inventory_delta'],global_path_guard='UNCHANGED',fixed_ALPM_root='/var/lib/pacman/local',bound_to_exact349_inventory=True,primary_error_policy=p['primary_error_policy']),cap_add_raw_encodings=[['CHOWN'],['CAP_CHOWN']],work_volume_policy=dict(nocopy_both=True,both_created_before_initializer_start=True,preentry_before_any_work_write=True,preentry_receipt='work-preentry-v5.json',preentry_receipt_domain='ALREADY_CREATED_PRIVATE_ACTOR_OUTPUT',existing_actor_stdout_and_JSON_ABI_unchanged=True,budget_increase_seconds=0),derived_default_argv=dict(Entrypoint=['/usr/bin/false'],Cmd=['/usr/bin/false']),captured_config_fields=['AttachStderr','AttachStdout','Hostname','Image'],native_acceptance=False,XS_acceptance=False)),0o644)
 files['source-map.json']=(encode(dict(schema=1,actual=ACTUAL,scope='PROPOSED_SEPARATE_NATIVE_XS_V6_FIXED_ROOT_INVENTORY_BOUND_ALPM_DESC_READ',files=atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'}))),0o644)
 atomic.need(len(files)==321 and sum(len(b)for b,_ in files.values())<=96*1024**2,'finite321 v6 Source');atomic.need(inverse(files)==before,'full exact316 inverse relation');return files

def construct(parent,profile_sha,output):
 parent,output=map(atomic.absolute,(parent,output));atomic.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in (REPO,parent)),'fresh disjoint Source DATA output')
 files=render(parent,profile_sha);atomic.publish(files,output);return dict(status='CONSTRUCTED_XS_V6_SOURCE_DATA_ONLY',actual=ACTUAL,files=len(files),bytes=sum(len(b)for b,_ in files.values()),map=atomic.pin(files['source-map.json'][0]),prospective_tree=atomic.tree(files),parent_source=PARENT,native_acceptance=False,XS_acceptance=False)
if __name__=='__main__':
 atomic.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Source DATA constructor');p=argparse.ArgumentParser(description=__doc__)
 for name in ('previous-xs-source','profile-sha256','output'):p.add_argument('--'+name,required=True)
 a=p.parse_args();print(json.dumps(construct(Path(a.previous_xs_source),a.profile_sha256,Path(a.output)),sort_keys=True))
