#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent passive v5 DATA checks; Root authentication and acceptance external."""
import argparse,importlib.util,json,stat,sys,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_v5_passive_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);d=B.d
SOURCE='ac06bdbe5093e73fe7c67ad75cd830255f897c3b';REF='refs/heads/codex/native-arm-perl5423-xs-v5-20261115';MAP='465a227c13249c72bc298266a18e5720721a89de49b01e4bbe7d336ecf127111';TREE='d11f4f8cbe708f10d590e127cb316bb68e548d94';OUTER='perl5423-native-xs-v5';INNER='perl5423-native-xs-v1'
PARENT=B.parent.SOURCE;PARENT_MAP=B.parent.MAP;PARENT_TREE=B.parent.TREE
PROFILE=dict(bytes=1477,sha256='1d2e6ca3b7822d64a22e5db04b85ee324a6100e0ee4e2731172514795687e041');ACTUAL=B.parent.ACTUAL
ARCHIVE_MAP={'consumer/native_adapter/native.py':'previous-v4/native.py','xs/entry.py':'previous-v4/entry.py','.github/workflows/native-arm-build.yml':'previous-v4/workflow.yml','xs-provenance.json':'previous-v4/provenance.json','source-map.json':'previous-v4/source-map.json'}
def binding(value):
 d.need(type(value)is dict and set(value)=={'schema','binding','artifact'},'exact Root Reader envelope')
 b=value['binding'];d.need(type(b)is dict and b.get('source')==SOURCE and d.sha(b.get('source'),40)and b.get('ref')==REF and b.get('source_map_sha256')==MAP and b.get('operation')==OUTER,'actual new v5 Root Source/ref/map/operation required; NULL refuses')
 B.previous.binding(dict(value,binding=dict(b,source_map_sha256=B.previous.MAP,operation='perl5423-native-xs-v2')));return b,value['artifact']

def inverse311(leaves):
 old=dict(leaves)
 for name,saved in ARCHIVE_MAP.items():d.need(saved in old,'all five exact v4 inverse bodies');old[name]=old.pop(saved)
 d.need('.github/workflows/native-arm-perl5423-xs-v5.yml'in old,'one dedicated new v5 alias');del old['.github/workflows/native-arm-perl5423-xs-v5.yml'];old['.github/workflows/native-arm-perl5423-xs-v4.yml']=old['.github/workflows/native-arm-build.yml']
 d.need(len(old)==311 and B.previous.git_tree(old)==PARENT_TREE and d.pin(old['source-map.json'][0])==dict(bytes=60699,sha256=PARENT_MAP),'exact316→311 body/mode/map/tree inverse');return old

def source(root,b):
 d.need(b['source']==SOURCE and b['ref']==REF and b['source_map_sha256']==MAP and b['operation']==OUTER,'exact new authenticated v5 source tuple')
 raw=d.read(root,'source-map.json',d.MIB);d.need(d.pin(raw)==dict(bytes=61529,sha256=MAP),'whole316 Source map');m=d.decode(raw);d.need(m['actual']==ACTUAL and len(m['files'])==315,'316 NULL-declared Source')
 names=d.inventory(root,316,96*d.MIB);d.need(names==set(m['files'])|{'source-map.json'},'complete316 physical namespace');leaves={}
 for name in sorted(names):
  body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode);d.need(mode in(0o644,0o755),'ordinary Source mode')
  if name!='source-map.json':d.need(dict(**d.pin(body),mode=mode)==m['files'][name],'whole316 Source body/mode: '+name)
  leaves[name]=(body,mode)
 d.need(sum(len(r[0])for r in leaves.values())==87801470 and B.previous.git_tree(leaves)==TREE,'whole316 body/mode/tree')
 old=inverse311(leaves);B.source4(old,dict(b,source=PARENT,ref=B.parent.REF,source_map_sha256=PARENT_MAP,operation='perl5423-native-xs-v4'))
 original={n[len('held/original/'):]:r for n,r in leaves.items()if n.startswith('held/original/')};om=d.decode(original['native/source-map.json'][0]);d.need(len(original)==200 and sum(len(r[0])for r in original.values())==40287605 and d.pin(original['native/source-map.json'][0])==dict(bytes=39985,sha256='0c37bef7218caa6cb0f0e6d1b22ed5053b10a228f53e15076f5803d2fcf86b3e')and B.previous.git_tree(original)=='f1757dbedeed1591cdb8538f6c91e493cd451966'and om['files']=={n:dict(**d.pin(r[0]),mode=r[1])for n,r in original.items()if n!='native/source-map.json'},'exact full original200 body/mode/map/tree')
 consumer={n:r for n,r in leaves.items()if n.startswith('consumer/')};d.need(len(consumer)==13 and sum(r==old[n]for n,r in consumer.items())==12,'12 frozen consumer bodies, explicit one revision')
 import ast
 functions=lambda text:{n.name:ast.get_source_segment(text,n).encode()for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 before,after=functions(old['consumer/native_adapter/native.py'][0].decode()),functions(leaves['consumer/native_adapter/native.py'][0].decode())
 v=d.decode(leaves['xs-provenance.json'][0]);rev=v['native_adapter_revision'];d.need(set(rev['frozen_functions'])=={'actor','operation','inputs','bundle_check','daemon_join'}and all(before[n]==after[n]and d.pin(before[n])==p for n,p in rev['frozen_functions'].items()),'byte-identical actor/runtime/input policies')
 d.need(rev['old_body']==d.pin(old['consumer/native_adapter/native.py'][0])and rev['new_body']==d.pin(leaves['consumer/native_adapter/native.py'][0])==dict(bytes=44312,sha256='1db474ed81295c3604212998617bb44c1ed0339c224d63f61b06768cef6bde4f')and rev['consumer_files']==13 and rev['unchanged_consumer_files']==12,'exact explicit whole native-adapter revision')
 d.need(v['operation']==OUTER and v['delegated_consumer_operation']==INNER and v['delegated_image_seal_operation']=='perl5423-native-xs-v4'and v['parent_source']==PARENT and v['parent_map_sha256']==PARENT_MAP and v['parent_tree']==PARENT_TREE and v['constructor_profile_sha256']==PROFILE['sha256']and v['actual']==ACTUAL and v['closed_failed_run']=='43723410450'and v['closed_failed_job']=='132840063834'and v['closed_failed_artifact']=='14165811876'and v['native_acceptance']is v['XS_acceptance']is False and v['cap_add_raw_encodings']==[['CHOWN'],['CAP_CHOWN']],'v5 scope and closed v4 failure, no inherited qualification')
 d.need(v['work_volume_policy']==dict(nocopy_both=True,both_created_before_initializer_start=True,preentry_before_any_work_write=True,preentry_receipt='work-preentry-v5.json',preentry_receipt_domain='ALREADY_CREATED_PRIVATE_ACTOR_OUTPUT',existing_actor_stdout_and_JSON_ABI_unchanged=True,budget_increase_seconds=0),'exact source preentry/receipt/order policy')
 for n in ('xs/compiler_image.py','xs/prepare_inputs.py'):d.need(leaves[n]==old[n],'unchanged v4 image/preparation delegation')
 d.need(leaves['.github/workflows/native-arm-build.yml']==leaves['.github/workflows/native-arm-perl5423-xs-v5.yml'],'exact v5 aliases');return m

def validate(args):
 d.start();d.need(sys.flags.isolated and not sys.flags.optimize and sys.dont_write_bytecode and sys.version_info>=(3,14),'isolated unoptimized Python3.14+ passive zstd Reader')
 p=d.absolute(args.binding);raw=d.read(p.parent,p.name,2*d.MIB);d.need(d.sha(args.binding_sha256)and d.pin(raw)['sha256']==args.binding_sha256,'external Root whole binding pin');b,a=binding(d.decode(raw));root,evidence=d.absolute(args.source_root),d.absolute(args.evidence);m=source(root,b)
 meta=d.absolute(args.artifact_metadata);origin=B.original(args.original_artifact,evidence,a,d.read(meta.parent,meta.name,2*d.MIB),b)
 def get(name,cap=16*d.MIB):d.need(name in d._evidence_names,'missing Original evidence leaf: '+name);return d.read(evidence,name,cap)
 spec=importlib.util.spec_from_file_location('xs_v5_passive_adapters',HERE/'adapters.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A);context=A.bootstrap(get,root,b,m,d);result=A.consumer(get,root,b,context,d);d.tick()
 return dict(schema=1,status='PASS_SCOPED_XS_V5_ORIGINAL_DATA_CHECKS',binding=b,original=origin,source_files=316,prior_source_files=[311,305,298],held_files=272,original_files=200,outer_operation=OUTER,frozen_inner_operation=INNER,compiler_image=context['compiler_image'],work_preentry=context['work_preentry'],accepted_pair_input='HISTORICAL_NATIVE_ARM4K_PAIR_ONLY_NO_NEW_PACKAGE_BUILD',consumer=result,Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False,qualification='NOT_GRANTED',install_lifecycle='NOT_QUALIFIED',native16K='NOT_QUALIFIED',M2='NOT_QUALIFIED',performance='NOT_MEASURED',release='NOT_QUALIFIED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ['binding','binding-sha256','source-root','original-artifact','artifact-metadata','evidence']:p.add_argument('--'+n,required=True)
 a=p.parse_args()
 try:print(json.dumps(validate(a),sort_keys=True,indent=2,allow_nan=False))
 except(ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile,RuntimeError)as error:print(json.dumps(dict(status='REFUSED_XS_V5_DATA',reason=type(error).__name__+': '+str(error),Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False)));sys.exit(2)
