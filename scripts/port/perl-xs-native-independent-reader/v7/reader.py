#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Bounded passive Source326/Original DATA checks; external Root trust stays external."""
import argparse,ast,importlib.util,json,stat,sys,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('xs_v7_passive_base',HERE/'base.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B);d=B.d
SOURCE=None;REF='refs/heads/codex/native-arm-perl5423-xs-v7-20261115';MAP='89493dbeeb686f9606c03337aa6a824a756bc312cdc7b1e3a0e7ce96827cd43d';TREE='cb3684c7583c499f4f90f759314c7e03b9a0d428';OUTER='perl5423-native-xs-v7';INNER='perl5423-native-xs-v1'
PARENT=B.parent.SOURCE;PARENT_MAP=B.parent.MAP;PARENT_TREE=B.parent.TREE;ACTUAL=B.parent.ACTUAL
PROFILE=dict(bytes=1639,sha256='8a2d76467267eefaa052aa512750b30ea2546f79707961c159e61596ee68c76a')
ARCHIVE_MAP={'consumer/native_adapter/native.py':'previous-v6/native.py','xs/entry.py':'previous-v6/entry.py','.github/workflows/native-arm-build.yml':'previous-v6/workflow.yml','xs-provenance.json':'previous-v6/provenance.json','source-map.json':'previous-v6/source-map.json'}
BEFORE=b"runner.execute('/inputs/xs-plan.json', a['plan_sha256'], sandbox_path,"
AFTER=b"runner.execute('/inputs/xs-plan.json', a['plan_sha256'], str(sandbox_path),"
def binding(value):
 d.need(type(value)is dict and set(value)=={'schema','binding','artifact'},'exact external Root Reader envelope')
 b=value['binding'];d.need(type(b)is dict and d.sha(b.get('source'),40)and b['source']not in(PARENT,B.parent.PARENT)and b.get('ref')==REF and b.get('source_map_sha256')==MAP and b.get('operation')==OUTER,'actual Root Source40hex/ref326/map/operation; NULL and closed sources refuse')
 # The older structural predicate sees only its historical map/operation. Actual
 # Source/ref/run/job/approval remain unchanged; this never authenticates Root.
 B.previous.binding(dict(value,binding=dict(b,source_map_sha256=B.previous.MAP,operation='perl5423-native-xs-v2')));return b,value['artifact']
def inverse321(leaves):
 old=dict(leaves)
 for name,saved in ARCHIVE_MAP.items():d.need(saved in old,'all five exact archived6 bodies');old[name]=old.pop(saved)
 new='.github/workflows/native-arm-perl5423-xs-v7.yml';previous='.github/workflows/native-arm-perl5423-xs-v6.yml'
 d.need(new in old and previous not in old,'one current7 workflow alias');del old[new];old[previous]=old['.github/workflows/native-arm-build.yml']
 d.need(len(old)==321 and sum(len(r[0])for r in old.values())==87959648 and B.previous.git_tree(old)==PARENT_TREE and d.pin(old['source-map.json'][0])==dict(bytes=62358,sha256=PARENT_MAP),'exact326→321 whole bytes/modes/map/tree inverse');return old
def native_delta(old,new):
 d.need(old.count(BEFORE)==new.count(AFTER)==1 and new.replace(AFTER,BEFORE)==old,'whole native exact one typed operand seam')
 def functions(raw):
  text=raw.decode();return {n.name:ast.get_source_segment(text,n).encode()for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 a,b=functions(old),functions(new);d.need(a.keys()==b.keys()and all(a[n]==b[n]for n in a if n!='actor'),'every other native function byte-identical')
 return dict(kind='EXACT_PATH_OBJECT_TO_STRING_AT_RUNNER_SANDBOX_ARGUMENT_ONLY',before=d.pin(a['actor']),after=d.pin(b['actor']),before_literal=BEFORE.decode(),after_literal=AFTER.decode(),global_path_guard='UNCHANGED',runner='BYTE_IDENTICAL',preflight='BYTE_IDENTICAL')
def source(root,b):
 d.need(d.sha(b['source'],40)and b['source']not in(PARENT,B.parent.PARENT)and b['ref']==REF and b['source_map_sha256']==MAP and b['operation']==OUTER,'actual exact Root-selected7 tuple')
 raw=d.read(root,'source-map.json',d.MIB);d.need(d.pin(raw)==dict(bytes=63172,sha256=MAP),'whole326 map');m=d.decode(raw);d.need(m['schema']==1 and m['actual']==ACTUAL and len(m['files'])==325,'326 NULL-declared Source')
 names=d.inventory(root,326,96*d.MIB);d.need(names==set(m['files'])|{'source-map.json'},'complete326 physical namespace');leaves={}
 for name in sorted(names):
  body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode);d.need(mode in(0o644,0o755),'ordinary Source mode')
  if name!='source-map.json':d.need(dict(**d.pin(body),mode=mode)==m['files'][name],'whole326 body/mode: '+name)
  leaves[name]=(body,mode)
 d.need(sum(len(r[0])for r in leaves.values())==88117546 and B.previous.git_tree(leaves)==TREE,'whole326 bytes/modes/tree')
 old=inverse321(leaves)
 # Historical Source-leaf DATA only. Runtime binding is never projected.
 B.source6(old,dict(b,source=PARENT,ref=B.parent.REF,source_map_sha256=PARENT_MAP,operation=B.parent.OUTER))
 change=native_delta(old['consumer/native_adapter/native.py'][0],leaves['consumer/native_adapter/native.py'][0]);v=d.decode(leaves['xs-provenance.json'][0]);rev=v['native_adapter_revision']
 d.need(v['schema']==1 and v['actual']==ACTUAL and v['operation']==OUTER and v['parent_source']==PARENT and v['parent_map_sha256']==PARENT_MAP and v['parent_tree']==PARENT_TREE and v['constructor_profile_sha256']==PROFILE['sha256']and v['delegated_consumer_operation']==INNER and v['delegated_image_seal_operation']=='perl5423-native-xs-v4'and v['closed_failed_run']=='43753943999'and v['closed_failed_job']=='132933814476'and v['closed_failed_artifact']=='14178075955'and v['closed_failure']=='PATH_OBJECT_PASSED_TO_STRING_ONLY_RUNNER_SANDBOX_OPERAND_CHECK_REPRODUCED'and v['actor_revision']==change and v['native_acceptance']is v['XS_acceptance']is False,'exact explicit7 provenance; no acceptance')
 native='consumer/native_adapter/native.py';consumer={n:r for n,r in leaves.items()if n.startswith('consumer/')}
 d.need(len(consumer)==13 and sum(r==old[n]for n,r in consumer.items())==12 and rev==dict(path=native,old_body=d.pin(old[native][0]),new_body=d.pin(leaves[native][0]),archived_body=ARCHIVE_MAP[native],consumer_files=13,unchanged_consumer_files=12)and rev['new_body']==dict(bytes=48300,sha256=B.NEW_NATIVE),'one native body; 12 unchanged including strict runner/preflight')
 for name in('runtime_manifest','compiler_manifest','accepted_archive','work_volume_policy','cap_add_raw_encodings'):d.need(v[name]==d.decode(old['xs-provenance.json'][0])[name],'unchanged exact7 policy: '+name)
 for name in('xs/compiler_image.py','xs/prepare_inputs.py'):d.need(leaves[name]==old[name],'frozen image/preparation')
 entry=leaves['xs/entry.py'][0];oldentry=old['xs/entry.py'][0];d.need(d.pin(entry)==dict(bytes=33187,sha256='38ee21bad53965e3acf7e22cac123f8d23f26ea619b472d5a1f5304e951aa8b1')and entry.count(B.NEW_NATIVE.encode())==1 and entry.replace(B.NEW_NATIVE.encode(),B.OLD_NATIVE.encode()).replace(b'native-arm-perl5423-xs-v7',b'native-arm-perl5423-xs-v6').replace(OUTER.encode(),B.parent.OUTER.encode())==oldentry,'whole hosted entry exact literal/hash inverse')
 generic='.github/workflows/native-arm-build.yml';d.need(leaves[generic]==leaves['.github/workflows/native-arm-perl5423-xs-v7.yml']and d.pin(leaves[generic][0])==dict(bytes=10323,sha256='0be05069585fabf4ff900ed755ee0547a3c7ab4375e425a0b28804a78cca07c3'),'exact new workflow aliases')
 return m

def validate(args):
 d.start();d.need(sys.flags.isolated and not sys.flags.optimize and sys.dont_write_bytecode and sys.version_info>=(3,14),'isolated unoptimized Python3.14+ passive zstd Reader')
 p=d.absolute(args.binding);raw=d.read(p.parent,p.name,2*d.MIB);d.need(d.sha(args.binding_sha256)and d.pin(raw)['sha256']==args.binding_sha256,'external Root whole binding pin');b,a=binding(d.decode(raw));root,evidence=d.absolute(args.source_root),d.absolute(args.evidence);m=source(root,b)
 meta=d.absolute(args.artifact_metadata);origin=B.original(args.original_artifact,evidence,a,d.read(meta.parent,meta.name,2*d.MIB),b)
 def get(name,cap=16*d.MIB):d.need(name in d._evidence_names,'missing Original evidence leaf: '+name);return d.read(evidence,name,cap)
 s=importlib.util.spec_from_file_location('xs_v7_passive_adapters',HERE/'adapters.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A);context=A.bootstrap(get,root,b,m,d);result=A.consumer(get,root,b,context,d);d.tick()
 return dict(schema=1,status='PASS_SCOPED_XS_V7_ORIGINAL_DATA_CHECKS',binding=b,original=origin,source_files=326,prior_source_files=[321,316,311,305,298],held_files=272,original_files=200,outer_operation=OUTER,frozen_inner_operation=INNER,compiler_image=context['compiler_image'],work_preentry=context['work_preentry'],native_actor_revision='EXACT_PATH_OBJECT_TO_STRING_AT_RUNNER_SANDBOX_ARGUMENT_ONLY',accepted_pair_input='HISTORICAL_NATIVE_ARM4K_PAIR_ONLY_NO_NEW_PACKAGE_BUILD',consumer=result,Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False,qualification='NOT_GRANTED',install_lifecycle='NOT_QUALIFIED',native16K='NOT_QUALIFIED',M2='NOT_QUALIFIED',performance='NOT_MEASURED',release='NOT_QUALIFIED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('binding','binding-sha256','source-root','original-artifact','artifact-metadata','evidence'):p.add_argument('--'+n,required=True)
 a=p.parse_args()
 try:print(json.dumps(validate(a),sort_keys=True,indent=2,allow_nan=False))
 except(ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile,RuntimeError)as error:print(json.dumps(dict(status='REFUSED_XS_V7_DATA',reason=type(error).__name__+': '+str(error),Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False)));sys.exit(2)
