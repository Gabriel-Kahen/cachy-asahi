#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent passive v6 DATA checks; Root authentication and acceptance external."""
import argparse,importlib.util,json,stat,sys,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_v6_passive_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);d=B.d
SOURCE='898554db64007b7b6071e7d94cfcbbb06d906145';REF='refs/heads/codex/native-arm-perl5423-xs-v6-20261115';MAP='2a32e63ca3eef8147ef0200cafdcaef27bc6d9653e791f727dcfbc35d878db22';TREE='23eb609e638450cab16e13666c433cca198520b6';OUTER='perl5423-native-xs-v6';INNER='perl5423-native-xs-v1'
PARENT=B.parent.SOURCE;PARENT_MAP=B.parent.MAP;PARENT_TREE=B.parent.TREE
PROFILE=dict(bytes=2023,sha256='5d609d09f1b0eaf2f2fdb2b0560dd6c2e69514890ba7bbe2b32d433b3294f61f');ACTUAL=B.parent.ACTUAL
ARCHIVE_MAP={'consumer/native_adapter/native.py':'previous-v5/native.py','xs/entry.py':'previous-v5/entry.py','.github/workflows/native-arm-build.yml':'previous-v5/workflow.yml','xs-provenance.json':'previous-v5/provenance.json','source-map.json':'previous-v5/source-map.json'}
def binding(value):
 d.need(type(value)is dict and set(value)=={'schema','binding','artifact'},'exact Root Reader envelope')
 b=value['binding'];d.need(type(b)is dict and b.get('source')==SOURCE and d.sha(b.get('source'),40)and b.get('ref')==REF and b.get('source_map_sha256')==MAP and b.get('operation')==OUTER,'actual new v6 Root Source/ref/map/operation required; NULL refuses')
 B.previous.binding(dict(value,binding=dict(b,source_map_sha256=B.previous.MAP,operation='perl5423-native-xs-v2')));return b,value['artifact']

def inverse316(leaves):
 old=dict(leaves)
 for name,saved in ARCHIVE_MAP.items():d.need(saved in old,'all five exact v5 inverse bodies');old[name]=old.pop(saved)
 d.need('.github/workflows/native-arm-perl5423-xs-v6.yml'in old,'one exact v6 alias');del old['.github/workflows/native-arm-perl5423-xs-v6.yml'];old['.github/workflows/native-arm-perl5423-xs-v5.yml']=old['.github/workflows/native-arm-build.yml']
 d.need(len(old)==316 and B.previous.git_tree(old)==PARENT_TREE and d.pin(old['source-map.json'][0])==dict(bytes=61529,sha256=PARENT_MAP),'exact321→316 body/mode/map/tree inverse');return old

def native_delta(leaves,old):
 spec=importlib.util.spec_from_file_location('xs_v6_fixed_native_delta',HERE/'delta.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 return module.validate(old['consumer/native_adapter/native.py'][0],leaves['consumer/native_adapter/native.py'][0],d)

def source(root,b):
 d.need(b['source']==SOURCE and b['ref']==REF and b['source_map_sha256']==MAP and b['operation']==OUTER,'exact authenticated v6 Source tuple')
 raw=d.read(root,'source-map.json',d.MIB);d.need(d.pin(raw)==dict(bytes=62358,sha256=MAP),'whole321 Source map');m=d.decode(raw);d.need(m['actual']==ACTUAL and len(m['files'])==320,'321 NULL-declared Source')
 names=d.inventory(root,321,96*d.MIB);d.need(names==set(m['files'])|{'source-map.json'},'complete321 physical namespace');leaves={}
 for name in sorted(names):
  body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode);d.need(mode in(0o644,0o755),'ordinary Source mode')
  if name!='source-map.json':d.need(dict(**d.pin(body),mode=mode)==m['files'][name],'whole321 body/mode: '+name)
  leaves[name]=(body,mode)
 d.need(sum(len(r[0])for r in leaves.values())==87959648 and B.previous.git_tree(leaves)==TREE,'whole321 body/mode/tree')
 old=inverse316(leaves);B.source5(old,dict(b,source=PARENT,ref=B.parent.REF,source_map_sha256=PARENT_MAP,operation='perl5423-native-xs-v5'));change=native_delta(leaves,old)
 v=d.decode(leaves['xs-provenance.json'][0]);rev=v['native_adapter_revision'];actor=v['actor_revision']
 d.need(v['operation']==OUTER and v['parent_source']==PARENT and v['parent_tree']==PARENT_TREE and v['parent_map_sha256']==PARENT_MAP and v['constructor_profile_sha256']==PROFILE['sha256']and v['actual']==ACTUAL and v['delegated_consumer_operation']==INNER and v['delegated_image_seal_operation']=='perl5423-native-xs-v4'and v['closed_failed_run']=='43733645464'and v['closed_failed_job']=='132871372912'and v['closed_failed_artifact']=='14168654559'and v['native_acceptance']is v['XS_acceptance']is False,'new v6 Source and closed v5 failure, no acceptance')
 d.need(actor['kind']=='EXPLICIT_FIXED_ROOT_INVENTORY_BOUND_ALPM_DESC_READER_NOT_BYTE_IDENTICAL'and actor['before']==change['actor_before']and actor['after']==change['actor_after']and actor['global_path_guard']=='UNCHANGED'and actor['fixed_ALPM_root']=='/var/lib/pacman/local'and actor['bound_to_exact349_inventory']is True and actor['primary_error_policy']==change['primary_error'],'explicit bounded ALPM path/data and primary-error delta')
 consumer={n:r for n,r in leaves.items()if n.startswith('consumer/')};d.need(len(consumer)==13 and sum(r==old[n]for n,r in consumer.items())==12 and rev['consumer_files']==13 and rev['unchanged_consumer_files']==12 and rev['new_body']==d.pin(leaves['consumer/native_adapter/native.py'][0])==dict(bytes=48295,sha256='c492eb1b7175407d20a78305d8d1d499c67960d3b295aeea5ae206b9222d04cd')and rev['old_body']==d.pin(old['consumer/native_adapter/native.py'][0]),'explicit one native revision/12 frozen consumers')
 d.need(rev['frozen_functions']==change['frozen_functions']and 'actor'not in rev['frozen_functions'],'no false frozen-actor claim')
 d.need(v['work_volume_policy']==d.decode(old['xs-provenance.json'][0])['work_volume_policy'],'unchanged work-volume NoCopy/order/preentry/JSON/budget policy')
 for n in('xs/compiler_image.py','xs/prepare_inputs.py'):d.need(leaves[n]==old[n],'unchanged image/preparation')
 d.need(leaves['.github/workflows/native-arm-build.yml']==leaves['.github/workflows/native-arm-perl5423-xs-v6.yml'],'exact v6 workflow aliases');return m

def validate(args):
 d.start();d.need(sys.flags.isolated and not sys.flags.optimize and sys.dont_write_bytecode and sys.version_info>=(3,14),'isolated unoptimized Python3.14+ passive zstd Reader')
 p=d.absolute(args.binding);raw=d.read(p.parent,p.name,2*d.MIB);d.need(d.sha(args.binding_sha256)and d.pin(raw)['sha256']==args.binding_sha256,'external Root whole binding pin');b,a=binding(d.decode(raw));root,evidence=d.absolute(args.source_root),d.absolute(args.evidence);m=source(root,b)
 meta=d.absolute(args.artifact_metadata);origin=B.original(args.original_artifact,evidence,a,d.read(meta.parent,meta.name,2*d.MIB),b)
 def get(name,cap=16*d.MIB):d.need(name in d._evidence_names,'missing Original evidence leaf: '+name);return d.read(evidence,name,cap)
 spec=importlib.util.spec_from_file_location('xs_v6_passive_adapters',HERE/'adapters.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A);context=A.bootstrap(get,root,b,m,d);result=A.consumer(get,root,b,context,d);d.tick()
 return dict(schema=1,status='PASS_SCOPED_XS_V6_ORIGINAL_DATA_CHECKS',binding=b,original=origin,source_files=321,prior_source_files=[316,311,305,298],held_files=272,original_files=200,outer_operation=OUTER,frozen_inner_operation=INNER,compiler_image=context['compiler_image'],work_preentry=context['work_preentry'],native_actor_revision='EXACT_BOUNDED_ALPM_DESC_AND_PRIMARY_ERROR_DELTA_ONLY',accepted_pair_input='HISTORICAL_NATIVE_ARM4K_PAIR_ONLY_NO_NEW_PACKAGE_BUILD',consumer=result,Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False,qualification='NOT_GRANTED',install_lifecycle='NOT_QUALIFIED',native16K='NOT_QUALIFIED',M2='NOT_QUALIFIED',performance='NOT_MEASURED',release='NOT_QUALIFIED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ['binding','binding-sha256','source-root','original-artifact','artifact-metadata','evidence']:p.add_argument('--'+n,required=True)
 a=p.parse_args()
 try:print(json.dumps(validate(a),sort_keys=True,indent=2,allow_nan=False))
 except(ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile,RuntimeError)as error:print(json.dumps(dict(status='REFUSED_XS_V6_DATA',reason=type(error).__name__+': '+str(error),Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False)));sys.exit(2)
